package main

// Read-only hardware probe for the restricted nearby setup protocol. It never
// requests a nonce, writes Wi-Fi settings, or reserves a Cloud identity.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wendylabsinc/wendy/go/internal/shared/ble/central"
	"github.com/wendylabsinc/wendy/go/internal/shared/ble/scan"
	"google.golang.org/protobuf/encoding/protowire"
)

func setupBytes(tag protowire.Number, data []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, tag, protowire.BytesType), data)
}
func setupUnwrap(data []byte, expected protowire.Number) ([]byte, error) {
	tag, kind, n := protowire.ConsumeTag(data)
	if n < 0 || tag != expected || kind != protowire.BytesType {
		return nil, fmt.Errorf("unexpected setup message")
	}
	body, m := protowire.ConsumeBytes(data[n:])
	if m < 0 || n+m != len(data) {
		return nil, fmt.Errorf("malformed setup message")
	}
	return body, nil
}
func setupExchange(conn net.Conn, command []byte) ([]byte, error) {
	if len(command) > 65535 {
		return nil, fmt.Errorf("setup frame too large")
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(command)))
	frame = append(frame, command...)
	if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	response := make([]byte, binary.BigEndian.Uint16(header))
	_, err := io.ReadFull(conn, response)
	return response, err
}
func setupProbe(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := scan.DiscoverBluetoothContinuous(ctx, scan.Options{Services: []string{"7565e9eb-4c20-4b67-9272-d708b397b632"}})
	if err != nil {
		return err
	}
	var devices []scan.BLEDeviceInfo
	for snapshot := range stream {
		devices = snapshot
	}
	var candidates []scan.BLEDeviceInfo
	for _, d := range devices {
		if d.Address == name || d.Name == name || (len(d.Name) >= 8 && strings.HasPrefix(name, d.Name)) {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) != 1 {
		return fmt.Errorf("found %d setup devices matching %q", len(candidates), name)
	}
	device := candidates[0]
	conn, err := central.Connect(device.Address, 10)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.OpenL2CAP(131, 10); err != nil {
		return err
	}
	wire := central.NewL2CAPStream(conn)
	// wire.Close owns conn; the defer above handles all paths without a double close.
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hello, err := setupExchange(wire, setupBytes(20, setupBytes(1, key.PublicKey().Bytes())))
	if err != nil {
		return fmt.Errorf("setup hello: %w", err)
	}
	hello, err = setupUnwrap(hello, 21)
	if err != nil {
		return err
	}
	peerBytes, err := setupUnwrap(hello, 1)
	if err != nil {
		return err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return err
	}
	secret, err := key.ECDH(peer)
	if err != nil {
		return err
	}
	salt := append(bytes.Clone(key.PublicKey().Bytes()), peerBytes...)
	keys, err := hkdf.Key(sha256.New, secret, salt, "wendy-ble-setup-v1", 64)
	if err != nil {
		return err
	}
	defer clear(keys)
	defer clear(secret)
	a, _ := aes.NewCipher(keys[:32])
	b, _ := aes.NewCipher(keys[32:])
	write, _ := cipher.NewGCM(a)
	read, _ := cipher.NewGCM(b)
	var counter uint64
	request := func(tag protowire.Number) ([]byte, error) {
		counter++
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[4:], counter)
		sealed := write.Seal(bytes.Clone(nonce), nonce, setupBytes(tag, nil), nil)
		response, err := setupExchange(wire, setupBytes(21, setupBytes(1, sealed)))
		if err != nil {
			return nil, err
		}
		response, err = setupUnwrap(response, 22)
		if err != nil {
			return nil, err
		}
		response, err = setupUnwrap(response, 1)
		if err != nil {
			return nil, err
		}
		if len(response) < 28 || !bytes.Equal(response[:12], nonce) {
			return nil, fmt.Errorf("invalid setup response counter")
		}
		return read.Open(nil, nonce, response[12:], nil)
	}
	raw, err := request(18)
	if err != nil {
		return err
	}
	status, err := setupUnwrap(raw, 19)
	if err != nil {
		return err
	}
	result := map[string]any{"name": device.Name, "address": device.Address, "rssi": device.RSSI, "encryptedSetup": true}
	for len(status) > 0 {
		tag, kind, n := protowire.ConsumeTag(status)
		if n < 0 {
			return fmt.Errorf("invalid status")
		}
		status = status[n:]
		if kind == protowire.BytesType {
			value, n := protowire.ConsumeBytes(status)
			if n < 0 {
				return fmt.Errorf("invalid status")
			}
			status = status[n:]
			if tag == 4 {
				result["deviceClass"] = string(value)
			}
			if tag == 6 {
				result["hardwareId"] = string(value)
			}
		} else if kind == protowire.VarintType {
			value, n := protowire.ConsumeVarint(status)
			if n < 0 {
				return fmt.Errorf("invalid status")
			}
			status = status[n:]
			if tag == 1 {
				result["enrolled"] = value != 0
			}
			if tag == 7 {
				result["liteSupported"] = value != 0
			}
		} else {
			return fmt.Errorf("unexpected status wire type")
		}
	}
	raw, err = request(3)
	if err != nil {
		return err
	}
	wifi, err := setupUnwrap(raw, 3)
	if err != nil {
		return err
	}
	result["wifiConnected"] = len(wifi) >= 2 && wifi[0] == 8 && wifi[1] == 1
	raw, err = request(1)
	if err != nil {
		return err
	}
	networks, err := setupUnwrap(raw, 1)
	if err != nil {
		return err
	}
	count := 0
	for len(networks) > 0 {
		tag, kind, n := protowire.ConsumeTag(networks)
		if n < 0 || tag != 1 || kind != protowire.BytesType {
			return fmt.Errorf("invalid Wi-Fi list")
		}
		_, m := protowire.ConsumeBytes(networks[n:])
		if m < 0 {
			return fmt.Errorf("invalid Wi-Fi list")
		}
		networks = networks[n+m:]
		count++
	}
	result["wifiNetworks"] = count
	return json.NewEncoder(os.Stdout).Encode(result)
}
