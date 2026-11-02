//go:build ignore

// Independent standard-library signer and compact CBOR oracle. Binary fixtures
// stay in files; this driver never transcodes certificates/signatures to text.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

type raw []byte

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 255:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 65535:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = major<<5 | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = major<<5 | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}
func cbor(v any) []byte {
	switch x := v.(type) {
	case raw:
		return x
	case string:
		return append(head(3, uint64(len(x))), []byte(x)...)
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case uint64:
		return head(0, x)
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case []any:
		b := head(4, uint64(len(x)))
		for _, v := range x {
			b = append(b, cbor(v)...)
		}
		return b
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		b := head(5, uint64(len(x)))
		for _, k := range keys {
			b = append(b, cbor(k)...)
			b = append(b, cbor(x[k])...)
		}
		return b
	default:
		panic(fmt.Sprintf("unsupported %T", v))
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: driver C_CONSUMER")
	}
	dir, err := os.MkdirTemp("", "native-manifest-")
	must(err)
	defer os.RemoveAll(dir)
	const principal = "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004"
	service := map[string]any{"a": "app.test", "m": "default", "s": "temperature", "n": "Room", "t": "_sensor._tcp", "p": uint64(7000), "x": []any{"unit=celsius"}}
	body := cbor(map[string]any{"P": uint64(5054), "R": uint64(42), "T": "mtls-v1", "a": []any{map[string]any{"p": uint64(43022), "t": "tls-v1"}}, "c": []any{"sensors"}, "d": "00000000-0000-4000-8000-000000000004", "e": uint64(1800000900000), "i": uint64(1800000000000), "l": "Lite", "n": "interop", "r": map[string]any{"p": "fd45:b891:567f:4000:8000:0:0:4/128", "r": uint64(444), "s": uint64(7)}, "s": []any{service}, "v": uint64(4)})
	preimage := append([]byte("wendy-local-mesh/manifest/4\x00"), 0, 0, 0, 105)
	preimage = append(preimage, []byte(principal)...)
	preimage = append(preimage, body...)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ml, err := mldsa.GenerateKey(mldsa.MLDSA65())
	must(err)
	ml87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	must(err)
	for index, key := range []crypto.Signer{ec, ml, ml87} {
		pub, err := x509.MarshalPKIXPublicKey(key.Public())
		must(err)
		message, opts := preimage, crypto.SignerOpts(crypto.Hash(0))
		if _, ok := key.(*ecdsa.PrivateKey); ok {
			digest := sha256.Sum256(preimage)
			message = digest[:]
			opts = crypto.SHA256
		}
		signature, err := key.Sign(rand.Reader, message, opts)
		must(err)
		wire := cbor(map[string]any{"b": raw(body), "p": principal, "s": signature})
		kp, wp, out := filepath.Join(dir, "public.der"), filepath.Join(dir, "manifest.cbor"), filepath.Join(dir, "c-body.cbor")
		must(os.WriteFile(kp, pub, 0600))
		must(os.WriteFile(wp, wire, 0600))
		args := []string{kp, wp, out}
		if index == 2 {
			args = append(args, "unsupported")
		}
		cmd := exec.Command(os.Args[1], args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		must(cmd.Run())
		if index == 2 {
			continue
		}
		got, err := os.ReadFile(out)
		must(err)
		if !bytes.Equal(got, body) {
			panic("C and Go complete-manifest bodies differ")
		}
	}
}
