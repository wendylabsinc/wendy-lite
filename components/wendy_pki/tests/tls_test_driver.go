//go:build ignore

// Exercise the actual firmware TLS adapter against Go's independent TLS stack.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var nativeComposedApplication func(*tls.Conn, bool)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	directory, err := os.MkdirTemp("", "lite-tls-")
	must(err)
	defer os.RemoveAll(directory)
	profile := "p256"
	if len(os.Args) > 2 {
		profile = os.Args[2]
	}
	if profile == "mixed87" {
		exerciseMixedMLDSACAs(directory)
		return
	}
	newIssuer := func() (crypto.Signer, error) {
		switch profile {
		case "p256":
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "mldsa65":
			return mldsa.GenerateKey(mldsa.MLDSA65())
		default:
			return nil, fmt.Errorf("unknown issuer profile %q", profile)
		}
	}
	rootKey, err := newIssuer()
	must(err)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	must(os.WriteFile(filepath.Join(directory, "root.pem"), rootPEM, 0600))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	liteRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	liteRoot := *root
	liteRoot.Subject = pkix.Name{CommonName: "separate Lite operator authority"}
	liteRootDER, err := x509.CreateCertificate(rand.Reader, &liteRoot, &liteRoot, liteRootKey.Public(), liteRootKey)
	must(err)
	must(os.WriteFile(filepath.Join(directory, "lite-root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: liteRootDER}), 0600))
	leaf := func(name string, expiry time.Time, usages []x509.ExtKeyUsage, uri string, issuer crypto.Signer, parent *x509.Certificate, signature x509.SignatureAlgorithm) (tls.Certificate, []byte, []byte) {
		var key crypto.Signer
		var err error
		if os.Getenv("WENDY_TLS_OWN_MLDSA65") == "1" {
			key, err = mldsa.GenerateKey(mldsa.MLDSA65())
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		must(err)
		u, err := url.Parse(uri)
		must(err)
		template := &x509.Certificate{SignatureAlgorithm: signature, SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{"localhost"}, URIs: []*url.URL{u}}
		if strings.HasPrefix(name, "lite-") && name != "lite-unmarked" {
			template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 65441, 1, 9}}
		}
		switch name {
		case "lan-device-ca":
			template.IsCA, template.BasicConstraintsValid = true, true
			template.KeyUsage |= x509.KeyUsageCertSign
		case "lan-device-duplicate-uri":
			template.URIs = []*url.URL{u, u}
		case "lan-device-extra-uri":
			other, err := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/operator/user")
			must(err)
			template.URIs = []*url.URL{u, other}
		case "lan-device-missing-uri":
			template.URIs = nil
		case "lan-device-future":
			template.NotBefore = time.Now().Add(time.Minute)
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuer)
		must(err)
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, raw, certPEM
	}
	tenant := "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/"
	serverUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if os.Getenv("WENDY_TLS_OWNED_STREAM") != "" {
		serverUsages = append(serverUsages, x509.ExtKeyUsageClientAuth)
	}
	_, keyDER, serverPEM := leaf("device", time.Now().Add(time.Hour), serverUsages, tenant+"device/00000000-0000-4000-8000-000000000004", rootKey, root, 0)
	must(os.WriteFile(filepath.Join(directory, "key.der"), keyDER, 0600))
	must(os.WriteFile(filepath.Join(directory, "server.pem"), serverPEM, 0600))
	cases := []string{"valid", "wrong-tenant", "wrong-role", "wrong-eku", "expired", "untrusted", "no-client", "tls12", "truncate", "extra", "intermediate", "intermediate-key-usage", "intermediate-not-ca", "intermediate-path-length", "intermediate-expired", "intermediate-sha1", "relay-valid", "relay-operator-expiry", "relay-device-expiry", "relay-wrong-key", "relay-old", "relay-wlg2", "relay-truncated", "relay-expired", "relay-long-presentation", "relay-device-client",
		"lan-operator", "lan-device", "lan-device-wrong-tenant", "lan-device-wrong-eku", "lan-device-missing-eku",
		"lan-device-ca", "lan-device-duplicate-uri", "lan-device-extra-uri", "lan-device-missing-uri",
		"lan-device-expired", "lan-device-future", "lan-device-untrusted", "lan-device-tampered", "lan-no-client",
		"lite-valid", "lite-wrong-role", "lite-wrong-tenant", "lite-unmarked", "lite-extra-eku", "lite-untrusted", "lite-primary-operator", "lite-lan-device",
		"stream-valid", "stream-wrong-tenant", "stream-device", "stream-no-client", "stream-expired", "stream-untrusted", "stream-tls12", "stream-timeout"}
	for _, name := range cases {
		if os.Getenv("WENDY_TLS_NORMAL_ONLY") == "1" && name != "stream-valid" {
			continue
		}
		if os.Getenv("WENDY_TLS_OWNED_STREAM") != "" && !strings.HasPrefix(name, "stream-") {
			continue
		}
		expiry := time.Now().Add(time.Hour)
		usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		uri := tenant + "operator/11111111-1111-4111-8111-111111111111"
		issuer := rootKey
		if strings.HasPrefix(name, "lan-device") || name == "relay-device-client" {
			uri = tenant + "device/consumer-agent"
		}
		parent := root
		if strings.HasPrefix(name, "lite-") && name != "lite-primary-operator" {
			issuer, parent = liteRootKey, &liteRoot
		}
		var chain [][]byte
		if strings.HasPrefix(name, "intermediate") {
			levels := 1
			if name == "intermediate-path-length" {
				levels = 2
			}
			for level := 0; level < levels; level++ {
				caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(e)
				ca := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + level)), Subject: pkix.Name{CommonName: fmt.Sprintf("intermediate %d", level)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: name != "intermediate-not-ca", BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
				if name == "intermediate-key-usage" {
					ca.KeyUsage = x509.KeyUsageDigitalSignature
				}
				if !ca.IsCA {
					ca.MaxPathLen = -1
					ca.MaxPathLenZero = false
				}
				if name == "intermediate-expired" {
					ca.NotAfter = time.Now().Add(-time.Minute)
				}
				der, e := x509.CreateCertificate(rand.Reader, ca, parent, caKey.Public(), issuer)
				must(e)
				chain = append([][]byte{der}, chain...)
				parent, issuer = ca, caKey
			}
		}
		switch name {
		case "relay-operator-expiry":
			expiry = time.Now().Add(90 * time.Second)
		case "expired", "lan-device-expired", "stream-expired":
			expiry = time.Now().Add(-time.Minute)
		case "wrong-tenant", "lan-device-wrong-tenant", "lite-wrong-tenant", "stream-wrong-tenant":
			uri = strings.Replace(uri, "2558fd76", "3558fd76", 1)
		case "wrong-role", "lite-wrong-role", "lite-lan-device", "stream-device":
			uri = tenant + "device/00000000-0000-4000-8000-000000000004"
		case "wrong-eku", "lan-device-wrong-eku":
			usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "lan-device-missing-eku":
			usages = nil
		case "lite-extra-eku":
			usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		case "untrusted", "lan-device-untrusted", "lite-untrusted", "stream-untrusted":
			issuer, err = newIssuer()
			must(err)
		}
		var signature x509.SignatureAlgorithm
		if name == "intermediate-sha1" {
			signature = x509.ECDSAWithSHA1
		}
		cert, _, _ := leaf(name, expiry, usages, uri, issuer, parent, signature)
		if name == "lan-device-tampered" {
			cert.Certificate[0][len(cert.Certificate[0])-1] ^= 1
		}
		cert.Certificate = append(cert.Certificate, chain...)
		mode := "reject"
		if name == "valid" || name == "intermediate" || name == "truncate" || name == "extra" {
			mode = name
			if name == "intermediate" {
				mode = "valid"
			}
		}
		if name == "lan-device" {
			mode = "valid-device"
		}
		if name == "lan-operator" {
			mode = "valid"
		}
		if name == "lite-valid" || name == "stream-valid" {
			mode = "valid"
		}
		args := []string{filepath.Join(directory, "key.der"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "root.pem"), mode}
		var grant []byte
		if strings.HasPrefix(name, "lan-") {
			args[3] = "lan-" + mode
		}
		if strings.HasPrefix(name, "lite-") {
			args[2], args[3] = filepath.Join(directory, "lite-root.pem"), "lite-"+mode
			if name == "lite-lan-device" {
				args[2], args[3] = filepath.Join(directory, "root.pem"), "lan-reject"
			}
		}
		stream := strings.HasPrefix(name, "stream-")
		if stream {
			args[3] = "stream-" + mode
			if name == "stream-timeout" {
				args[3] = "stream-timeout"
			}
		}
		relay := strings.HasPrefix(name, "relay-") && name != "relay-device-client"
		if relay {
			mode = "relay-reject"
			if name == "relay-valid" || name == "relay-operator-expiry" || name == "relay-device-expiry" {
				mode = "relay"
			}
			args[3] = mode
			signer, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(e)
			issued := time.Now().Unix()
			if name == "relay-expired" {
				issued -= 120
			}
			presentBy := issued + 60
			if name == "relay-long-presentation" {
				presentBy = issued + 61
			}
			// WLG3 is the only accepted layout; relay-wlg2 is a correctly
			// signed record of the retired layout with its asset UUID.
			magic, ids := "WLG3", 2
			if name == "relay-wlg2" {
				magic, ids = "WLG2", 3
			}
			grant = append([]byte(magic), 4)
			grant = append(grant, []byte("test")...)
			grant = binary.BigEndian.AppendUint64(grant, uint64(issued))
			grant = binary.BigEndian.AppendUint64(grant, uint64(presentBy))
			var session [16]byte
			_, e = rand.Read(session[:])
			must(e)
			grant = append(grant, session[:]...)
			// jti and correlation ID (plus the asset ID for WLG2).
			for range ids {
				id := make([]byte, 16)
				_, e = rand.Read(id)
				must(e)
				grant = append(grant, id...)
			}
			deviceHash := sha256.Sum256([]byte(tenant + "device/00000000-0000-4000-8000-000000000004"))
			operatorHash := sha256.Sum256([]byte(uri))
			publicKey := cert.PrivateKey.(crypto.Signer).Public()
			if name == "relay-wrong-key" {
				other, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(e)
				publicKey = other.Public() // Same authenticated URI, different bound key.
			}
			spki, e := x509.MarshalPKIXPublicKey(publicKey)
			must(e)
			spkiHash := sha256.Sum256(spki)
			for _, h := range [][32]byte{deviceHash, operatorHash, spkiHash, sha256.Sum256([]byte("principal")), sha256.Sum256([]byte("attestation"))} {
				grant = append(grant, h[:]...)
			}
			if name == "relay-old" {
				grant = grant[:149+4]
			}
			digest := sha256.Sum256(grant)
			r, ss, e := ecdsa.Sign(rand.Reader, signer, digest[:])
			must(e)
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			ss.FillBytes(sig[32:])
			grant = append(grant, sig...)
			grantHash := sha256.Sum256(grant)
			trust := elliptic.Marshal(elliptic.P256(), signer.X, signer.Y)
			trust = append(trust, session[:]...)
			trust = append(trust, grantHash[:]...)
			trust = append(trust, deviceHash[:]...)
			trustPath := filepath.Join(directory, "trust.bin")
			must(os.WriteFile(trustPath, trust, 0600))
			deviceExpiry := time.Now().Add(time.Hour).Unix()
			if name == "relay-device-expiry" {
				deviceExpiry = time.Now().Add(120 * time.Second).Unix()
			}
			sessionExpiry := min(issued+1800, expiry.Unix(), deviceExpiry)
			args = append(args, trustPath, fmt.Sprint(deviceExpiry), fmt.Sprint(sessionExpiry))
			if name == "relay-truncated" {
				grant = grant[:len(grant)-1]
			}
		}
		cmd := exec.Command(os.Args[1], args...)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		must(err)
		must(cmd.Start())
		line, err := bufio.NewReader(stdout).ReadString('\n')
		must(err)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
		must(err)
		must(conn.SetDeadline(time.Now().Add(4 * time.Second)))
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{cert}}
		if name == "no-client" || name == "lan-no-client" || name == "stream-no-client" {
			cfg.Certificates = nil
		}
		if name == "tls12" || name == "stream-tls12" {
			cfg.MinVersion = tls.VersionTLS12
			cfg.MaxVersion = tls.VersionTLS12
		}
		client := tls.Client(conn, cfg)
		handshake := client.Handshake()
		if mode != "reject" {
			must(handshake)
			if relay {
				_, err = client.Write(grant)
				must(err)
				if name == "relay-truncated" || name == "relay-old" {
					must(client.CloseWrite())
				}
				var ack [4]byte
				_, err = io.ReadFull(client, ack[:])
				if mode == "relay" {
					must(err)
					if string(ack[:]) != "WLA2" {
						panic("invalid grant ack")
					}
				} else if err == nil {
					panic("invalid relay grant accepted")
				}
			} else if stream {
				_, err = client.Write([]byte("hello"))
				must(err)
				var response [5]byte
				_, err = io.ReadFull(client, response[:])
				must(err)
				if string(response[:]) != "world" {
					panic("invalid stream application data")
				}
			} else {
				switch name {
				case "truncate":
					conn.Close()
				case "extra":
					_, err = client.Write([]byte("unexpected"))
					must(err)
				default:
					must(client.CloseWrite())
					var b [1]byte
					_, err = client.Read(b[:])
					if err != io.EOF {
						panic(fmt.Sprintf("expected close_notify, got %v", err))
					}
					must(conn.SetDeadline(time.Now().Add(4 * time.Second)))
					_, err = conn.Write([]byte("raw"))
					must(err)
				}
			}
		}
		if mode == "reject" {
			if handshake == nil {
				var b [1]byte
				_, _ = client.Read(b[:])
			}
		}
		conn.Close()
		if err = cmd.Wait(); err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		fmt.Println("PASS", profile, name)
	}
	if profile == "mldsa65" {
		exerciseMixedMLDSACAs(directory)
	}

	// Exercise the firmware's outbound role. Three ML-DSA-65 intermediates
	// cross the TLS record boundary, with a P-256 device key.
	issuer, parent := rootKey, root
	var middleIssuer crypto.Signer
	var middleCA *x509.Certificate
	chain := [][]byte{rootDER}
	for level := range 3 {
		caKey, e := newIssuer()
		must(e)
		ca := &x509.Certificate{SerialNumber: big.NewInt(int64(200 + level)), Subject: pkix.Name{CommonName: fmt.Sprintf("outbound intermediate %d", level)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, ca, parent, caKey.Public(), issuer)
		must(e)
		if level == 2 {
			// A different but cryptographically valid issuer with the same
			// subject/key and DER length must still fail the exact verified
			// presentation binding if the source changes after verification.
			alternative := *ca
			alternative.SerialNumber = big.NewInt(203)
			var changed []byte
			for range 128 {
				changed, e = x509.CreateCertificate(rand.Reader, &alternative, parent, caKey.Public(), issuer)
				must(e)
				if len(changed) == len(der) {
					break
				}
			}
			if len(changed) != len(der) {
				panic("could not match alternative issuer length")
			}
			must(os.WriteFile(filepath.Join(directory, "alternative-own-issuer.der"), changed, 0600))
		}
		chain = append([][]byte{der}, chain...)
		parent, issuer = ca, caKey
		if level == 1 {
			middleIssuer = caKey
			middleCA = ca
		}
	}
	otherKey, err := newIssuer()
	must(err)
	otherCA := &x509.Certificate{SerialNumber: big.NewInt(999), Subject: pkix.Name{CommonName: "different tenant identity tier"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherCA, middleCA, otherKey.Public(), middleIssuer)
	must(err)
	device, deviceKey, devicePEM := leaf("outbound device", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, tenant+"device/00000000-0000-4000-8000-000000000004", issuer, parent, 0)
	chain = append(device.Certificate, chain...)
	chainBytes := 0
	for index, der := range chain {
		chainBytes += len(der)
		if index > 0 {
			devicePEM = append(devicePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
	}
	if profile != "p256" && chainBytes <= 16384 {
		panic("outbound ML-DSA fixture must exceed one TLS record")
	}
	must(os.WriteFile(filepath.Join(directory, "outbound-key.der"), deviceKey, 0600))
	must(os.WriteFile(filepath.Join(directory, "outbound-device.pem"), devicePEM, 0600))

	// The broker's HTTPS identity is independent of the device enrollment CA.
	// A P-384 issuer also covers the public server-chain verification path.
	serverCAKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(err)
	serverCA := &x509.Certificate{SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: "outbound server CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	serverCADER, err := x509.CreateCertificate(rand.Reader, serverCA, serverCA, serverCAKey.Public(), serverCAKey)
	must(err)
	must(os.WriteFile(filepath.Join(directory, "outbound-root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCADER}), 0600))
	broker, _, _ := leaf("localhost", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, tenant+"device/broker-test", serverCAKey, serverCA, 0)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer listener.Close()
	must(listener.SetDeadline(time.Now().Add(10 * time.Second)))
	cmd := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"), filepath.Join(directory, "outbound-device.pem"), filepath.Join(directory, "outbound-root.pem"), "connect", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	must(cmd.Start())
	defer cmd.Process.Kill()
	raw, err := listener.Accept()
	must(err)
	defer raw.Close()
	must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
	if len(os.Args) > 3 && os.Args[3] == "slow-uplink" {
		must(raw.SetDeadline(time.Now().Add(30 * time.Second)))
		time.Sleep(16 * time.Second)
	}
	server := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{broker}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		// Keep default session tickets enabled. The firmware must not negotiate
		// unused PSK resumption and then reject a fragmented post-handshake ticket.
	})
	must(server.Handshake())
	state := server.ConnectionState()
	if len(state.PeerCertificates) != len(chain) || len(state.VerifiedChains) == 0 {
		panic("outbound client chain was not authenticated")
	}
	var hello [5]byte
	_, err = io.ReadFull(server, hello[:])
	must(err)
	if string(hello[:]) != "hello" {
		panic("invalid outbound application data")
	}
	_, err = server.Write([]byte("world"))
	must(err)
	must(cmd.Wait())
	fmt.Printf("PASS %s outbound-short-writes chain_bytes=%d certificates=%d cipher=%s\n", profile, chainBytes, len(chain), tls.CipherSuiteName(state.CipherSuite))
	for _, protocol := range []string{"wendy-net-endpoint/2", "wendy-app-mesh-tls/1", "wendy-local-mesh-ble/2"} {
		// Native mesh TLS consumes temporary key/PEM input before handshake.
		for _, test := range []struct {
			name, mode                                                      string
			wrongDevice, tampered, expired                                  bool
			tamperedIssuer                                                  int
			derInput, corruptSource, corruptPublic, reloadTrust, lateSource bool
			stream, unknownPeer, wrongTenant, selfPeer                      bool
		}{
			{name: "borrowed-input", mode: "connect-net"},
			{name: "verified-input", mode: "connect-net-verified"},
			{name: "parsed-input", mode: "connect-net-parsed"},
			{name: "lazy-der-input", mode: "connect-net-parsed", derInput: true},
			{name: "corrupt-lazy-own-chain", mode: "connect-net-parsed", derInput: true, corruptSource: true},
			{name: "corrupt-public-binding", mode: "connect-net-parsed", derInput: true, corruptPublic: true},
			{name: "changed-verified-own-issuer", mode: "connect-net-reject", derInput: true, lateSource: true},
			{name: "lazy-trust", mode: "connect-net-parsed", derInput: true, reloadTrust: true},
			{name: "router-byte-stream", mode: "connect-net-parsed", derInput: true, reloadTrust: true, stream: true},
			{name: "router-stream-short-hint", mode: "connect-net-parsed", derInput: true, reloadTrust: true, stream: true, unknownPeer: true},
			{name: "router-stream-wrong-device", mode: "connect-net-reject", derInput: true, stream: true, wrongDevice: true},
			{name: "router-stream-wrong-tenant", mode: "connect-net-reject", derInput: true, stream: true, unknownPeer: true, wrongTenant: true},
			{name: "router-stream-self", mode: "connect-net-reject", derInput: true, stream: true, unknownPeer: true, selfPeer: true},
			{name: "wrong-device", mode: "connect-net-reject", wrongDevice: true},
			{name: "tampered-leaf", mode: "connect-net-reject", tampered: true},
			{name: "expired-leaf", mode: "connect-net-reject", expired: true},
			{name: "tampered-first-issuer", mode: "connect-net-reject", tamperedIssuer: 1},
			{name: "tampered-last-issuer", mode: "connect-net-reject", tamperedIssuer: 3},
		} {
			if os.Getenv("WENDY_TLS_NORMAL_ONLY") == "1" &&
				(test.wrongDevice || test.tampered || test.expired || test.tamperedIssuer != 0 ||
					test.corruptSource || test.corruptPublic || test.lateSource || test.wrongTenant || test.selfPeer) {
				continue
			}
			if (test.corruptPublic || test.reloadTrust || test.stream) && protocol != "wendy-local-mesh-ble/2" {
				continue
			}
			if protocol == "wendy-app-mesh-tls/1" {
				if strings.HasSuffix(test.mode, "reject") {
					test.mode = "connect-app-reject"
				} else {
					test.mode = "connect-app"
				}
			}
			principal := tenant + "device/00000000-0000-4000-8000-000000000005"
			if test.wrongDevice {
				principal = tenant + "device/00000000-0000-4000-8000-000000000006"
			}
			if test.selfPeer {
				principal = tenant + "device/00000000-0000-4000-8000-000000000004"
			}
			if test.wrongTenant {
				principal = "spiffe://wendy.sh/tenant/3558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000005"
			}
			expiry := time.Now().Add(time.Hour)
			if test.expired {
				expiry = time.Now().Add(-time.Hour)
			}
			peer, _, _ := leaf("native peer", expiry,
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				principal, issuer, parent, 0)
			if test.tampered {
				peer.Certificate[0][len(peer.Certificate[0])-1] ^= 1
			}
			peer.Certificate = append(peer.Certificate, chain[1:]...)
			if test.tamperedIssuer > 0 {
				i := test.tamperedIssuer
				peer.Certificate[i] = append([]byte(nil), peer.Certificate[i]...)
				peer.Certificate[i][len(peer.Certificate[i])-1] ^= 1
			}
			listen, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			must(e)
			must(listen.SetDeadline(time.Now().Add(10 * time.Second)))
			command := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"),
				filepath.Join(directory, "outbound-device.pem"), filepath.Join(directory, "root.pem"),
				test.mode, fmt.Sprint(listen.Addr().(*net.TCPAddr).Port))
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if test.derInput {
				command.Env = append(os.Environ(), "WENDY_TLS_DER_INPUT=1")
			}
			if test.corruptSource {
				command.Env = append(command.Env, "WENDY_TLS_DER_CORRUPT=1")
			}
			if test.lateSource {
				command.Env = append(command.Env, "WENDY_TLS_LATE_DER_PATH="+filepath.Join(directory, "alternative-own-issuer.der"))
			}
			if protocol == "wendy-local-mesh-ble/2" {
				if command.Env == nil {
					command.Env = os.Environ()
				}
				command.Env = append(command.Env, "WENDY_TLS_ROUTER=1")
			}
			if test.corruptPublic {
				command.Env = append(command.Env, "WENDY_TLS_PUBLIC_CORRUPT=1")
			}
			if test.reloadTrust {
				command.Env = append(command.Env, "WENDY_TLS_RELOAD_TRUST=1")
			}
			if test.stream {
				command.Env = append(command.Env, "WENDY_TLS_ROUTER_STREAM=1")
			}
			if test.unknownPeer {
				command.Env = append(command.Env, "WENDY_TLS_UNKNOWN_PEER=1")
			}
			must(command.Start())
			if test.corruptSource || test.corruptPublic {
				connected := make(chan bool, 1)
				go func() {
					raw, err := listen.Accept()
					if err == nil {
						raw.Close()
					}
					connected <- err == nil
				}()
				must(command.Wait())
				listen.Close()
				if <-connected {
					panic("invalid cached own chain reached TCP dial")
				}
				continue
			}
			raw, e := listen.Accept()
			must(e)
			listen.Close()
			must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
			secure := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{peer}, ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs: pool, NextProtos: []string{protocol}, SessionTicketsDisabled: true})
			handshakeError := secure.Handshake()
			if strings.HasSuffix(test.mode, "-reject") {
				if handshakeError == nil {
					var byte [1]byte
					n, e := secure.Read(byte[:])
					if n != 0 || e == nil {
						panic("rejected native peer sent application data")
					}
				}
				must(command.Wait())
				secure.Close()
				fmt.Printf("PASS %s native mesh rejects %s\n", profile, test.name)
				continue
			}
			must(handshakeError)
			if len(secure.ConnectionState().PeerCertificates) != len(chain)-1 {
				panic("native client should omit its pinned root from the presented chain")
			}
			var request [5]byte
			_, e = io.ReadFull(secure, request[:])
			must(e)
			if string(request[:]) != "hello" {
				panic("invalid native TLS application data")
			}
			_, e = secure.Write([]byte("world"))
			must(e)
			bulkEcho(secure)
			must(command.Wait())
			secure.Close()
			fmt.Printf("PASS %s native mesh owned-input TLS %s\n", profile, test.name)
		}
		for _, ownedLAN := range []bool{false, true} {
			if ownedLAN && protocol != "wendy-net-endpoint/2" {
				continue
			}
			for _, test := range []string{"valid", "other-issuer", "other-operator-issuer", "wrong-tenant", "operator", "expired", "tampered", "no-client", "wrong-alpn", "self"} {
				if os.Getenv("WENDY_TLS_NORMAL_ONLY") == "1" && test != "valid" && test != "other-issuer" &&
					!(ownedLAN && (test == "operator" || test == "other-operator-issuer")) {
					continue
				}
				if ownedLAN && (test == "wrong-alpn" || test == "self") {
					continue
				}
				valid := test == "valid" || test == "other-issuer" || (ownedLAN && (test == "operator" || test == "other-operator-issuer"))
				uri := tenant + "device/00000000-0000-4000-8000-000000000005"
				expiry := time.Now().Add(time.Hour)
				if test == "wrong-tenant" {
					uri = "spiffe://wendy.sh/tenant/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/device/00000000-0000-4000-8000-000000000005"
				}
				if test == "operator" || test == "other-operator-issuer" {
					uri = tenant + "operator/11111111-1111-4111-8111-111111111111"
					if os.Getenv("WENDY_TLS_OPERATOR_OPAQUE") == "1" {
						uri = tenant + "operator/oidc%7Calice"
					}
				}
				if test == "self" {
					uri = tenant + "device/00000000-0000-4000-8000-000000000004"
				}
				if test == "expired" {
					expiry = time.Now().Add(-time.Hour)
				}
				peerIssuer, peerParent := issuer, parent
				if strings.HasPrefix(test, "other-") {
					peerIssuer = otherKey
					peerParent = otherCA
				}
				peer, _, _ := leaf("native accepting client", expiry, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, uri, peerIssuer, peerParent, 0)
				if strings.HasPrefix(test, "other-") {
					peer.Certificate = append(peer.Certificate, otherDER)
					peer.Certificate = append(peer.Certificate, chain[2:]...)
				} else {
					peer.Certificate = append(peer.Certificate, chain[1:]...)
				}
				if test == "tampered" {
					peer.Certificate[0][len(peer.Certificate[0])-1] ^= 1
				}
				mode := "native-net-reject"
				if valid {
					mode = "native-net-valid"
				}
				if ownedLAN {
					mode = strings.Replace(mode, "native-net-", "owned-lan-", 1)
				}
				if protocol == "wendy-app-mesh-tls/1" {
					mode = strings.Replace(mode, "native-net-", "app-net-", 1)
				}
				command := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"), filepath.Join(directory, "outbound-device.pem"), filepath.Join(directory, "root.pem"), mode)
				if protocol == "wendy-local-mesh-ble/2" {
					command.Env = append(os.Environ(), "WENDY_TLS_ROUTER=1", "WENDY_TLS_DER_INPUT=1", "WENDY_TLS_RELOAD_TRUST=1")
					if test == "valid" || test == "wrong-tenant" || test == "self" || test == "no-client" {
						command.Env = append(command.Env, "WENDY_TLS_ROUTER_STREAM=1")
					}
				}
				if ownedLAN {
					role := "device"
					if test == "operator" || test == "other-operator-issuer" {
						role = "operator"
					}
					command.Env = append(os.Environ(), "WENDY_TLS_DER_INPUT=1", "WENDY_TLS_EXPECT_ROLE="+role)
				}
				stdout, e := command.StdoutPipe()
				must(e)
				command.Stderr = os.Stderr
				must(command.Start())
				line, e := bufio.NewReader(stdout).ReadString('\n')
				must(e)
				port, e := strconv.Atoi(strings.TrimSpace(line))
				must(e)
				config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", NextProtos: []string{protocol}, Certificates: []tls.Certificate{peer}, SessionTicketsDisabled: true}
				if ownedLAN {
					config.NextProtos = nil
					if os.Getenv("WENDY_TLS_LARGE_FIRST_RECORD") == "1" {
						config.DynamicRecordSizingDisabled = true
					}
				}
				if test == "no-client" {
					config.Certificates = nil
				}
				if test == "wrong-alpn" {
					config.NextProtos = []string{"unrelated/1"}
				}
				raw, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
				must(e)
				must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
				secure := tls.Client(raw, config)
				handshakeError := secure.Handshake()
				if ownedLAN && os.Getenv("WENDY_TLS_CV_CANCEL") == "1" {
					// The ordinary application owner turns mesh OFF during its own
					// pending CertificateVerify output. No malformed peer traffic.
					if handshakeError == nil {
						panic("owner cancellation did not interrupt the pending handshake")
					}
					secure.Close()
					must(command.Wait())
					fmt.Printf("PASS %s ordinary owner OFF during CertificateVerify %s\n", profile, test)
					continue
				}
				if valid {
					must(handshakeError)
					if ownedLAN && os.Getenv("WENDY_TLS_CLOSE_WITHOUT_APP") == "1" {
						// Normal TLS close immediately after authentication.
					} else if ownedLAN && nativeComposedApplication != nil {
						nativeComposedApplication(secure, test == "operator" || test == "other-operator-issuer")
					} else {
						_, e = secure.Write([]byte("hello"))
						must(e)
						var response [5]byte
						_, e = io.ReadFull(secure, response[:])
						must(e)
						if string(response[:]) != "world" {
							panic("native accept response mismatch")
						}
						bulkEcho(secure)
					}
				} else if handshakeError == nil {
					var response [1]byte
					n, e := secure.Read(response[:])
					if n != 0 || e == nil {
						panic("native accept granted rejected client data")
					}
				}
				secure.Close()
				must(command.Wait())
				fmt.Printf("PASS %s native accepting TLS %s\n", profile, test)
			}

		}
	}
	operator, operatorKey, operatorPEM := leaf("large-chain operator", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, tenant+"operator/11111111-1111-4111-8111-111111111111", rootKey, root, 0)
	exerciseLargeServerStream(directory, profile, pool, operator, chainBytes, len(chain))
	if os.Getenv("WENDY_TLS_NORMAL_ONLY") == "1" {
		return
	}
	if profile == "mldsa65" {
		must(os.WriteFile(filepath.Join(directory, "operator-key.der"), operatorKey, 0600))
		must(os.WriteFile(filepath.Join(directory, "operator-chain.pem"), append(operatorPEM, rootPEM...), 0600))
		exerciseRecordFragmentedPeer(directory)
		exerciseTruncatedOutboundCertificate(directory, broker, pool)
		largeOperator, _, _ := leaf("oversized operator", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, tenant+"operator/11111111-1111-4111-8111-111111111111", issuer, parent, 0)
		largeOperator.Certificate = append(largeOperator.Certificate, chain[1:]...)
		// Repeating the trusted root preserves a valid certification path but
		// forces the Certificate message over the bounded reassembly buffer.
		for size := chainBytes; size <= 32768; size += len(rootDER) {
			largeOperator.Certificate = append(largeOperator.Certificate, rootDER)
		}
		exerciseOversizedIncomingCertificate(directory, pool, largeOperator)
	}
	if profile == "p256" {
		exerciseEnrollmentHTTP(directory, broker, pool)
	}
}

func exerciseRecordFragmentedPeer(directory string) {
	server := exec.Command(os.Args[1], filepath.Join(directory, "key.der"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "root.pem"), "stream-valid")
	server.Stderr = os.Stderr
	stdout, err := server.StdoutPipe()
	must(err)
	must(server.Start())
	defer server.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	must(err)
	client := exec.Command(os.Args[1], filepath.Join(directory, "operator-key.der"), filepath.Join(directory, "operator-chain.pem"), filepath.Join(directory, "root.pem"), "fragment-client", strings.TrimSpace(line))
	client.Stdout, client.Stderr = os.Stdout, os.Stderr
	must(client.Run())
	must(server.Wait())
	fmt.Println("PASS mldsa65 incoming-512-byte-records")
}

// Enrollment CAs use 87 at the root/customer tiers and 65 at the tenant and
// identity tiers. Exercise that complete chain with a P-256 device and a real
// ML-DSA-65 operator CertificateVerify, rather than only P-256 operator keys.
func exerciseMixedMLDSACAs(directory string) {
	newKey := func(params mldsa.Parameters) *mldsa.PrivateKey {
		key, err := mldsa.GenerateKey(params)
		must(err)
		return key
	}
	rootKey := newKey(mldsa.MLDSA87())
	newCA := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	root := newCA(500, "mixed ML-DSA-87 root")
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	rootPath := filepath.Join(directory, "mixed-root.pem")
	must(os.WriteFile(rootPath, rootPEM, 0600))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	parent, issuer := root, rootKey
	var chain [][]byte
	for index, params := range []mldsa.Parameters{mldsa.MLDSA87(), mldsa.MLDSA65(), mldsa.MLDSA65()} {
		key := newKey(params)
		ca := newCA(int64(501+index), fmt.Sprintf("mixed intermediate %d", index))
		der, err := x509.CreateCertificate(rand.Reader, ca, parent, key.Public(), issuer)
		must(err)
		chain = append([][]byte{der}, chain...)
		parent, issuer = ca, key
	}
	leafSerial := int64(510)
	makeLeaf := func(key crypto.Signer, role string) tls.Certificate {
		subject := "mixed-test"
		if role == "device" && os.Getenv("WENDY_TLS_OWNED_STREAM") != "" {
			subject = "00000000-0000-4000-8000-000000000004"
		}
		uri, err := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/" + role + "/" + subject)
		must(err)
		template := &x509.Certificate{SerialNumber: big.NewInt(leafSerial), Subject: pkix.Name{CommonName: "mixed " + role}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{"localhost"}, URIs: []*url.URL{uri}}
		if role == "device" {
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		}
		leafSerial++
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuer)
		must(err)
		return tls.Certificate{Certificate: append([][]byte{der}, chain...), PrivateKey: key}
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	device := makeLeaf(deviceKey, "device")
	deviceKeyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	must(err)
	keyPath, serverPath := filepath.Join(directory, "mixed-device-key.der"), filepath.Join(directory, "mixed-device.pem")
	must(os.WriteFile(keyPath, deviceKeyDER, 0600))
	var serverPEM []byte
	for _, der := range device.Certificate {
		serverPEM = append(serverPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	must(os.WriteFile(serverPath, serverPEM, 0600))
	for _, name := range []string{"valid-65-operator", "tampered-87-intermediate", "tampered-87-issuer-signature", "reject-87-operator", "reject-44-operator"} {
		if os.Getenv("WENDY_TLS_NORMAL_ONLY") == "1" && name != "valid-65-operator" {
			continue
		}
		params := mldsa.MLDSA65()
		if name == "reject-87-operator" {
			params = mldsa.MLDSA87()
		}
		if name == "reject-44-operator" {
			params = mldsa.MLDSA44()
		}
		operator := makeLeaf(newKey(params), "operator")
		if name == "tampered-87-intermediate" || name == "tampered-87-issuer-signature" {
			index := 3 // Customer CA signed by the ML-DSA-87 root.
			if name == "tampered-87-issuer-signature" {
				index = 2 // Tenant CA signed by the ML-DSA-87 customer CA.
			}
			operator.Certificate[index] = append([]byte{}, operator.Certificate[index]...)
			operator.Certificate[index][len(operator.Certificate[index])-1] ^= 1
		}
		chainBytes := 0
		for _, der := range operator.Certificate {
			chainBytes += len(der)
		}
		if chainBytes <= 16384 {
			panic("complete mixed CA operator chain must cross the 16 KiB TLS record boundary")
		}
		mode := "stream-reject"
		if name == "valid-65-operator" {
			mode = "stream-valid"
		}
		command := exec.Command(os.Args[1], keyPath, serverPath, rootPath, mode)
		var sessionLogs bytes.Buffer
		command.Stderr = io.MultiWriter(os.Stderr, &sessionLogs)
		stdout, err := command.StdoutPipe()
		must(err)
		must(command.Start())
		reader := bufio.NewReader(stdout)
		repeat := 1
		if count := os.Getenv("WENDY_TLS_NORMAL_REPEAT"); count != "" {
			repeat, err = strconv.Atoi(count)
			must(err)
			if os.Getenv("WENDY_TLS_NORMAL_ONLY") != "1" || repeat < 1 || repeat > 8 {
				panic("invalid normal reconnect bounds")
			}
		}
		for iteration := 0; iteration < repeat; iteration++ {
			line, err := reader.ReadString('\n')
			must(err)
			raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
			must(err)
			must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
			requested := false
			client := tls.Client(raw, &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				RootCAs: pool, ServerName: "localhost",
				GetClientCertificate: func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					requested = true
					found65 := false
					for _, algorithm := range request.SignatureSchemes {
						if algorithm == tls.MLDSA44 || algorithm == tls.MLDSA87 {
							return nil, fmt.Errorf("firmware advertised unsupported CertificateVerify algorithm %v", algorithm)
						}
						found65 = found65 || algorithm == tls.MLDSA65
					}
					if !found65 {
						return nil, fmt.Errorf("firmware did not advertise ML-DSA-65 CertificateVerify")
					}
					return &operator, nil
				},
			})
			handshake := client.Handshake()
			if mode == "stream-valid" {
				must(handshake)
				if iteration == 1 && repeat > 1 {
					// Normal certificate renewal: a new valid serial on the same key.
					device = makeLeaf(deviceKey, "device")
					var renewed []byte
					for _, der := range device.Certificate {
						renewed = append(renewed, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
					}
					must(os.WriteFile(serverPath, renewed, 0600))
				}
				_, err = client.Write([]byte("hello"))
				must(err)
				var reply [5]byte
				_, err = io.ReadFull(client, reply[:])
				must(err)
				if string(reply[:]) != "world" || !requested {
					panic("mixed CA chain did not authenticate and exchange application data")
				}
			} else if handshake == nil {
				var reply [1]byte
				if _, err = client.Read(reply[:]); err == nil {
					panic("invalid mixed CA operator was accepted")
				}
			}
			raw.Close()
			if !requested {
				panic("mixed CA reconnect did not authenticate its client")
			}
			fmt.Printf("PASS mixed87 normal_session=%d operator_chain_bytes=%d\n", iteration+1, chainBytes)
		}
		must(command.Wait())
		if repeat == 4 {
			logs := sessionLogs.String()
			expected := []string{"verified and cached", "reused", "verified and cached", "reused"}
			remaining := logs
			for _, state := range expected {
				prefix := "local certificate path: "
				index := strings.Index(remaining, prefix)
				if index < 0 || !strings.HasPrefix(remaining[index+len(prefix):], state+"\n") {
					panic("normal renewal did not invalidate the local path cache at the next connection")
				}
				remaining = remaining[index+len(prefix)+len(state)+1:]
			}
			if strings.Count(logs, "local certificate path: verified and cached") != 2 ||
				strings.Count(logs, "local certificate path: reused") != 2 {
				panic("normal reconnect/renewal did not verify twice and reuse twice")
			}
		}
		fmt.Printf("PASS mixed87 %s operator_chain_bytes=%d\n", name, chainBytes)
	}
}

// Incoming Certificate reassembly remains bounded even when every certificate
// is valid and the TLS records themselves respect the 16 KiB record limit.
func exerciseOversizedIncomingCertificate(directory string, roots *x509.CertPool, operator tls.Certificate) {
	chainBytes := 0
	for _, cert := range operator.Certificate {
		chainBytes += len(cert)
	}
	if chainBytes <= 32768 {
		panic("oversized peer fixture must exceed the incoming handshake buffer")
	}
	command := exec.Command(os.Args[1], filepath.Join(directory, "key.der"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "root.pem"), "stream-reject")
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	must(err)
	must(command.Start())
	defer command.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	must(err)
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
	must(err)
	defer raw.Close()
	must(raw.SetDeadline(time.Now().Add(4 * time.Second)))
	client := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{operator},
	})
	if client.Handshake() == nil {
		var reply [1]byte
		if _, err = client.Read(reply[:]); err == nil {
			panic("oversized incoming Certificate was accepted")
		}
	}
	must(command.Wait())
	fmt.Printf("PASS mldsa65 incoming-oversized-certificate chain_bytes=%d\n", chainBytes)
}

func exerciseTruncatedOutboundCertificate(directory string, broker tls.Certificate, roots *x509.CertPool) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer listener.Close()
	must(listener.SetDeadline(time.Now().Add(10 * time.Second)))
	command := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"), filepath.Join(directory, "outbound-device.pem"), filepath.Join(directory, "outbound-root.pem"), "connect-truncated", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	must(command.Start())
	defer command.Process.Kill()
	raw, err := listener.Accept()
	must(err)
	defer raw.Close()
	must(raw.SetDeadline(time.Now().Add(10 * time.Second)))
	server := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{broker}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	})
	err = server.Handshake()
	state := server.ConnectionState()
	if err == nil || state.HandshakeComplete || len(state.VerifiedChains) != 0 {
		panic("truncated fragmented Certificate was authenticated")
	}
	must(command.Wait())
	fmt.Println("PASS mldsa65 outbound-truncated-certificate")
}

// Exercise the same multi-record Certificate writer in the server role over
// callbacks that fragment reads/writes and return both WANT directions.
func exerciseLargeServerStream(directory, profile string, roots *x509.CertPool, operator tls.Certificate, chainBytes, chainLength int) {
	command := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"), filepath.Join(directory, "outbound-device.pem"), filepath.Join(directory, "root.pem"), "stream-valid")
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	must(err)
	must(command.Start())
	defer command.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	must(err)
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
	must(err)
	defer raw.Close()
	must(raw.SetDeadline(time.Now().Add(4 * time.Second)))
	client := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{operator},
	})
	must(client.Handshake())
	state := client.ConnectionState()
	presentedLength := chainLength
	if os.Getenv("WENDY_TLS_OWNED_STREAM") != "" {
		presentedLength-- // The independently pinned anchor is omitted on wire.
	}
	if len(state.PeerCertificates) != presentedLength || len(state.VerifiedChains) == 0 {
		panic("stream server chain was not authenticated")
	}
	_, err = client.Write([]byte("hello"))
	must(err)
	var reply [5]byte
	_, err = io.ReadFull(client, reply[:])
	must(err)
	if string(reply[:]) != "world" {
		panic("invalid large-chain stream application data")
	}
	must(command.Wait())
	fmt.Printf("PASS %s server-stream-short-writes chain_bytes=%d certificates=%d\n", profile, chainBytes, chainLength)
}

func exerciseEnrollmentHTTP(directory string, broker tls.Certificate, deviceRoots *x509.CertPool) {
	const headerName = "X-Wendy-Lite-Operator-Authority"
	const authority = "dGVzdC1saXRlLWF1dGhvcml0eQ=="
	for _, tc := range []struct {
		name, header, expected             string
		renew, reject, truncate, untrusted bool
		large, chunked                     bool
		status, recordBytes                int
	}{
		{name: "fragmented mixed-case header", header: "x-WeNdY-LiTe-OpErAtOr-AuThOrItY: " + authority + "\r\n", expected: authority},
		{name: "renewal header", header: headerName + ": " + authority + "\r\n", expected: authority, renew: true},
		{name: "missing header"},
		{name: "40KiB issuance body", header: headerName + ": " + authority + "\r\n", expected: authority, large: true},
		{name: "40KiB issuance body in full TLS records", header: headerName + ": " + authority + "\r\n", expected: authority, large: true, recordBytes: 16384},
		{name: "40KiB chunked issuance body", header: headerName + ": " + authority + "\r\n", expected: authority, large: true, chunked: true},
		{name: "maximum header", header: headerName + ": " + strings.Repeat("A", 4096) + "\r\n", expected: strings.Repeat("A", 4096)},
		{name: "oversized header", header: headerName + ": " + strings.Repeat("A", 4097) + "\r\n", reject: true},
		{name: "duplicate header", header: headerName + ": " + authority + "\r\n" + strings.ToLower(headerName) + ": " + authority + "\r\n", reject: true},
		{name: "empty header", header: headerName + ":\r\n", reject: true},
		{name: "failed issuance", header: headerName + ": " + authority + "\r\n", status: 403, reject: true},
		{name: "truncated issuance", header: headerName + ": " + authority + "\r\n", truncate: true, reject: true},
		{name: "untrusted HTTPS", header: headerName + ": " + authority + "\r\n", untrusted: true, reject: true},
	} {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		must(err)
		must(listener.SetDeadline(time.Now().Add(5 * time.Second)))
		mode, expectedPath := "http-valid", "-"
		if tc.large {
			mode = "http-large"
		}
		if tc.renew {
			mode = "http-renew"
		}
		if tc.reject {
			mode = "http-reject"
		}
		if tc.expected != "" {
			expectedPath = filepath.Join(directory, "expected-header")
			must(os.WriteFile(expectedPath, []byte(tc.expected), 0600))
		}
		rootPath := filepath.Join(directory, "outbound-root.pem")
		if tc.untrusted {
			rootPath = filepath.Join(directory, "lite-root.pem")
		}
		endpoint := fmt.Sprintf("https://localhost:%d/v1/enroll", listener.Addr().(*net.TCPAddr).Port)
		command := exec.Command(os.Args[1], filepath.Join(directory, "outbound-key.der"), filepath.Join(directory, "outbound-device.pem"), rootPath, mode, endpoint, expectedPath)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		must(command.Start())
		raw, err := listener.Accept()
		must(err)
		listener.Close()
		must(raw.SetDeadline(time.Now().Add(5 * time.Second)))
		config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{broker}, DynamicRecordSizingDisabled: true}
		if tc.renew {
			config.ClientAuth, config.ClientCAs = tls.RequireAndVerifyClientCert, deviceRoots
		}
		server := tls.Server(raw, config)
		err = server.Handshake()
		if tc.untrusted {
			if err == nil {
				panic("untrusted HTTP issuer was accepted")
			}
		} else {
			must(err)
			request, err := http.ReadRequest(bufio.NewReader(server))
			must(err)
			body, err := io.ReadAll(request.Body)
			must(err)
			request.Body.Close()
			if request.Method != "POST" || string(body) != "{}" {
				panic("unexpected enrollment HTTP request")
			}
			if !tc.renew && request.Header.Get("Authorization") != "Bearer test-token" {
				panic("missing enrollment token")
			}
			if tc.renew && request.Header.Get("Authorization") != "" {
				panic("renewal sent an enrollment token")
			}
			statusCode := tc.status
			if statusCode == 0 {
				statusCode = 200
			}
			responseBody := "{}"
			if tc.large {
				responseBody = strings.Repeat("x", 40000)
			}
			response := fmt.Sprintf("HTTP/1.1 %d result\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusCode, tc.header, len(responseBody), responseBody)
			if tc.chunked {
				response = fmt.Sprintf("HTTP/1.1 %d result\r\n%sTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", statusCode, tc.header, len(responseBody), responseBody)
			}
			if tc.truncate {
				response = strings.TrimSuffix(response, "}")
			}
			// Small records split header names/values; full records exercise asymmetric buffers.
			recordBytes := tc.recordBytes
			if recordBytes == 0 {
				recordBytes = 7
			}
			for offset := 0; offset < len(response); {
				end := min(offset+recordBytes, len(response))
				if _, err := server.Write([]byte(response[offset:end])); err != nil {
					if !tc.reject {
						must(err)
					}
					break
				}
				offset = end
			}
		}
		server.Close()
		raw.Close()
		if err := command.Wait(); err != nil {
			panic(fmt.Sprintf("HTTP %s: %v", tc.name, err))
		}
		fmt.Println("PASS enrollment HTTP", tc.name)
	}
}

// Valid 16KiB TLS records must survive demand growth, partial reads and shrink.
func bulkEcho(c *tls.Conn) {
	payload := make([]byte, 65536)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	written := make(chan error, 1)
	go func() { _, err := c.Write(payload); written <- err }()
	received := make([]byte, len(payload))
	_, err := io.ReadFull(c, received)
	must(err)
	must(<-written)
	if !bytes.Equal(payload, received) {
		panic("demand-record bulk echo corruption")
	}
}
