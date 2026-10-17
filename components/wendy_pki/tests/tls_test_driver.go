//go:build ignore

// Exercise the actual firmware TLS adapter against Go's independent TLS stack.
package main

import (
	"bufio"
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
	"strings"
	"time"
)

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
	newIssuer := func() (crypto.Signer, error) {
		switch profile {
		case "p256":
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "mldsa44":
			return mldsa.GenerateKey(mldsa.MLDSA44())
		case "mldsa65":
			return mldsa.GenerateKey(mldsa.MLDSA65())
		case "mldsa87":
			return mldsa.GenerateKey(mldsa.MLDSA87())
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
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	_, keyDER, serverPEM := leaf("device", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, tenant+"device/lite-test", rootKey, root, 0)
	must(os.WriteFile(filepath.Join(directory, "key.der"), keyDER, 0600))
	must(os.WriteFile(filepath.Join(directory, "server.pem"), serverPEM, 0600))
	cases := []string{"valid", "wrong-tenant", "wrong-role", "wrong-eku", "expired", "untrusted", "no-client", "tls12", "truncate", "extra", "intermediate", "intermediate-key-usage", "intermediate-not-ca", "intermediate-path-length", "intermediate-expired", "intermediate-sha1", "relay-valid", "relay-operator-expiry", "relay-device-expiry", "relay-wrong-key", "relay-old", "relay-truncated", "relay-expired", "relay-long-presentation", "relay-device-client",
		"lan-operator", "lan-device", "lan-device-wrong-tenant", "lan-device-wrong-eku", "lan-device-missing-eku",
		"lan-device-ca", "lan-device-duplicate-uri", "lan-device-extra-uri", "lan-device-missing-uri",
		"lan-device-expired", "lan-device-future", "lan-device-untrusted", "lan-device-tampered", "lan-no-client",
		"lite-valid", "lite-wrong-role", "lite-wrong-tenant", "lite-unmarked", "lite-extra-eku", "lite-untrusted", "lite-primary-operator", "lite-lan-device",
		"stream-valid", "stream-wrong-tenant", "stream-device", "stream-no-client", "stream-expired", "stream-untrusted", "stream-tls12", "stream-timeout"}
	for _, name := range cases {
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
			uri = tenant + "device/lite-test"
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
			grant = append([]byte("WLG2"), 4)
			grant = append(grant, []byte("test")...)
			grant = binary.BigEndian.AppendUint64(grant, uint64(issued))
			grant = binary.BigEndian.AppendUint64(grant, uint64(presentBy))
			var session [16]byte
			_, e = rand.Read(session[:])
			must(e)
			grant = append(grant, session[:]...)
			// jti, correlation ID, asset ID: four UUID fields including session.
			for range 3 {
				id := make([]byte, 16)
				_, e = rand.Read(id)
				must(e)
				grant = append(grant, id...)
			}
			deviceHash := sha256.Sum256([]byte(tenant + "device/lite-test"))
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

	// Exercise the firmware's outbound role. Three issuer intermediates make
	// every ML-DSA profile cross the TLS record boundary, with a P-256 device key.
	issuer, parent := rootKey, root
	chain := [][]byte{rootDER}
	for level := range 3 {
		caKey, e := newIssuer()
		must(e)
		ca := &x509.Certificate{SerialNumber: big.NewInt(int64(200 + level)), Subject: pkix.Name{CommonName: fmt.Sprintf("outbound intermediate %d", level)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, ca, parent, caKey.Public(), issuer)
		must(e)
		chain = append([][]byte{der}, chain...)
		parent, issuer = ca, caKey
	}
	device, deviceKey, devicePEM := leaf("outbound device", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, tenant+"device/lite-test", issuer, parent, 0)
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
	if profile == "p256" {
		exerciseEnrollmentHTTP(directory, broker, pool)
	}
}

func exerciseEnrollmentHTTP(directory string, broker tls.Certificate, deviceRoots *x509.CertPool) {
	const headerName = "X-Wendy-Lite-Operator-Authority"
	const authority = "dGVzdC1saXRlLWF1dGhvcml0eQ=="
	for _, tc := range []struct {
		name, header, expected             string
		renew, reject, truncate, untrusted bool
		status                             int
	}{
		{name: "fragmented mixed-case header", header: "x-WeNdY-LiTe-OpErAtOr-AuThOrItY: " + authority + "\r\n", expected: authority},
		{name: "renewal header", header: headerName + ": " + authority + "\r\n", expected: authority, renew: true},
		{name: "missing header"},
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
		config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{broker}}
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
			response := fmt.Sprintf("HTTP/1.1 %d result\r\n%sContent-Length: 2\r\nConnection: close\r\n\r\n{}", statusCode, tc.header)
			if tc.truncate {
				response = strings.TrimSuffix(response, "}")
			}
			// Separate TLS records split both field names and values across parser calls.
			for offset := 0; offset < len(response); {
				end := min(offset+7, len(response))
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
