//go:build ignore

// Ordinary operator/device clients for the real native TLS/WendyCom fixture.
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	dir, err := os.MkdirTemp("", "native-agent-normal-")
	must(err)
	defer os.RemoveAll(dir)
	profile := os.Args[2]
	newCAKey := func() crypto.Signer {
		if profile == "mldsa65" {
			key, err := mldsa.GenerateKey(mldsa.MLDSA65())
			must(err)
			return key
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		return key
	}
	serial := int64(1)
	template := func(name string) *x509.Certificate {
		serial++
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	}
	rootKey := newCAKey()
	root := template("normal root")
	root.IsCA = true
	root.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	parent, issuer := root, rootKey
	chain := [][]byte{rootDER}
	for i := 0; i < 3; i++ {
		key := newCAKey()
		ca := template(fmt.Sprintf("normal intermediate %d", i))
		ca.IsCA = true
		ca.KeyUsage = x509.KeyUsageCertSign
		der, err := x509.CreateCertificate(rand.Reader, ca, parent, key.Public(), issuer)
		must(err)
		chain = append([][]byte{der}, chain...)
		parent, issuer = ca, key
	}
	leaf := func(role, id string) (tls.Certificate, []byte) {
		var key crypto.Signer
		var err error
		if profile == "mldsa65" && role == "operator" {
			key, err = mldsa.GenerateKey(mldsa.MLDSA65())
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		must(err)
		cert := template("normal " + role)
		cert.KeyUsage = x509.KeyUsageDigitalSignature
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert.DNSNames = []string{"localhost"}
		u, err := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/" + role + "/" + id)
		must(err)
		cert.URIs = []*url.URL{u}
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), issuer)
		must(err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		return tls.Certificate{Certificate: append([][]byte{der}, chain...), PrivateKey: key}, keyDER
	}
	server, key := leaf("device", "00000000-0000-4000-8000-000000000004")
	var serverPEM []byte
	for _, der := range server.Certificate {
		serverPEM = append(serverPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	for name, data := range map[string][]byte{"key.der": key, "server.pem": serverPEM, "root.pem": rootPEM} {
		must(os.WriteFile(filepath.Join(dir, name), data, 0600))
	}
	for _, role := range []string{"operator", "device"} {
		id := "00000000-0000-4000-8000-000000000005"
		if role == "operator" {
			id = "alice_1"
		}
		client, _ := leaf(role, id)
		command := exec.Command(os.Args[1], filepath.Join(dir, "key.der"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "root.pem"), "owned-lan-valid")
		command.Env = append(os.Environ(), "WENDY_TLS_EXPECT_ROLE="+role)
		command.Stderr = os.Stderr
		stdout, err := command.StdoutPipe()
		must(err)
		must(command.Start())
		line, err := bufio.NewReader(stdout).ReadString('\n')
		must(err)
		raw, err := net.DialTimeout("tcp4", "127.0.0.1:"+strings.TrimSpace(line), time.Second)
		must(err)
		must(raw.SetDeadline(time.Now().Add(30 * time.Second)))
		secure := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{client}, SessionTicketsDisabled: true})
		must(secure.Handshake())
		nativeComposedApplication(secure, role == "operator")
		must(secure.Close())
		must(command.Wait())
		fmt.Printf("PASS %s native TLS/WendyCom/SensorLink/Console role=%s\n", profile, role)
	}
}
