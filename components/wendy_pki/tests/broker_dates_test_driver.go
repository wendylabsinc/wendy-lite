//go:build ignore

// Connect the production outbound TLS, built without mbedTLS date checks as on
// the firmware, to Go TLS servers that present chains with bad dates.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type dates struct{ from, to time.Time }
type chainDates struct{ root, intermediate, leaf dates }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func certificate(name string, serial int64, validity dates, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: validity.from, NotAfter: validity.to, BasicConstraintsValid: true}
	if ca {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	must(err)
	return template, key, der
}

// run starts one server and one client, and checks the result on both sides.
func run(binary, directory, name, mode string, validity chainDates, clock int64, accept bool) {
	root, rootKey, rootDER := certificate("test root", 1, validity.root, true, nil, nil)
	intermediate, intermediateKey, intermediateDER := certificate("test intermediate", 2, validity.intermediate, true, root, rootKey)
	_, leafKey, leafDER := certificate("localhost", 3, validity.leaf, false, intermediate, intermediateKey)
	roots := filepath.Join(directory, "roots.pem")
	must(os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600))

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	defer listener.Close()
	must(listener.SetDeadline(time.Now().Add(10 * time.Second)))
	expect := "reject"
	if accept {
		expect = "accept"
	}
	command := exec.Command(binary, mode, roots, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), fmt.Sprint(clock), expect)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	must(command.Start())
	defer command.Process.Kill()

	connection, err := listener.Accept()
	must(err)
	defer connection.Close()
	must(connection.SetDeadline(time.Now().Add(10 * time.Second)))
	server := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, intermediateDER}, PrivateKey: leafKey}}})
	handshake := server.Handshake()
	if accept != (handshake == nil) {
		panic(fmt.Sprintf("%s %s: server handshake result %v, expected %s", name, mode, handshake, expect))
	}
	if mode == "http" && handshake == nil {
		request, err := http.ReadRequest(bufio.NewReader(server))
		must(err)
		if request.Header.Get("Content-Type") != "application/timestamp-query" {
			panic(fmt.Sprintf("%s: unexpected request %v", name, request.Header))
		}
		_, err = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
		must(err)
		must(server.CloseWrite())
	}
	if err := command.Wait(); err != nil {
		panic(fmt.Sprintf("%s %s: %v", name, mode, err))
	}
	fmt.Printf("PASS %s %s %s\n", name, mode, expect)
}

func main() {
	binary := os.Args[1]
	directory, err := os.MkdirTemp("", "broker-dates-")
	must(err)
	defer os.RemoveAll(directory)
	// X.509 dates have a resolution of one second.
	now := time.Now().UTC().Truncate(time.Second)
	clock := now.Unix()
	good := dates{now.Add(-time.Hour), now.Add(time.Hour)}
	expired := dates{now.Add(-2 * time.Hour), now.Add(-time.Minute)}
	future := dates{now.Add(time.Minute), now.Add(2 * time.Hour)}
	valid := chainDates{good, good, good}

	// The broker connection refuses each of these chains. The undated connection
	// accepts them. This shows that the dates are the only fault in each chain,
	// and that mbedTLS itself does not check dates in this test.
	for _, bad := range []struct {
		name     string
		validity chainDates
	}{
		{"expired-leaf", chainDates{good, good, expired}},
		{"future-leaf", chainDates{good, good, future}},
		{"expired-intermediate", chainDates{good, expired, good}},
		{"future-intermediate", chainDates{good, future, good}},
		{"expired-root", chainDates{expired, good, good}},
		{"future-root", chainDates{future, good, good}},
		// Same limit as the device identity check: the end date is not valid.
		{"leaf-ends-now", chainDates{good, good, dates{good.from, now}}},
	} {
		run(binary, directory, bad.name, "dated", bad.validity, clock, false)
		run(binary, directory, bad.name, "undated", bad.validity, clock, true)
	}

	run(binary, directory, "valid", "dated", valid, clock, true)
	run(binary, directory, "leaf-starts-now", "dated", chainDates{good, good, dates{now, good.to}}, clock, true)
	// Without a verified clock, the broker connection fails closed.
	run(binary, directory, "clock-not-set", "dated", valid, 0, false)
	// The time fetch does not use the clock, which can be wrong in both directions.
	run(binary, directory, "clock-not-set", "http", valid, 0, true)
	run(binary, directory, "clock-too-late", "http", valid, now.AddDate(10, 0, 0).Unix(), true)
}
