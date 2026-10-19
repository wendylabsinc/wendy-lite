//go:build ignore

// Generate disposable certificates for the production legacy LAN/BLE policy.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const organization = "2558fd76-afc7-466e-9613-6b715296a526"
const tenant = "spiffe://wendy.sh/tenant/" + organization + "/"
const operatorURI = tenant + "operator/11111111-1111-4111-8111-111111111111"
const deviceURI = tenant + "device/00000000-0000-4000-8000-000000000004"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func newKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	return key
}

func uris(values ...string) []*url.URL {
	result := make([]*url.URL, 0, len(values))
	for _, value := range values {
		parsed, err := url.Parse(value)
		must(err)
		result = append(result, parsed)
	}
	return result
}

func setRawURIs(template *x509.Certificate, values ...string) {
	template.URIs = nil
	if len(values) == 0 {
		template.ExtraExtensions = nil
		return
	}
	// Encode SANs directly so malformed bytes, including NUL, reach the helper.
	var names []asn1.RawValue
	for _, value := range values {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(value)})
	}
	san, err := asn1.Marshal(names)
	must(err)
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
}

func certificate(name string, uri string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, URIs: uris(uri),
	}
}

func issue(template, parent *x509.Certificate, key, issuer *ecdsa.PrivateKey) []byte {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuer)
	must(err)
	return der
}

func runUnit(binary string, args ...string) {
	command := exec.Command(binary, args...)
	if output, err := command.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("%v: %v\n%s", args, err, output))
	}
}

func handshake(binary, directory, name, authMode string, version uint16, clientCert *tls.Certificate, roots *x509.CertPool, valid bool, expectedRole string) {
	mode := "reject"
	if valid {
		mode = "valid"
		if expectedRole == "device" {
			mode = "valid-device"
		}
	}
	deviceFile, expectedAck := "device.der", "authenticated"
	if authMode == "unprovisioned" {
		deviceFile, expectedAck = "unprovisioned.der", "setup allowed"
	}
	command := exec.Command(binary, filepath.Join(directory, "key.der"), filepath.Join(directory, deviceFile), filepath.Join(directory, "root.pem"), mode, authMode)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	must(err)
	must(command.Start())
	defer command.Process.Kill()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	must(err)
	connection, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
	must(err)
	must(connection.SetDeadline(time.Now().Add(5 * time.Second)))
	config := &tls.Config{MinVersion: version, MaxVersion: version, RootCAs: roots, ServerName: "localhost"}
	if clientCert != nil {
		// Send every fixture, even if the server's acceptable CA list differs.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}
	client := tls.Client(connection, config)
	result := client.Handshake()
	var ack [13]byte
	if result == nil {
		_, result = io.ReadFull(client, ack[:])
	}
	connection.Close()
	if valid && (result != nil || string(ack[:]) != expectedAck) {
		panic(fmt.Sprintf("%s %s TLS %x: expected connection accepted: %v", name, authMode, version, result))
	}
	if !valid && result == nil {
		panic(fmt.Sprintf("%s %s TLS %x: invalid peer authenticated", name, authMode, version))
	}
	if err := command.Wait(); err != nil {
		panic(fmt.Sprintf("%s %s TLS %x: %v", name, authMode, version, err))
	}
	fmt.Printf("PASS legacy peer %s TLS %x %s\n", authMode, version, name)
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: operator_auth_test_driver.go operator_auth_test operator_auth_tls_test")
	}
	directory, err := os.MkdirTemp("", "wendy-operator-auth-")
	must(err)
	defer os.RemoveAll(directory)
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		must(os.WriteFile(path, data, 0600))
		return path
	}
	rootKey := newKey()
	root := certificate("wendy-auth test root", tenant+"authority/test")
	root.SerialNumber = big.NewInt(1)
	root.IsCA, root.KeyUsage, root.ExtKeyUsage, root.URIs = true, x509.KeyUsageCertSign, nil, nil
	rootDER := issue(root, root, rootKey, rootKey)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	write("root.pem", rootPEM)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		panic("invalid generated trust root")
	}
	device := certificate("device", deviceURI)
	device.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	deviceKey := newKey()
	devicePath := write("device.der", issue(device, root, deviceKey, rootKey))
	keyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	must(err)
	write("key.der", keyDER)
	// Model the unprovisioned adapter with a self-signed identity and no tenant.
	// The client trusts this disposable fixture solely to test anonymous access.
	unprovisioned := certificate("unprovisioned device", deviceURI)
	unprovisioned.URIs = nil
	unprovisioned.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	unprovisionedDER := issue(unprovisioned, unprovisioned, deviceKey, deviceKey)
	write("unprovisioned.der", unprovisionedDER)
	unprovisionedPool := x509.NewCertPool()
	unprovisionedCert, err := x509.ParseCertificate(unprovisionedDER)
	must(err)
	unprovisionedPool.AddCert(unprovisionedCert)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		handshake(os.Args[2], directory, "no-client", "unprovisioned", version, nil, unprovisionedPool, true, "none")
	}

	deviceCases := []struct {
		name  string
		uris  []string
		ca    bool
		valid bool
	}{
		{name: "valid", uris: []string{deviceURI}, valid: true},
		{name: "missing-uri"},
		{name: "duplicate-uri", uris: []string{deviceURI, deviceURI}},
		{name: "extra-uri", uris: []string{deviceURI, "https://wendy.sh/device"}},
		{name: "wrong-role", uris: []string{operatorURI}},
		{name: "wrong-authority", uris: []string{strings.Replace(deviceURI, "wendy.sh", "other.sh", 1)}},
		{name: "upper-tenant", uris: []string{strings.Replace(deviceURI, organization, strings.ToUpper(organization), 1)}},
		{name: "invalid-tenant", uris: []string{strings.Replace(deviceURI, organization, "not-a-uuid", 1)}},
		{name: "empty-device", uris: []string{tenant + "device/"}},
		{name: "device-path", uris: []string{deviceURI + "/extra"}, valid: true},
		{name: "device-name", uris: []string{tenant + "device/Camera_1.test"}, valid: true},
		{name: "device-at", uris: []string{deviceURI + "@other"}},
		{name: "device-pipe", uris: []string{deviceURI + "|other"}},
		{name: "device-empty-segment", uris: []string{deviceURI + "//extra"}},
		{name: "device-dot-segment", uris: []string{deviceURI + "/./extra"}},
		{name: "device-parent-segment", uris: []string{deviceURI + "/../extra"}},
		{name: "device-long-segment", uris: []string{tenant + "device/" + strings.Repeat("a", 65)}},
		{name: "device-query", uris: []string{deviceURI + "?tenant=other"}},
		{name: "device-fragment", uris: []string{deviceURI + "#other"}},
		{name: "device-percent", uris: []string{deviceURI + "%31"}},
		{name: "device-nul", uris: []string{deviceURI + "\x00other"}},
		{name: "ca-device", uris: []string{deviceURI}, ca: true},
	}
	for _, test := range deviceCases {
		template := certificate("device", deviceURI)
		setRawURIs(template, test.uris...)
		template.IsCA = test.ca
		path := write("device-"+test.name+".der", issue(template, root, deviceKey, rootKey))
		expected := "invalid"
		if test.valid {
			expected = "valid"
		}
		runUnit(os.Args[1], "init", path, expected, organization)
		fmt.Println("PASS device identity", test.name)
	}

	for _, name := range []string{
		"valid", "intermediate", "wrong-tenant", "wrong-role", "missing-uri", "duplicate-uri", "extra-uri",
		"operator-name", "upper-operator", "operator-path", "operator-query", "operator-fragment", "wrong-authority",
		"operator-at", "operator-pipe", "operator-empty", "operator-empty-segment", "operator-dot-segment",
		"operator-parent-segment", "operator-long-segment", "operator-percent", "operator-nul",
		"wrong-eku", "missing-eku", "ca-leaf", "expired", "future", "untrusted", "tampered", "no-client",
	} {
		peer := certificate("operator", operatorURI)
		key := newKey()
		issuer, parent := rootKey, root
		var chain [][]byte
		valid, identityValid := name == "valid" || name == "intermediate", true
		switch name {
		case "wrong-tenant":
			peer.URIs = uris(strings.Replace(operatorURI, "2558fd76", "3558fd76", 1))
			identityValid = false
		case "wrong-role":
			peer.URIs = uris(deviceURI)
			identityValid = false
		case "missing-uri":
			peer.URIs = nil
			identityValid = false
		case "duplicate-uri":
			peer.URIs = uris(operatorURI, operatorURI)
			identityValid = false
		case "extra-uri":
			peer.URIs = uris(operatorURI, "https://wendy.sh/operator")
			identityValid = false
		case "operator-name":
			peer.URIs = uris(tenant + "operator/Auth0_user-1.test")
			valid = true
		case "upper-operator":
			peer.URIs = uris(tenant + "operator/AAAAAAAA-1111-4111-8111-111111111111")
			valid = true
		case "operator-path":
			peer.URIs = uris(operatorURI + "/provider/user-1")
			valid = true
		case "operator-query":
			peer.URIs = uris(operatorURI + "?role=operator")
			identityValid = false
		case "operator-fragment":
			peer.URIs = uris(operatorURI + "#other")
			identityValid = false
		case "operator-at", "operator-pipe", "operator-empty", "operator-empty-segment", "operator-dot-segment",
			"operator-parent-segment", "operator-long-segment", "operator-percent", "operator-nul":
			subjects := map[string]string{
				"operator-at": "user@other", "operator-pipe": "user|other", "operator-empty": "",
				"operator-empty-segment": "user//other", "operator-dot-segment": "user/./other",
				"operator-parent-segment": "user/../other", "operator-long-segment": strings.Repeat("a", 65),
				"operator-percent": "user%31", "operator-nul": "user\x00other",
			}
			setRawURIs(peer, tenant+"operator/"+subjects[name])
			identityValid = false
		case "wrong-authority":
			peer.URIs = uris(strings.Replace(operatorURI, "wendy.sh", "other.sh", 1))
			identityValid = false
		case "wrong-eku":
			peer.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			identityValid = false
		case "missing-eku":
			peer.ExtKeyUsage = nil
			identityValid = false
		case "ca-leaf":
			peer.IsCA = true
			peer.KeyUsage |= x509.KeyUsageCertSign
			identityValid = false
		case "expired":
			peer.NotAfter = time.Now().Add(-time.Minute)
		case "future":
			peer.NotBefore = time.Now().Add(time.Minute)
		case "untrusted":
			issuer = newKey()
		case "intermediate":
			issuer = newKey()
			parent = certificate("test intermediate", tenant+"authority/intermediate")
			parent.IsCA, parent.KeyUsage, parent.ExtKeyUsage = true, x509.KeyUsageCertSign, nil
			chain = [][]byte{issue(parent, root, issuer, rootKey)}
		}
		der := issue(peer, parent, key, issuer)
		if name == "tampered" {
			der[len(der)-1] ^= 1
		}
		path := write("operator-"+name+".der", der)
		expected := "invalid"
		if identityValid {
			expected = "valid"
		}
		runUnit(os.Args[1], "verify", devicePath, path, expected)
		peerRole := "none"
		if identityValid {
			peerRole = "operator"
		}
		if name == "wrong-role" {
			peerRole = "device"
		}
		runUnit(os.Args[1], "peer", devicePath, path, peerRole)
		clientCert := &tls.Certificate{Certificate: append([][]byte{der}, chain...), PrivateKey: key}
		if name == "no-client" {
			clientCert = nil
		}
		for _, authMode := range []string{"callback", "post-handshake", "callback-lan", "post-handshake-lan"} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				handshake(os.Args[2], directory, name, authMode, version, clientCert, pool, valid || (name == "wrong-role" && strings.HasSuffix(authMode, "-lan")), peerRole)
			}
		}
	}
	for _, name := range []string{"valid", "wrong-tenant", "service-role", "duplicate-uri", "extra-uri", "missing-uri", "missing-eku", "wrong-eku", "ca-leaf", "expired", "future", "untrusted", "tampered", "no-client"} {
		peer := certificate("sensor consumer", tenant+"device/agent-1")
		key, issuer := newKey(), rootKey
		valid, identityValid := name == "valid", true
		switch name {
		case "wrong-tenant":
			peer.URIs = uris(strings.Replace(tenant+"device/agent-1", "2558fd76", "3558fd76", 1))
			identityValid = false
		case "service-role":
			peer.URIs = uris(tenant + "service/agent-1")
			identityValid = false
		case "duplicate-uri":
			peer.URIs = uris(tenant+"device/agent-1", tenant+"device/agent-1")
			identityValid = false
		case "extra-uri":
			peer.URIs = uris(tenant+"device/agent-1", operatorURI)
			identityValid = false
		case "missing-uri":
			peer.URIs = nil
			identityValid = false
		case "missing-eku":
			peer.ExtKeyUsage = nil
			identityValid = false
		case "wrong-eku":
			peer.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			identityValid = false
		case "ca-leaf":
			peer.IsCA = true
			peer.KeyUsage |= x509.KeyUsageCertSign
			identityValid = false
		case "expired":
			peer.NotAfter = time.Now().Add(-time.Minute)
		case "future":
			peer.NotBefore = time.Now().Add(time.Minute)
		case "untrusted":
			issuer = newKey()
		}
		der := issue(peer, root, key, issuer)
		if name == "tampered" {
			der[len(der)-1] ^= 1
		}
		path := write("consumer-"+name+".der", der)
		role := "none"
		if identityValid {
			role = "device"
		}
		runUnit(os.Args[1], "peer", devicePath, path, role)
		clientCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		if name == "no-client" {
			clientCert = nil
		}
		for _, authMode := range []string{"callback", "post-handshake", "callback-lan", "post-handshake-lan"} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				handshake(os.Args[2], directory, "device-"+name, authMode, version, clientCert, pool,
					valid && strings.HasSuffix(authMode, "-lan"), "device")
			}
		}
	}

}
