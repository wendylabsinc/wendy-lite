//go:build ignore

// Generate disposable certificates for the Lite authority and operator policy.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const organization = "2558fd76-afc7-466e-9613-6b715296a526"
const tenant = "spiffe://wendy.sh/tenant/" + organization + "/"
const operatorURI = tenant + "operator/test-user"

var liteEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65441, 1, 9}
var clientEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
var keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}
var extendedKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func newKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	must(err)
	return key
}

func uris(values ...string) []*url.URL {
	var result []*url.URL
	for _, value := range values {
		parsed, err := url.Parse(value)
		must(err)
		result = append(result, parsed)
	}
	return result
}

func certificate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lite test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 0, MaxPathLenZero: true,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
}

func operator() *x509.Certificate {
	leaf := certificate()
	leaf.SerialNumber = big.NewInt(2)
	leaf.Subject.CommonName = "Lite test operator"
	leaf.IsCA = false
	leaf.MaxPathLenZero = false
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{liteEKU}
	leaf.URIs = uris(operatorURI)
	return leaf
}

func issue(template, parent *x509.Certificate, key, signer crypto.Signer) []byte {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	must(err)
	return der
}

func extension(template *x509.Certificate, oid asn1.ObjectIdentifier, critical bool, value any) {
	der, err := asn1.Marshal(value)
	must(err)
	template.ExtraExtensions = append(template.ExtraExtensions,
		pkix.Extension{Id: oid, Critical: critical, Value: der})
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: lite_authority_test_driver.go lite_authority_test")
	}
	directory, err := os.MkdirTemp("", "wendy-lite-authority-")
	must(err)
	defer os.RemoveAll(directory)
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		must(os.WriteFile(path, data, 0600))
		return path
	}
	run := func(args ...string) {
		command := exec.Command(os.Args[1], args...)
		if output, err := command.CombinedOutput(); err != nil {
			panic(fmt.Sprintf("%v: %v\n%s", args, err, output))
		}
	}
	authority := func(name, header string, der []byte, valid bool) {
		expected := "invalid"
		if valid {
			expected = "valid"
		}
		run("authority", write(name+".header", []byte(header)), expected, write(name+".der", der))
		fmt.Println("PASS Lite authority", name)
	}
	rootKey := newKey(elliptic.P256())
	otherKey := newKey(elliptic.P256())
	root := certificate()
	rootDER := issue(root, root, rootKey, rootKey)
	encoded := base64.StdEncoding.EncodeToString
	authority("valid-pathlen-zero", encoded(rootDER), rootDER, true)
	for _, name := range []string{
		"not-ca", "missing-basic-constraints", "missing-key-usage", "wrong-key-usage", "extra-key-usage",
		"omitted-path-length", "unlimited-path-length", "positive-path-length", "negative-path-length",
		"not-self-issued", "wrong-self-signature", "p384-key", "rsa-key", "ed25519-key", "sha384-signature",
		"expired", "future", "tampered", "truncated", "extra-der", "two-authorities",
	} {
		template := certificate()
		parent := template
		var key, signer crypto.Signer = rootKey, rootKey
		valid := false
		switch name {
		case "not-ca":
			template.IsCA = false
			template.MaxPathLenZero = false
		case "missing-basic-constraints":
			template.BasicConstraintsValid = false
		case "omitted-path-length":
			template.MaxPathLenZero = false
		case "unlimited-path-length":
			template.MaxPathLen, template.MaxPathLenZero = -1, false
		case "positive-path-length":
			template.MaxPathLen, template.MaxPathLenZero = 1, false
		case "negative-path-length":
			extension(template, asn1.ObjectIdentifier{2, 5, 29, 19}, true, struct {
				IsCA       bool
				MaxPathLen int
			}{true, -1})
		case "missing-key-usage":
			template.KeyUsage = 0
		case "wrong-key-usage":
			template.KeyUsage = x509.KeyUsageDigitalSignature
		case "extra-key-usage":
			template.KeyUsage |= x509.KeyUsageCRLSign
			valid = true
		case "not-self-issued":
			parent = certificate()
			parent.Subject.CommonName = "Other issuer"
		case "wrong-self-signature":
			signer = otherKey
		case "p384-key":
			key = newKey(elliptic.P384())
			signer = key
		case "rsa-key":
			key, err = rsa.GenerateKey(rand.Reader, 2048)
			must(err)
			signer, template.SignatureAlgorithm = key, x509.SHA256WithRSA
		case "ed25519-key":
			_, key, err = ed25519.GenerateKey(rand.Reader)
			must(err)
			signer, template.SignatureAlgorithm = key, x509.PureEd25519
		case "sha384-signature":
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case "expired":
			template.NotAfter = time.Now().Add(-time.Minute)
			valid = true // The boot clock is not authenticated during enrollment.
		case "future":
			template.NotBefore = time.Now().Add(time.Minute)
			valid = true
		}
		der := issue(template, parent, key, signer)
		switch name {
		case "tampered":
			der[len(der)-1] ^= 1
		case "truncated":
			der = der[:len(der)-1]
		case "extra-der":
			der = append(der, 0)
		case "two-authorities":
			der = append(der, rootDER...)
		}
		authority(name, encoded(der), der, valid)
	}

	// Control DER size despite the one-byte variation in ECDSA signatures.
	sizedAuthority := func(size int) []byte {
		padding := size - len(rootDER) - 20
		for attempt := 0; attempt < 100; attempt++ {
			template := certificate()
			extension(template, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65441, 99, 1}, false, make([]byte, padding))
			der := issue(template, template, rootKey, rootKey)
			if len(der) == size {
				return der
			}
			padding += size - len(der)
		}
		panic("could not generate authority certificate at exact size")
	}
	limit := sizedAuthority(3072)
	authority("header-at-limit", encoded(limit), limit, true)
	oversize := sizedAuthority(3073)
	authority("header-over-limit", encoded(oversize), oversize, false)
	padded := sizedAuthority(601)
	header := encoded(padded)
	urlEncoded := base64.URLEncoding.EncodeToString(padded)
	if urlEncoded == header {
		// Keep the alphabet rejection case deterministic for random test keys.
		urlEncoded = "-" + header[1:]
	}
	for _, test := range []struct{ name, value string }{
		{"empty", ""}, {"whitespace", " " + header}, {"newline", header[:20] + "\n" + header[20:]},
		{"trailing-whitespace", header + " "}, {"missing-padding", strings.TrimRight(header, "=")},
		{"extra-padding", header + "="}, {"invalid-character", "!" + header[1:]},
		{"base64url", urlEncoded},
		{"pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: padded}))},
		{"non-der", encoded([]byte("not a certificate"))},
		{"invalid-length", "A"}, {"bound-junk", strings.Repeat("A", 4096)},
		{"over-bound-junk", strings.Repeat("A", 4097)},
	} {
		authority(test.name, test.value, padded, false)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, size := range []int{601, 602} {
		der := sizedAuthority(size)
		canonical := encoded(der)
		last := strings.IndexByte(canonical, '=') - 1
		index := strings.IndexByte(alphabet, canonical[last])
		noncanonical := canonical[:last] + string(alphabet[index+1]) + canonical[last+1:]
		authority(fmt.Sprintf("noncanonical-padding-%d", size%3), noncanonical, der, false)
	}

	leafKey := newKey(elliptic.P256())
	validDER := issue(operator(), root, leafKey, rootKey)
	run("arguments", write("arguments.der", validDER), "valid", organization)
	for _, name := range []string{
		"valid", "reversed-eku", "critical-eku", "missing-basic-constraints", "nested-operator",
		"wrong-tenant", "invalid-tenant", "device-role", "missing-uri", "duplicate-uri", "extra-uri", "invalid-uri",
		"missing-key-usage", "noncritical-key-usage", "wrong-key-usage", "extra-key-usage", "unknown-key-usage", "duplicate-key-usage",
		"missing-eku", "missing-client-eku", "missing-lite-eku", "extra-eku", "extra-unknown-eku",
		"duplicate-client-eku", "duplicate-lite-eku", "duplicate-eku-extension", "wrong-lite-eku", "ca-leaf", "p384-leaf", "rsa-leaf", "ed25519-leaf",
		"truncated", "extra-der", "two-leaves", "pem-leaf",
	} {
		leaf := operator()
		var key crypto.Signer = leafKey
		targetTenant := organization
		valid := false
		switch name {
		case "valid":
			valid = true
		case "reversed-eku", "critical-eku":
			extension(leaf, extendedKeyUsageOID, name == "critical-eku", []asn1.ObjectIdentifier{liteEKU, clientEKU})
			valid = true
		case "missing-basic-constraints":
			leaf.BasicConstraintsValid = false
			valid = true
		case "nested-operator":
			leaf.URIs = uris(tenant + "operator/Auth0_user-1.test/nested")
			valid = true
		case "wrong-tenant":
			targetTenant = "3558fd76-afc7-466e-9613-6b715296a526"
		case "invalid-tenant":
			targetTenant = "not-a-tenant"
		case "device-role":
			leaf.URIs = uris(tenant + "device/test-device")
		case "missing-uri":
			leaf.URIs = nil
		case "duplicate-uri":
			leaf.URIs = uris(operatorURI, operatorURI)
		case "extra-uri":
			leaf.URIs = uris(operatorURI, "https://wendy.sh/operator")
		case "invalid-uri":
			leaf.URIs = uris(operatorURI + "?role=operator")
		case "missing-key-usage":
			leaf.KeyUsage = 0
		case "noncritical-key-usage":
			extension(leaf, keyUsageOID, false, asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
		case "wrong-key-usage":
			leaf.KeyUsage = x509.KeyUsageKeyEncipherment
		case "extra-key-usage":
			leaf.KeyUsage |= x509.KeyUsageKeyAgreement
		case "unknown-key-usage":
			extension(leaf, keyUsageOID, true, asn1.BitString{Bytes: []byte{0x80, 0x40}, BitLength: 10})
		case "duplicate-key-usage":
			for i := 0; i < 2; i++ {
				extension(leaf, keyUsageOID, true, asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
			}
		case "missing-eku":
			leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage = nil, nil
		case "missing-client-eku":
			leaf.ExtKeyUsage = nil
		case "missing-lite-eku":
			leaf.UnknownExtKeyUsage = nil
		case "extra-eku":
			leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		case "extra-unknown-eku":
			leaf.UnknownExtKeyUsage = append(leaf.UnknownExtKeyUsage, asn1.ObjectIdentifier{1, 2, 3, 4})
		case "duplicate-client-eku":
			leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "duplicate-lite-eku":
			leaf.UnknownExtKeyUsage = append(leaf.UnknownExtKeyUsage, liteEKU)
		case "duplicate-eku-extension":
			for i := 0; i < 2; i++ {
				extension(leaf, extendedKeyUsageOID, false, []asn1.ObjectIdentifier{clientEKU, liteEKU})
			}
		case "wrong-lite-eku":
			leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 65441, 1, 8}}
		case "ca-leaf":
			leaf.IsCA = true
		case "p384-leaf":
			key = newKey(elliptic.P384())
		case "rsa-leaf":
			key, err = rsa.GenerateKey(rand.Reader, 2048)
			must(err)
		case "ed25519-leaf":
			_, key, err = ed25519.GenerateKey(rand.Reader)
			must(err)
		}
		der := issue(leaf, root, key, rootKey)
		switch name {
		case "truncated":
			der = der[:len(der)-1]
		case "extra-der":
			der = append(der, 0)
		case "two-leaves":
			der = append(der, validDER...)
		case "pem-leaf":
			der = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		expected := "invalid"
		if valid {
			expected = "valid"
		}
		run("operator", write("operator-"+name+".der", der), expected, targetTenant)
		fmt.Println("PASS Lite operator", name)
	}
}
