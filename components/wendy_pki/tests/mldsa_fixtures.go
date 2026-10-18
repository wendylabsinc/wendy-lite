// Regenerate disposable ML-DSA fixtures with Go 1.27 or newer:
// go run mldsa_fixtures.go mldsa-fixtures
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func value(v any) []byte { b, e := asn1.Marshal(v); must(e); return b }
func der(tag byte, values ...[]byte) []byte {
	body := bytes.Join(values, nil)
	length := []byte{byte(len(body))}
	if len(body) >= 128 {
		length = nil
		for n := len(body); n > 0; n >>= 8 {
			length = append([]byte{byte(n)}, length...)
		}
		length = append([]byte{0x80 | byte(len(length))}, length...)
	}
	return bytes.Join([][]byte{{tag}, length, body}, nil)
}
func oid(v ...int) []byte { return value(asn1.ObjectIdentifier(v)) }
func cert(t, parent *x509.Certificate, pub any, key crypto.Signer) *x509.Certificate {
	b, e := x509.CreateCertificate(rand.Reader, t, parent, pub, key)
	must(e)
	c, e := x509.ParseCertificate(b)
	must(e)
	return c
}
func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func ecKey() *ecdsa.PrivateKey {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	return k
}

var now = time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)

const principal = "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/lite-test"

func template(serial int64, name string, ca bool) *x509.Certificate {
	t := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		t.KeyUsage = x509.KeyUsageCertSign
		t.MaxPathLen = 2
	}
	return t
}
func timestamp(leaf, intermediate *x509.Certificate, key *mldsa.PrivateKey, level int, nonce []byte, extra ...*x509.Certificate) []byte {
	imprint := sha256.Sum256(nonce)
	sha := der(0x30, oid(2, 16, 840, 1, 101, 3, 4, 2, 1), der(5))
	tstOID := oid(1, 2, 840, 113549, 1, 9, 16, 1, 4)
	generation, e := asn1.MarshalWithParams(now, "generalized")
	must(e)
	tst := der(0x30, value(1), oid(1, 2, 3, 4), der(0x30, sha, value(imprint[:])), value(1), generation, value(new(big.Int).SetBytes(nonce)))
	hash := sha256.Sum256(tst)
	ch := sha256.Sum256(leaf.Raw)
	ess := der(0x30, der(0x30, der(0x30, value(ch[:]), der(0x30, der(0x30, der(0xa4, leaf.RawIssuer)), value(leaf.SerialNumber)))))
	attrs := [][]byte{
		der(0x30, oid(1, 2, 840, 113549, 1, 9, 3), der(0x31, tstOID)),
		der(0x30, oid(1, 2, 840, 113549, 1, 9, 4), der(0x31, value(hash[:]))),
		der(0x30, oid(1, 2, 840, 113549, 1, 9, 16, 2, 47), der(0x31, ess)),
	}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
	signature, e := key.Sign(rand.Reader, der(0x31, attrs...), crypto.Hash(0))
	must(e)
	si := der(0x30, value(1), der(0x30, leaf.RawIssuer, value(leaf.SerialNumber)), sha, der(0xa0, attrs...), der(0x30, oid(2, 16, 840, 1, 101, 3, 4, 3, level)), value(signature))
	certificates := append(append([]byte{}, leaf.Raw...), intermediate.Raw...)
	for _, c := range extra {
		certificates = append(certificates, c.Raw...)
	}
	sd := der(0x30, value(3), der(0x31, sha), der(0x30, tstOID, der(0xa0, value(tst))), der(0xa0, certificates), der(0x31, si))
	return der(0x30, der(0x30, value(0)), der(0x30, oid(1, 2, 840, 113549, 1, 7, 2), der(0xa0, sd)))
}
func main() {
	out := os.Args[1]
	must(os.MkdirAll(out, 0755))
	write := func(n string, b []byte) { must(os.WriteFile(filepath.Join(out, n), b, 0644)) }
	if len(os.Args) > 2 && os.Args[2] == "mixed-only" {
		raw, err := os.ReadFile(filepath.Join(out, "device-key.der"))
		must(err)
		device, err := x509.ParseECPrivateKey(raw)
		must(err)
		mixedFixtures(device, write)
		return
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	write("nonce.bin", nonce)
	peerHash := sha256.Sum256([]byte(principal))
	write("peer-hash.bin", peerHash[:])
	device := ecKey()
	raw, e := x509.MarshalECPrivateKey(device)
	must(e)
	write("device-key.der", raw)
	wrong := ecKey()
	raw, e = x509.MarshalECPrivateKey(wrong)
	must(e)
	write("wrong-key.der", raw)
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	et := template(99, "Disallowed Ed25519 root", true)
	write("ed25519-root.pem", pemCert(cert(et, et, ed.Public(), ed)))
	for i, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		prefix := []string{"44", "65", "87"}[i]
		rootKey, e := mldsa.GenerateKey(params)
		must(e)
		rt := template(1, "Disposable ML-DSA "+prefix+" root", true)
		root := cert(rt, rt, rootKey.Public(), rootKey)
		write(prefix+"-root.pem", pemCert(root))
		expiredRootTemplate := *rt
		expiredRootTemplate.NotAfter = now.Add(-time.Minute)
		expiredRoot := cert(&expiredRootTemplate, &expiredRootTemplate, rootKey.Public(), rootKey)
		write(prefix+"-expired-root.pem", pemCert(expiredRoot))
		futureRootTemplate := *rt
		futureRootTemplate.NotBefore = now.Add(time.Minute)
		futureRoot := cert(&futureRootTemplate, &futureRootTemplate, rootKey.Public(), rootKey)
		write(prefix+"-future-root.pem", pemCert(futureRoot))
		ik := ecKey()
		it := template(2, "Disposable P-256 intermediate "+prefix, true)
		intermediates := map[string]*x509.Certificate{}
		for _, kind := range []string{"valid", "expired-intermediate", "future-intermediate", "nonca-intermediate", "no-keysign", "pathlen-zero"} {
			t := *it
			if kind == "expired-intermediate" {
				t.NotAfter = now.Add(-time.Minute)
			}
			if kind == "future-intermediate" {
				t.NotBefore = now.Add(time.Minute)
			}
			if kind == "nonca-intermediate" {
				t.IsCA = false
				t.MaxPathLen = -1
			}
			if kind == "no-keysign" {
				t.KeyUsage = x509.KeyUsageDigitalSignature
			}
			if kind == "pathlen-zero" {
				t.MaxPathLen = 0
				t.MaxPathLenZero = true
			}
			intermediates[kind] = cert(&t, root, &ik.PublicKey, rootKey)
		}
		uri, e := url.Parse(principal)
		must(e)
		for _, kind := range []string{"valid", "expired-intermediate", "future-intermediate", "nonca-intermediate", "no-keysign", "pathlen-zero", "expired", "wrong-eku", "wrong-uri", "duplicate-uri"} {
			t := template(3, "Disposable P-256 device", false)
			t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			t.URIs = []*url.URL{uri}
			if kind == "expired" {
				t.NotAfter = now.Add(-time.Minute)
			}
			if kind == "wrong-eku" {
				t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			if kind == "wrong-uri" {
				u, _ := url.Parse(principal + "-wrong")
				t.URIs = []*url.URL{u}
			}
			if kind == "duplicate-uri" {
				t.URIs = append(t.URIs, uri)
			}
			intermediate := intermediates[kind]
			if intermediate == nil {
				intermediate = intermediates["valid"]
			}
			chain := pemCert(intermediate)
			signer := ik
			if kind == "pathlen-zero" {
				signer = ecKey()
				intermediate = cert(template(5, "Subordinate CA", true), intermediate, &signer.PublicKey, ik)
				chain = append(pemCert(intermediate), chain...)
			}
			leaf := cert(t, intermediate, &device.PublicKey, signer)
			write(prefix+"-identity-"+kind+".pem", append(pemCert(leaf), chain...))
			if kind == "valid" || kind == "duplicate-uri" {
				write(prefix+"-identity-"+kind+".der", leaf.Raw)
			}
		}
		sk, e := mldsa.GenerateKey(params)
		must(e)
		for _, kind := range []string{"valid", "expired-intermediate", "future-intermediate", "nonca-intermediate", "no-keysign", "pathlen-zero", "expired", "wrong-eku", "noncritical-eku"} {
			t := template(4, "Disposable ML-DSA TSA "+prefix, false)
			usage := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
			if kind == "wrong-eku" {
				usage[8] = 1
			}
			t.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: kind != "noncritical-eku", Value: value([]asn1.ObjectIdentifier{usage})}}
			if kind == "expired" {
				t.NotAfter = now.Add(-time.Minute)
			}
			intermediate := intermediates[kind]
			if intermediate == nil {
				intermediate = intermediates["valid"]
			}
			var extra []*x509.Certificate
			signer := ik
			if kind == "pathlen-zero" {
				extra = append(extra, intermediate)
				signer = ecKey()
				intermediate = cert(template(5, "Subordinate CA", true), intermediate, &signer.PublicKey, ik)
			}
			leaf := cert(t, intermediate, sk.Public(), signer)
			write(prefix+"-time-"+kind+".der", timestamp(leaf, intermediate, sk, 17+i, nonce, extra...))
		}
		fmt.Println("generated ML-DSA", prefix, "mixed-chain fixtures")
	}
	mixedFixtures(device, write)
}

// Keep the production chain shape: ML-DSA-87 root and customer CA,
// ML-DSA-65 tenant and identity CAs, then a P-256 device or ML-DSA operator.
func mixedFixtures(device *ecdsa.PrivateKey, write func(string, []byte)) {
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	must(err)
	rt := template(100, "Disposable mixed ML-DSA-87 root", true)
	rt.MaxPathLen = 3
	root := cert(rt, rt, rootKey.Public(), rootKey)
	write("mixed87-root.pem", pemCert(root))
	var parent = root
	var signer crypto.Signer = rootKey
	var chain []*x509.Certificate
	for index, params := range []mldsa.Parameters{mldsa.MLDSA87(), mldsa.MLDSA65(), mldsa.MLDSA65()} {
		key, err := mldsa.GenerateKey(params)
		must(err)
		t := template(int64(101+index), fmt.Sprintf("Disposable mixed CA %d", index), true)
		t.MaxPathLen = 2 - index
		t.MaxPathLenZero = t.MaxPathLen == 0
		parent = cert(t, parent, key.Public(), signer)
		signer = key
		chain = append([]*x509.Certificate{parent}, chain...)
	}
	uri, err := url.Parse(principal)
	must(err)
	t := template(110, "Disposable mixed P-256 device", false)
	t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	t.URIs = []*url.URL{uri}
	deviceCert := cert(t, parent, device.Public(), signer)
	bundle := pemCert(deviceCert)
	for _, ca := range chain {
		bundle = append(bundle, pemCert(ca)...)
	}
	write("mixed87-identity-valid.pem", bundle)
	for _, kind := range []string{"tampered-intermediate", "tampered-issuer", "hash87-intermediate", "44-intermediate"} {
		index := 2
		if kind == "tampered-issuer" {
			index = 1
		}
		raw := append([]byte{}, chain[index].Raw...)
		if kind == "tampered-intermediate" || kind == "tampered-issuer" {
			raw[len(raw)-1] ^= 1
		} else {
			// Replace all pure ML-DSA-87 OIDs in this CA only. Both
			// signature AlgorithmIdentifiers and its SPKI are disallowed.
			replacement := byte(34) // HashML-DSA-87 with SHA-512.
			if kind == "44-intermediate" {
				replacement = 17
			}
			raw = bytes.ReplaceAll(raw, oid(2, 16, 840, 1, 101, 3, 4, 3, 19), oid(2, 16, 840, 1, 101, 3, 4, 3, int(replacement)))
		}
		write("mixed87-ca-"+kind+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	operatorURI, err := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/operator/test")
	must(err)
	for index, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		must(err)
		t := template(int64(120+index), "Disposable mixed operator", false)
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		t.URIs = []*url.URL{operatorURI}
		leaf := cert(t, parent, key.Public(), signer)
		write(fmt.Sprintf("mixed87-operator-%d.der", []int{44, 65, 87}[index]), leaf.Raw)
	}
	fmt.Println("generated mixed ML-DSA-87 CA / ML-DSA-65 identity fixtures")
}
