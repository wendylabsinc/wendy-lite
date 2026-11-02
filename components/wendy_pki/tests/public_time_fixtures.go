// Regenerate the disposable P-384 fixtures with:
// go run public_time_fixtures.go public-time-fixtures
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
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

func value(v any) []byte {
	b, err := asn1.Marshal(v)
	must(err)
	return b
}

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

func main() {
	out := os.Args[1]
	must(os.MkdirAll(out, 0755))
	write := func(name string, data []byte) { must(os.WriteFile(filepath.Join(out, name), data, 0644)) }
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(err)
	now := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable P-384 TSA root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	must(err)
	root, err := x509.ParseCertificate(rootDER)
	must(err)
	write("test-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	normalOnly := len(os.Args) == 3
	if normalOnly {
		nonce, err = hex.DecodeString(os.Args[2])
		must(err)
		if len(nonce) != 32 {
			panic("normal nonce must contain 32 bytes")
		}
		write("nonce.bin", nonce)
	}
	imprint := sha256.Sum256(nonce)
	sha256Algorithm := der(0x30, oid(2, 16, 840, 1, 101, 3, 4, 2, 1), der(5))
	tstOID := oid(1, 2, 840, 113549, 1, 9, 16, 1, 4)
	generation, err := asn1.MarshalWithParams(now, "generalized")
	must(err)
	tst := der(0x30, value(1), oid(1, 2, 3, 4),
		der(0x30, sha256Algorithm, value(imprint[:])), value(1), generation, value(new(big.Int).SetBytes(nonce)))
	digest := sha256.Sum256(tst)
	if normalOnly {
		request := struct {
			Version int
			Imprint struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			Nonce   *big.Int
			CertReq bool
		}{Version: 1, Nonce: new(big.Int).SetBytes(nonce), CertReq: true}
		request.Imprint.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.RawValue{Tag: 5}}
		request.Imprint.Digest = imprint[:]
		write("request.der", value(request))
	}
	names := []string{"issuer-present", "issuer-absent", "wrong-issuer", "wrong-serial", "extra-issuer", "unsupported-curve"}
	if normalOnly {
		names = []string{"issuer-present"}
	}
	for _, name := range names {
		curve := elliptic.P384()
		if name == "unsupported-curve" {
			curve = elliptic.P521()
		}
		signer, err := ecdsa.GenerateKey(curve, rand.Reader)
		must(err)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable TSA signer"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true,
				Value: value([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})}},
		}
		leaf, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &signer.PublicKey, key)
		must(err)
		certHash := sha256.Sum256(leaf)
		issuer, serial := root.RawSubject, value(leafTemplate.SerialNumber)
		if name == "wrong-issuer" {
			issuer = value(pkix.Name{CommonName: "Wrong issuer"}.ToRDNSequence())
		}
		if name == "wrong-serial" {
			serial = value(3)
		}
		names := der(0x30, der(0xa4, issuer))
		if name == "extra-issuer" {
			names = der(0x30, der(0xa4, issuer), der(0xa4, issuer))
		}
		issuerSerial := der(0x30, names, serial)
		if name == "issuer-absent" {
			issuerSerial = nil
		}
		ess := der(0x30, der(0x30, der(0x30, value(certHash[:]), issuerSerial)))
		attrs := [][]byte{
			der(0x30, oid(1, 2, 840, 113549, 1, 9, 3), der(0x31, tstOID)),
			der(0x30, oid(1, 2, 840, 113549, 1, 9, 4), der(0x31, value(digest[:]))),
			der(0x30, oid(1, 2, 840, 113549, 1, 9, 16, 2, 47), der(0x31, ess)),
		}
		sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 })
		attrHash := sha256.Sum256(der(0x31, attrs...))
		signature, err := ecdsa.SignASN1(rand.Reader, signer, attrHash[:])
		must(err)
		si := der(0x30, value(1), der(0x30, root.RawSubject, value(leafTemplate.SerialNumber)),
			sha256Algorithm, der(0xa0, attrs...), der(0x30, oid(1, 2, 840, 10045, 4, 3, 2)), value(signature))
		sd := der(0x30, value(3), der(0x31, sha256Algorithm), der(0x30, tstOID, der(0xa0, value(tst))),
			der(0xa0, leaf), der(0x31, si))
		response := der(0x30, der(0x30, value(0)), der(0x30, oid(1, 2, 840, 113549, 1, 7, 2), der(0xa0, sd)))
		write(name+".der", response)
	}
}
