//go:build ignore

// Disposable fixtures for the current Swift LiteSessionGrant layout.
// Run: go run lite_grant_fixture.go lite-fixtures

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"time"
)

func main() {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	d := new(big.Int).SetBytes(seed)
	x, y := elliptic.P256().ScalarBaseMult(seed)
	sk := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	pub := elliptic.Marshal(elliptic.P256(), x, y)
	device := "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/device/lite-test"
	operator := "spiffe://wendy.sh/tenant/00000000-0000-4000-8000-000000000001/operator/00000000-0000-4000-8000-000000000002"
	kid := "conformance-cloud-key"
	// The operator caller key: a second fixed scalar, public test material.
	opSeed := make([]byte, 32)
	for i := range opSeed {
		opSeed[i] = byte(32 + i)
	}
	ox, oy := elliptic.P256().ScalarBaseMult(opSeed)
	opSPKI, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: ox, Y: oy})
	if err != nil {
		panic(err)
	}
	r := append([]byte("WLG2"), byte(len(kid)))
	r = append(r, []byte(kid)...)
	r = binary.BigEndian.AppendUint64(r, 1700000000)
	r = binary.BigEndian.AppendUint64(r, 1700000060)
	session := make([]byte, 16)
	session[15] = 3
	jti := make([]byte, 16)
	jti[15] = 5
	correlation := make([]byte, 16)
	correlation[15] = 6
	asset := make([]byte, 16)
	asset[15] = 4
	r = append(r, session...)
	r = append(r, jti...)
	r = append(r, correlation...)
	r = append(r, asset...)
	for _, b := range [][]byte{[]byte(device), []byte(operator), opSPKI, []byte("conformance principal descriptor"), []byte("conformance.pki.attestation")} {
		h := sha256.Sum256(b)
		r = append(r, h[:]...)
	}
	unsigned := append([]byte{}, r...)
	sign := func(body []byte) []byte {
		digest := sha256.Sum256(body)
		sr, ss, err := ecdsa.Sign(rand.Reader, sk, digest[:])
		if err != nil {
			panic(err)
		}
		signed := append([]byte{}, body...)
		signed = append(signed, sr.FillBytes(make([]byte, 32))...)
		return append(signed, ss.FillBytes(make([]byte, 32))...)
	}
	root := os.Args[1] + "/"
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(root, 0755))
	write := func(name string, data []byte) { must(os.WriteFile(root+name, data, 0644)) }
	write("operator-spki.der", opSPKI)
	opKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: ox, Y: oy}, D: new(big.Int).SetBytes(opSeed)}
	uri, err := url.Parse(operator)
	must(err)
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Lite operator"}, NotBefore: time.Unix(1699999000, 0), NotAfter: time.Unix(1700003600, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	cert, err := x509.CreateCertificate(rand.Reader, t, t, &opKey.PublicKey, opKey)
	must(err)
	write("operator.der", cert)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	cert, err = x509.CreateCertificate(rand.Reader, t, t, &wrongKey.PublicKey, wrongKey)
	must(err)
	write("operator-wrong-key.der", cert)
	// Same principal, distinct authenticated TLS key: admission must fail.
	for name, dates := range map[string][2]uint64{
		"long-window": {1700000000, 1700000061}, "zero-window": {1700000000, 1700000000},
		"reversed-window": {1700000000, 1699999999}, "zero-issued": {0, 60},
		"overflow": {uint64(1<<63-1) - 100, uint64(1<<63-1) - 40},
	} {
		body := append([]byte{}, unsigned...)
		at := 5 + len(kid)
		binary.BigEndian.PutUint64(body[at:], dates[0])
		binary.BigEndian.PutUint64(body[at+8:], dates[1])
		write(name+".bin", sign(body))
	}
	maxKid := bytes.Repeat([]byte("k"), 128)
	maxBody := append([]byte("WLG2"), byte(len(maxKid)))
	maxBody = append(maxBody, maxKid...)
	maxBody = append(maxBody, unsigned[5+len(kid):]...)
	write("maximum-kid.bin", sign(maxBody))
	if _, err := os.Stat(root + "legacy-grant.bin"); os.IsNotExist(err) {
		legacy := append([]byte{}, unsigned[:5+len(kid)]...)
		legacy = binary.BigEndian.AppendUint64(legacy, 1700000000)
		legacy = binary.BigEndian.AppendUint64(legacy, 1700001800)
		legacy = append(legacy, session...)
		legacy = append(legacy, asset...)
		for _, input := range [][]byte{[]byte(device), []byte(operator), []byte("conformance principal descriptor")} {
			digest := sha256.Sum256(input)
			legacy = append(legacy, digest[:]...)
		}
		write("legacy-grant.bin", sign(legacy))
	}

	// Preserve the exact canonical shared signature when only the unsigned
	// fields are unchanged; otherwise regenerate it with the disposable key.
	r = sign(unsigned)
	if previous, err := os.ReadFile(root + "grant.bin"); err == nil && len(previous) == len(r) && bytes.Equal(previous[:len(previous)-64], unsigned) {
		r = previous
	}
	hash := sha256.Sum256(r)
	write("grant.bin", r)
	write("cloud-key.bin", pub)
	v := map[string]any{"key_id": kid, "public_key_hex": hex.EncodeToString(pub), "record_hex": hex.EncodeToString(r), "grant_hash_hex": hex.EncodeToString(hash[:]), "device_uri": device, "operator_uri": operator, "operator_spki_hex": hex.EncodeToString(opSPKI), "issued_at": 1700000000, "expires_at": 1700000060, "jti_hex": hex.EncodeToString(jti), "correlation_id_hex": hex.EncodeToString(correlation), "attestation": "conformance.pki.attestation", "session_id_hex": hex.EncodeToString(session), "asset_id_hex": hex.EncodeToString(asset), "private_seed_hex": hex.EncodeToString(seed)}
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	write("vector.json", append(b, '\n'))
}
