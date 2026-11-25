package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type cert struct {
	*x509.Certificate
	key crypto.Signer
}

var (
	now    = time.Now().UTC()
	serial int64
	dir    string
	tenant = "f8640111-6f74-4336-82b1-d3195cab40dc"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mldsaKey() crypto.Signer { k, e := mldsa.GenerateKey(mldsa.MLDSA65()); check(e); return k }
func ecKey() *ecdsa.PrivateKey {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(e)
	return k
}
func makeCert(name string, key crypto.Signer, parent *cert, depth int) cert {
	serial++
	t := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-30 * time.Minute), NotAfter: now.Add(72 * time.Hour), BasicConstraintsValid: true}
	t.IsCA = true
	t.MaxPathLen = depth
	t.MaxPathLenZero = depth == 0
	t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	signer := key
	p := t
	if parent != nil {
		p = parent.Certificate
		signer = parent.key
	}
	der, e := x509.CreateCertificate(rand.Reader, t, p, key.Public(), signer)
	check(e)
	c, e := x509.ParseCertificate(der)
	check(e)
	return cert{c, key}
}
func put(name string, data []byte) { check(os.WriteFile(filepath.Join(dir, name), data, 0600)) }
func cms(name string, certs ...cert) {
	type signedData struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		Content          struct{ Type asn1.ObjectIdentifier }
		Certificates     []asn1.RawValue `asn1:"optional,tag:0"`
		Signers          []asn1.RawValue `asn1:"set"`
	}
	s := signedData{Version: 1}
	s.Content.Type = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	for _, c := range certs {
		s.Certificates = append(s.Certificates, asn1.RawValue{FullBytes: c.Raw})
	}
	der, e := asn1.Marshal(s)
	check(e)
	body, e := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{
		asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}})
	check(e)
	put(name, []byte(base64.StdEncoding.EncodeToString(body)))
}
func main() {
	var err error
	dir, err = os.MkdirTemp("", "pki-est-rollover-")
	check(err)
	defer os.RemoveAll(dir)
	platform := makeCert("EST Fixture Platform Root", mldsaKey(), nil, 3)
	customer := makeCert("EST Fixture Customer Intermediate", mldsaKey(), &platform, 2)
	oldParent := makeCert("EST Fixture Tenant Intermediate CA", mldsaKey(), &customer, 1)
	newParent := makeCert("EST Fixture Tenant Intermediate CA", mldsaKey(), &customer, 1)
	oldDev := makeCert("EST Fixture Tenant Identity CA", mldsaKey(), &oldParent, 0)
	newDev := makeCert("EST Fixture Tenant Device Identity CA", mldsaKey(), &newParent, 0)
	oldOp := makeCert("EST Fixture Tenant Operator Authority CA", mldsaKey(), &oldParent, 0)
	newOp := makeCert("EST Fixture Tenant Operator Authority CA", mldsaKey(), &newParent, 0)
	wrong := makeCert("Unrelated Signing CA", mldsaKey(), &customer, 0)
	liteKey := ecKey()
	liteName := tenant + " Lite Device CA"
	lite := makeCert(liteName, liteKey, &newParent, 0)
	twin := makeCert(liteName, liteKey, nil, 0)
	liteOp := makeCert("Unrelated Lite CA", ecKey(), nil, 0)
	put("lite-twin.der", twin.Raw)
	put("wrong-twin.der", liteOp.Raw)
	cms("lite.cms.b64", customer, lite, newParent)
	cms("overlap.cms.b64", oldDev, newOp, platform, newParent, wrong, oldOp, customer, newDev, oldParent)
	cms("cutover.cms.b64", newOp, customer, newDev, newParent, platform)
	cms("revoked-operator.cms.b64", newDev, newParent, customer, platform)
	cms("revoked-both.cms.b64", newParent, customer, platform)
	cms("invalid-operator.cms.b64", newDev, oldOp, newParent, customer, platform)
	cms("wrong-branch.cms.b64", newDev, oldOp, oldParent, customer, platform)
	for n, c := range map[string]cert{"old-device": oldDev, "new-device": newDev, "old-operator": oldOp, "new-operator": newOp} {
		put(n+".der", c.Raw)
	}
	cmd := exec.Command(os.Args[1], dir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	check(cmd.Run())
}
