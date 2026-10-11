// Run inside a temporary directory under pki-core to use its real timestamp encoder.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/wendylabsinc/pki-core/internal/ca"
	"github.com/wendylabsinc/pki-core/internal/cryptoalg"
	"github.com/wendylabsinc/pki-core/internal/keymgr"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type memorySigner struct {
	keymgr.KeyManager
	key crypto.PrivateKey
}

func (m memorySigner) Sign(_ context.Context, _ *keymgr.KeyHandle, message []byte) ([]byte, error) {
	a, _ := cryptoalg.Lookup("ML_DSA_65")
	return a.Sign(m.key, message)
}
func (m memorySigner) SignDigest(_ context.Context, _ *keymgr.KeyHandle, digest []byte, _ keymgr.HashAlg) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, m.key.(*ecdsa.PrivateKey), digest)
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	out := os.Args[1]
	must(os.MkdirAll(out, 0700))
	write := func(n string, b []byte) { must(os.WriteFile(filepath.Join(out, n), b, 0600)) }
	rootAlg, _ := cryptoalg.Lookup("ML_DSA_87")
	key, pub, err := rootAlg.KeyGen(rand.Reader)
	must(err)
	now := time.Now().UTC().Truncate(time.Second)
	rootT := &cryptoalg.MLDSACertTemplate{Serial: big.NewInt(1), Subject: pkix.Name{CommonName: "pki-core test root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, PathLen: 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := cryptoalg.BuildMLDSASelfSignedCert(rootT, key, pub)
	must(err)
	root, err := x509.ParseCertificate(rootDER)
	must(err)
	write("root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	write("nonce.bin", nonce)
	digest := sha256.Sum256(nonce)
	for _, name := range []string{"valid", "wrong-eku", "expired", "wrong-imprint", "wrong-nonce", "valid-ecdsa"} {
		algorithm := keymgr.AlgoMLDSA65
		if name == "valid-ecdsa" {
			algorithm = keymgr.AlgoECDSAP256
		}
		alg, _ := cryptoalg.Lookup(string(algorithm))
		sk, pk, err := alg.KeyGen(rand.Reader)
		must(err)
		eku := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}
		if name == "wrong-eku" {
			eku[0] = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
		}
		ekuDER, err := asn1.Marshal(eku)
		must(err)
		leafT := &cryptoalg.MLDSACertTemplate{Serial: big.NewInt(2), Subject: pkix.Name{CommonName: "pki-core TSA test signer"}, RawIssuer: root.RawSubject, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), PathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: ekuDER}}}
		if name == "expired" {
			leafT.NotAfter = now.Add(-time.Minute)
		}
		leafDER, err := cryptoalg.BuildMLDSAIssuedCert(leafT, pk, key, pub)
		must(err)
		d := append([]byte(nil), digest[:]...)
		if name == "wrong-imprint" {
			d[0] ^= 1
		}
		n := new(big.Int).SetBytes(nonce)
		if name == "wrong-nonce" {
			n.Add(n, big.NewInt(1))
		}
		request, err := asn1.Marshal(struct {
			Version int
			Imprint struct {
				Algorithm pkix.AlgorithmIdentifier
				Digest    []byte
			}
			Nonce   *big.Int
			CertReq bool
		}{Version: 1, Imprint: struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}, d}, Nonce: n, CertReq: true})
		must(err)
		if name == "valid" {
			// Exercise the firmware's actual TimeStampReq encoder against PKI.
			request, err = os.ReadFile(filepath.Join(out, "request.der"))
			must(err)
		}
		engine := new(ca.Engine)
		engine.SetTSASigner(leafDER, &keymgr.KeyHandle{}, memorySigner{key: sk}, algorithm)
		response, err := engine.IssueTimestamp(context.Background(), request)
		must(err)
		write(name+".der", response)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	deviceKeyDER, err := x509.MarshalECPrivateKey(deviceKey)
	must(err)
	write("device-key.der", deviceKeyDER)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	wrongDER, err := x509.MarshalECPrivateKey(wrongKey)
	must(err)
	write("wrong-key.der", wrongDER)
	principal, _ := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/lite-test")
	// The same mixed-family certificate builder is used by pki-core issuance.
	for _, name := range []string{"identity", "identity-expired", "identity-wrong-eku", "identity-wrong-uri", "identity-duplicate-uri"} {
		template := &cryptoalg.MLDSACertTemplate{Serial: big.NewInt(5), Subject: pkix.Name{CommonName: "lite-test"}, RawIssuer: root.RawSubject, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), PathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{principal}}
		switch name {
		case "identity-expired":
			template.NotAfter = now.Add(-time.Minute)
		case "identity-wrong-eku":
			template.ExtKeyUsage = template.ExtKeyUsage[:1]
		case "identity-wrong-uri":
			u, _ := url.Parse("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/other")
			template.URIs = []*url.URL{u}
		case "identity-duplicate-uri":
			template.URIs = append(template.URIs, principal)
		}
		ekus := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}}
		if len(template.ExtKeyUsage) > 1 {
			ekus = append(ekus, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		}
		ekuDER, err := asn1.Marshal(ekus)
		must(err)
		var san []asn1.RawValue
		for _, u := range template.URIs {
			san = append(san, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(u.String())})
		}
		sanDER, err := asn1.Marshal(san)
		must(err)
		template.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuDER}, {Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanDER}}
		der, err := cryptoalg.BuildMLDSAIssuedCert(template, &deviceKey.PublicKey, key, pub)
		must(err)
		write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

}
