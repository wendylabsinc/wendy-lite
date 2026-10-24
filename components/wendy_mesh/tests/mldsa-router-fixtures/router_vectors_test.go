//go:build wendy_lite_vectors

// Generates Wendy Lite leaf fixtures with the Linux router's production
// manifest signer (WendyOS localmesh.SignManifest). It is compiled into a
// WendyOS checkout's localmesh package through `go test -overlay`; see the
// fixture README in wendy-lite. Disposable keys only; nothing is persisted
// outside the output directory and private keys are never written.
package localmesh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wendylabsinc/WendyOS/go/babel"
	"github.com/wendylabsinc/wendy/go/internal/shared/meshid"
)

const (
	liteVectorTenant      = "7c1e4a52-9d3b-4f60-8a21-5e0f3c9b2d14"
	liteVectorMLDSARouter = "3f8a2c61-7b4e-4d95-a0c3-1e6f9b2d5a87"
	liteVectorECDSARouter = "a9d24e70-1c5b-4f8e-9b36-2f7a0c4e8d13"
)

func TestLiteRouterVectors(t *testing.T) {
	out := os.Getenv("WENDY_LITE_VECTOR_DIR")
	if out == "" {
		t.Skip("set WENDY_LITE_VECTOR_DIR")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		must(os.WriteFile(filepath.Join(out, name), data, 0o644))
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	newMLDSA := func(params mldsa.Parameters) *mldsa.PrivateKey {
		key, err := mldsa.GenerateKey(params)
		must(err)
		return key
	}
	ca := func(serial int64, name string, lifetime time.Duration) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(lifetime), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	// The production enrollment shape: ML-DSA-87 root and customer CA, then
	// ML-DSA-65 tenant and identity CAs. The router sends every certificate
	// except the root, as its TLS chain.
	rootKey := newMLDSA(mldsa.MLDSA87())
	root := ca(1, "lite vector ML-DSA-87 root", 10*365*24*time.Hour)
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	write("roots.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	// An unrelated root with the same name and algorithm, but another key.
	otherRootKey := newMLDSA(mldsa.MLDSA87())
	otherRootDER, err := x509.CreateCertificate(rand.Reader, root, root, otherRootKey.Public(), otherRootKey)
	must(err)
	write("other-root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherRootDER}))
	parent, issuer := root, crypto.Signer(rootKey)
	var intermediates [][]byte
	for i, step := range []struct {
		name   string
		params mldsa.Parameters
	}{{"customer CA", mldsa.MLDSA87()}, {"tenant CA", mldsa.MLDSA65()}, {"identity CA", mldsa.MLDSA65()}} {
		key := newMLDSA(step.params)
		cert := ca(int64(2+i), "lite vector "+step.name, 365*24*time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), issuer)
		must(err)
		intermediates = append([][]byte{der}, intermediates...)
		parent, issuer = cert, key
	}
	leafNotAfter := now.Add(30 * 24 * time.Hour)
	leaf := func(serial int64, device string, key crypto.Signer) ([][]byte, *x509.Certificate) {
		uri, err := url.Parse("spiffe://wendy.sh/tenant/" + liteVectorTenant + "/device/" + device)
		must(err)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: device},
			NotBefore: now.Add(-time.Hour), NotAfter: leafNotAfter, BasicConstraintsValid: true,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			URIs:        []*url.URL{uri}}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), issuer)
		must(err)
		cert, err := x509.ParseCertificate(der)
		must(err)
		return append([][]byte{der}, intermediates...), cert
	}
	// The same body Node.publish signs, including the agent metadata that
	// cmd/wendy-agent supplies to configured carriers.
	manifest := func(cert *x509.Certificate, routerID babel.RouterID) (Manifest, meshid.Device) {
		device, err := meshid.PeerFromCert(cert)
		must(err)
		return Manifest{Version: ManifestVersionRoute, Device: device.UUID(), Name: "jetson-router",
			AgentPort: 50052, Revision: 42, Issued: now.UnixMilli(), Expires: now.Add(time.Minute).UnixMilli(),
			Route: &RouteOrigin{Prefix: netip.PrefixFrom(device.MeshAddress(), 128), RouterID: routerID, Seqno: 7},
			Agent: &AgentMetadata{Version: "0.0.0-dev", OS: "WendyOS", OSVersion: "2026.10.1",
				DeviceType: "jetson-orin-nano", CPUArchitecture: "arm64"}}, device
	}
	control := func(m ControlMessage) []byte {
		data, err := json.Marshal(m)
		must(err)
		if len(data) > MaxControlMessage {
			t.Fatalf("%s control message exceeds the router limit", m.Kind)
		}
		return data
	}

	mldsaKey := newMLDSA(mldsa.MLDSA65())
	mldsaChain, mldsaLeaf := leaf(10, liteVectorMLDSARouter, mldsaKey)
	m, device := manifest(mldsaLeaf, babel.RouterID(0x0123456789abcdef))
	signed, err := SignManifest(m, mldsaChain, mldsaKey, now)
	must(err)
	if !validManifestSignature(signed, mldsaLeaf) {
		t.Fatal("router signer output does not verify")
	}
	write("mldsa-router-bundle.json", control(ControlMessage{Kind: "bundle", Bundle: mldsaChain}))
	write("mldsa-router-manifest.json", control(ControlMessage{Kind: "manifest", Manifest: &signed}))

	// Signatures a leaf must reject: they are valid ML-DSA-65 signatures by
	// the certified key, or by another key, over the wrong message.
	input, opts := signingInput(mldsaKey.Public(), device.Principal(), signed.Body)
	if opts.HashFunc() != 0 {
		t.Fatal("ML-DSA router signatures must be unhashed")
	}
	digest := sha256.Sum256(input)
	other := newMLDSA(mldsa.MLDSA65())
	unbound := make([]byte, 0, len(signed.Body)+64)
	unbound = binary.BigEndian.AppendUint32(append(unbound, manifestDomain...), uint32(len(signed.Body)))
	for _, bad := range []struct {
		name string
		sign func() ([]byte, error)
	}{
		{"hashed", func() ([]byte, error) { return mldsaKey.Sign(nil, digest[:], nil) }},
		{"context", func() ([]byte, error) {
			return mldsaKey.Sign(nil, input, &mldsa.Options{Context: "wendy-local-mesh/manifest/3"})
		}},
		{"other-key", func() ([]byte, error) { return other.Sign(nil, input, nil) }},
		{"no-principal", func() ([]byte, error) { return mldsaKey.Sign(nil, append(unbound, signed.Body...), nil) }},
	} {
		w := cloneSignedManifest(signed)
		w.Signature, err = bad.sign()
		must(err)
		if validManifestSignature(w, mldsaLeaf) {
			t.Fatalf("%s signature unexpectedly verifies", bad.name)
		}
		write("mldsa-router-manifest-"+bad.name+".json", control(ControlMessage{Kind: "manifest", Manifest: &w}))
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ecdsaChain, ecdsaLeaf := leaf(11, liteVectorECDSARouter, ecdsaKey)
	m, _ = manifest(ecdsaLeaf, babel.RouterID(0xfedcba9876543210))
	signed, err = SignManifest(m, ecdsaChain, ecdsaKey, now)
	must(err)
	if !validManifestSignature(signed, ecdsaLeaf) {
		t.Fatal("ECDSA router signer output does not verify")
	}
	write("ecdsa-router-bundle.json", control(ControlMessage{Kind: "bundle", Bundle: ecdsaChain}))
	write("ecdsa-router-manifest.json", control(ControlMessage{Kind: "manifest", Manifest: &signed}))

	write("vector.txt", []byte(fmt.Sprintf("%s %s %s %d %d\n", liteVectorTenant, liteVectorMLDSARouter,
		liteVectorECDSARouter, now.Unix(), leafNotAfter.Unix())))
}
