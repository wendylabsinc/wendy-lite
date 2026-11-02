//go:build ignore

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	dir, e := os.MkdirTemp("", "mesh-cert-policy-")
	must(e)
	defer os.RemoveAll(dir)
	base := time.Unix(1800000000, 0)
	for _, scheme := range []string{"p256", "mldsa65"} {
		key := func() crypto.Signer {
			if scheme == "mldsa65" {
				k, e := mldsa.GenerateKey(mldsa.MLDSA65())
				must(e)
				return k
			}
			k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(e)
			return k
		}
		for i, tc := range []struct {
			name               string
			caNB, caNA, nb, na int64
			uncertain, certain int
		}{
			{"ordinary", -1000, 900000, -500, 800000, 0, 0},
			{"issuer-window", -100, 900000, -500, 800000, 0, 0},
			{"future-leaf", -1000, 900000, 3600, 800000, 0, 1},
			{"leaf-grace-boundary", -1000, 900000, 86400, 800000, 0, 1},
			{"leaf-too-future", -1000, 900000, 86401, 800000, 1, 1},
			{"future-ca", 1, 900000, 3600, 800000, 1, 1},
			{"expired-ca", -1000, 0, -500, 800000, 1, 1},
			{"expired-leaf", -1000, 900000, -500, 0, 1, 1},
			{"long-leaf", -1000, 100000000, -500, 732*86400 + 1, 1, 1},
		} {
			rootK, leafK := key(), key()
			root := &x509.Certificate{SerialNumber: big.NewInt(int64(i*2 + 1)), Subject: pkix.Name{CommonName: tc.name + " root"}, NotBefore: base.Add(time.Duration(tc.caNB) * time.Second), NotAfter: base.Add(time.Duration(tc.caNA) * time.Second), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rootK.Public(), rootK)
			must(e)
			for _, role := range []string{"device", "operator"} {
				principal := "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-000000000004"
				if role == "operator" {
					principal = "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/operator/alice"
				}
				uri, e := url.Parse(principal)
				must(e)
				leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i*2 + 2)), Subject: pkix.Name{CommonName: tc.name}, NotBefore: base.Add(time.Duration(tc.nb) * time.Second), NotAfter: base.Add(time.Duration(tc.na) * time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}}
				leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, leafK.Public(), rootK)
				must(e)
				rp, cp := filepath.Join(dir, "root.der"), filepath.Join(dir, "chain.der")
				must(os.WriteFile(rp, rootDER, 0600))
				must(os.WriteFile(cp, leafDER, 0600))
				nb, na := tc.nb, tc.na
				if tc.caNB > nb {
					nb = tc.caNB
				}
				if tc.caNA < na {
					na = tc.caNA
				}
				cmd := exec.Command(os.Args[1], rp, cp, strconv.Itoa(tc.uncertain), strconv.FormatInt(base.Unix()+nb, 10), strconv.FormatInt(base.Unix()+na, 10), strconv.Itoa(tc.certain), role, strconv.FormatInt(base.Unix()+tc.nb, 10), strconv.FormatInt(base.Unix()+tc.caNB, 10))
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				must(cmd.Run())
				fmt.Println(scheme, role, tc.name, "passed")
			}
		}
	}
}
