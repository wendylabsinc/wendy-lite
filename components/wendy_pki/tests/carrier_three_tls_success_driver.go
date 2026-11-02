//go:build ignore

// Positive independent Go TLS peers for the production carrier/MbedTLS fixture.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const rounds = 24

var lengths = [3]int{80, 1024, 1100}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func content(k, peer, direction, sequence int) []byte {
	p := make([]byte, lengths[k])
	p[0] = []byte{2, 'M', 1}[k]
	p[1] = byte(peer)
	p[2] = byte(direction)
	p[3] = byte(sequence)
	for i := 4; i < len(p); i++ {
		p[i] = byte(i*29 + peer*61 + direction*17 + sequence*13 + k*7)
	}
	return p
}
func wire(k, peer, sequence int) []byte {
	p := content(k, peer, 1, sequence)
	prefix := 5
	if k == 1 {
		prefix = 9
	}
	out := make([]byte, prefix+len(p))
	out[0] = 2
	if k == 1 {
		out[0] = 1
		binary.BigEndian.PutUint32(out[5:9], uint32(len(p)))
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(out)-5))
	copy(out[prefix:], p)
	return out
}

type clientResult struct {
	index      int
	sent, got  string
	connection *tls.Conn
	err        error
}

func exchange(raw net.Conn, config *tls.Config, index int) clientResult {
	r := clientResult{index: index}
	var err error
	secure := tls.Client(raw, config)
	r.connection = secure
	must(secure.SetDeadline(time.Now().Add(45 * time.Second)))
	if err = secure.Handshake(); err != nil {
		r.err = err
		return r
	}
	var send bytes.Buffer
	for sequence := 0; sequence < rounds; sequence++ {
		for k := 0; k < 3; k++ {
			send.Write(wire(k, index, sequence))
		}
	}
	plain := send.Bytes()
	h := sha256.Sum256(plain)
	r.sent = hex.EncodeToString(h[:])
	written := make(chan error, 1)
	go func() {
		for len(plain) > 0 {
			n := 997
			if n > len(plain) {
				n = len(plain)
			}
			used, e := secure.Write(plain[:n])
			if e != nil {
				written <- e
				return
			}
			plain = plain[used:]
		}
		written <- nil
	}()
	digest := sha256.New()
	var counts [3]int
	for received := 0; received < 3*rounds; received++ {
		var head [5]byte
		if _, err = io.ReadFull(secure, head[:]); err != nil {
			r.err = err
			return r
		}
		size := int(binary.BigEndian.Uint32(head[1:]))
		if size <= 0 || size > 2048 {
			r.err = fmt.Errorf("frame bound %d", size)
			return r
		}
		body := make([]byte, size)
		if _, err = io.ReadFull(secure, body); err != nil {
			r.err = err
			return r
		}
		digest.Write(head[:])
		digest.Write(body)
		control := head[0] == 1
		if control {
			if len(body) < 4 || int(binary.BigEndian.Uint32(body)) != len(body)-4 {
				r.err = fmt.Errorf("inner frame length")
				return r
			}
			body = body[4:]
		} else if head[0] != 2 {
			r.err = fmt.Errorf("frame type")
			return r
		}
		k := 2
		if control {
			k = 1
		} else if body[0] == 2 {
			k = 0
		}
		if counts[k] >= rounds || !bytes.Equal(body, content(k, index, 0, counts[k])) {
			r.err = fmt.Errorf("peer %d class %d FIFO/bytes mismatch", index, k)
			return r
		}
		counts[k]++
	}
	if err = <-written; err != nil {
		r.err = err
		return r
	}
	r.got = hex.EncodeToString(digest.Sum(nil))
	return r
}
func main() {
	if len(os.Args) != 3 {
		panic("usage fixture-binary p256|mldsa65")
	}
	profile := os.Args[2]
	directory, err := os.MkdirTemp("", "carrier-three-tls-")
	must(err)
	defer os.RemoveAll(directory)
	var rootKey crypto.Signer
	if profile == "mldsa65" {
		rootKey, err = mldsa.GenerateKey(mldsa.MLDSA65())
	} else {
		rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	must(err)
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "normal carrier fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	root, err = x509.ParseCertificate(rootDER)
	must(err)
	issue := func(id int, server bool) (crypto.Signer, []byte) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(e)
		uri, e := url.Parse(fmt.Sprintf("spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/device/00000000-0000-4000-8000-%012d", id))
		must(e)
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(id)), Subject: pkix.Name{CommonName: uri.String()}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}}
		if server {
			cert.DNSNames = []string{"server"}
		}
		der, e := x509.CreateCertificate(rand.Reader, cert, root, key.Public(), rootKey)
		must(e)
		return key, der
	}
	serverKey, serverDER := issue(4, true)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	must(err)
	rootsPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), rootsPEM...)
	keyPath := filepath.Join(directory, "key.der")
	certPath := filepath.Join(directory, "cert.pem")
	rootPath := filepath.Join(directory, "root.pem")
	must(os.WriteFile(keyPath, keyDER, 0600))
	must(os.WriteFile(certPath, certPEM, 0600))
	must(os.WriteFile(rootPath, rootsPEM, 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[1], keyPath, certPath, rootPath)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	stdout, err := command.StdoutPipe()
	must(err)
	must(command.Start())
	defer command.Process.Kill()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		panic(diagnostics.String())
	}
	port, err := strconv.Atoi(scanner.Text())
	must(err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	results := make(chan clientResult, 3)
	for i := 0; i < 3; i++ {
		key, der := issue(i+5, false)
		config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "server", Certificates: []tls.Certificate{{Certificate: [][]byte{der, rootDER}, PrivateKey: key}}}
		raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
		must(err)
		go func(index int) { results <- exchange(raw, config, index) }(i)
	}
	clients := map[int]clientResult{}
	for i := 0; i < 3; i++ {
		r := <-results
		if r.connection != nil {
			defer r.connection.Close()
		}
		if r.err != nil {
			panic(fmt.Sprintf("client %d: %v\n%s", r.index, r.err, diagnostics.String()))
		}
		clients[r.index] = r
	}
	summaries := 0
	for scanner.Scan() {
		var s struct {
			Peer                         int `json:"peer"`
			Sent, Got                    string
			Wants, Retries, LoanProgress uint64
		}
		must(json.Unmarshal(scanner.Bytes(), &s))
		r := clients[s.Peer]
		if s.Sent != r.got || s.Got != r.sent || s.Wants == 0 || s.Retries == 0 || s.LoanProgress == 0 {
			panic(fmt.Sprintf("digest/retry/loan mismatch %+v", s))
		}
		fmt.Printf("context %d: WANT=%d pinned-retries=%d loan-progress=%d PASS\n", s.Peer, s.Wants, s.Retries, s.LoanProgress)
		summaries++
	}
	must(scanner.Err())
	if err = command.Wait(); err != nil {
		panic(fmt.Sprintf("C fixture: %v\n%s", err, diagnostics.String()))
	}
	if summaries != 3 {
		panic("missing context summaries")
	}
	fmt.Printf("%s: 3 real TLS contexts x 53352B/direction, fair-frame bytes/FIFO, 512B BIO, WANT retry and independent loan progress PASS\n", profile)
	fmt.Print(diagnostics.String())
}
