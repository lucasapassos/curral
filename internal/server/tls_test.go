package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cf, kf
}

func TestCertLoaderReload(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writeCert(t, dir, "first")
	l, err := NewCertLoader(cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", l.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go srv.Serve(ln)
	defer srv.Close()

	peerCN := func() string {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if cn := peerCN(); cn != "first" {
		t.Fatalf("cn=%s", cn)
	}
	writeCert(t, dir, "renewed")
	if err := l.Reload(); err != nil {
		t.Fatal(err)
	}
	if cn := peerCN(); cn != "renewed" {
		t.Fatalf("after reload cn=%s", cn)
	}
	os.WriteFile(kf, []byte("broken"), 0o600)
	if err := l.Reload(); err == nil {
		t.Fatal("broken pair accepted")
	}
	if cn := peerCN(); cn != "renewed" {
		t.Fatalf("broken reload replaced the certificate: %s", cn)
	}
	// TLS 1.1 is refused.
	if _, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
}
