package server

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// CertLoader serves a certificate that can be replaced at runtime (e.g. after
// renewal) without dropping the listener.
type CertLoader struct {
	certFile, keyFile string
	cert              atomic.Pointer[tls.Certificate]
}

// NewCertLoader loads the pair once; a broken pair fails startup.
func NewCertLoader(certFile, keyFile string) (*CertLoader, error) {
	l := &CertLoader{certFile: certFile, keyFile: keyFile}
	if err := l.Reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// Reload reads the files again. On error the current certificate stays.
func (l *CertLoader) Reload() error {
	c, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	l.cert.Store(&c)
	return nil
}

// TLSConfig is a server config using the current certificate, TLS 1.2+.
func (l *CertLoader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return l.cert.Load(), nil
		},
	}
}
