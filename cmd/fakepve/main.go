// Command fakepve serves Morche's fake Proxmox VE cluster for development:
// the same HTTPS API, tasks, consoles and backups as a small three-node
// cluster, kept in memory. Only the TLS certificate survives a restart, so
// a fingerprint pinned in the panel stays valid.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/morcheh/backend/internal/proxmox/fake"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("FAKEPVE_ADDR", ":8006")
	tokenID := env("FAKEPVE_TOKEN_ID", "root@pam!morche")
	secret := env("FAKEPVE_TOKEN_SECRET", "00000000-fake-4000-8000-000000000000")
	data := env("FAKEPVE_DATA", "/data")

	cert, err := loadCert(data)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = fmt.Sprintf("%02X", b)
	}
	log.Printf("fake Proxmox VE on %s, token %s, fingerprint %s", addr, tokenID, strings.Join(pairs, ":"))

	f := fake.New(fake.Options{TokenID: tokenID, Secret: secret})
	srv := &http.Server{
		Addr:              addr,
		Handler:           f.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// loadCert reads data/pve.crt + pve.key, making a self-signed pair the first time.
func loadCert(dir string) (tls.Certificate, error) {
	crt, key := filepath.Join(dir, "pve.crt"), filepath.Join(dir, "pve.key")
	if c, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return c, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pve1.morcheh.test", Organization: []string{"PVE Cluster Node"}},
		DNSNames:     []string{"pve1.morcheh.test", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(crt, key)
}
