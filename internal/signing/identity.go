package signing

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// Signer bundles a private key with the signing certificate and chain.
type Signer struct {
	PrivKey crypto.Signer
	Cert    *x509.Certificate
	Chain   []*x509.Certificate
}

// LoadP12 loads a signing identity from a PKCS#12 (.p12/.pfx) file.
func LoadP12(path, password string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("decode p12: %w", err)
	}
	priv, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("p12 private key is not a signer")
	}
	// Avoid including the signer certificate itself in the chain.
	var chain []*x509.Certificate
	for _, c := range caCerts {
		if c.Raw == nil || (cert != nil && string(c.Raw) == string(cert.Raw)) {
			continue
		}
		chain = append(chain, c)
	}
	return &Signer{PrivKey: priv, Cert: cert, Chain: chain}, nil
}

// LoadPEM loads a signing identity from PEM files: a private key plus one or
// more certificates (the first is the signer, the rest form the chain).
func LoadPEM(keyPath, certPath string) (*Signer, error) {
	keyDER, err := readPEMBlock(keyPath, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		if k, e2 := x509.ParsePKCS1PrivateKey(keyDER); e2 == nil {
			return signerFromPEMKey(keyDER, certPath, k)
		}
		if k, e2 := x509.ParseECPrivateKey(keyDER); e2 == nil {
			return signerFromPEMKey(keyDER, certPath, k)
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signerFromPEMKey(keyDER, certPath, key)
}

func signerFromPEMKey(keyDER []byte, certPath string, key interface{}) (*Signer, error) {
	priv, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := certData
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in cert file")
	}
	return &Signer{PrivKey: priv, Cert: certs[0], Chain: certs[1:]}, nil
}

func readPEMBlock(path string, types ...string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		for _, t := range types {
			if block.Type == t {
				return block.Bytes, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching PEM block in %s", path)
}
