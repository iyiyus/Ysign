package signing

import (
	"crypto/x509"
	"errors"
)

// AppleChainForLeaf returns the Apple intermediate certificate that issued
// leaf and the Apple root CA that issued that intermediate, matching the
// behaviour of zsign's GenerateCMS (WWDR G1-G8 embedded, root selected by
// which root signs the intermediate).
//
// Fallbacks (mirroring zsign when no WWDR matches, e.g. self-signed test
// certificates): if no embedded intermediate matches the leaf's issuer, the
// chain degrades to just the leaf; if an intermediate is found but no
// embedded root signs it, the chain is [intermediate, leaf].
func AppleChainForLeaf(leaf *x509.Certificate) (inter, root *x509.Certificate, err error) {
	if leaf == nil {
		return nil, nil, errors.New("nil leaf certificate")
	}
	for _, c := range appleChainCerts {
		cert, perr := x509.ParseCertificate(c.raw)
		if perr != nil {
			continue
		}
		// Skip roots: an intermediate's subject must equal the leaf's issuer.
		if string(cert.RawSubject) != string(leaf.RawIssuer) {
			continue
		}
		inter = cert
		break
	}
	if inter == nil {
		return nil, nil, nil // no WWDR match: degrade to a leaf-only chain
	}
	for _, c := range appleChainCerts {
		cert, perr := x509.ParseCertificate(c.raw)
		if perr != nil {
			continue
		}
		if string(cert.RawSubject) == string(inter.RawIssuer) {
			root = cert
			break
		}
	}
	// root may stay nil: chain = [intermediate, leaf] is still usable.
	return inter, root, nil
}
