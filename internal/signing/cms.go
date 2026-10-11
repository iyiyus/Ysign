package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// OIDs used in CMS SignedData for Apple-compatible code signing.
var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidDigestSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func sha256Alg() algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oidDigestSHA256, Parameters: asn1.RawValue{Tag: 5}}
}

func rsaSHA256Alg() algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.RawValue{Tag: 5}}
}

func ecdsaSHA256Alg() algorithmIdentifier {
	return algorithmIdentifier{Algorithm: oidECDSAWithSHA256}
}

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT CertificateSet
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version                   int
	Sid                       issuerAndSerial
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT SignedAttributes
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
}

// attribute mirrors CMS Attribute: SEQUENCE { type OID, values SET }.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// BuildCMS constructs an encapsulated CMS SignedData over content (the
// CodeDirectory blob) using SHA-256 and the given private key (RSA or ECDSA).
// The signer certificate and any chain certificates are embedded.
func BuildCMS(content []byte, cert *x509.Certificate, chain []*x509.Certificate, priv crypto.Signer) ([]byte, error) {
	digest := sha256.Sum256(content)

	// --- Authenticated attributes (sorted by DER for DER SET semantics) ---
	oidDER, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}
	mdDER, err := asn1.Marshal(asn1.RawValue{Tag: 4, Bytes: digest[:]}) // OCTET STRING
	if err != nil {
		return nil, err
	}
	timeDER, err := asn1.Marshal(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	attrs := []attribute{
		{Type: oidAttrContentType, Values: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: oidDER}},
		{Type: oidAttrMessageDigest, Values: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: mdDER}},
		{Type: oidAttrSigningTime, Values: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: timeDER}},
	}
	attrDERs := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		d, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		attrDERs = append(attrDERs, d)
	}
	// Insertion sort by lexicographic DER (RFC 5652 requires sorted SET).
	for i := 1; i < len(attrDERs); i++ {
		for j := i; j > 0 && string(attrDERs[j]) < string(attrDERs[j-1]); j-- {
			attrDERs[j], attrDERs[j-1] = attrDERs[j-1], attrDERs[j]
		}
	}
	var setContent []byte
	for _, d := range attrDERs {
		setContent = append(setContent, d...)
	}
	signedAttrs := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: setContent}
	signedAttrsDER, err := asn1.Marshal(signedAttrs)
	if err != nil {
		return nil, err
	}

	// --- Signature over the DER of signedAttrs ---
	digestAlg, sigAlg, signature, err := signAttributes(signedAttrsDER, priv)
	if err != nil {
		return nil, err
	}

	// --- Assemble ---
	encap := encapsulatedContentInfo{
		ContentType: oidData,
		Content:     content,
	}
	allCerts := append([]*x509.Certificate{cert}, chain...)
	certSet := make([]byte, 0, len(allCerts)*512)
	for _, c := range allCerts {
		if c != nil {
			certSet = append(certSet, c.Raw...)
		}
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{digestAlg},
		EncapContentInfo: encap,
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certSet},
		SignerInfos: []signerInfo{{
			Version:                   1,
			Sid:                       issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, SerialNumber: cert.SerialNumber},
			DigestAlgorithm:           digestAlg,
			AuthenticatedAttributes:   signedAttrs,
			DigestEncryptionAlgorithm: sigAlg,
			EncryptedDigest:           signature,
		}},
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	outer := cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func signAttributes(der []byte, priv crypto.Signer) (algorithmIdentifier, algorithmIdentifier, []byte, error) {
	hash := sha256.Sum256(der)
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			return algorithmIdentifier{}, algorithmIdentifier{}, nil, err
		}
		return sha256Alg(), rsaSHA256Alg(), sig, nil
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			return algorithmIdentifier{}, algorithmIdentifier{}, nil, err
		}
		return sha256Alg(), ecdsaSHA256Alg(), sig, nil
	default:
		return algorithmIdentifier{}, algorithmIdentifier{}, nil, fmt.Errorf("unsupported private key type %T", priv)
	}
}

// BuildCMSAdHoc constructs a CMS SignedData with no signers (an ad-hoc
// signature, equivalent to codesign -s -). It carries the content but no
// cryptographic signature.
func BuildCMSAdHoc(content []byte) ([]byte, error) {
	encap := encapsulatedContentInfo{
		ContentType: oidData,
		Content:     content,
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{sha256Alg()},
		EncapContentInfo: encap,
		SignerInfos:      []signerInfo{},
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	outer := cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// ParseCMSContent extracts the embedded content (eContent) from a CMS
// SignedData, used for reading mobileprovision profiles.
func ParseCMSContent(der []byte) ([]byte, error) {
	var outer cmsContentInfo
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after CMS content info")
	}
	if !outer.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("unexpected CMS content type %v", outer.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	return sd.EncapContentInfo.Content, nil
}
