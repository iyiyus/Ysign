package signing

import "encoding/binary"

const (
	csMagicRequirement = 0xfade0c00 // CSMAGIC_REQUIREMENT

	// Requirement expression opcodes, as emitted by Apple's csreq encoder.
	reqOpIdent              = 0x00000002
	reqOpAnd                = 0x00000006
	reqOpCertField          = 0x0000000b
	reqOpCertGeneric        = 0x0000000e
	reqOpAppleGenericAnchor = 0x0000000f

	// requirement kind stored in the requirements superblob index.
	reqKindDesignated = 0x00000003
)

// reqFieldSubjectCN is the certificate field matched by the designated
// requirement ("subject.CN"), and reqApplePolicyOID is the Apple signing
// policy marker OID (1.2.840.113635.100.6.2.1).
const (
	reqFieldSubjectCN = "subject.CN"
	reqApplePolicyOID = "\x2a\x86\x48\x86\xf7\x63\x64\x06\x02\x01"
)

// BuildRequirementsBlob returns the CSSLOT_REQUIREMENTS blob (a requirements
// superblob holding one designated requirement) for the given code identifier
// and signing certificate common name.
//
// The encoded expression is:
//
//	identifier "<identifier>" and anchor apple generic
//	  and certificate 0[subject.CN] = "<certCN>"
//	  and certificate 1[field.1.2.840.113635.100.6.2.1] exists
//
// The requirement must be satisfied by the certificate that actually signs the
// binary, so it can never be a fixed blob: reusing one captured from another
// identity leaves the designated requirement naming a certificate that is not
// in the signature, and iOS rejects the code as invalidly signed.
//
// When certCN is empty (ad-hoc signing) only the identifier term is emitted.
func BuildRequirementsBlob(identifier, certCN string) []byte {
	var expr []byte
	put32 := func(v uint32) { expr = binary.BigEndian.AppendUint32(expr, v) }
	putStr := func(s string) {
		expr = append(expr, s...)
		if pad := len(s) % 4; pad != 0 {
			expr = append(expr, make([]byte, 4-pad)...)
		}
	}

	put32(0x00000001)
	put32(reqOpAnd)
	put32(reqOpIdent)
	put32(uint32(len(identifier)))
	putStr(identifier)

	if certCN != "" {
		put32(reqOpAnd)
		put32(reqOpAppleGenericAnchor)

		put32(reqOpAnd)
		put32(reqOpCertField)
		put32(0) // certificate index 0: the leaf
		put32(uint32(len(reqFieldSubjectCN)))
		putStr(reqFieldSubjectCN)
		put32(0x00000001)
		put32(uint32(len(certCN)))
		putStr(certCN)

		put32(reqOpCertGeneric)
		put32(1) // certificate index 1: the Apple intermediate
		put32(uint32(len(reqApplePolicyOID)))
		putStr(reqApplePolicyOID)
		put32(0)
	}

	req := make([]byte, 0, 8+len(expr))
	req = binary.BigEndian.AppendUint32(req, csMagicRequirement)
	req = binary.BigEndian.AppendUint32(req, uint32(8+len(expr)))
	req = append(req, expr...)

	// superblob: magic, length, count=1, then one index {kind, offset}.
	const idxOff = 20
	out := make([]byte, 0, idxOff+len(req))
	out = binary.BigEndian.AppendUint32(out, csMagicRequirements)
	out = binary.BigEndian.AppendUint32(out, uint32(idxOff+len(req)))
	out = binary.BigEndian.AppendUint32(out, 1)
	out = binary.BigEndian.AppendUint32(out, reqKindDesignated)
	out = binary.BigEndian.AppendUint32(out, idxOff)
	out = append(out, req...)
	return out
}

// SignerCommonName returns the subject CN of the signer's certificate, or ""
// when no signing identity is available (ad-hoc signing).
func SignerCommonName(s *Signer) string {
	if s == nil || s.Cert == nil {
		return ""
	}
	return s.Cert.Subject.CommonName
}
