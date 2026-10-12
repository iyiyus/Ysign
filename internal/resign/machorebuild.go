package resign

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"ysign/internal/macho"
	"ysign/internal/signing"
)

const (
	csMagicEmbeddedSignature = 0xfade0cc0
	csMagicBlobWrapper       = 0xfade0b01

	slotCodeDirectory = 0
	slotRequirements  = 2
	slotEntitlements  = 5
	slotSignature     = 0x10000

	csFlagAdhoc           = 0x0002
	csFlagHardenedRuntime = 0x10000
)

// signContext carries everything needed to rebuild one Mach-O signature.
type signContext struct {
	BundleID string
	TeamID   string
	AdHoc    bool
	Force    bool
	Cache    *signing.DiskCache
	Signer   *signing.Signer // nil for adhoc

	// Main-binary overrides: recompute slot -1 (Info) and slot -5 (Entitlements).
	InfoPlist       []byte
	EntitlementsXML []byte
	// KeepAllSpecialHashes true for embedded (framework/appex) binaries whose
	// Info/entitlements are unchanged, so their original special hashes are reused.
	KeepAllSpecialHashes bool
	// ForceSHA256 (from -2/--sha256_only) rebuilds the CodeDirectory with a
	// SHA-256 hash type instead of inheriting the original binary's hash type.
	ForceSHA256 bool
	// SpecialInfoPlist and SpecialCodeResources are the owning bundle's
	// Info.plist and CodeResources file bytes, used to recompute special slots
	// (-1 / -3) at the active hash size when forcing SHA-256.
	SpecialInfoPlist    []byte
	SpecialCodeResources []byte
}

// rebuildBinary re-signs every slice of a thin or universal binary.
func rebuildBinary(data []byte, ctx *signContext) ([]byte, error) {
	f, err := macho.Parse(data)
	if err != nil {
		return nil, err
	}
	if !f.IsFat {
		if len(f.Slices) != 1 {
			return nil, errors.New("unexpected slice count")
		}
		return rebuildSlice(f.Slices[0], ctx)
	}

	newSlices := make([][]byte, len(f.Slices))
	for i, thin := range f.Slices {
		ns, err := rebuildSlice(thin, ctx)
		if err != nil {
			return nil, fmt.Errorf("slice %d (%s): %w", i, thin.CPUName(), err)
		}
		newSlices[i] = ns
	}
	return f.Reassemble(newSlices)
}

// rebuildSlice re-signs a single thin image.
func rebuildSlice(thin *macho.ThinFile, ctx *signContext) ([]byte, error) {
	if thin.Signature == nil {
		return rebuildUnsignedSlice(thin, ctx)
	}
	sb, err := thin.ParseSuperblob()
	if err != nil {
		return nil, err
	}
	cd, err := sb.ParseCodeDirectory(thin.Endian)
	if err != nil {
		return nil, err
	}
	hashType := cd.HashType
	hashSize := cd.HashSize
	pageSize := cd.PageSize
	if hashType == 0 || hashSize == 0 {
		hashType, hashSize = signing.HashSHA256, 32
	}
	if pageSize == 0 {
		pageSize = 12
	}
	if ctx.ForceSHA256 {
		hashType, hashSize = signing.HashSHA256, 32
	}

	codeLimit := thin.Signature.DataOffset
	if codeLimit == 0 || int(codeLimit) > len(thin.Data) {
		codeLimit = uint32(len(thin.Data))
	}
	// Determine requirements + entitlements blobs to carry into the superblob.
	var reqBlob []byte
	if sb.RequirementsSlot != nil && sb.RequirementsSlot.Blob != nil {
		reqBlob = sb.RequirementsSlot.Blob.Data
	}
	var entBlob []byte
	if ctx.EntitlementsXML != nil {
		entBlob = signing.BuildEntitlementsBlob(ctx.EntitlementsXML)
	} else if sb.EntitlementsSlot != nil && sb.EntitlementsSlot.Blob != nil {
		entBlob = sb.EntitlementsSlot.Blob.Data
	}

	// Special slot hashes.
	nSpecial := int(cd.NSpecialSlots)
	special := make([][]byte, nSpecial)
	for i := 0; i < nSpecial; i++ {
		special[i] = cd.SpecialSlotHash(-(i + 1))
	}
	if ctx.ForceSHA256 {
		// -2/--sha256_only: recompute every special slot at the forced SHA-256
		// size from the actual sealed data (Info.plist, requirements,
		// CodeResources, entitlements), zero-filling slots whose data is
		// unavailable -- mirroring upstream zsign.
		special = specialHashesAt(special, ctx, reqBlob, entBlob, hashType, hashSize)
	} else if !ctx.KeepAllSpecialHashes {
		if ctx.InfoPlist != nil && nSpecial > 0 {
			if h, err := signing.HashBytes(hashType, ctx.InfoPlist); err == nil {
				special[0] = h // slot -1
			}
		}
		if ctx.EntitlementsXML != nil && nSpecial >= 5 {
			blob := signing.BuildEntitlementsBlob(ctx.EntitlementsXML)
			if h, err := signing.HashBytes(hashType, blob); err == nil {
				special[4] = h // slot -5
			}
		}
	}

	// Determine identifier/team: only the main binary gets the new identity;
	// embedded binaries (frameworks/extensions) keep their own identifier.
	identifier, teamID := cd.Identifier, cd.TeamID
	if !ctx.KeepAllSpecialHashes {
		identifier = ctx.BundleID
		teamID = ctx.TeamID
	}

	// Two-pass build: page hashes must cover the post-patch LC_CODE_SIGNATURE
	// datasize, but the blob length is independent of the hash values.
	buildPass := func(hashes [][]byte) ([]byte, error) {
		params := &signing.CodeDirectoryParams{
			Version:       cd.Version,
			Flags:         cd.Flags,
			Platform:      cd.Platform,
			PageSizeLog:   pageSize,
			HashType:      hashType,
			HashSize:      hashSize,
			Identifier:    identifier,
			TeamID:        teamID,
			CodeLimit:     codeLimit,
			SpecialHashes: special,
			CodeHashes:    hashes,
			ExecSegBase:   cd.ExecSegBase,
			ExecSegLimit:  cd.ExecSegLimit,
			ExecSegFlags:  cd.ExecSegFlags,
		}
		if ctx.AdHoc {
			params.Flags |= csFlagAdhoc
		}
		return signing.BuildCodeDirectory(thin.Data[:codeLimit], params)
	}

	// Pass 1: provisional CD (page hashes over unpatched bytes) -> blob size.
	code := thin.Data[:codeLimit]
	provHashes := pageHashesCached(ctx, code, codeLimit, pageSize, hashType)
	provCD, err := buildPass(provHashes)
	if err != nil {
		return nil, err
	}
	sig1, err := buildSignature(provCD, ctx)
	if err != nil {
		return nil, err
	}
	blob1 := buildSuperblob(provCD, reqBlob, entBlob, sig1)
	finalSize := len(blob1)

	// Patch the LC_CODE_SIGNATURE datasize (this changes the hashed code bytes).
	if err := thin.PatchSignatureSize(uint32(finalSize)); err != nil {
		return nil, err
	}

	// Pass 2: recompute page hashes over the patched code, rebuild CD + sig.
	code = thin.Data[:codeLimit]
	hashes := pageHashesCached(ctx, code, codeLimit, pageSize, hashType)
	finalCD, err := buildPass(hashes)
	if err != nil {
		return nil, err
	}
	sig2, err := buildSignature(finalCD, ctx)
	if err != nil {
		return nil, err
	}
	blob2 := buildSuperblob(finalCD, reqBlob, entBlob, sig2)

	out := make([]byte, 0, len(code)+len(blob2))
	out = append(out, code...)
	out = append(out, blob2...)
	return out, nil
}

func pageHashesCached(ctx *signContext, code []byte, codeLimit uint32, pageSizeLog, hashType uint8) [][]byte {
	if ctx.Cache != nil && !ctx.Force {
		key := "ph_" + signing.Key(code)
		if data, ok := ctx.Cache.Get(key); ok {
			hs := int(hashSizeFor(hashType))
			if hs > 0 && len(data)%hs == 0 {
				out := make([][]byte, 0, len(data)/hs)
				for i := 0; i+hs <= len(data); i += hs {
					out = append(out, data[i:i+hs])
				}
				return out
			}
		}
	}
	hashes, err := signing.ComputePageHashes(code, codeLimit, pageSizeLog, hashType)
	if err != nil {
		return nil
	}
	if ctx.Cache != nil {
		var joined []byte
		for _, h := range hashes {
			joined = append(joined, h...)
		}
		_ = ctx.Cache.Set("ph_"+signing.Key(code), joined)
	}
	return hashes
}

func hashSizeFor(hashType uint8) int {
	switch hashType {
	case signing.HashSHA256:
		return 32
	case signing.HashSHA1:
		return 20
	default:
		return 0
	}
}

// specialHashesAt recomputes special slot hashes at the given hash size for a
// forced SHA-256 code directory. Slots -1, -2, -3 and -5 are derived from the
// sealed Info.plist, requirements blob, CodeResources and entitlements blob
// respectively; other slots are kept when their original size already matches,
// otherwise zero-filled.
func specialHashesAt(orig [][]byte, ctx *signContext, reqBlob, entBlob []byte, hashType, hashSize uint8) [][]byte {
	out := make([][]byte, len(orig))
	zero := make([]byte, hashSize)
	hash := func(data []byte) []byte {
		if len(data) == 0 {
			return zero
		}
		if h, err := signing.HashBytes(hashType, data); err == nil {
			return h
		}
		return zero
	}
	reuse := func(i int) []byte {
		if len(orig[i]) == int(hashSize) {
			return orig[i]
		}
		return zero
	}
	for i := range orig {
		switch i {
		case 0: // -1 Info.plist
			src := ctx.SpecialInfoPlist
			if src == nil {
				src = ctx.InfoPlist
			}
			out[i] = hash(src)
		case 1: // -2 requirements
			out[i] = hash(reqBlob)
		case 2: // -3 CodeResources
			out[i] = hash(ctx.SpecialCodeResources)
		case 4: // -5 entitlements
			out[i] = hash(entBlob)
		default:
			out[i] = reuse(i)
		}
	}
	return out
}

// buildSignature produces the CMS signature blob (or ad-hoc) for a CD.
func buildSignature(cd []byte, ctx *signContext) ([]byte, error) {
	var cms []byte
	var err error
	if ctx.AdHoc {
		cms, err = signing.BuildCMSAdHoc(cd)
	} else if ctx.Signer != nil {
		cdKey := signing.Key(cd)
		key := "cms_" + cdKey + "_" + certID(ctx.Signer)
		if cached, ok := ctx.Cache.Get(key); ok && !ctx.Force {
			cms = cached
		} else {
			cms, err = signing.BuildCMS(cd, ctx.Signer.Cert, ctx.Signer.Chain, ctx.Signer.PrivKey)
			if err == nil {
				_ = ctx.Cache.Set(key, cms)
			}
		}
	} else {
		return nil, errors.New("no signer and not adhoc")
	}
	if err != nil {
		return nil, err
	}
	// Wrap CMS in a blob wrapper: magic + length + cms.
	out := make([]byte, 8+len(cms))
	binary.BigEndian.PutUint32(out[0:], csMagicBlobWrapper)
	binary.BigEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], cms)
	return out, nil
}

func certID(s *signing.Signer) string {
	if s == nil || s.Cert == nil {
		return "anon"
	}
	return fmt.Sprintf("%x", s.Cert.SerialNumber)
}

// buildSuperblob assembles a CSMAGIC_EMBEDDED_SIGNATURE blob from slots.
func buildSuperblob(cd, req, ent, sig []byte) []byte {
	type slot struct {
		typ uint32
		b   []byte
	}
	var slots []slot
	if cd != nil {
		slots = append(slots, slot{slotCodeDirectory, cd})
	}
	if req != nil {
		slots = append(slots, slot{slotRequirements, req})
	}
	if ent != nil {
		slots = append(slots, slot{slotEntitlements, ent})
	}
	if sig != nil {
		slots = append(slots, slot{slotSignature, sig})
	}
	// Sort ascending by slot type (codesign convention).
	for i := 1; i < len(slots); i++ {
		for j := i; j > 0 && slots[j].typ < slots[j-1].typ; j-- {
			slots[j], slots[j-1] = slots[j-1], slots[j]
		}
	}
	total := 12 + len(slots)*8
	for _, s := range slots {
		total += len(s.b)
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:], csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(out[4:], uint32(total))
	binary.BigEndian.PutUint32(out[8:], uint32(len(slots)))
	off := 12 + len(slots)*8
	for i, s := range slots {
		pos := 12 + i*8
		binary.BigEndian.PutUint32(out[pos:], s.typ)
		binary.BigEndian.PutUint32(out[pos+4:], uint32(off)) // offset relative to superblob start
		copy(out[off:], s.b)
		off += len(s.b)
	}
	return out
}

// rebuildUnsignedSlice signs a thin image that has no LC_CODE_SIGNATURE at all.
// It mirrors zsign: write the 16-byte LC_CODE_SIGNATURE into the padding right
// after the existing load commands (no segment shifting), then append the
// signature blob at end of file.
func rebuildUnsignedSlice(thin *macho.ThinFile, ctx *signContext) ([]byte, error) {
	headerLen := 32
	if !thin.Is64 {
		headerLen = 28
	}
	lcEnd := headerLen + int(thin.SizeOfCmds)

	// Work on a mutable copy of the original image.
	img := make([]byte, len(thin.Data))
	copy(img, thin.Data)

	// Write LC_CODE_SIGNATURE (linkedit_data_command) at lcEnd.
	thin.Endian.PutUint32(img[lcEnd:], 0x1d)       // LC_CODE_SIGNATURE
	thin.Endian.PutUint32(img[lcEnd+4:], 16)       // cmdsize
	thin.Endian.PutUint32(img[lcEnd+8:], uint32(len(img))) // dataoff = end of code
	// datasize patched after first blob build.

	// Update ncmds / sizeofcmds in the header.
	thin.Endian.PutUint32(img[16:20], thin.NCmds+1)
	thin.Endian.PutUint32(img[20:24], thin.SizeOfCmds+16)

	codeLimit := uint32(len(img))

	// Extract exec-segment bounds from the __TEXT LC_SEGMENT_64.
	var execBase, execLimit uint64
	for _, c := range thin.LoadCmds {
		if c.Cmd != 0x19 && c.Cmd != 0x1 {
			continue
		}
		if len(c.Payload) < 32 {
			continue
		}
		name := string(c.Payload[0:16])
		if idx := strings.IndexByte(name, 0); idx >= 0 {
			name = name[:idx]
		}
		if name != "__TEXT" {
			continue
		}
		if c.Cmd == 0x19 {
			execBase = thin.Endian.Uint64(c.Payload[16:24])
			vmsize := thin.Endian.Uint64(c.Payload[24:32])
			execLimit = execBase + vmsize
		} else {
			execBase = uint64(thin.Endian.Uint32(c.Payload[16:20]))
			vmsize := uint64(thin.Endian.Uint32(c.Payload[20:24]))
			execLimit = execBase + vmsize
		}
	}

	hashType, hashSize := uint8(0x2), uint8(32) // SHA-256
	entBlob := signing.BuildEntitlementsBlob(ctx.EntitlementsXML)

	special := make([][]byte, 5)
	if ctx.SpecialInfoPlist != nil {
		if h, err := signing.HashBytes(hashType, ctx.SpecialInfoPlist); err == nil {
			special[0] = h
		}
	}
	if ctx.SpecialCodeResources != nil {
		if h, err := signing.HashBytes(hashType, ctx.SpecialCodeResources); err == nil {
			special[2] = h
		}
	}
	if len(entBlob) > 0 {
		if h, err := signing.HashBytes(hashType, entBlob); err == nil {
			special[4] = h
		}
	}
	for i := range special {
		if len(special[i]) == 0 {
			special[i] = make([]byte, hashSize)
		}
	}

	buildPass := func(hashes [][]byte) ([]byte, error) {
		params := &signing.CodeDirectoryParams{
			Version:       0x20400,
			Flags:         0,
			PageSizeLog:   12,
			HashType:      hashType,
			HashSize:      hashSize,
			Identifier:    ctx.BundleID,
			TeamID:        ctx.TeamID,
			CodeLimit:     codeLimit,
			SpecialHashes: special,
			CodeHashes:    hashes,
			ExecSegBase:   execBase,
			ExecSegLimit:  execLimit,
			ExecSegFlags:  0,
		}
		if ctx.AdHoc {
			params.Flags |= csFlagAdhoc
		}
		return signing.BuildCodeDirectory(img[:codeLimit], params)
	}

	// Pass 1: provisional blob to learn its size.
	provHashes := pageHashesCached(ctx, img[:codeLimit], codeLimit, 12, hashType)
	provCD, err := buildPass(provHashes)
	if err != nil {
		return nil, err
	}
	provSig, err := buildSignature(provCD, ctx)
	if err != nil {
		return nil, err
	}
	provBlob := buildSuperblob(provCD, nil, entBlob, provSig)

	// Patch datasize in the LC we just wrote.
	thin.Endian.PutUint32(img[lcEnd+12:], uint32(len(provBlob)))

	// Pass 2: recompute page hashes over the patched image.
	hashes := pageHashesCached(ctx, img[:codeLimit], codeLimit, 12, hashType)
	finalCD, err := buildPass(hashes)
	if err != nil {
		return nil, err
	}
	finalSig, err := buildSignature(finalCD, ctx)
	if err != nil {
		return nil, err
	}
	finalBlob := buildSuperblob(finalCD, nil, entBlob, finalSig)

	out := make([]byte, 0, codeLimit+uint32(len(finalBlob)))
	out = append(out, img[:codeLimit]...)
	out = append(out, finalBlob...)
	return out, nil
}
