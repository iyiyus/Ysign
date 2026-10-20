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

	slotCodeDirectory    = 0
	slotRequirements     = 2
	slotEntitlements     = 5
	slotDerEntitlements  = 7
	slotSignature        = 0x10000

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

const (
	// signSpaceSlack is the extra room reserved after the signature blob.
	// A CMS signature can differ by a few bytes between build passes; without
	// slack the LC_CODE_SIGNATURE datasize baked into the hashed code bytes
	// would no longer match the blob actually written.
	signSpaceSlack = 4096
	// signSpaceAlign keeps the reserved region page aligned.
	signSpaceAlign = 4096
)

// signatureAllocSize returns how many bytes to reserve for the code signature
// region. Mirroring zsign's ReallocCodeSignSpace, the region is never shrunk:
// an existing (larger) region is reused as-is, and only growth is allowed.
func signatureAllocSize(blobLen, existing int) int {
	n := blobLen + signSpaceSlack
	if r := n % signSpaceAlign; r != 0 {
		n += signSpaceAlign - r
	}
	if n < existing {
		n = existing
	}
	return n
}

func alignUp64(v, a uint64) uint64 {
	if r := v % a; r != 0 {
		v += a - r
	}
	return v
}

// growLinkEdit extends __LINKEDIT (filesize and vmsize) so the signature
// region ends at needEnd, keeping the blob inside the segment the way zsign
// does. It only ever grows the segment.
//
// dst selects where the patched segment command is written. When dst is nil the
// load-command payload (which aliases thin.Data) is patched in place; callers
// working on a private copy of the image pass that copy together with the
// matching command offsets instead.
func growLinkEdit(thin *macho.ThinFile, dst []byte, needEnd uint64) {
	headerLen := 32
	if !thin.Is64 {
		headerLen = 28
	}
	off := headerLen
	for i := range thin.LoadCmds {
		lc := &thin.LoadCmds[i]
		cmdOff := off
		off += int(lc.Size)
		if lc.Cmd != 0x19 && lc.Cmd != 0x1 {
			continue
		}
		name := string(lc.Payload[0:16])
		if idx := strings.IndexByte(name, 0); idx >= 0 {
			name = name[:idx]
		}
		if name != "__LINKEDIT" {
			continue
		}
		// payload starts 8 bytes (cmd + cmdsize) after the command base
		base := cmdOff + 8
		put := func(vmsize, filesize uint64) {
			if dst != nil {
				if lc.Cmd == 0x19 {
					thin.Endian.PutUint64(dst[base+24:], vmsize)
					thin.Endian.PutUint64(dst[base+40:], filesize)
				} else {
					thin.Endian.PutUint32(dst[base+20:], uint32(vmsize))
					thin.Endian.PutUint32(dst[base+28:], uint32(filesize))
				}
				return
			}
			if lc.Cmd == 0x19 {
				thin.Endian.PutUint64(lc.Payload[24:32], vmsize)
				thin.Endian.PutUint64(lc.Payload[40:48], filesize)
			} else {
				thin.Endian.PutUint32(lc.Payload[20:24], uint32(vmsize))
				thin.Endian.PutUint32(lc.Payload[28:32], uint32(filesize))
			}
		}
		if lc.Cmd == 0x19 { // LC_SEGMENT_64
			if len(lc.Payload) < 48 {
				return
			}
			fileoff := thin.Endian.Uint64(lc.Payload[32:40])
			filesize := thin.Endian.Uint64(lc.Payload[40:48])
			vmsize := thin.Endian.Uint64(lc.Payload[24:32])
			if fileoff+filesize >= needEnd {
				return
			}
			filesize = needEnd - fileoff
			if v := alignUp64(filesize, signSpaceAlign); vmsize < v {
				vmsize = v
			}
			put(vmsize, filesize)
			return
		}
		// LC_SEGMENT (32-bit)
		if len(lc.Payload) < 32 {
			return
		}
		fileoff := uint64(thin.Endian.Uint32(lc.Payload[24:28]))
		filesize := uint64(thin.Endian.Uint32(lc.Payload[28:32]))
		vmsize := uint64(thin.Endian.Uint32(lc.Payload[20:24]))
		if fileoff+filesize >= needEnd {
			return
		}
		filesize = needEnd - fileoff
		if v := alignUp64(filesize, signSpaceAlign); vmsize < v {
			vmsize = v
		}
		put(vmsize, filesize)
		return
	}
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
	// SHA-256 is the default: both Apple codesign and zsign emit SHA-256 code
	// directories, while inheriting the original binary's hash type keeps
	// SHA-1 for ipas that were themselves produced by a re-signing tool.
	// Changing the size invalidates the inherited special-slot hashes, so
	// remember to recompute them below.
	rehashSpecials := ctx.ForceSHA256 || hashType != signing.HashSHA256
	if rehashSpecials {
		hashType, hashSize = signing.HashSHA256, 32
	}

	// Clamp the inherited CodeDirectory version. 0x20500 and above are not
	// Apple-defined versions (they come from other re-signing tools) and iOS
	// rejects a directory whose version it does not know.
	cdVersion := cd.Version
	if cdVersion > signing.CDVersionMax {
		cdVersion = signing.CDVersionMax
	}

	codeLimit := thin.Signature.DataOffset
	if codeLimit == 0 || int(codeLimit) > len(thin.Data) {
		codeLimit = uint32(len(thin.Data))
	}
	nSpecial := int(cd.NSpecialSlots)

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
	// Slot 7 carries the DER-encoded entitlements. Modern iOS parses that form,
	// so it has to be regenerated together with slot 5 -- otherwise the CD
	// seals a stale DER hash and installd rejects the entitlements.
	var derEntBlob []byte
	if nSpecial >= 7 {
		if ctx.EntitlementsXML != nil {
			derEntBlob = signing.BuildDerEntitlementsBlob(ctx.EntitlementsXML)
		} else if sb.DerEntitlementsSlot != nil && sb.DerEntitlementsSlot.Blob != nil {
			derEntBlob = sb.DerEntitlementsSlot.Blob.Data
		}
	}

	// Special slot hashes.
	special := make([][]byte, nSpecial)
	for i := 0; i < nSpecial; i++ {
		special[i] = cd.SpecialSlotHash(-(i + 1))
	}
	if rehashSpecials {
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
	// Slot -3 seals CodeResources. Every bundle's copy is regenerated on this
	// run, including nested ones, so the hash has to be refreshed here too --
	// it cannot stay inside the branch above, which skips binaries that keep
	// their original special hashes.
	if ctx.SpecialCodeResources != nil && nSpecial >= 3 {
		if h, err := signing.HashBytes(hashType, ctx.SpecialCodeResources); err == nil {
			special[2] = h // slot -3
		}
	}
	// Keep slot -7 in sync with the DER blob that is actually embedded below.
	if derEntBlob != nil && nSpecial >= 7 {
		if h, err := signing.HashBytes(hashType, derEntBlob); err == nil {
			special[6] = h // slot -7
		}
	}

	// Determine identifier/team: only the main binary gets the new identity;
	// embedded binaries (frameworks/extensions) keep their own identifier.
	identifier, teamID := cd.Identifier, cd.TeamID
	if !ctx.KeepAllSpecialHashes {
		identifier = ctx.BundleID
		teamID = ctx.TeamID
	}

	// Replace the inherited designated requirement: it names the previous
	// signer's certificate, which ours does not satisfy. Rebuild it for the
	// identity actually signing and reseal the slot -2 hash.
	if cn := signing.SignerCommonName(ctx.Signer); cn != "" {
		reqBlob = signing.BuildRequirementsBlob(identifier, cn)
		if len(special) >= 2 {
			if h, err := signing.HashBytes(hashType, reqBlob); err == nil {
				special[1] = h // slot -2
			}
		}
	}

	// Two-pass build: page hashes must cover the post-patch LC_CODE_SIGNATURE
	// datasize, but the blob length is independent of the hash values.
	buildPass := func(hashes [][]byte) ([]byte, error) {
		params := &signing.CodeDirectoryParams{
			Version:       cdVersion,
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

	// Iterative build: LC_CODE_SIGNATURE's datasize is part of the hashed code
	// bytes, so it must be patched before the page hashes are computed, but the
	// reserved size depends on the blob length. Reserve slack (never shrinking
	// an existing region, as zsign does) and iterate until the blob fits.
	//
	// Pass 1 sizes the blob with zeroed page digests: the CodeDirectory length
	// depends only on the page COUNT, never on the digests, so the multi-GB
	// code bytes are hashed exactly once, in pass 2.
	existing := int(thin.Signature.DataSize)
	nPages := (int(codeLimit) + (1 << pageSize) - 1) / (1 << pageSize)
	if nPages == 0 {
		nPages = 1
	}
	alloc := 0
	var finalBlob []byte
	for iter := 0; iter < 4; iter++ {
		code := thin.Data[:codeLimit]
		var hashes [][]byte
		if alloc == 0 {
			hashes = zeroPageHashes(nPages, int(hashSize))
		} else {
			var err error
			hashes, err = pageHashesCached(ctx, code, codeLimit, pageSize, hashType)
			if err != nil {
				return nil, err
			}
		}
		finalCD, err := buildPass(hashes)
		if err != nil {
			return nil, err
		}
		sig, err := buildSignature(finalCD, ctx)
		if err != nil {
			return nil, err
		}
		blob := buildSuperblob(finalCD, reqBlob, entBlob, derEntBlob, sig)
		if alloc > 0 && len(blob) <= alloc {
			finalBlob = blob
			break
		}
		next := signatureAllocSize(len(blob), existing)
		if next <= alloc {
			// Guarantee forward progress so the loop cannot spin.
			next = alloc + signSpaceAlign
		}
		alloc = next
		if err := thin.PatchSignatureSize(uint32(alloc)); err != nil {
			return nil, err
		}
		growLinkEdit(thin, nil, uint64(codeLimit)+uint64(alloc))
	}
	if finalBlob == nil {
		return nil, errors.New("code signature did not converge")
	}

	return emitImage(thin.Data[:codeLimit], finalBlob, alloc), nil
}

// emitImage appends blob plus zero padding to code, producing an image of
// exactly len(code)+alloc bytes.
//
// Appending into code's spare capacity (the previous signature region when
// re-signing) reuses the buffer instead of allocating and copying a whole
// multi-GB image a second time; growing once up front keeps it to at most a
// single copy when there is not enough room.
func emitImage(code []byte, blob []byte, alloc int) []byte {
	total := len(code) + alloc
	out := code
	if cap(out) < total {
		grown := make([]byte, len(out), total)
		copy(grown, out)
		out = grown
	}
	out = append(out, blob...)
	if pad := total - len(out); pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// zeroPageHashes returns n page digests that all alias one zero buffer. The
// CodeDirectory's size depends only on the page count, so this sizes the blob
// without hashing any code bytes.
func zeroPageHashes(n, hashSize int) [][]byte {
	zero := make([]byte, hashSize)
	out := make([][]byte, n)
	for i := range out {
		out[i] = zero
	}
	return out
}

// cacheMaxPayload caps how large a code payload may be before the cache is
// skipped entirely. The cache key costs a full SHA-256 pass over the payload
// and the stored value holds one digest per 4 KiB page (32 MB of digests per
// GB of code), so on big images the cache costs far more than the parallel
// hashing it would save.
const cacheMaxPayload = 32 << 20

func pageHashesCached(ctx *signContext, code []byte, codeLimit uint32, pageSizeLog, hashType uint8) ([][]byte, error) {
	cacheable := ctx.Cache != nil && !ctx.Force && len(code) <= cacheMaxPayload
	// The digest size must be part of the key: a cached SHA-1 array (20 bytes
	// per page) also divides evenly by 32, so without it switching to SHA-256
	// would return the old digests reinterpreted as SHA-256 ones.
	key := fmt.Sprintf("ph_%d_%s", hashType, signing.Key(code))
	if cacheable {
		if data, ok := ctx.Cache.Get(key); ok {
			hs := int(hashSizeFor(hashType))
			if hs > 0 && len(data)%hs == 0 {
				out := make([][]byte, 0, len(data)/hs)
				for i := 0; i+hs <= len(data); i += hs {
					out = append(out, data[i:i+hs])
				}
				return out, nil
			}
		}
	}
	hashes, err := signing.ComputePageHashes(code, codeLimit, pageSizeLog, hashType)
	if err != nil {
		return nil, err
	}
	if cacheable {
		joined := make([]byte, 0, len(hashes)*int(hashSizeFor(hashType)))
		for _, h := range hashes {
			joined = append(joined, h...)
		}
		_ = ctx.Cache.Set(key, joined)
	}
	return hashes, nil
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

// cmsCacheVersion namespaces cached CMS blobs. Bump it whenever the CMS
// encoding changes: a stale entry is returned verbatim for an identical
// CodeDirectory, so an old blob would otherwise keep shadowing new builds and
// silently ship invalid signatures.
const cmsCacheVersion = "v2"

// buildSignature produces the CMS signature blob (or ad-hoc) for a CD.
func buildSignature(cd []byte, ctx *signContext) ([]byte, error) {
	var cms []byte
	var err error
	if ctx.AdHoc {
		cms, err = signing.BuildCMSAdHoc(cd)
	} else if ctx.Signer != nil {
		cdKey := signing.Key(cd)
		key := "cms_" + cmsCacheVersion + "_" + cdKey + "_" + certID(ctx.Signer)
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
func buildSuperblob(cd, req, ent, derEnt, sig []byte) []byte {
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
	if derEnt != nil {
		slots = append(slots, slot{slotDerEntitlements, derEnt})
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

	// The command goes into the padding that usually sits between the load
	// commands and the first section. Verify the room is really free: writing
	// over section data would silently corrupt the image.
	if lcEnd+16 > len(img) {
		return nil, errors.New("no room to add LC_CODE_SIGNATURE after the load commands")
	}
	for _, b := range img[lcEnd : lcEnd+16] {
		if b != 0 {
			return nil, errors.New("no free padding to add LC_CODE_SIGNATURE; binary has no header slack")
		}
	}

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
	// zsign writes execSegBase=0 and execSegLimit=__TEXT vmsize; follow that
	// exactly so the CodeDirectory matches what zsign produces.
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
			vmsize := thin.Endian.Uint64(c.Payload[24:32])
			execLimit = vmsize
		} else {
			vmsize := uint64(thin.Endian.Uint32(c.Payload[20:24]))
			execLimit = vmsize
		}
		execBase = 0
		break
	}

	hashType, hashSize := uint8(0x2), uint8(32) // SHA-256
	isExecutable := thin.FileType == 2 // MH_EXECUTE
	entBlob := signing.BuildEntitlementsBlob(ctx.EntitlementsXML)
	derEntBlob := signing.BuildDerEntitlementsBlob(ctx.EntitlementsXML)
	// The designated requirement names the certificate that signs this binary,
	// so it must be rebuilt from the signer's subject CN; a captured blob would
	// name some other certificate and iOS would reject the signature.
	reqBlob := signing.BuildRequirementsBlob(ctx.BundleID, signing.SignerCommonName(ctx.Signer))

	// Special hashes are indexed by CSSLOT type:
	//   1=Info.plist, 2=Requirements, 3=CodeResources, 5=XML Entitlements, 7=DER Entitlements
	special := make([][]byte, 8)
	if ctx.SpecialInfoPlist != nil {
		if h, err := signing.HashBytes(hashType, ctx.SpecialInfoPlist); err == nil {
			special[1] = h
		}
	}
	if len(reqBlob) > 0 {
		if h, err := signing.HashBytes(hashType, reqBlob); err == nil {
			special[2] = h
		}
	}
	if ctx.SpecialCodeResources != nil {
		if h, err := signing.HashBytes(hashType, ctx.SpecialCodeResources); err == nil {
			special[3] = h
		}
	}
	if len(entBlob) > 0 {
		if h, err := signing.HashBytes(hashType, entBlob); err == nil {
			special[5] = h
		}
	}
	if len(derEntBlob) > 0 {
		if h, err := signing.HashBytes(hashType, derEntBlob); err == nil {
			special[7] = h
		}
	}
	for i := range special {
		if len(special[i]) == 0 {
			special[i] = make([]byte, hashSize)
		}
	}
	// Match zsign: trim trailing (high-index) empty special slots, keeping
	// slots 1..H where H is the highest slot that carries a real hash.
	// Empty slots between 1 and H (e.g. 4, 6) stay as zero hashes.
	high := 1
	for i := 7; i >= 1; i-- {
		if !allZero(special[i]) {
			high = i
			break
		}
	}
	special = special[1 : high+1]

	// execSegFlags: main binary flag + ALLOW_UNSIGNED when get-task-allow.
	execFlags := uint64(0)
	if isExecutable {
		execFlags |= 0x1 // CS_EXECSEG_MAIN_BINARY
		if hasGetTaskAllow(ctx.EntitlementsXML) {
			execFlags |= 0x10 // CS_EXECSEG_ALLOW_UNSIGNED
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
			ExecSegFlags:  execFlags,
		}
		if ctx.AdHoc {
			params.Flags |= csFlagAdhoc
		}
		return signing.BuildCodeDirectory(img[:codeLimit], params)
	}

	// Iterative build: reserve slack up front (zsign never sizes the region to
	// the exact blob length) so a few bytes of CMS length jitter between
	// passes cannot desync datasize / __LINKEDIT from what is written.
	//
	// Pass 1 sizes the blob from zeroed page digests, so the code bytes are
	// hashed once (in pass 2) instead of twice.
	//
	// thin.LoadCmds point into thin.Data, not into img, so patching through
	// the load-command list would not touch img; patch img explicitly instead.
	nPages := (int(codeLimit) + (1 << 12) - 1) / (1 << 12)
	if nPages == 0 {
		nPages = 1
	}
	alloc := 0
	var finalBlob []byte
	for iter := 0; iter < 4; iter++ {
		var hashes [][]byte
		if alloc == 0 {
			hashes = zeroPageHashes(nPages, int(hashSize))
		} else {
			var err error
			hashes, err = pageHashesCached(ctx, img[:codeLimit], codeLimit, 12, hashType)
			if err != nil {
				return nil, err
			}
		}
		finalCD, err := buildPass(hashes)
		if err != nil {
			return nil, err
		}
		finalSig, err := buildSignature(finalCD, ctx)
		if err != nil {
			return nil, err
		}
		blob := buildSuperblob(finalCD, reqBlob, entBlob, derEntBlob, finalSig)
		if alloc > 0 && len(blob) <= alloc {
			finalBlob = blob
			break
		}
		next := signatureAllocSize(len(blob), 0)
		if next <= alloc {
			next = alloc + signSpaceAlign
		}
		alloc = next

		// Patch datasize in the LC we just wrote.
		thin.Endian.PutUint32(img[lcEnd+12:], uint32(alloc))

		// Extend __LINKEDIT vmsize/filesize so the reserved region lives
		// inside the segment, matching zsign. The load commands alias
		// thin.Data, so patch the private copy img explicitly.
		growLinkEdit(thin, img, uint64(codeLimit)+uint64(alloc))
	}
	if finalBlob == nil {
		return nil, errors.New("code signature did not converge")
	}

	return emitImage(img[:codeLimit], finalBlob, alloc), nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// hasGetTaskAllow reports whether the XML entitlements contain
// <key>get-task-allow</key> followed by <true /> (development builds).
func hasGetTaskAllow(xml []byte) bool {
	if len(xml) == 0 {
		return false
	}
	s := string(xml)
	i := strings.Index(s, "<key>get-task-allow</key>")
	if i < 0 {
		return false
	}
	after := s[i:]
	ti := strings.Index(after, "<true")
	fi := strings.Index(after, "<false")
	if ti < 0 {
		return false
	}
	if fi >= 0 && fi < ti {
		return false
	}
	return true
}
