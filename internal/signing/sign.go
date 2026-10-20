package signing

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"

	"howett.net/plist"
)

// Code signature blob magics and slots (mirror of macho package constants).
const (
	csMagicCodeDirectory        = 0xfade0c02
	csMagicEmbeddedEntitlements = 0xfade7171
	csMagicDerEntitlements      = 0xfade7172
	csMagicRequirements         = 0xfade0c01
	csMagicEmbeddedSignature    = 0xfade0cc0
	csMagicBlobWrapper          = 0xfade0b01

	slotInfo            = 1
	slotRequirements    = 2
	slotResourceDir     = 3
	slotApplication     = 4
	slotEntitlements    = 5
	slotDerEntitlements = 7
	slotSignature       = 0x10000
)

const (
	HashSHA1   = 1
	HashSHA256 = 2

	cdVersion2     = 0x20000
	cdVersion20100 = 0x20100 // + scatterOffset
	cdVersion20200 = 0x20200 // + teamOffset
	cdVersion20300 = 0x20300 // + spare3 + codeLimit64
	cdVersion3     = 0x20400 // + execSegBase/Limit/Flags
)

// CDVersionMax is the newest CodeDirectory version Apple defines
// (CS_SUPPORTS_EXECSEG). Versions above it are not recognised by iOS, so an
// inherited one is clamped to this value.
const CDVersionMax = cdVersion3

// HashBytes returns the code-signing hash of b for the given hash type.
func HashBytes(hashType uint8, b []byte) ([]byte, error) {
	switch hashType {
	case HashSHA256:
		s := sha256.Sum256(b)
		return s[:], nil
	case HashSHA1:
		s := sha1.Sum(b)
		return s[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash type %d", hashType)
	}
}

// CodeDirectoryParams describes a CodeDirectory to build.
type CodeDirectoryParams struct {
	Version       uint32
	Flags         uint32
	Platform      uint8
	PageSizeLog   uint8
	HashType      uint8
	HashSize      uint8
	Identifier    string
	TeamID        string
	CodeLimit     uint32
	SpecialHashes [][]byte // in special-slot order: -1,-2,-3,-4,-5,-6
	ExecSegBase   uint64
	ExecSegLimit  uint64
	ExecSegFlags  uint64
	// CodeHashes, when non-nil, supplies precomputed code-slot hashes in order,
	// skipping the per-page hashing step (used by the signature cache).
	CodeHashes [][]byte
}

// PageBytes returns the code page size in bytes.
func (p *CodeDirectoryParams) PageBytes() int { return 1 << p.PageSizeLog }

// BuildCodeDirectory constructs the CodeDirectory blob with the standard
// Apple layout for version 0x20400 (88-byte header):
//
//	0   magic
//	4   length
//	8   version
//	12  flags
//	16  hashOffset
//	20  identOffset
//	24  nSpecialSlots
//	28  nCodeSlots
//	32  codeLimit
//	36  hashSize
//	37  hashType
//	38  platform
//	39  pageSize (log2)
//	40  spare2 (4)
//	44  scatterOffset (4)
//	48  teamOffset (4)
//	52  spare3 (4)
//	56  codeLimit64 (8)
//	64  execSegBase (8)
//	72  execSegLimit (8)
//	80  execSegFlags (8)
//	88  identifier\0 team\0 special hashes code hashes
//
// Special hashes are written from the highest slot index down to 1 so that
// the slot -1 hash (Info.plist) ends up immediately before the code hashes,
// matching Apple codesign and zsign.
func BuildCodeDirectory(content []byte, p *CodeDirectoryParams) ([]byte, error) {
	if p.PageSizeLog == 0 {
		return nil, errors.New("pageSize must not be zero")
	}
	pageBytes := p.PageBytes()
	if int(p.CodeLimit) > len(content) {
		return nil, fmt.Errorf("codeLimit %d exceeds content %d", p.CodeLimit, len(content))
	}
	// Bump the version when the caller needs fields the requested version
	// cannot express: a team id needs 0x20200, exec-segment info 0x20400.
	version := p.Version
	minVersion := uint32(cdVersion2)
	if p.TeamID != "" {
		minVersion = cdVersion20200
	}
	if p.ExecSegBase != 0 || p.ExecSegLimit != 0 || p.ExecSegFlags != 0 {
		minVersion = cdVersion3
	}
	if version < minVersion {
		version = minVersion
	}
	headerLen := 44
	if version >= cdVersion2 {
		headerLen += 4 // scatterOffset
	}
	if version >= cdVersion20200 {
		headerLen += 4 // teamOffset
	}
	if version >= cdVersion20300 {
		headerLen += 4 + 8 // spare3 + codeLimit64
	}
	if version >= cdVersion3 {
		headerLen += 8 + 8 + 8 // execSegBase + execSegLimit + execSegFlags
	}
	nCodeSlots := (int(p.CodeLimit) + pageBytes - 1) / pageBytes
	if nCodeSlots == 0 {
		nCodeSlots = 1
	}
	identOffset := uint32(headerLen)
	teamOffset := uint32(0)
	hashOffset := identOffset + uint32(len(p.Identifier)+1)
	if p.TeamID != "" {
		teamOffset = hashOffset
		hashOffset += uint32(len(p.TeamID) + 1)
	}
	hashOffset += uint32(len(p.SpecialHashes)) * uint32(p.HashSize)
	total := int(hashOffset) + nCodeSlots*int(p.HashSize)

	buf := make([]byte, total)
	order := binary.BigEndian // code signature blobs are always big-endian
	order.PutUint32(buf[0:], csMagicCodeDirectory)
	order.PutUint32(buf[4:], uint32(total))
	order.PutUint32(buf[8:], version)
	order.PutUint32(buf[12:], p.Flags)
	order.PutUint32(buf[16:], hashOffset)
	order.PutUint32(buf[20:], identOffset)
	order.PutUint32(buf[24:], uint32(len(p.SpecialHashes)))
	order.PutUint32(buf[28:], uint32(nCodeSlots))
	order.PutUint32(buf[32:], p.CodeLimit)
	buf[36] = p.HashSize
	buf[37] = p.HashType
	buf[38] = p.Platform
	buf[39] = p.PageSizeLog
	// Trailer fields exist only from their version onwards; writing them
	// unconditionally would overwrite the identifier string on older CDs.
	if version >= cdVersion20100 {
		order.PutUint32(buf[44:], 0) // scatterOffset
	}
	if version >= cdVersion20200 {
		order.PutUint32(buf[48:], teamOffset)
	}
	if version >= cdVersion20300 {
		order.PutUint32(buf[52:], 0) // spare3
		// codeLimit64 stays 0: Apple only fills it when the code limit does not
		// fit in 32 bits, and zsign leaves it zero too. Writing the real limit
		// here diverges from both and is needlessly risky.
		order.PutUint64(buf[56:], 0)
	}
	if version >= cdVersion3 {
		order.PutUint64(buf[64:], p.ExecSegBase)
		order.PutUint64(buf[72:], p.ExecSegLimit)
		order.PutUint64(buf[80:], p.ExecSegFlags)
	}

	// identifier + team strings.
	pos := headerLen
	copy(buf[pos:], p.Identifier)
	pos += len(p.Identifier) + 1
	if p.TeamID != "" {
		copy(buf[pos:], p.TeamID)
		pos += len(p.TeamID) + 1
	}

	// Special slot hashes, written from the highest slot index down to 1.
	for i := len(p.SpecialHashes) - 1; i >= 0; i-- {
		h := p.SpecialHashes[i]
		if len(h) != int(p.HashSize) {
			return nil, fmt.Errorf("special slot hash has %d bytes, want %d", len(h), p.HashSize)
		}
		copy(buf[pos:], h)
		pos += int(p.HashSize)
	}
	// Code page hashes. When the caller did not supply them, hash the pages
	// here (in parallel) rather than one at a time.
	if p.CodeHashes == nil {
		hashes, err := ComputePageHashes(content, p.CodeLimit, p.PageSizeLog, p.HashType)
		if err != nil {
			return nil, err
		}
		p.CodeHashes = hashes
	}
	for i := 0; i < nCodeSlots; i++ {
		var h []byte
		if i < len(p.CodeHashes) {
			h = p.CodeHashes[i]
		} else {
			h = make([]byte, p.HashSize)
		}
		if len(h) != int(p.HashSize) {
			return nil, fmt.Errorf("code slot hash %d has %d bytes, want %d", i, len(h), p.HashSize)
		}
		copy(buf[pos:], h)
		pos += int(p.HashSize)
	}
	return buf, nil
}

// HashSize returns the digest length in bytes for a code-signing hash type,
// or 0 when the type is unsupported.
func HashSize(hashType uint8) int {
	switch hashType {
	case HashSHA256:
		return sha256.Size
	case HashSHA1:
		return sha1.Size
	default:
		return 0
	}
}

// hashInto writes the hash of data into dst, which must be HashSize bytes.
func hashInto(dst, data []byte, hashType uint8) error {
	switch hashType {
	case HashSHA256:
		s := sha256.Sum256(data)
		copy(dst, s[:])
		return nil
	case HashSHA1:
		s := sha1.Sum(data)
		copy(dst, s[:])
		return nil
	default:
		return fmt.Errorf("unsupported hash type %d", hashType)
	}
}

// parallelHashPages is the minimum number of code pages that must be hashed
// before spawning goroutines pays off; below it the scheduling cost dominates.
const parallelHashPages = 64

// ComputePageHashes returns the code-slot hashes for content[:codeLimit].
//
// Pages are independent, so the work is split into contiguous chunks hashed
// concurrently: for multi-hundred-MB and multi-GB images this is the single
// hottest loop in the whole signer and scales with the core count. All digests
// share one backing array to avoid a million tiny allocations.
func ComputePageHashes(content []byte, codeLimit uint32, pageSizeLog, hashType uint8) ([][]byte, error) {
	pageBytes := 1 << pageSizeLog
	n := (int(codeLimit) + pageBytes - 1) / pageBytes
	if n == 0 {
		n = 1
	}
	hs := HashSize(hashType)
	if hs == 0 {
		return nil, fmt.Errorf("unsupported hash type %d", hashType)
	}
	buf := make([]byte, n*hs)
	out := make([][]byte, n)
	for i := range out {
		out[i] = buf[i*hs : (i+1)*hs]
	}
	limit := int(codeLimit)
	if limit > len(content) {
		limit = len(content)
	}
	hashPage := func(i int) error {
		start := i * pageBytes
		end := start + pageBytes
		if end > limit {
			end = limit
		}
		if start > end {
			start = end
		}
		return hashInto(out[i], content[start:end], hashType)
	}

	workers := runtime.NumCPU()
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	if workers == 1 || n < parallelHashPages {
		for i := 0; i < n; i++ {
			if err := hashPage(i); err != nil {
				return nil, err
			}
		}
		return out, nil
	}

	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			// hash type was validated above, so hashPage cannot fail here
			for i := s; i < e; i++ {
				_ = hashPage(i)
			}
		}(start, end)
	}
	wg.Wait()
	return out, nil
}

// BuildEntitlementsBlob wraps an XML entitlements plist into an embedded
// entitlements blob (magic + length + plist).
func BuildEntitlementsBlob(plistXML []byte) []byte {
	out := make([]byte, 8+len(plistXML))
	binary.BigEndian.PutUint32(out[0:], csMagicEmbeddedEntitlements)
	binary.BigEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], plistXML)
	return out
}

// BuildDerEntitlementsBlob converts the XML entitlements plist into the Apple
// DER-encoded plist form (slot 7, magic 0xfade7172). Modern iOS requires this
// slot in addition to slot 5; the payload must be ASN.1 DER (SET OF entries),
// NOT a binary plist, or installd fails to parse entitlements.
func BuildDerEntitlementsBlob(plistXML []byte) []byte {
	var v map[string]interface{}
	if err := plistUnmarshalXML(plistXML, &v); err != nil {
		return nil
	}
	der := derEncodePlistValue(v)
	if len(der) == 0 {
		return nil
	}
	out := make([]byte, 8+len(der))
	binary.BigEndian.PutUint32(out[0:], csMagicDerEntitlements)
	binary.BigEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], der)
	return out
}

func derEncodePlistValue(v interface{}) []byte {
	switch x := v.(type) {
	case string:
		return derTLV(0x0c, []byte(x))
	case bool:
		if x {
			return []byte{0x01, 0x01, 0xff}
		}
		return []byte{0x01, 0x01, 0x00}
	case uint64:
		return derInteger(x)
	case int64:
		return derInteger(uint64(x))
	case int:
		return derInteger(uint64(x))
	case []byte:
		return derTLV(0x04, x)
	case []interface{}:
		var body []byte
		for _, e := range x {
			body = append(body, derEncodePlistValue(e)...)
		}
		return derTLV(0x30, body)
	case map[string]interface{}:
		// dict -> SET (0x31) OF SEQUENCE { key UTF8String, value }
		//
		// DER (X.690 11.6) requires SET OF members to be ordered by their
		// encoded bytes, not by key: the length octets take part in the
		// comparison, so an entry with a short value sorts before one with a
		// long key. installd rejects a set that is not in canonical order,
		// which shows up as an app that cannot be installed.
		entries := make([][]byte, 0, len(x))
		for k, v := range x {
			entry := append(derTLV(0x0c, []byte(k)), derEncodePlistValue(v)...)
			entries = append(entries, derTLV(0x30, entry))
		}
		sort.Slice(entries, func(i, j int) bool {
			return bytes.Compare(entries[i], entries[j]) < 0
		})
		var body []byte
		for _, e := range entries {
			body = append(body, e...)
		}
		return derTLV(0x31, body)
	}
	return nil
}

func derTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	out := []byte{0x80 | byte(len(tmp)-i)}
	return append(out, tmp[i:]...)
}

func derInteger(u uint64) []byte {
	if u == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var tmp [8]byte
	i := len(tmp)
	for u > 0 {
		i--
		tmp[i] = byte(u)
		u >>= 8
	}
	body := tmp[i:]
	// prepend 0x00 to keep the value positive
	if body[0]&0x80 != 0 {
		body = append([]byte{0x00}, body...)
	}
	return derTLV(0x02, body)
}

func plistUnmarshalXML(data []byte, v interface{}) error {
	_, err := plist.Unmarshal(data, v)
	return err
}
