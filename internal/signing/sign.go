package signing

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Code signature blob magics and slots (mirror of macho package constants).
const (
	csMagicCodeDirectory        = 0xfade0c02
	csMagicEmbeddedEntitlements = 0xfade7171
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

	cdVersion2 = 0x20000
	cdVersion3 = 0x20400
)

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

// BuildCodeDirectory constructs the CodeDirectory blob, laying out
// header -> identifier -> team -> hashes (special then code) so that the
// team offset stays within a single byte, matching Apple's codesign.
func BuildCodeDirectory(content []byte, p *CodeDirectoryParams) ([]byte, error) {
	if p.PageSizeLog == 0 {
		return nil, errors.New("pageSize must not be zero")
	}
	pageBytes := p.PageBytes()
	if int(p.CodeLimit) > len(content) {
		return nil, fmt.Errorf("codeLimit %d exceeds content %d", p.CodeLimit, len(content))
	}
	headerLen := 44
	if p.Version >= cdVersion3 {
		headerLen = 76
	}
	nCodeSlots := (int(p.CodeLimit) + pageBytes - 1) / pageBytes
	if nCodeSlots == 0 {
		nCodeSlots = 1
	}
	identOffset := uint32(headerLen)
	teamOffset := identOffset + uint32(len(p.Identifier)+1)
	hashOffset := teamOffset + uint32(len(p.TeamID)+1)
	total := int(hashOffset) + (len(p.SpecialHashes)+nCodeSlots)*int(p.HashSize)

	buf := make([]byte, total)
	order := binary.BigEndian // code signature blobs are always big-endian
	order.PutUint32(buf[0:], csMagicCodeDirectory)
	order.PutUint32(buf[4:], uint32(total))
	order.PutUint32(buf[8:], p.Version)
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
	buf[40] = 0 // spare2
	if p.Version >= cdVersion2 {
		buf[41] = 0 // scatterOffset
		buf[42] = byte(teamOffset)
		buf[43] = 0 // spare3
	}
	if p.Version >= cdVersion3 {
		order.PutUint64(buf[44:], uint64(p.CodeLimit))
		order.PutUint64(buf[52:], p.ExecSegBase)
		order.PutUint64(buf[60:], p.ExecSegLimit)
		order.PutUint64(buf[68:], p.ExecSegFlags)
	}

	// identifier + team strings.
	pos := headerLen
	copy(buf[pos:], p.Identifier)
	pos += len(p.Identifier) + 1
	copy(buf[pos:], p.TeamID)
	pos += len(p.TeamID) + 1

	// special slot hashes.
	for _, h := range p.SpecialHashes {
		if len(h) != int(p.HashSize) {
			return nil, fmt.Errorf("special slot hash has %d bytes, want %d", len(h), p.HashSize)
		}
		copy(buf[pos:], h)
		pos += int(p.HashSize)
	}
	// code page hashes.
	for i := 0; i < nCodeSlots; i++ {
		var h []byte
		if p.CodeHashes != nil && i < len(p.CodeHashes) {
			h = p.CodeHashes[i]
		} else {
			start := i * pageBytes
			end := start + pageBytes
			if end > int(p.CodeLimit) {
				end = int(p.CodeLimit)
			}
			var err error
			h, err = HashBytes(p.HashType, content[start:end])
			if err != nil {
				return nil, err
			}
		}
		if len(h) != int(p.HashSize) {
			return nil, fmt.Errorf("code slot hash %d has %d bytes, want %d", i, len(h), p.HashSize)
		}
		copy(buf[pos:], h)
		pos += int(p.HashSize)
	}
	return buf, nil
}

// ComputePageHashes returns the code-slot hashes for content[:codeLimit].
func ComputePageHashes(content []byte, codeLimit uint32, pageSizeLog, hashType uint8) ([][]byte, error) {
	pageBytes := 1 << pageSizeLog
	n := (int(codeLimit) + pageBytes - 1) / pageBytes
	if n == 0 {
		n = 1
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * pageBytes
		end := start + pageBytes
		if end > int(codeLimit) {
			end = int(codeLimit)
		}
		h, err := HashBytes(hashType, content[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
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
