package macho

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Code signature blob magics.
const (
	csMagicRequirement             = 0xfade0c00
	csMagicRequirements            = 0xfade0c01
	csMagicCodeDirectory           = 0xfade0c02
	csMagicEmbeddedSignature       = 0xfade0cc0
	csMagicEmbeddedSignatureOld    = 0xfade0b02
	csMagicEmbeddedEntitlements    = 0xfade7171
	csMagicEmbeddedDerEntitlements = 0xfade7172
	csMagicDetachedSignature       = 0xfade0cc1
	csMagicBlobWrapper             = 0xfade0b01
)

// Code signature slot numbers.
const (
	slotCodeDirectory     = 0
	slotInfo              = 1
	slotRequirements      = 2
	slotResourceDir       = 3
	slotApplication       = 4
	slotEntitlements      = 5
	slotDerEntitlements   = 7
	slotAlternateCodeDirs = 0x1000
	slotSignature         = 0x10000
)

// Hash types (HashType field).
const (
	hashSHA1       = 1
	hashSHA256     = 2
	hashSHA256Trim = 3
	hashSHA384     = 4
)

// CodeDirectory version constants.
const (
	cdVersion1 = 0x10000
	cdVersion2 = 0x20000
	cdVersion3 = 0x20400
)

// CodeDirectory is the parsed representation of a CSMAGIC_CODEDIRECTORY blob.
type CodeDirectory struct {
	Magic         uint32
	Length        uint32
	Version       uint32
	Flags         uint32
	HashOffset    uint32
	IdentOffset   uint32
	NSpecialSlots uint32
	NCodeSlots    uint32
	CodeLimit     uint32
	HashSize      uint8
	HashType      uint8
	Platform      uint8
	PageSize      uint8 // stored as log2(page size)
	ScatterOffset uint8
	TeamOffset    uint8

	// Raw blob bytes for hashing/reconstruction.
	Raw []byte
	// Identifier string decoded from IdentOffset.
	Identifier string
	// TeamID decoded from TeamOffset (v2+, may be empty).
	TeamID string
	// ExecSeg* fields are present in version 3 and later.
	ExecSegBase  uint64
	ExecSegLimit uint64
	ExecSegFlags uint64
}

// PageBytes returns the actual page size in bytes.
func (cd *CodeDirectory) PageBytes() int { return 1 << cd.PageSize }

// HashAlgorithm returns a stable name for display.
func (cd *CodeDirectory) HashAlgorithm() string {
	switch cd.HashType {
	case hashSHA1:
		return "sha1"
	case hashSHA256, hashSHA256Trim:
		return "sha256"
	case hashSHA384:
		return "sha384"
	default:
		return fmt.Sprintf("hashtype=%d", cd.HashType)
	}
}

// Slot describes one blob inside a Superblob.
type Slot struct {
	Type   uint32
	Offset uint32
	Blob   *Blob
}

// Superblob is a CSMAGIC_EMBEDDED_SIGNATURE (or OLD variant).
type Superblob struct {
	Magic  uint32
	Length uint32
	Count  uint32
	Slots  []Slot
	// SignatureOffset/Size allow the caller to swap out the CMS signature blob.
	SignatureSlot *Slot
	// CodeDirectorySlot holds the primary code directory.
	CodeDirectorySlot *Slot
	// EntitlementsSlot holds the embedded entitlements (may be nil).
	EntitlementsSlot *Slot
	// RequirementsSlot holds the requirements blob (may be nil).
	RequirementsSlot *Slot
}

// Blob is a generic code signature blob: magic + length + payload.
type Blob struct {
	Magic  uint32
	Length uint32
	Data   []byte
}

// ParseSuperblob parses the code signature region of a slice.
func (t *ThinFile) ParseSuperblob() (*Superblob, error) {
	if t.Signature == nil {
		return nil, errors.New("slice has no LC_CODE_SIGNATURE")
	}
	start := int(t.Signature.DataOffset)
	end := start + int(t.Signature.DataSize)
	if start < 0 || end > len(t.Data) || start+12 > end {
		return nil, errors.New("code signature blob out of range")
	}
	// The code signature region is always big-endian, independent of the
	// Mach-O slice's own endianness.
	order := binary.BigEndian
	magic := order.Uint32(t.Data[start : start+4])
	if magic != csMagicEmbeddedSignature && magic != csMagicEmbeddedSignatureOld {
		return nil, fmt.Errorf("unexpected signature magic 0x%08x", magic)
	}
	length := order.Uint32(t.Data[start+4 : start+8])
	count := order.Uint32(t.Data[start+8 : start+12])
	if int(length) > (end-start) || int(length) > len(t.Data)-start {
		return nil, errors.New("superblob length out of range")
	}
	sb := &Superblob{Magic: magic, Length: length, Count: count}
	for i := 0; i < int(count); i++ {
		off := start + 12 + i*8
		if off+8 > start+int(length) {
			return nil, errors.New("superblob slot entry out of range")
		}
		stype := order.Uint32(t.Data[off : off+4])
		soffset := order.Uint32(t.Data[off+4 : off+8])
		blobStart := start + int(soffset)
		if blobStart+8 > start+int(length) {
			return nil, fmt.Errorf("slot %d (type 0x%x) out of range", i, stype)
		}
		blobMagic := order.Uint32(t.Data[blobStart : blobStart+4])
		blobLen := order.Uint32(t.Data[blobStart+4 : blobStart+8])
		if blobStart+int(blobLen) > start+int(length) {
			return nil, fmt.Errorf("slot %d blob length out of range", i)
		}
		b := &Blob{
			Magic:  blobMagic,
			Length: blobLen,
			Data:   t.Data[blobStart : blobStart+int(blobLen)],
		}
		s := Slot{Type: stype, Offset: soffset, Blob: b}
		sb.Slots = append(sb.Slots, s)
		switch stype {
		case slotSignature:
			sb.SignatureSlot = &s
		case slotCodeDirectory:
			sb.CodeDirectorySlot = &s
		case slotEntitlements:
			sb.EntitlementsSlot = &s
		case slotRequirements:
			sb.RequirementsSlot = &s
		}
	}
	return sb, nil
}

// ParseCodeDirectory parses the primary CodeDirectory from a superblob.
func (sb *Superblob) ParseCodeDirectory(order binary.ByteOrder) (*CodeDirectory, error) {
	if sb.CodeDirectorySlot == nil || sb.CodeDirectorySlot.Blob == nil {
		return nil, errors.New("no code directory slot")
	}
	return ParseCodeDirectory(order, sb.CodeDirectorySlot.Blob.Data)
}

// ParseCodeDirectory parses a CodeDirectory blob from raw bytes.
func ParseCodeDirectory(order binary.ByteOrder, raw []byte) (*CodeDirectory, error) {
	if len(raw) < 44 {
		return nil, errors.New("code directory too short")
	}
	be := binary.BigEndian
	cd := &CodeDirectory{
		Magic:         be.Uint32(raw[0:4]),
		Length:        be.Uint32(raw[4:8]),
		Version:       be.Uint32(raw[8:12]),
		Flags:         be.Uint32(raw[12:16]),
		HashOffset:    be.Uint32(raw[16:20]),
		IdentOffset:   be.Uint32(raw[20:24]),
		NSpecialSlots: be.Uint32(raw[24:28]),
		NCodeSlots:    be.Uint32(raw[28:32]),
		CodeLimit:     be.Uint32(raw[32:36]),
		HashSize:      raw[36],
		HashType:      raw[37],
		Platform:      raw[38],
		PageSize:      raw[39],
		ScatterOffset: raw[41],
		TeamOffset:    raw[42],
		Raw:           raw,
	}
	if int(cd.Length) > len(raw) {
		return nil, errors.New("code directory length out of range")
	}
	// Identifier is a C string at IdentOffset.
	if id, err := cstring(raw, int(cd.IdentOffset)); err == nil {
		cd.Identifier = id
	}
	if cd.Version >= cdVersion2 && cd.TeamOffset > 0 {
		if team, err := cstring(raw, int(cd.TeamOffset)); err == nil {
			cd.TeamID = team
		}
	}
	if cd.Version >= cdVersion3 && len(raw) >= 76 {
		cd.ExecSegBase = be.Uint64(raw[52:60])
		cd.ExecSegLimit = be.Uint64(raw[60:68])
		cd.ExecSegFlags = be.Uint64(raw[68:76])
	}
	return cd, nil
}

// SpecialSlotIndex maps a special slot number (-1..-6) to its index in the
// special-slot hash array stored inside the CodeDirectory.
func SpecialSlotIndex(slotNumber int) int {
	return -slotNumber - 1
}

// SpecialSlotHash returns the raw hash (of HashSize bytes) for a special slot
// number (e.g. -1 for Info.plist, -2 for requirements, -5 for entitlements).
// Returns nil if the slot is out of range.
func (cd *CodeDirectory) SpecialSlotHash(slotNumber int) []byte {
	idx := SpecialSlotIndex(slotNumber)
	if idx < 0 || idx >= int(cd.NSpecialSlots) {
		return nil
	}
	base := int(cd.HashOffset) + idx*int(cd.HashSize)
	end := base + int(cd.HashSize)
	if end > len(cd.Raw) {
		return nil
	}
	return cd.Raw[base:end]
}

// CodeSlotHash returns the hash for a code page slot (>=0).
func (cd *CodeDirectory) CodeSlotHash(slot int) []byte {
	if slot < 0 || slot >= int(cd.NCodeSlots) {
		return nil
	}
	base := int(cd.HashOffset) + int(cd.NSpecialSlots)*int(cd.HashSize) + slot*int(cd.HashSize)
	end := base + int(cd.HashSize)
	if end > len(cd.Raw) {
		return nil
	}
	return cd.Raw[base:end]
}

// ParseEntitlements extracts the embedded XML entitlements blob, if present.
func (sb *Superblob) ParseEntitlements() ([]byte, error) {
	if sb.EntitlementsSlot == nil || sb.EntitlementsSlot.Blob == nil {
		return nil, nil
	}
	b := sb.EntitlementsSlot.Blob
	// The entitlements blob is a standard blob: magic + length + plist data.
	if len(b.Data) < 8 {
		return nil, nil
	}
	// Strip the blob header (8 bytes: magic+length) to get the plist payload.
	return b.Data[8:], nil
}

// ParseRequirements returns the requirements blob payload (after its own
// magic+length header), or nil.
func (sb *Superblob) ParseRequirements() ([]byte, error) {
	if sb.RequirementsSlot == nil || sb.RequirementsSlot.Blob == nil {
		return nil, nil
	}
	if len(sb.RequirementsSlot.Blob.Data) < 8 {
		return nil, nil
	}
	return sb.RequirementsSlot.Blob.Data[8:], nil
}

// ParseSignatureBlob returns the raw CMS signature (blob wrapper payload).
// The CMS blob itself has a csMagicBlobWrapper header; this returns everything
// after the 8-byte header, i.e. the DER-encoded CMS structure.
func (sb *Superblob) ParseSignatureBlob() ([]byte, error) {
	if sb.SignatureSlot == nil || sb.SignatureSlot.Blob == nil {
		return nil, errors.New("no signature slot")
	}
	b := sb.SignatureSlot.Blob
	if b.Magic != csMagicBlobWrapper {
		return nil, fmt.Errorf("signature slot magic 0x%08x is not a blob wrapper", b.Magic)
	}
	if len(b.Data) < 8 {
		return nil, errors.New("signature blob too short")
	}
	return b.Data[8:], nil
}

func cstring(b []byte, off int) (string, error) {
	if off < 0 || off >= len(b) {
		return "", errors.New("offset out of range")
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	if end >= len(b) {
		return "", errors.New("unterminated string")
	}
	return string(b[off:end]), nil
}
