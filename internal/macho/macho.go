// Package macho parses Mach-O binaries (fat/thin) and locates code signature
// load commands, the foundation for re-signing IPA bundles.
package macho

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Fat magic (on-disk big-endian).
	fatMagic   = 0xcafebabe
	fatMagic64 = 0xcafebabf

	// Thin magic.
	mhMagic   = 0xfeedface
	mhMagic64 = 0xfeedfacf
	mhCigam   = 0xcefaedfe
	mhCigam64 = 0xcffaedfe

	// LC_CODE_SIGNATURE : linkedit_data_command -> Code Signature blob.
	lcCodeSignature = 0x1d

	// defaultFatAlign is used when a fat arch entry carries no alignment
	// requirement. iOS arm64 slices are page-aligned at 16 KB.
	defaultFatAlign = uint64(0x4000)
)

// LoadCommand is a raw Mach-O load command.
type LoadCommand struct {
	Cmd     uint32
	Size    uint32
	Payload []byte
}

// CodeSignatureCmd is the payload of LC_CODE_SIGNATURE.
type CodeSignatureCmd struct {
	DataOffset uint32
	DataSize   uint32
}

// ThinFile is one thin Mach-O image (a slice inside a fat file, or a standalone binary).
type ThinFile struct {
	// Start is the byte offset of this image within the original file (0 for thin).
	Start uint64
	// Data is the byte range of this image inside the original file.
	Data []byte

	CPUType    uint32
	CPUSubtype uint32
	FileType   uint32
	Flags      uint32
	Endian     binary.ByteOrder
	Is64       bool
	NCmds      uint32
	SizeOfCmds uint32
	LoadCmds   []LoadCommand
	Signature  *CodeSignatureCmd // nil when the image has no LC_CODE_SIGNATURE
}

// FatArch describes one architecture entry in a universal binary.
type FatArch struct {
	CPUType    uint32
	CPUSubtype uint32
	Offset     uint64
	Size       uint64
	Align      uint32
}

// File represents a whole binary: either one thin image or a fat universal binary.
type File struct {
	IsFat   bool
	Fat64   bool
	FatArch []FatArch
	Slices  []*ThinFile
}

// SignatureBlobRange returns the absolute byte range (in the original file) of
// the code signature blob for the given slice, or an error if absent.
func (t *ThinFile) SignatureBlobRange() (start uint64, size uint64, err error) {
	if t.Signature == nil {
		return 0, 0, errors.New("no LC_CODE_SIGNATURE in slice")
	}
	return t.Start + uint64(t.Signature.DataOffset), uint64(t.Signature.DataSize), nil
}

// Parse reads a Mach-O binary (fat or thin) and returns a File.
func Parse(data []byte) (*File, error) {
	if len(data) < 4 {
		return nil, errors.New("file too short to be Mach-O")
	}
	magic := binary.BigEndian.Uint32(data[0:4]) // fat magic is big-endian on disk
	switch magic {
	case fatMagic, fatMagic64:
		return parseFat(data)
	}
	// Not fat: treat the whole file as one thin image. Detect byte order from magic.
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(data[0:4]) {
	case mhMagic, mhMagic64:
		order = binary.LittleEndian
	case mhCigam, mhCigam64:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("unrecognized Mach-O magic 0x%08x", magic)
	}
	thin, err := parseThin(data, 0, order)
	if err != nil {
		return nil, err
	}
	return &File{IsFat: false, Slices: []*ThinFile{thin}}, nil
}

func parseFat(data []byte) (*File, error) {
	is64 := binary.BigEndian.Uint32(data[0:4]) == fatMagic64
	headerSize := 8
	archSize := 20
	if is64 {
		archSize = 32
	}
	if len(data) < headerSize {
		return nil, errors.New("fat file truncated header")
	}
	n := binary.BigEndian.Uint32(data[4:8])
	f := &File{IsFat: true, Fat64: is64}
	for i := 0; i < int(n); i++ {
		off := headerSize + i*archSize
		if off+archSize > len(data) {
			return nil, fmt.Errorf("fat arch entry %d out of range", i)
		}
		a := FatArch{
			CPUType:    binary.BigEndian.Uint32(data[off+0 : off+4]),
			CPUSubtype: binary.BigEndian.Uint32(data[off+4 : off+8]),
			Offset:     uint64(binary.BigEndian.Uint32(data[off+8 : off+12])),
			Size:       uint64(binary.BigEndian.Uint32(data[off+12 : off+16])),
			Align:      binary.BigEndian.Uint32(data[off+16 : off+20]),
		}
		if is64 {
			a.Offset = binary.BigEndian.Uint64(data[off+8 : off+16])
			a.Size = binary.BigEndian.Uint64(data[off+16 : off+24])
			a.Align = binary.BigEndian.Uint32(data[off+24 : off+28])
		}
		f.FatArch = append(f.FatArch, a)
		if a.Offset+uint64(a.Size) > uint64(len(data)) {
			return nil, fmt.Errorf("fat slice %d out of file range", i)
		}
		slice := data[a.Offset : a.Offset+a.Size]
		var order binary.ByteOrder = binary.LittleEndian
		switch binary.LittleEndian.Uint32(slice[0:4]) {
		case mhMagic, mhMagic64:
			order = binary.LittleEndian
		case mhCigam, mhCigam64:
			order = binary.BigEndian
		default:
			return nil, fmt.Errorf("fat slice %d is not a Mach-O image", i)
		}
		thin, err := parseThin(slice, a.Offset, order)
		if err != nil {
			return nil, err
		}
		f.Slices = append(f.Slices, thin)
	}
	return f, nil
}

func parseThin(data []byte, start uint64, order binary.ByteOrder) (*ThinFile, error) {
	if len(data) < 32 {
		return nil, errors.New("thin Mach-O header truncated")
	}
	is64 := order.Uint32(data[0:4]) == mhMagic64 || order.Uint32(data[0:4]) == mhCigam64
	t := &ThinFile{
		Start:      start,
		Data:       data,
		CPUType:    order.Uint32(data[4:8]),
		CPUSubtype: order.Uint32(data[8:12]),
		FileType:   order.Uint32(data[12:16]),
		Endian:     order,
		Is64:       is64,
	}
	ncmds := order.Uint32(data[16:20])
	sizeofcmds := order.Uint32(data[20:24])
	t.NCmds = ncmds
	t.SizeOfCmds = sizeofcmds
	if !is64 {
		t.Flags = order.Uint32(data[24:28])
	} else {
		t.Flags = order.Uint32(data[28:32])
	}
	// Header size differs: 28 bytes for 32-bit, 32 bytes for 64-bit.
	headerBytes := 28
	if is64 {
		headerBytes = 32
	}
	if headerBytes+int(sizeofcmds) > len(data) {
		return nil, errors.New("load command region out of range")
	}
	lcData := data[headerBytes:]
	cursor := 0
	for i := 0; i < int(ncmds); i++ {
		if cursor+8 > len(lcData) {
			return nil, fmt.Errorf("load command %d truncated", i)
		}
		cmd := order.Uint32(lcData[cursor : cursor+4])
		size := order.Uint32(lcData[cursor+4 : cursor+8])
		if size < 8 || cursor+int(size) > len(lcData) {
			return nil, fmt.Errorf("load command %d invalid size %d", i, size)
		}
		lc := LoadCommand{Cmd: cmd, Size: size, Payload: lcData[cursor+8 : cursor+int(size)]}
		if cmd == lcCodeSignature && len(lc.Payload) >= 8 {
			t.Signature = &CodeSignatureCmd{
				DataOffset: order.Uint32(lc.Payload[0:4]),
				DataSize:   order.Uint32(lc.Payload[4:8]),
			}
		}
		t.LoadCmds = append(t.LoadCmds, lc)
		cursor += int(size)
	}
	return t, nil
}

// PatchSignatureSize updates the datasize field of LC_CODE_SIGNATURE in place
// (the load-command payload is a sub-slice of the underlying Data). The data
// offset stays unchanged. Returns an error if the command is absent.
func (t *ThinFile) PatchSignatureSize(newSize uint32) error {
	for i := range t.LoadCmds {
		lc := &t.LoadCmds[i]
		if lc.Cmd == lcCodeSignature && len(lc.Payload) >= 8 {
			t.Endian.PutUint32(lc.Payload[4:8], newSize)
			t.Signature.DataSize = newSize
			return nil
		}
	}
	return errors.New("LC_CODE_SIGNATURE not found")
}

// PatchSignatureOffset updates the dataoff field of LC_CODE_SIGNATURE in place.
func (t *ThinFile) PatchSignatureOffset(off uint32) error {
	for i := range t.LoadCmds {
		lc := &t.LoadCmds[i]
		if lc.Cmd == lcCodeSignature && len(lc.Payload) >= 4 {
			t.Endian.PutUint32(lc.Payload[0:4], off)
			t.Signature.DataOffset = off
			return nil
		}
	}
	return errors.New("LC_CODE_SIGNATURE not found")
}

// Reassemble writes a new binary file from per-slice bytes. For thin binaries
// it returns slices[0]; for fat binaries it rebuilds the header and arch table.
func (f *File) Reassemble(slices [][]byte) ([]byte, error) {
	if len(slices) != len(f.Slices) {
		return nil, errors.New("slice count mismatch")
	}
	if !f.IsFat {
		return slices[0], nil
	}
	offset := uint64(8 + len(slices)*20)
	if f.Fat64 {
		offset = uint64(8 + len(slices)*32)
	}
	offsets := make([]uint64, len(slices))
	for i, ns := range slices {
		// Each slice must start at a multiple of 2^align (iOS arm64 uses
		// 0x4000). Skipping this produces a universal binary the loader
		// rejects, so pad with zeros between slices.
		align := defaultFatAlign
		if i < len(f.FatArch) {
			if a := f.FatArch[i].Align; a > 0 && a < 31 {
				align = uint64(1) << a
			}
		}
		if align > 1 {
			offset = (offset + align - 1) &^ (align - 1)
		}
		offsets[i] = offset
		offset += uint64(len(ns))
	}
	hdr := make([]byte, 0, offset)
	o := binary.BigEndian
	magic := uint32(fatMagic)
	if f.Fat64 {
		magic = fatMagic64
	}
	hdr = append(hdr, u32(o, magic)...)
	hdr = append(hdr, u32(o, uint32(len(slices)))...)
	for i := range slices {
		a := f.FatArch[i]
		hdr = append(hdr, u32(o, a.CPUType)...)
		hdr = append(hdr, u32(o, a.CPUSubtype)...)
		if f.Fat64 {
			hdr = append(hdr, u64(o, offsets[i])...)
			hdr = append(hdr, u64(o, uint64(len(slices[i])))...)
			hdr = append(hdr, u32(o, a.Align)...)
		} else {
			hdr = append(hdr, u32(o, uint32(offsets[i]))...)
			hdr = append(hdr, u32(o, uint32(len(slices[i])))...)
			hdr = append(hdr, u32(o, a.Align)...)
		}
	}
	// Zero-filled buffer: the gaps between slices are the alignment padding.
	out := make([]byte, offset)
	copy(out, hdr)
	for i, ns := range slices {
		copy(out[offsets[i]:], ns)
	}
	return out, nil
}

func u32(o binary.ByteOrder, v uint32) []byte {
	var b [4]byte
	o.PutUint32(b[:], v)
	return b[:]
}

func u64(o binary.ByteOrder, v uint64) []byte {
	var b [8]byte
	o.PutUint64(b[:], v)
	return b[:]
}

// CPUName returns a human-readable architecture name for display.
func (t *ThinFile) CPUName() string {
	switch t.CPUType {
	case 0x0100000c:
		return "arm64"
	case 0x01000007:
		return "x86_64"
	case 12:
		return "arm"
	case 7:
		return "i386"
	default:
		return fmt.Sprintf("cputype=%d", t.CPUType)
	}
}
