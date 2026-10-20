package macho

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
)

// Load command constants used for dylib injection/removal.
const (
	lcLoadDylib       = 0xc
	lcLoadWeakDylib   = 0x80000018
	lcSegment         = 0x1
	lcSegment64       = 0x19
	lcDyldInfo        = 0x22
	lcDyldInfoOnly    = 0x80000022
	lcSegmentSplit    = 0x1e
	lcFunctionStarts  = 0x26
	lcDataInCode      = 0x29
	lcDyldChained     = 0x80000034
	lcDyldExports     = 0x80000033
	lcEncryptionInfo  = 0x21
	lcEncryption64    = 0x2c
	lcDylibCodeSigDRs = 0x2b
	lcSymtab          = 0x2
	lcDysymtab        = 0xb
)

// buildDylibCommand constructs a dylib_command load command.
func buildDylibCommand(path string, weak bool, order binary.ByteOrder) []byte {
	cmd := uint32(lcLoadDylib)
	if weak {
		cmd = lcLoadWeakDylib
	}
	size := 24 + len(path) + 1
	size = (size + 7) &^ 7 // align to 8 bytes
	buf := make([]byte, size)
	order.PutUint32(buf[0:], cmd)
	order.PutUint32(buf[4:], uint32(size))
	order.PutUint32(buf[8:], 24)       // name offset
	order.PutUint32(buf[12:], 2)       // timestamp
	order.PutUint32(buf[16:], 0x10000) // current_version 1.0
	order.PutUint32(buf[20:], 0)       // compatibility_version
	copy(buf[24:], path)
	return buf
}

// dylibName extracts the dylib path from a dylib_command load command.
func dylibName(cmd uint32, payload []byte, order binary.ByteOrder) string {
	if cmd != lcLoadDylib && cmd != lcLoadWeakDylib {
		return ""
	}
	if len(payload) < 24 {
		return ""
	}
	nameOff := int(order.Uint32(payload[0:4]))
	if nameOff < 24 || nameOff >= len(payload) {
		return ""
	}
	end := nameOff
	for end < len(payload) && payload[end] != 0 {
		end++
	}
	return string(payload[nameOff:end])
}

// AddLoadDylib injects an LC_LOAD_DYLIB (or weak) command into every slice of
// a thin or universal binary, shifting subsequent file offsets accordingly.
func AddLoadDylib(data []byte, path string, weak bool) ([]byte, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	newSlices := make([][]byte, len(f.Slices))
	for i, thin := range f.Slices {
		cmd := buildDylibCommand(path, weak, thin.Endian)
		ns, err := rewriteLoadCommands(thin, func(cmd uint32, payload []byte, order binary.ByteOrder) ([]byte, bool, error) {
			return nil, true, nil // keep original, then append new
		}, cmd)
		if err != nil {
			return nil, fmt.Errorf("slice %d: %w", i, err)
		}
		newSlices[i] = ns
	}
	return f.Reassemble(newSlices)
}

// RemoveLoadDylib removes all LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB commands whose
// name matches path. Matching is exact on the full install name or on the file
// name only (so -D libfoo.dylib also drops @rpath/libfoo.dylib), which avoids
// the accidental removals a substring match would cause.
func RemoveLoadDylib(data []byte, path string) ([]byte, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	newSlices := make([][]byte, len(f.Slices))
	for i, thin := range f.Slices {
		ns, err := rewriteLoadCommands(thin, func(cmd uint32, payload []byte, order binary.ByteOrder) ([]byte, bool, error) {
			name := dylibName(cmd, payload, order)
			if name != "" && (name == path || filepath.Base(name) == filepath.Base(path)) {
				return nil, false, nil // drop
			}
			return nil, true, nil // keep
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("slice %d: %w", i, err)
		}
		newSlices[i] = ns
	}
	return f.Reassemble(newSlices)
}

// rewriteLoadCommands rebuilds a thin image's header + load command region.
// keep is called for each existing command; it may return replacement bytes or
// drop the command. extra (if non-nil) is appended after the kept commands.
func rewriteLoadCommands(thin *ThinFile, keep func(cmd uint32, payload []byte, order binary.ByteOrder) ([]byte, bool, error), extra []byte) ([]byte, error) {
	headerLen := 28
	if thin.Is64 {
		headerLen = 32
	}
	loadStart := headerLen
	loadEnd := headerLen + int(thin.SizeOfCmds)
	if loadEnd > len(thin.Data) {
		return nil, errors.New("load command region out of range")
	}
	oldLoads := thin.Data[loadStart:loadEnd]

	var newLoads []byte
	ncmds := uint32(0)
	for _, lc := range thin.LoadCmds {
		rep, keepIt, err := keep(lc.Cmd, lc.Payload, thin.Endian)
		if err != nil {
			return nil, err
		}
		if !keepIt {
			continue
		}
		ncmds++
		if rep != nil {
			newLoads = append(newLoads, rep...)
			continue
		}
		// Reconstruct the original command bytes from cmd+size+payload.
		var hdr [8]byte
		thin.Endian.PutUint32(hdr[0:], lc.Cmd)
		thin.Endian.PutUint32(hdr[4:], lc.Size)
		newLoads = append(newLoads, hdr[:]...)
		newLoads = append(newLoads, lc.Payload...)
	}
	if extra != nil {
		newLoads = append(newLoads, extra...)
		ncmds++
	}
	delta := int32(len(newLoads)) - int32(len(oldLoads))

	// Patch every file offset in the new load commands by delta. Only offsets
	// at or past the original end of the load-command region move.
	adjustOffsets(newLoads, thin.Endian, delta, uint32(loadEnd))

	// New header with updated ncmds/sizeofcmds.
	newHeader := make([]byte, headerLen)
	copy(newHeader, thin.Data[:headerLen])
	thin.Endian.PutUint32(newHeader[16:20], ncmds)
	thin.Endian.PutUint32(newHeader[20:24], uint32(len(newLoads)))

	rest := thin.Data[loadEnd:]
	out := make([]byte, 0, headerLen+len(newLoads)+len(rest))
	out = append(out, newHeader...)
	out = append(out, newLoads...)
	out = append(out, rest...)
	return out, nil
}

// adjustOffsets shifts every file offset inside the rebuilt load-command block
// by delta. shiftFrom is the original end of the load-command region: only
// offsets pointing at (or after) it actually move. Offsets such as __TEXT's
// fileoff (0) or __PAGEZERO's must be left alone, or the image is corrupted.
func adjustOffsets(loads []byte, order binary.ByteOrder, delta int32, shiftFrom uint32) {
	off := 0
	for off+8 <= len(loads) {
		cmd := order.Uint32(loads[off : off+4])
		size := int(order.Uint32(loads[off+4 : off+8]))
		if size < 8 || off+size > len(loads) {
			break
		}
		payload := loads[off+8 : off+size]
		adjustCommand(cmd, payload, order, delta, shiftFrom)
		off += size
	}
}

// shiftOffset adds delta to the uint32 at payload[pos], but only when that
// value denotes a location at or after shiftFrom.
func shiftOffset(payload []byte, pos int, order binary.ByteOrder, delta int32, shiftFrom uint32) {
	if pos < 0 || pos+4 > len(payload) {
		return
	}
	cur := order.Uint32(payload[pos : pos+4])
	if cur < shiftFrom {
		return
	}
	order.PutUint32(payload[pos:pos+4], cur+uint32(int64(delta)))
}

func adjustCommand(cmd uint32, payload []byte, order binary.ByteOrder, delta int32, shiftFrom uint32) {
	// Commands whose first payload word is a file offset (linkedit_data_command,
	// dyld_info_command, encryption_info_command).
	switch cmd {
	case lcCodeSignature, lcSegmentSplit, lcFunctionStarts, lcDataInCode,
		lcDyldChained, lcDyldExports, lcEncryptionInfo, lcEncryption64,
		lcDylibCodeSigDRs, lcDyldInfo, lcDyldInfoOnly:
		shiftOffset(payload, 0, order, delta, shiftFrom)
		// dyld_info_command: rebase/bind/weak_bind/lazy_bind/export offsets sit
		// every 8 bytes (offset followed by its size) -- only the offsets shift.
		if cmd == lcDyldInfo || cmd == lcDyldInfoOnly {
			for i := 8; i+4 <= len(payload) && i <= 32; i += 8 {
				shiftOffset(payload, i, order, delta, shiftFrom)
			}
		}
	case lcSymtab:
		// symtab_command: symoff, nsyms, stroff, strsize.
		shiftOffset(payload, 0, order, delta, shiftFrom)
		shiftOffset(payload, 8, order, delta, shiftFrom)
	case lcDysymtab:
		// dysymtab_command: 18 words, offsets at every even index.
		for i := 0; i+4 <= len(payload) && i <= 64; i += 8 {
			shiftOffset(payload, i, order, delta, shiftFrom)
		}
	case lcSegment, lcSegment64:
		adjustSegment(cmd, payload, order, delta, shiftFrom)
	}
}

func adjustSegment(cmd uint32, payload []byte, order binary.ByteOrder, delta int32, shiftFrom uint32) {
	is64 := cmd == lcSegment64
	// Payload layout (cmd+cmdsize already stripped):
	//   segname[16] vmaddr vmsize fileoff filesize maxprot initprot nsects flags
	addrSize := 4
	if is64 {
		addrSize = 8
	}
	fileoffPos := 16 + 2*addrSize
	nsectsPos := fileoffPos + 2*addrSize + 8 // filesize + maxprot + initprot
	sectStart := nsectsPos + 8               // nsects + flags
	sectSize := 68
	// section offset field: sectname[16] + segname[16] + addr + size
	offField := 32 + 2*addrSize
	if is64 {
		sectSize = 80
	}
	if len(payload) < fileoffPos+4 {
		return
	}
	if is64 && len(payload) >= fileoffPos+8 {
		// fileoff is a 64-bit word here; shift the whole thing so that
		// big-endian images are handled correctly as well.
		cur := order.Uint64(payload[fileoffPos : fileoffPos+8])
		if cur >= uint64(shiftFrom) {
			order.PutUint64(payload[fileoffPos:fileoffPos+8], cur+uint64(int64(delta)))
		}
	} else {
		shiftOffset(payload, fileoffPos, order, delta, shiftFrom)
	}
	if nsectsPos+4 > len(payload) {
		return
	}
	nsects := int(order.Uint32(payload[nsectsPos : nsectsPos+4]))
	for i := 0; i < nsects; i++ {
		base := sectStart + i*sectSize
		if base+offField+4 > len(payload) {
			break
		}
		shiftOffset(payload, base+offField, order, delta, shiftFrom)
	}
}

// InjectLoadCommand appends a raw load command (cmd+cmdsize+payload) to a thin
// image, shifting all subsequent file offsets. Used to add LC_CODE_SIGNATURE to
// an otherwise unsigned binary.
func InjectLoadCommand(thin *ThinFile, cmd []byte) ([]byte, error) {
	return rewriteLoadCommands(thin, func(cmd uint32, payload []byte, order binary.ByteOrder) ([]byte, bool, error) {
		return nil, true, nil
	}, cmd)
}
