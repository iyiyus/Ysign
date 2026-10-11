package macho

import (
	"encoding/binary"
	"errors"
	"fmt"
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
// name equals path (or contains it) from every slice.
func RemoveLoadDylib(data []byte, path string) ([]byte, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	newSlices := make([][]byte, len(f.Slices))
	for i, thin := range f.Slices {
		ns, err := rewriteLoadCommands(thin, func(cmd uint32, payload []byte, order binary.ByteOrder) ([]byte, bool, error) {
			name := dylibName(cmd, payload, order)
			if name != "" && (name == path || contains(name, path)) {
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

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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

	// Patch every file offset in the new load commands by delta.
	adjustOffsets(newLoads, thin.Endian, delta)

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

func adjustOffsets(loads []byte, order binary.ByteOrder, delta int32) {
	off := 0
	for off+8 <= len(loads) {
		cmd := order.Uint32(loads[off : off+4])
		size := int(order.Uint32(loads[off+4 : off+8]))
		if size < 8 || off+size > len(loads) {
			break
		}
		payload := loads[off+8 : off+size]
		adjustCommand(cmd, payload, order, delta)
		off += size
	}
}

func adjustCommand(cmd uint32, payload []byte, order binary.ByteOrder, delta int32) {
	// Commands whose first payload word is a file offset (linkedit_data_command,
	// dyld_info_command, encryption_info_command).
	switch cmd {
	case lcCodeSignature, lcSegmentSplit, lcFunctionStarts, lcDataInCode,
		lcDyldChained, lcDyldExports, lcEncryptionInfo, lcEncryption64,
		lcDylibCodeSigDRs, lcDyldInfo, lcDyldInfoOnly:
		if len(payload) >= 4 {
			order.PutUint32(payload[0:4], order.Uint32(payload[0:4])+uint32(int64(delta)))
		}
		// dyld_info_command also has bind/weak/lazy/export offsets.
		if cmd == lcDyldInfo || cmd == lcDyldInfoOnly {
			for i := 4; i+4 <= len(payload) && i <= 16; i += 4 {
				order.PutUint32(payload[i:i+4], order.Uint32(payload[i:i+4])+uint32(int64(delta)))
			}
		}
	case lcSegment, lcSegment64:
		adjustSegment(cmd, payload, order, delta)
	}
}

func adjustSegment(cmd uint32, payload []byte, order binary.ByteOrder, delta int32) {
	is64 := cmd == lcSegment64
	// Segment header: segname[16] + vmaddr/vmsize + fileoff/filesize (+maxprot...)
	fileoffPos := 24 + 8
	if is64 {
		fileoffPos = 24 + 8 + 8 // segname16 + vmaddr8 + vmsize8
	} else {
		fileoffPos = 24 + 4 + 4
	}
	if len(payload) < fileoffPos+4 {
		return
	}
	order.PutUint32(payload[fileoffPos:fileoffPos+4], order.Uint32(payload[fileoffPos:fileoffPos+4])+uint32(int64(delta)))
	// sections
	nsectsPos := fileoffPos + 12 // fileoff4 + filesize4 + maxprot4
	nsects := int(order.Uint32(payload[nsectsPos : nsectsPos+4]))
	sectStart := nsectsPos + 8 // + initprot4 + flags4
	sectSize := 68
	if is64 {
		sectSize = 80
	}
	for i := 0; i < nsects; i++ {
		base := sectStart + i*sectSize
		if base+44 > len(payload) {
			break
		}
		// section offset field: after sectname16+segname16+addr(4or8)+size(4or8)
		offField := base + 32
		if is64 {
			offField = base + 40
		}
		if offField+4 <= len(payload) {
			order.PutUint32(payload[offField:offField+4], order.Uint32(payload[offField:offField+4])+uint32(int64(delta)))
		}
	}
}
