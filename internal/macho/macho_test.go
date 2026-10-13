package macho

import (
	"encoding/binary"
	"testing"
)

// buildSyntheticThin builds a minimal 64-bit little-endian Mach-O with a single
// LC_CODE_SIGNATURE load command pointing at an embedded superblob containing
// a v2 code directory (identifier "com.example.test", 2 special slots, 2 code
// slots) and a blob-wrapper signature slot.
func buildSyntheticThin(t *testing.T) []byte {
	t.Helper()
	const headerLen = 32
	lcSize := 16

	// --- CodeDirectory (0x20200: scatterOffset + teamOffset) ---
	ident := "com.example.test"
	team := "ABCDE12345"
	headerLenCD := 52 // 44 base + scatter(4) + team(4)
	identOffset := headerLenCD
	teamOffset := headerLenCD + len(ident) + 1
	hashOffset := teamOffset + len(team) + 1
	nSpecial, nCode := 2, 2
	hashSize := 32
	cdLen := int(hashOffset) + (nSpecial+nCode)*hashSize
	cd := make([]byte, cdLen)
	o := binary.LittleEndian
	be := binary.BigEndian
	be.PutUint32(cd[0:], 0xfade0c02)
	be.PutUint32(cd[4:], uint32(cdLen))
	be.PutUint32(cd[8:], 0x20200)
	// Apple semantics: the hashOffset field points at the CODE-hash block;
	// the special-slot block (nSpecialSlots * hashSize) precedes it.
	codeHashOffset := hashOffset + nSpecial*hashSize
	be.PutUint32(cd[16:], uint32(codeHashOffset))
	be.PutUint32(cd[20:], uint32(identOffset))
	be.PutUint32(cd[24:], uint32(nSpecial))
	be.PutUint32(cd[28:], uint32(nCode))
	be.PutUint32(cd[32:], 4096)
	cd[36] = byte(hashSize)
	cd[37] = 2 // sha256
	cd[39] = 12
	be.PutUint32(cd[44:], 0)                   // scatterOffset
	be.PutUint32(cd[48:], uint32(teamOffset))  // teamOffset
	copy(cd[identOffset:], ident)
	copy(cd[teamOffset:], team)
	// hashes filled with deterministic bytes
	for i := int(hashOffset); i < cdLen; i++ {
		cd[i] = byte(i)
	}
	// --- blob wrapper signature (dummy CMS) ---
	cms := []byte{0x30, 0x03, 0x02, 0x01, 0x01} // minimal DER
	sigBlob := make([]byte, 8+len(cms))
	be.PutUint32(sigBlob[0:], 0xfade0b01)
	be.PutUint32(sigBlob[4:], uint32(len(sigBlob)))
	copy(sigBlob[8:], cms)

	// --- superblob ---
	slots := []struct {
		typ uint32
		b   []byte
	}{{0, cd}, {0x10000, sigBlob}}
	blobStart := 12 + len(slots)*8
	total := blobStart
	for _, s := range slots {
		total += len(s.b)
	}
	sb := make([]byte, total)
	be.PutUint32(sb[0:], 0xfade0cc0)
	be.PutUint32(sb[4:], uint32(total))
	be.PutUint32(sb[8:], uint32(len(slots)))
	off := blobStart
	for i, s := range slots {
		pos := 12 + i*8
		be.PutUint32(sb[pos:], s.typ)
		be.PutUint32(sb[pos+4:], uint32(off))
		copy(sb[off:], s.b)
		off += len(s.b)
	}

	// --- Mach-O header + LC_CODE_SIGNATURE ---
	dataoff := headerLen + lcSize
	datasize := uint32(len(sb))
	totalLen := dataoff + len(sb)
	data := make([]byte, totalLen)
	o.PutUint32(data[0:], 0xfeedfacf)
	o.PutUint32(data[4:], 0x0100000c)      // arm64
	o.PutUint32(data[12:], 2)              // MH_EXECUTE
	o.PutUint32(data[16:], 1)              // ncmds
	o.PutUint32(data[20:], uint32(lcSize)) // sizeofcmds
	// load command at 32
	o.PutUint32(data[headerLen:], 0x1d) // LC_CODE_SIGNATURE
	o.PutUint32(data[headerLen+4:], uint32(lcSize))
	o.PutUint32(data[headerLen+8:], uint32(dataoff))
	o.PutUint32(data[headerLen+12:], datasize)
	copy(data[dataoff:], sb)
	return data
}

func TestParseSyntheticThin(t *testing.T) {
	data := buildSyntheticThin(t)
	f, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if f.IsFat {
		t.Fatal("expected thin")
	}
	if len(f.Slices) != 1 {
		t.Fatalf("expected 1 slice, got %d", len(f.Slices))
	}
	thin := f.Slices[0]
	if thin.Signature == nil {
		t.Fatal("expected code signature")
	}
	if thin.Signature.DataOffset != 48 {
		t.Fatalf("dataoff=%d, want 48", thin.Signature.DataOffset)
	}
	sb, err := thin.ParseSuperblob()
	if err != nil {
		t.Fatal(err)
	}
	if sb.CodeDirectorySlot == nil || sb.SignatureSlot == nil {
		t.Fatal("missing code directory or signature slot")
	}
	cd, err := sb.ParseCodeDirectory(thin.Endian)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("debug: version=%#x teamOff=%d hashOff=%d identOff=%d len=%d raw48=%x", cd.Version, cd.TeamOffset, cd.HashOffset, cd.IdentOffset, len(cd.Raw), cd.Raw[48:56])
	if cd.Identifier != "com.example.test" {
		t.Fatalf("identifier=%q", cd.Identifier)
	}
	if cd.TeamID != "ABCDE12345" {
		t.Fatalf("team=%q", cd.TeamID)
	}
	if cd.NCodeSlots != 2 || cd.NSpecialSlots != 2 {
		t.Fatalf("slots special=%d code=%d", cd.NSpecialSlots, cd.NCodeSlots)
	}
	if cd.HashAlgorithm() != "sha256" {
		t.Fatalf("hash=%q", cd.HashAlgorithm())
	}
	// special slot hashes
	if h := cd.SpecialSlotHash(-1); len(h) != 32 {
		t.Fatalf("special slot -1 hash len=%d", len(h))
	}
	if h := cd.CodeSlotHash(0); len(h) != 32 {
		t.Fatalf("code slot 0 hash len=%d", len(h))
	}
	if sig, err := sb.ParseSignatureBlob(); err != nil || len(sig) == 0 {
		t.Fatalf("signature blob err=%v", err)
	}
}

func TestPatchSignatureSize(t *testing.T) {
	data := buildSyntheticThin(t)
	f, _ := Parse(data)
	thin := f.Slices[0]
	if err := thin.PatchSignatureSize(999); err != nil {
		t.Fatal(err)
	}
	if thin.Signature.DataSize != 999 {
		t.Fatalf("datasize=%d", thin.Signature.DataSize)
	}
	// verify it was written back to the underlying data
	if got := thin.Endian.Uint32(thin.Data[headerOff() : headerOff()+16][12:16]); got != 999 {
		t.Fatalf("patch not reflected in data: %d", got)
	}
}

func headerOff() int { return 32 }
