package resign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ysign/internal/macho"
	"ysign/internal/plistutil"
	"ysign/internal/signing"
)

// buildSyntheticMachO builds a thin arm64 Mach-O with an embedded v3 code
// signature (5 special slots + code slots) and a dummy CMS signature.
func buildSyntheticMachO(t *testing.T, ident, team string) []byte {
	t.Helper()
	const headerLen = 32
	lcSize := 16

	// v3 CodeDirectory (0x20400): 44 base + scatter(4) + team(4) + spare3/
	// codeLimit64(12) + execSeg(24) = 88-byte header.
	headerLenCD := 88
	identOffset := headerLenCD
	teamOffset := headerLenCD + len(ident) + 1
	hashOffset := teamOffset + len(team) + 1 // special-slot block start
	nSpecial, nCode := 5, 1
	hashSize := 32
	// Apple semantics: the hashOffset field points at the CODE-hash block;
	// the special-slot block (nSpecialSlots*hashSize) precedes it.
	codeHashOffset := hashOffset + nSpecial*hashSize
	cdLen := int(codeHashOffset) + nCode*hashSize
	cd := make([]byte, cdLen)
	be := binary.BigEndian
	o := binary.LittleEndian
	be.PutUint32(cd[0:], 0xfade0c02)
	be.PutUint32(cd[4:], uint32(cdLen))
	be.PutUint32(cd[8:], 0x20400)
	be.PutUint32(cd[16:], uint32(codeHashOffset))
	be.PutUint32(cd[20:], uint32(identOffset))
	be.PutUint32(cd[24:], uint32(nSpecial))
	be.PutUint32(cd[28:], uint32(nCode))
	be.PutUint32(cd[32:], 4096)
	cd[36] = byte(hashSize)
	cd[37] = 2
	cd[39] = 12
	be.PutUint32(cd[44:], 0) // scatterOffset
	be.PutUint32(cd[48:], uint32(teamOffset))
	be.PutUint64(cd[64:], 0x100000000) // execSegBase
	be.PutUint64(cd[72:], 0x4000)      // execSegLimit
	copy(cd[identOffset:], ident)
	copy(cd[teamOffset:], team)
	for i := int(hashOffset); i < cdLen; i++ {
		cd[i] = byte(i)
	}

	cms := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	sigBlob := make([]byte, 8+len(cms))
	be.PutUint32(sigBlob[0:], 0xfade0b01)
	be.PutUint32(sigBlob[4:], uint32(len(sigBlob)))
	copy(sigBlob[8:], cms)

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

	dataoff := headerLen + lcSize
	data := make([]byte, dataoff+len(sb))
	o.PutUint32(data[0:], 0xfeedfacf)
	o.PutUint32(data[4:], 0x0100000c)
	o.PutUint32(data[12:], 2)
	o.PutUint32(data[16:], 1)
	o.PutUint32(data[20:], uint32(lcSize))
	o.PutUint32(data[headerLen:], 0x1d)
	o.PutUint32(data[headerLen+4:], uint32(lcSize))
	o.PutUint32(data[headerLen+8:], uint32(dataoff))
	o.PutUint32(data[headerLen+12:], uint32(len(sb)))
	copy(data[dataoff:], sb)
	return data
}

func testSigner(t *testing.T) *signing.Signer {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iPhone Developer: Test (TEAMX)", OrganizationalUnit: []string{"TEAMX"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return &signing.Signer{PrivKey: key, Cert: cert}
}

func buildApp(t *testing.T) string {
	t.Helper()
	appDir := t.TempDir()
	// Info.plist
	info := map[string]interface{}{
		"CFBundleIdentifier": "com.orig.test",
		"CFBundleExecutable": "App",
		"CFBundleName":       "Orig",
	}
	data, _ := plistutil.EncodeXML(info)
	_ = os.WriteFile(filepath.Join(appDir, "Info.plist"), data, 0o644)
	// main binary
	_ = os.WriteFile(filepath.Join(appDir, "App"), buildSyntheticMachO(t, "com.orig.test", "TEAMX"), 0o755)
	return appDir
}

func TestResignEndToEnd(t *testing.T) {
	appDir := buildApp(t)
	signer := testSigner(t)

	opts := &Options{
		BundleID:      "com.new.test",
		BundleName:    "NewName",
		BundleVersion: "2.0",
		MinOSVersion:  "13.0",
		CacheDir:      filepath.Join(t.TempDir(), "cache"),
		Signer:        signer,
		Force:         true,
	}
	if err := Resign(appDir, opts); err != nil {
		t.Fatal(err)
	}

	// Verify Info.plist was updated.
	infoData, _ := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	info, _ := plistutil.Decode(infoData)
	if plistutil.ReadBundleID(info) != "com.new.test" {
		t.Fatalf("bundle id not updated: %q", plistutil.ReadBundleID(info))
	}
	if plistutil.GetString(info, "CFBundleDisplayName") != "NewName" {
		t.Fatal("name not updated")
	}
	if plistutil.GetString(info, "MinimumOSVersion") != "13.0" {
		t.Fatal("minos not updated")
	}

	// Verify binary signature rebuilt.
	binData, _ := os.ReadFile(filepath.Join(appDir, "App"))
	f, err := macho.Parse(binData)
	if err != nil {
		t.Fatal(err)
	}
	thin := f.Slices[0]
	sb, err := thin.ParseSuperblob()
	if err != nil {
		t.Fatal(err)
	}
	cd, err := sb.ParseCodeDirectory(thin.Endian)
	if err != nil {
		t.Fatal(err)
	}
	if cd.Identifier != "com.new.test" {
		t.Fatalf("CD identifier=%q, want com.new.test", cd.Identifier)
	}
	// team id comes from the provisioning profile; none embedded in this
	// unit test, so it stays empty (the real-ipa test below covers the profile
	// path). The entitlements blob must still exist and parse.
	ent, err := sb.ParseEntitlements()
	if err != nil {
		t.Fatal(err)
	}
	if ent == nil {
		t.Fatal("expected entitlements blob")
	}
	sig, err := sb.ParseSignatureBlob()
	if err != nil || len(sig) == 0 {
		t.Fatalf("expected CMS signature, err=%v", err)
	}
	// The signature should be a real CMS (signer present) since Signer set.
	// Production signature is detached (zsign/OpenSSL CMS_DETACHED): the
	// CodeDirectory is linked through the messageDigest attribute, so the
	// eContent is intentionally empty.
	if _, err := signing.ParseCMSContent(sig); err != nil {
		t.Fatalf("CMS not parseable: %v", err)
	}

	// Re-signing again must succeed (cache path).
	opts2 := &Options{CacheDir: opts.CacheDir, Signer: signer}
	if err := Resign(appDir, opts2); err != nil {
		t.Fatalf("second resign: %v", err)
	}
}

func TestResignAdHoc(t *testing.T) {
	appDir := buildApp(t)
	opts := &Options{
		BundleID: "com.adhoc.test",
		AdHoc:    true,
		Force:    true,
		CacheDir: filepath.Join(t.TempDir(), "cache"),
	}
	if err := Resign(appDir, opts); err != nil {
		t.Fatal(err)
	}
	binData, _ := os.ReadFile(filepath.Join(appDir, "App"))
	f, _ := macho.Parse(binData)
	sb, _ := f.Slices[0].ParseSuperblob()
	cd, _ := sb.ParseCodeDirectory(f.Slices[0].Endian)
	if cd.Flags&0x2 == 0 {
		t.Fatalf("adhoc flag not set: flags=0x%x", cd.Flags)
	}
}
