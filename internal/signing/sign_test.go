package signing_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ysign/internal/macho"
	"ysign/internal/signing"
)

func TestBuildCodeDirectoryRoundTrip(t *testing.T) {
	content := make([]byte, 4096)
	for i := range content {
		content[i] = byte(i)
	}
	params := &signing.CodeDirectoryParams{
		Version:     0x20400,
		Flags:       0,
		Platform:    0,
		PageSizeLog: 12,
		HashType:    signing.HashSHA256,
		HashSize:    32,
		Identifier:  "com.example.test",
		TeamID:      "ABCDE12345",
		CodeLimit:   4096,
		SpecialHashes: [][]byte{
			make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32),
		},
		ExecSegBase: 0x100000000, ExecSegLimit: 0x4000, ExecSegFlags: 0,
	}
	cd, err := signing.BuildCodeDirectory(content, params)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := macho.ParseCodeDirectory(binary.LittleEndian, cd)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Identifier != "com.example.test" {
		t.Fatalf("identifier=%q", parsed.Identifier)
	}
	if parsed.TeamID != "ABCDE12345" {
		t.Fatalf("team=%q", parsed.TeamID)
	}
	if parsed.NSpecialSlots != 5 || parsed.NCodeSlots != 1 {
		t.Fatalf("slots special=%d code=%d", parsed.NSpecialSlots, parsed.NCodeSlots)
	}
	if parsed.Version != 0x20400 {
		t.Fatalf("version=0x%x", parsed.Version)
	}
	// verify code slot 0 hash = sha256 of first page
	want := sha256.Sum256(content[:4096])
	got := parsed.CodeSlotHash(0)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("code slot hash mismatch")
	}
}

func selfSignedCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "iPhone Developer: Test (ABCDE12345)", OrganizationalUnit: []string{"ABCDE12345"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func TestCMSRoundTrip(t *testing.T) {
	cert, key := selfSignedCert(t)
	content := []byte("hello code directory")
	out, err := signing.BuildCMSWithContent(content, cert, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signing.ParseCMSContent(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch")
	}
	// The production signature path is detached: no eContent, but the
	// messageDigest attribute still links the CodeDirectory.
	det, err := signing.BuildCMS(content, cert, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := signing.ParseCMSContent(det)
	if err != nil {
		t.Fatal(err)
	}
	if len(ec) != 0 {
		t.Fatalf("detached CMS should have no eContent, got %d bytes", len(ec))
	}
}

func TestCMSAdHocRoundTrip(t *testing.T) {
	content := []byte("adhoc content")
	out, err := signing.BuildCMSAdHoc(content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signing.ParseCMSContent(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch")
	}
}

func TestDiskCache(t *testing.T) {
	dir := t.TempDir()
	c, err := signing.NewDiskCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := signing.Key([]byte("payload"))
	if _, ok := c.Get(key); ok {
		t.Fatal("unexpected cache hit")
	}
	if err := c.Set(key, []byte("value")); err != nil {
		t.Fatal(err)
	}
	v, ok := c.Get(key)
	if !ok || string(v) != "value" {
		t.Fatalf("cache miss or wrong value: %q %v", v, ok)
	}
}

func TestParseProvision(t *testing.T) {
	cert, key := selfSignedCert(t)
	plist := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>UUID</key><string>12345678-ABCD</string>
	<key>Name</key><string>iOS Team Provisioning Profile: com.example.test</string>
	<key>TeamIdentifier</key><array><string>ABCDE12345</string></array>
	<key>ApplicationIdentifierPrefix</key><array><string>TEAMPREFIX</string></array>
	<key>ExpirationDate</key><date>2030-01-01T00:00:00Z</date>
	<key>Entitlements</key><dict>
		<key>application-identifier</key><string>TEAMPREFIX.com.example.test</string>
	</dict>
</dict></plist>`)
	der, err := signing.BuildCMSWithContent(plist, cert, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := signing.ParseProvision(der)
	if err != nil {
		t.Fatal(err)
	}
	if p.UUID != "12345678-ABCD" {
		t.Fatalf("uuid=%q", p.UUID)
	}
	if p.TeamID() != "ABCDE12345" {
		t.Fatalf("team=%q", p.TeamID())
	}
	if p.AppIDPrefix() != "TEAMPREFIX" {
		t.Fatalf("prefix=%q", p.AppIDPrefix())
	}
	if p.Expired(time.Now()) {
		t.Fatal("should not be expired")
	}
}

func TestLoadPEM(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSignedCert(t)
	certPEM := pemEncode("CERTIFICATE", cert.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pemEncode("PRIVATE KEY", keyDER)
	cp := filepath.Join(dir, "cert.pem")
	kp := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cp, certPEM, 0o644)
	_ = os.WriteFile(kp, keyPEM, 0o644)
	s, err := signing.LoadPEM(kp, cp)
	if err != nil {
		t.Fatal(err)
	}
	if s.Cert.Subject.CommonName != "iPhone Developer: Test (ABCDE12345)" {
		t.Fatalf("cn=%q", s.Cert.Subject.CommonName)
	}
}

func pemEncode(typ string, der []byte) []byte {
	return []byte("-----BEGIN " + typ + "-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END " + typ + "-----\n")
}
