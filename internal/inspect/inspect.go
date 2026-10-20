// Package inspect implements certificate checks (incl. OCSP), metadata
// extraction, and code-signature inspection for the ysign CLI.
package inspect

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ocsp"

	"ysign/internal/ipautil"
	"ysign/internal/macho"
	"ysign/internal/plistutil"
	"ysign/internal/signing"
)

// DescribeCert returns a human-readable summary of a certificate.
func DescribeCert(c *x509.Certificate) string {
	alg := c.PublicKeyAlgorithm.String()
	if sig, err := algorithmName(c.SignatureAlgorithm); err == nil {
		alg = sig
	}
	now := time.Now()
	status := "VALID"
	if now.Before(c.NotBefore) {
		status = "NOT YET VALID"
	} else if now.After(c.NotAfter) {
		status = "EXPIRED"
	}
	return fmt.Sprintf(`Name: %s
Subject: %s
Issuer: %s
Serial: %X
Type: %s
Org: %s
Team: %s
Algorithm: %s
Issued: %s
Expires: %s (%s)
Status: %s`,
		c.Subject.CommonName,
		c.Subject.String(),
		c.Issuer.String(),
		c.SerialNumber,
		c.Subject.CommonName,
		c.Subject.Organization,
		teamID(c),
		alg,
		c.NotBefore.Format(time.RFC3339),
		c.NotAfter.Format(time.RFC3339),
		formatDuration(now, c.NotAfter),
		status,
	)
}

func teamID(c *x509.Certificate) string {
	if len(c.Subject.OrganizationalUnit) > 0 {
		// Team IDs are commonly encoded in the OU (e.g. "TEAMID (TeamID)").
		return c.Subject.OrganizationalUnit[0]
	}
	return c.Subject.CommonName
}

func algorithmName(sa x509.SignatureAlgorithm) (string, error) {
	switch sa {
	case x509.SHA256WithRSA:
		return "RSA 2048-bit SHA256", nil
	case x509.SHA384WithRSA:
		return "RSA SHA384", nil
	case x509.ECDSAWithSHA256:
		return "ECDSA P-256 SHA256", nil
	case x509.ECDSAWithSHA384:
		return "ECDSA SHA384", nil
	default:
		return "", errors.New("unknown")
	}
}

func formatDuration(now, then time.Time) string {
	d := then.Sub(now)
	days := int(d.Hours() / 24)
	if days < 0 {
		days = -days
		return fmt.Sprintf("%d days ago", days)
	}
	return fmt.Sprintf("%d days remaining", days)
}

// ParseCertificateBytes parses a DER or PEM certificate.
func ParseCertificateBytes(data []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	return x509.ParseCertificate(data)
}

// OCSPStatus performs a best-effort OCSP revocation check for cert using
// issuer as the issuer certificate. Returns a human-readable status. When the
// responder cannot be reached or is absent, returns a "skipped" message.
func OCSPStatus(cert, issuer *x509.Certificate) (string, error) {
	if issuer == nil {
		return "skipped (no issuer certificate)", nil
	}
	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		return "skipped (no OCSP responder in certificate)", nil
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return "", fmt.Errorf("create OCSP request: %w", err)
	}
	// Bound the request: a slow/unreachable responder must not hang -C.
	client := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := client.Post(ocspURLs[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return "skipped (OCSP responder unreachable)", nil
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return "skipped (cannot read OCSP response)", nil
	}
	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return "skipped (cannot parse OCSP response)", nil
	}
	if resp.Status == ocsp.Good {
		return "valid (OCSP)", nil
	}
	if resp.Status == ocsp.Revoked {
		return "REVOKED", nil
	}
	return "unknown (OCSP)", nil
}

// CheckFile inspects a signing-related file and prints a report. It dispatches
// by content type: p12/pem/cer certificates, mobileprovision, ipa, or Mach-O.
func CheckFile(path, p12Password string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	ext := filepath.Ext(path)
	switch ext {
	case ".p12", ".pfx":
		s, err := signing.LoadP12(path, p12Password)
		if err != nil {
			return "", err
		}
		return DescribeCert(s.Cert), nil
	case ".mobileprovision":
		p, err := signing.ParseProvision(data)
		if err != nil {
			return "", err
		}
		status := "not expired"
		if p.Expired(time.Now()) {
			status = "EXPIRED"
		}
		out := fmt.Sprintf(`MobileProvision: %s
UUID: %s
AppID: %s
Team: %s
ProvisionedDevices: %d
ProvisionsAllDevices: %v
Expires: %s (%s)`,
			p.Name, p.UUID, p.AppIdentifier, p.TeamID(),
			len(p.ProvisionedDevices), p.ProvisionsAllDevices,
			p.ExpirationDate.Format(time.RFC3339), status)
		if len(p.DeveloperCertificates) > 0 {
			out += "\n" + DescribeCert(p.DeveloperCertificates[0])
		}
		return out, nil
	case ".ipa":
		return checkIPA(path)
	}
	// Certificate (PEM/DER) or Mach-O / IPA.
	if c, err := ParseCertificateBytes(data); err == nil {
		return DescribeCert(c), nil
	}
	return DescribeSignature(data)
}

// checkIPA inspects the code signature of an IPA's main executable and reports
// its embedded provisioning profile, mirroring zsign's -C IPA support.
func checkIPA(path string) (string, error) {
	tmp, err := os.MkdirTemp("", "ysign-check-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	appDir, err := ipautil.UnzipIPA(path, tmp)
	if err != nil {
		return "", fmt.Errorf("not a valid IPA: %w", err)
	}
	var out string
	if data, err := os.ReadFile(filepath.Join(appDir, "embedded.mobileprovision")); err == nil {
		if p, perr := signing.ParseProvision(data); perr == nil {
			out += fmt.Sprintf("IPA: %s\nProvision: %s\nAppID: %s\nTeam: %s\n",
				filepath.Base(path), p.Name, p.AppIdentifier, p.TeamID())
		}
	}
	if infoData, err := os.ReadFile(filepath.Join(appDir, "Info.plist")); err == nil {
		if info, perr := plistutil.Decode(infoData); perr == nil {
			if mainName := plistutil.GetString(info, "CFBundleExecutable"); mainName != "" {
				if mainData, rerr := os.ReadFile(filepath.Join(appDir, mainName)); rerr == nil {
					if sig, serr := DescribeSignature(mainData); serr == nil {
						out += sig
						return out, nil
					}
				}
			}
		}
	}
	if out == "" {
		return "", errors.New("no code signature found in IPA")
	}
	return out, nil
}

// DescribeSignature inspects a Mach-O binary or IPA file's code signature.
func DescribeSignature(data []byte) (string, error) {
	f, err := macho.Parse(data)
	if err != nil {
		return "", err
	}
	var out string
	for _, thin := range f.Slices {
		if thin.Signature == nil {
			out += fmt.Sprintf("[%s] no code signature\n", thin.CPUName())
			continue
		}
		sb, err := thin.ParseSuperblob()
		if err != nil {
			out += fmt.Sprintf("[%s] signature: %v\n", thin.CPUName(), err)
			continue
		}
		cd, err := sb.ParseCodeDirectory(thin.Endian)
		if err != nil {
			out += fmt.Sprintf("[%s] code directory: %v\n", thin.CPUName(), err)
			continue
		}
		out += fmt.Sprintf("[%s] Signed: yes\nIdentifier: %s\nTeam: %s\nVersion: 0x%x\nFlags: 0x%x\nHash: %s (%d)\nPages: %d x %d\nCodeLimit: %d\n",
			thin.CPUName(), cd.Identifier, cd.TeamID, cd.Version, cd.Flags,
			cd.HashAlgorithm(), cd.HashSize, cd.NCodeSlots, cd.PageBytes(), cd.CodeLimit)
		if ent, err := sb.ParseEntitlements(); err == nil && len(ent) > 0 {
			out += fmt.Sprintf("Entitlements: %d bytes\n", len(ent))
		}
		if sig, err := sb.ParseSignatureBlob(); err == nil {
			out += fmt.Sprintf("CMS signature: %d bytes\n", len(sig))
		}
	}
	return out, nil
}

// ExtractMetadata writes metadata.json and the primary app icon into outDir
// for an extracted .app bundle, mirroring zsign -x.
func ExtractMetadata(appDir, outDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	if err != nil {
		return "", err
	}
	info, err := plistutil.Decode(data)
	if err != nil {
		return "", err
	}
	meta := map[string]interface{}{
		"CFBundleIdentifier":         plistutil.GetString(info, "CFBundleIdentifier"),
		"CFBundleName":               plistutil.GetString(info, "CFBundleName"),
		"CFBundleDisplayName":        plistutil.GetString(info, "CFBundleDisplayName"),
		"CFBundleVersion":            plistutil.GetString(info, "CFBundleVersion"),
		"CFBundleShortVersionString": plistutil.GetString(info, "CFBundleShortVersionString"),
		"MinimumOSVersion":           plistutil.GetString(info, "MinimumOSVersion"),
		"CFBundleExecutable":         plistutil.GetString(info, "CFBundleExecutable"),
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	jsonBytes, err := plistutil.EncodeXML(meta)
	if err != nil {
		return "", err
	}
	// Store as metadata.json (XML plist content to keep it simple).
	jsonPath := filepath.Join(outDir, "metadata.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		return "", err
	}
	icon := findPrimaryIcon(appDir, info)
	var iconPath string
	if icon != "" {
		b, err := os.ReadFile(filepath.Join(appDir, icon))
		if err == nil {
			iconPath = filepath.Join(outDir, "icon.png")
			if err := os.WriteFile(iconPath, b, 0o644); err != nil {
				iconPath = ""
			}
		}
	}
	return fmt.Sprintf("metadata written to %s (icon: %v)", jsonPath, iconPath != ""), nil
}

func findPrimaryIcon(appDir string, info map[string]interface{}) string {
	if arr, ok := info["CFBundleIconFiles"].([]interface{}); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			return s
		}
	}
	return ""
}
