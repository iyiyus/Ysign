// Package resign orchestrates re-signing an extracted .app bundle.
package resign

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"ysign/internal/macho"
	"ysign/internal/plistutil"
	"ysign/internal/signing"
)

// Options configures a re-signing run.
type Options struct {
	BundleID           string
	BundleName         string
	BundleVersion      string
	MinOSVersion       string
	EntitlementsFile   string
	IconFile           string
	AdHoc              bool
	Force              bool
	Quiet              bool
	CacheDir           string
	EnableDocs         bool
	RemoveExtensions   bool
	RemoveWatch        bool
	RemoveUISD         bool
	RemoveProvision    bool
	Signer             *signing.Signer
	InjectDylibs       []string
	RemoveDylibs       []string
	WeakDylibs         []string
	InjectToExtensions bool
	// ExtProfiles are provisioning profiles for app extensions. The first entry
	// (when present) is treated as the main profile and embedded into the app;
	// the rest are matched to extension bundles by bundle id.
	ExtProfiles []string
}

// Logf is a minimal logger hook; by default logs to stdout unless Quiet.
func logf(opts *Options, format string, args ...interface{}) {
	if opts != nil && opts.Quiet {
		return
	}
	fmt.Printf(format+"\n", args...)
}

// Resign rewrites and re-signs every Mach-O binary inside an extracted .app
// bundle in place. The bundle's Info.plist is updated first so the code
// signature's special slots reflect the final files on disk.
func Resign(appDir string, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}
	infoPath := filepath.Join(appDir, "Info.plist")
	infoData, err := os.ReadFile(infoPath)
	if err != nil {
		return fmt.Errorf("read Info.plist: %w", err)
	}
	info, err := plistutil.Decode(infoData)
	if err != nil {
		return fmt.Errorf("decode Info.plist: %w", err)
	}

	origBundleID := plistutil.ReadBundleID(info)
	bundleID := opts.BundleID
	if bundleID == "" {
		bundleID = origBundleID
	}
	if bundleID == "" {
		return errors.New("cannot determine bundle id")
	}
	plistutil.Set(info, "CFBundleIdentifier", bundleID)
	if opts.BundleName != "" {
		plistutil.Set(info, "CFBundleDisplayName", opts.BundleName)
		plistutil.Set(info, "CFBundleName", opts.BundleName)
	}
	if opts.BundleVersion != "" {
		plistutil.Set(info, "CFBundleVersion", opts.BundleVersion)
		plistutil.Set(info, "CFBundleShortVersionString", opts.BundleVersion)
	}
	if opts.MinOSVersion != "" {
		plistutil.Set(info, "MinimumOSVersion", opts.MinOSVersion)
	}
	if opts.EnableDocs {
		plistutil.Set(info, "UISupportsDocumentBrowser", true)
		plistutil.Set(info, "UIFileSharingEnabled", true)
	}
	if opts.RemoveUISD {
		plistutil.Set(info, "UISupportedDevices", []interface{}{})
	}

	// Cleanup before hashing so the signature reflects the final bundle.
	if opts.RemoveExtensions {
		_ = os.RemoveAll(filepath.Join(appDir, "PlugIns"))
	}
	if opts.RemoveWatch {
		_ = os.RemoveAll(filepath.Join(appDir, "Watch"))
		_ = os.RemoveAll(filepath.Join(appDir, "com.apple.WatchPlaceholder"))
	}
	provisionPath := filepath.Join(appDir, "embedded.mobileprovision")
	if opts.RemoveProvision {
		_ = os.Remove(provisionPath)
	}
	// When -m is given, embed the first profile as the app's main provision.
	if len(opts.ExtProfiles) > 0 && !opts.RemoveProvision {
		if err := copyFile(opts.ExtProfiles[0], provisionPath); err != nil {
			return fmt.Errorf("embed provisioning profile: %w", err)
		}
	}
	// Parse extension profiles (entries after the main one).
	var extProfiles []*signing.Provision
	if len(opts.ExtProfiles) > 1 {
		for _, ep := range opts.ExtProfiles[1:] {
			data, err := os.ReadFile(ep)
			if err != nil {
				return fmt.Errorf("read extension profile %s: %w", ep, err)
			}
			p, err := signing.ParseProvision(data)
			if err != nil {
				return fmt.Errorf("parse extension profile %s: %w", ep, err)
			}
			extProfiles = append(extProfiles, p)
		}
	}

	// Resolve team id and entitlements.
	teamID := ""
	var provision *signing.Provision
	if provData, err := os.ReadFile(provisionPath); err == nil {
		if p, perr := signing.ParseProvision(provData); perr == nil {
			provision = p
			teamID = p.TeamID()
		}
	}
	entitlementsXML, err := resolveEntitlements(opts, provision, appDir, bundleID, teamID, info)
	if err != nil {
		return err
	}

	// Write the updated Info.plist and read back its exact bytes for hashing.
	newInfo, err := plistutil.EncodeXML(info)
	if err != nil {
		return err
	}
	if err := os.WriteFile(infoPath, newInfo, 0o644); err != nil {
		return err
	}
	infoBytes, err := os.ReadFile(infoPath)
	if err != nil {
		return err
	}

	// Icon replacement (copies over the primary icon file referenced in Info.plist).
	if err := replaceIcon(appDir, info, opts.IconFile); err != nil {
		logf(opts, "warn: icon: %v", err)
	}

	// Find the main executable name.
	mainName := plistutil.GetString(info, "CFBundleExecutable")
	mainPath := ""
	if mainName != "" {
		mainPath = filepath.Join(appDir, mainName)
	}

	cache, err := signing.NewDiskCache(opts.CacheDir)
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}

	// Re-sign every Mach-O binary.
	var binaries []string
	if err := filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if isMachO(path) {
			binaries = append(binaries, path)
		}
		return nil
	}); err != nil {
		return err
	}

	for _, bin := range binaries {
		isMain := bin == mainPath
		data, err := os.ReadFile(bin)
		if err != nil {
			return err
		}
		// dylib injection / removal (before signing so hashes cover final bytes).
		for _, d := range opts.InjectDylibs {
			if !opts.InjectToExtensions && !isMain {
				continue
			}
			weak := containsString(opts.WeakDylibs, d)
			data, err = applyInject(filepath.Dir(bin), d, weak, data)
			if err != nil {
				return fmt.Errorf("inject dylib %s into %s: %w", d, filepath.Base(bin), err)
			}
		}
		for _, d := range opts.RemoveDylibs {
			data, err = macho.RemoveLoadDylib(data, d)
			if err != nil {
				return fmt.Errorf("remove dylib %s from %s: %w", d, filepath.Base(bin), err)
			}
		}
		var ctx *signContext
		if isMain {
			ctx = &signContext{
				BundleID: bundleID, TeamID: teamID, AdHoc: opts.AdHoc, Force: opts.Force,
				Cache: cache, Signer: opts.Signer,
				InfoPlist: infoBytes, EntitlementsXML: entitlementsXML,
				KeepAllSpecialHashes: false,
			}
		} else if extCtx := extCtxFor(bin, extProfiles, cache, opts); extCtx != nil {
			ctx = extCtx
		} else {
			ctx = &signContext{
				BundleID: bundleID, TeamID: teamID, AdHoc: opts.AdHoc, Force: opts.Force,
				Cache: cache, Signer: opts.Signer,
				KeepAllSpecialHashes: true,
			}
		}
		out, err := rebuildBinary(data, ctx)
		if err != nil {
			return fmt.Errorf("re-sign %s: %w", filepath.Base(bin), err)
		}
		if err := os.WriteFile(bin, out, 0o755); err != nil {
			return err
		}
		if isMain {
			logf(opts, "signed main: %s", filepath.Base(bin))
		}
	}
	logf(opts, "re-signed %d binary(ies), bundle id=%s team=%s adhoc=%v", len(binaries), bundleID, teamID, opts.AdHoc)
	return nil
}

// applyInject copies a local dylib into the bundle directory (when it is an
// existing file) and adds an LC_LOAD_DYLIB load command to the binary bytes.
func applyInject(dir, dylib string, weak bool, data []byte) ([]byte, error) {
	loadPath := dylib
	if st, err := os.Stat(dylib); err == nil && !st.IsDir() {
		base := filepath.Base(dylib)
		dest := filepath.Join(dir, base)
		if err := copyFile(dylib, dest); err != nil {
			return nil, err
		}
		loadPath = "@executable_path/" + base
	}
	return macho.AddLoadDylib(data, loadPath, weak)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// extCtxFor builds a signing context for a binary inside an app extension
// (PlugIns/*.appex) using a matching extension provisioning profile. Returns
// nil when no profile matches or the binary is not in an extension.
func extCtxFor(bin string, extProfiles []*signing.Provision, cache *signing.DiskCache, opts *Options) *signContext {
	sep := string(os.PathSeparator)
	if !strings.Contains(bin, sep+"PlugIns"+sep) || len(extProfiles) == 0 {
		return nil
	}
	appexDir := bin
	for {
		parent := filepath.Dir(appexDir)
		if parent == appexDir {
			return nil
		}
		appexDir = parent
		if strings.HasSuffix(strings.ToLower(filepath.Base(appexDir)), ".appex") {
			break
		}
	}
	infoData, err := os.ReadFile(filepath.Join(appexDir, "Info.plist"))
	if err != nil {
		return nil
	}
	appexInfo, err := plistutil.Decode(infoData)
	if err != nil {
		return nil
	}
	appexID := plistutil.ReadBundleID(appexInfo)
	if appexID == "" {
		return nil
	}
	for _, p := range extProfiles {
		if !profileMatches(p, appexID) {
			continue
		}
		team := p.TeamID()
		ent, err := resolveEntitlements(&Options{Quiet: opts.Quiet}, p, appexDir, appexID, team, appexInfo)
		if err != nil {
			continue
		}
		return &signContext{
			BundleID: appexID, TeamID: team, AdHoc: opts.AdHoc, Force: opts.Force,
			Cache: cache, Signer: opts.Signer,
			InfoPlist: infoData, EntitlementsXML: ent,
			KeepAllSpecialHashes: false,
		}
	}
	return nil
}

// profileMatches reports whether a provisioning profile covers the bundle id.
func profileMatches(p *signing.Provision, bundleID string) bool {
	if p.Entitlements != nil {
		if ai, ok := p.Entitlements["application-identifier"].(string); ok && ai != "" {
			return ai == bundleID || strings.HasSuffix(ai, "."+bundleID)
		}
	}
	return false
}

// resolveEntitlements produces the XML entitlements plist to embed in the main
// binary. Priority: explicit file > provisioning profile > existing > empty.
func resolveEntitlements(opts *Options, provision *signing.Provision, appDir, bundleID, teamID string, info map[string]interface{}) ([]byte, error) {
	if opts.EntitlementsFile != "" {
		data, err := os.ReadFile(opts.EntitlementsFile)
		if err != nil {
			return nil, err
		}
		if _, err := plistutil.Decode(data); err != nil {
			return nil, fmt.Errorf("invalid entitlements plist: %w", err)
		}
		return data, nil
	}
	if provision != nil && provision.Entitlements != nil {
		ent := cloneMap(provision.Entitlements)
		prefix := provision.AppIDPrefix()
		if prefix == "" {
			prefix = teamID
		}
		if bundleID != "" {
			ent["application-identifier"] = prefix + "." + bundleID
			ent["com.apple.developer.team-identifier"] = teamID
			if groups, ok := ent["keychain-access-groups"]; ok {
				if arr, ok2 := groups.([]interface{}); ok2 && len(arr) > 0 {
					ent["keychain-access-groups"] = []interface{}{prefix + "." + bundleID}
				}
			}
		}
		return plistutil.EncodeXML(ent)
	}
	// Adhoc or no profile: keep existing entitlements, else empty.
	if provision == nil {
		if b, err := existingEntitlements(appDir); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return plistutil.EncodeXML(map[string]interface{}{})
}

// existingEntitlements reads the entitlements from the main binary's current
// signature if present.
func existingEntitlements(appDir string) ([]byte, error) {
	infoData, err := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	if err != nil {
		return nil, err
	}
	info, err := plistutil.Decode(infoData)
	if err != nil {
		return nil, err
	}
	mainName := plistutil.GetString(info, "CFBundleExecutable")
	if mainName == "" {
		return nil, errors.New("no CFBundleExecutable")
	}
	data, err := os.ReadFile(filepath.Join(appDir, mainName))
	if err != nil {
		return nil, err
	}
	f, err := macho.Parse(data)
	if err != nil {
		return nil, err
	}
	for _, thin := range f.Slices {
		if thin.Signature == nil {
			continue
		}
		sb, err := thin.ParseSuperblob()
		if err != nil {
			continue
		}
		if ent, err := sb.ParseEntitlements(); err == nil && len(ent) > 0 {
			return ent, nil
		}
	}
	return nil, errors.New("no existing entitlements")
}

// replaceIcon copies the given icon over the primary icon file referenced in
// Info.plist.
func replaceIcon(appDir string, info map[string]interface{}, iconFile string) error {
	if iconFile == "" {
		return nil
	}
	names := iconNames(info)
	if len(names) == 0 {
		return errors.New("no icon names in Info.plist")
	}
	target := filepath.Join(appDir, names[0])
	data, err := os.ReadFile(iconFile)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

func iconNames(info map[string]interface{}) []string {
	var out []string
	if v, ok := info["CFBundleIcons"]; ok {
		if m, ok2 := v.(map[string]interface{}); ok2 {
			if arr, ok3 := m["CFBundlePrimaryIcon"]; ok3 {
				if p, ok4 := arr.(map[string]interface{}); ok4 {
					if files, ok5 := p["CFBundleIconFiles"]; ok5 {
						if fa, ok6 := files.([]interface{}); ok6 {
							for _, f := range fa {
								if s, ok7 := f.(string); ok7 {
									out = append(out, s)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(out) == 0 {
		if arr, ok := info["CFBundleIconFiles"].([]interface{}); ok {
			for _, f := range arr {
				if s, ok2 := f.(string); ok2 {
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 {
		if v, ok := info["CFBundleIcons~ipad"]; ok {
			if m, ok2 := v.(map[string]interface{}); ok2 {
				if arr, ok3 := m["CFBundleIconFiles"].([]interface{}); ok3 {
					for _, f := range arr {
						if s, ok4 := f.(string); ok4 {
							out = append(out, s)
						}
					}
				}
			}
		}
	}
	return out
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// isMachO reports whether the file at path looks like a Mach-O binary.
func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	m := binary.BigEndian.Uint32(magic[:])
	switch m {
	case 0xcafebabe, 0xcafebabf:
		return true
	}
	le := binary.LittleEndian.Uint32(magic[:])
	be := binary.BigEndian.Uint32(magic[:])
	switch le {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	switch be {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}

// IsMachO exposes the magic check for other packages (e.g. CLI metadata).
func IsMachO(path string) bool { return isMachO(path) }
