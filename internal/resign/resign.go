// Package resign orchestrates re-signing an extracted .app bundle.
package resign

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

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
	// ForceSHA256 (from -2/--sha256_only) rebuilds every CodeDirectory with a
	// SHA-256 hash type instead of inheriting the original binary's hash type.
	ForceSHA256 bool
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
		// Skip the Apple Watch stub: re-signing it triggers
		// InvalidStubExecutableError during install (matches upstream zsign).
		if filepath.Base(path) == "_WatchKitStub" {
			return nil
		}
		if isMachO(path) {
			binaries = append(binaries, path)
		}
		return nil
	}); err != nil {
		return err
	}

	isMainBin := func(bin string) bool { return bin == mainPath }
	// A binary receives dylib injection when it is the main executable, or when
	// -P injects into every binary (extensions included).
	injectAllowed := func(isMain bool) bool { return isMain || opts.InjectToExtensions }

	// Pre-copy injected dylibs into their target directories sequentially so the
	// parallel signing pass never races writing the same destination file.
	isFileDylib := make(map[string]bool, len(opts.InjectDylibs))
	if len(opts.InjectDylibs) > 0 {
		copied := make(map[string]bool)
		for _, bin := range binaries {
			if !injectAllowed(isMainBin(bin)) {
				continue
			}
			for _, d := range opts.InjectDylibs {
				if st, err := os.Stat(d); err == nil && !st.IsDir() {
					dest := filepath.Join(filepath.Dir(bin), filepath.Base(d))
					if !copied[dest] {
						if err := copyFile(d, dest); err != nil {
							return err
						}
						copied[dest] = true
					}
					isFileDylib[d] = true
				}
			}
		}
	}

	// signOne re-signs a single binary in place. Every input it needs is
	// precomputed above, so it is safe to run concurrently.
	signOne := func(bin string, isMain bool) error {
		data, err := os.ReadFile(bin)
		if err != nil {
			return err
		}
		for _, d := range opts.InjectDylibs {
			if !injectAllowed(isMain) {
				break
			}
			loadPath := d
			if isFileDylib[d] {
				loadPath = "@executable_path/" + filepath.Base(d)
			}
			weak := containsString(opts.WeakDylibs, d)
			data, err = macho.AddLoadDylib(data, loadPath, weak)
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
				Cache: cache, Signer: opts.Signer, ForceSHA256: opts.ForceSHA256,
				InfoPlist: infoBytes, EntitlementsXML: entitlementsXML,
				KeepAllSpecialHashes: false,
			}
		} else if extCtx := extCtxFor(bin, extProfiles, cache, opts); extCtx != nil {
			extCtx.ForceSHA256 = opts.ForceSHA256
			ctx = extCtx
		} else {
			ctx = &signContext{
				BundleID: bundleID, TeamID: teamID, AdHoc: opts.AdHoc, Force: opts.Force,
				Cache: cache, Signer: opts.Signer, ForceSHA256: opts.ForceSHA256,
				KeepAllSpecialHashes: true,
			}
		}
		// For -2/--sha256_only, special slots -1/-3 are recomputed from the owning
		// bundle's Info.plist and CodeResources, so gather those file bytes.
		if bdir := owningBundle(bin); bdir != "" {
			if b, err := os.ReadFile(filepath.Join(bdir, "Info.plist")); err == nil {
				ctx.SpecialInfoPlist = b
			}
			if b, err := os.ReadFile(filepath.Join(bdir, "CodeResources")); err == nil {
				ctx.SpecialCodeResources = b
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
		return nil
	}

	// Split binaries into main executable vs. the rest. The main binary is
	// signed LAST, after CodeResources has been generated, because the Code
	// Directory's special slot -3 seals the exact bytes of CodeResources.
	var mainBin string
	var others []string
	for _, b := range binaries {
		if b == mainPath {
			mainBin = b
		} else {
			others = append(others, b)
		}
	}

	// Sign all non-main binaries in parallel.
	if err := parallelFor(len(others), func(i int) error {
		return signOne(others[i], false)
	}); err != nil {
		return err
	}

	// Build _CodeSignature/CodeResources: seal hashes of every resource file in
	// the bundle. This MUST happen after all other binaries are signed (their
	// bytes are hashed into CodeResources) and BEFORE the main binary is signed
	// (CodeResources bytes are sealed into the main binary's special slot -3).
	crData, err := generateCodeResources(appDir, mainName, opts.RemoveProvision)
	if err != nil {
		return fmt.Errorf("generate CodeResources: %w", err)
	}
	csDir := filepath.Join(appDir, "_CodeSignature")
	if err := os.MkdirAll(csDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(csDir, "CodeResources"), crData, 0o644); err != nil {
		return err
	}

	// Sign the main executable last, feeding it the freshly generated
	// CodeResources bytes for special slot -3.
	if mainBin != "" {
		data, err := os.ReadFile(mainBin)
		if err != nil {
			return err
		}
		for _, d := range opts.InjectDylibs {
			loadPath := d
			if isFileDylib[d] {
				loadPath = "@executable_path/" + filepath.Base(d)
			}
			weak := containsString(opts.WeakDylibs, d)
			data, err = macho.AddLoadDylib(data, loadPath, weak)
			if err != nil {
				return fmt.Errorf("inject dylib %s into %s: %w", d, filepath.Base(mainBin), err)
			}
		}
		for _, d := range opts.RemoveDylibs {
			data, err = macho.RemoveLoadDylib(data, d)
			if err != nil {
				return fmt.Errorf("remove dylib %s from %s: %w", d, filepath.Base(mainBin), err)
			}
		}
		ctx := &signContext{
			BundleID: bundleID, TeamID: teamID, AdHoc: opts.AdHoc, Force: opts.Force,
			Cache: cache, Signer: opts.Signer, ForceSHA256: opts.ForceSHA256,
			InfoPlist: infoBytes, EntitlementsXML: entitlementsXML,
			KeepAllSpecialHashes: false,
			SpecialInfoPlist:     infoBytes,
			SpecialCodeResources: crData,
		}
		out, err := rebuildBinary(data, ctx)
		if err != nil {
			return fmt.Errorf("re-sign %s: %w", filepath.Base(mainBin), err)
		}
		if err := os.WriteFile(mainBin, out, 0o755); err != nil {
			return err
		}
		logf(opts, "signed main: %s", filepath.Base(mainBin))
	}
	logf(opts, "re-signed %d binary(ies), bundle id=%s team=%s adhoc=%v", len(binaries), bundleID, teamID, opts.AdHoc)
	return nil
}

// parallelFor runs fn(i) for i in [0,n) across a bounded worker pool sized to
// the number of CPUs, returning the first non-nil error. When only one worker
// is needed it runs inline to avoid goroutine overhead.
func parallelFor(n int, fn func(int) error) error {
	if n <= 0 {
		return nil
	}
	workers := runtime.NumCPU()
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	if workers == 1 {
		for i := 0; i < n; i++ {
			if err := fn(i); err != nil {
				return err
			}
		}
		return nil
	}
	jobs := make(chan int)
	var (
		mu     sync.Mutex
		first  error
		cancel bool
		wg     sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				mu.Lock()
				stopped := cancel
				mu.Unlock()
				if stopped {
					return
				}
				if err := fn(i); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					cancel = true
					mu.Unlock()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := 0; i < n; i++ {
			mu.Lock()
			stopped := cancel
			mu.Unlock()
			if stopped {
				return
			}
			jobs <- i
		}
	}()
	wg.Wait()
	return first
}

// owningBundle returns the nearest enclosing bundle directory (.app, .appex,
// .framework or .bundle) for a binary path, or the binary's own directory.
func owningBundle(bin string) string {
	d := filepath.Dir(bin)
	for {
		low := strings.ToLower(filepath.Base(d))
		if strings.HasSuffix(low, ".app") || strings.HasSuffix(low, ".appex") ||
			strings.HasSuffix(low, ".framework") || strings.HasSuffix(low, ".bundle") {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return filepath.Dir(bin)
		}
		d = parent
	}
}

// copyFile copies src to dst.
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
		// Match zsign: use profile entitlements verbatim, do NOT rewrite
		// application-identifier / keychain-access-groups from bundleID.
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

// generateCodeResources builds the _CodeSignature/CodeResources XML plist for
// the given .app bundle, mirroring the layout produced by upstream zsign. It
// seals the SHA-1/SHA-256 hash of every non-excluded resource file. The caller
// writes the returned bytes to <app>/_CodeSignature/CodeResources and then
// re-signs the main binary so special slot -3 seals these exact bytes.
func generateCodeResources(appDir, mainExe string, removeProvision bool) ([]byte, error) {
	// Collect all files (relative, slash-separated), sorted for deterministic output.
	var files []string
	if err := filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(appDir, path)
		if err != nil {
			return nil
		}
		rel = strings.ReplaceAll(rel, "\\", "/")
		files = append(files, rel)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)

	// Exclude the seal file itself and the main executable.
	keep := make([]string, 0, len(files))
	for _, f := range files {
		if f == "_CodeSignature/CodeResources" || f == mainExe {
			continue
		}
		keep = append(keep, f)
	}

	sha1B64 := func(path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		s := sha1.Sum(b)
		return base64.StdEncoding.EncodeToString(s[:]), nil
	}
	sha256B64 := func(path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		s := sha256.Sum256(b)
		return base64.StdEncoding.EncodeToString(s[:]), nil
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>files</key>
	<dict>
`)
	for _, rel := range keep {
		full := filepath.Join(appDir, filepath.FromSlash(rel))
		// locversion.plist inside any .lproj is omitted entirely.
		if strings.HasSuffix(rel, ".lproj/locversion.plist") {
			continue
		}
		if removeProvision && rel == "embedded.mobileprovision" {
			continue
		}
		h1, err := sha1B64(full)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "\t\t<key>%s</key>\n", xmlEscape(rel))
		if strings.Contains(rel, ".lproj/") {
			b.WriteString("\t\t<dict>\n")
			fmt.Fprintf(&b, "\t\t\t<key>hash</key><data>%s</data>\n", h1)
			b.WriteString("\t\t\t<key>optional</key><true/>\n")
			b.WriteString("\t\t</dict>\n")
		} else {
			fmt.Fprintf(&b, "\t\t<data>%s</data>\n", h1)
		}
	}
	b.WriteString("\t</dict>\n")

	b.WriteString("\t<key>files2</key>\n\t<dict>\n")
	for _, rel := range keep {
		full := filepath.Join(appDir, filepath.FromSlash(rel))
		if strings.HasSuffix(rel, ".lproj/locversion.plist") {
			continue
		}
		// Info.plist, PkgInfo and .DS_Store are sealed only in files (SHA-1), not files2.
		if rel == "Info.plist" || rel == "PkgInfo" || strings.HasSuffix(rel, ".DS_Store") {
			continue
		}
		if removeProvision && rel == "embedded.mobileprovision" {
			continue
		}
		h1, err := sha1B64(full)
		if err != nil {
			return nil, err
		}
		h256, err := sha256B64(full)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "\t\t<key>%s</key>\n\t\t<dict>\n", xmlEscape(rel))
		fmt.Fprintf(&b, "\t\t\t<key>hash</key><data>%s</data>\n", h1)
		fmt.Fprintf(&b, "\t\t\t<key>hash2</key><data>%s</data>\n", h256)
		if strings.Contains(rel, ".lproj/") {
			b.WriteString("\t\t\t<key>optional</key><true/>\n")
		}
		b.WriteString("\t\t</dict>\n")
	}
	b.WriteString("\t</dict>\n")

	// Fixed rules / rules2 blocks, identical to upstream zsign output.
	b.WriteString(`	<key>rules</key>
	<dict>
		<key>^.*</key><true/>
		<key>^.*\.lproj/</key>
		<dict><key>optional</key><true/><key>weight</key><real>1000</real></dict>
		<key>^.*\.lproj/locversion.plist$</key>
		<dict><key>omit</key><true/><key>weight</key><real>1100</real></dict>
		<key>^Base\.lproj/</key>
		<dict><key>weight</key><real>1010</real></dict>
		<key>^version.plist$</key><true/>
	</dict>
	<key>rules2</key>
	<dict>
		<key>.*\.dSYM($|/)</key>
		<dict><key>weight</key><real>11</real></dict>
		<key>^(.*/)?\.DS_Store$</key>
		<dict><key>omit</key><true/><key>weight</key><real>2000</real></dict>
		<key>^.*</key><true/>
		<key>^.*\.lproj/</key>
		<dict><key>optional</key><true/><key>weight</key><real>1000</real></dict>
		<key>^.*\.lproj/locversion.plist$</key>
		<dict><key>omit</key><true/><key>weight</key><real>1100</real></dict>
		<key>^Base\.lproj/</key>
		<dict><key>weight</key><real>1010</real></dict>
		<key>^Info\.plist$</key>
		<dict><key>omit</key><true/><key>weight</key><real>20</real></dict>
		<key>^PkgInfo$</key>
		<dict><key>omit</key><true/><key>weight</key><real>20</real></dict>
		<key>^embedded\.provisionprofile$</key>
		<dict><key>weight</key><real>20</real></dict>
		<key>^version\.plist$</key>
		<dict><key>weight</key><real>20</real></dict>
	</dict>
</dict>
</plist>
`)
	return []byte(b.String()), nil
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
