// Command ysign is a fast, cross-platform iOS code-signing / re-signing tool
// modeled after zsign. It can sign and re-sign .ipa and .app bundles with a
// custom certificate and provisioning profile, without Xcode or macOS.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ysign/internal/inspect"
	"ysign/internal/ipautil"
	"ysign/internal/resign"
	"ysign/internal/signing"
)

type stringList []string

// version is bumped on releases; it is also injected by the build workflow.
var version = "1.0.0"

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		k                string
		m                stringList
		c                string
		a, f             bool
		o                string
		p                string
		b, n, r, e       string
		icon             string
		z                int
		l, d, w          stringList
		install          bool
		t                string
		sha256Only       bool
		check            bool
		metadata         string
		R, S, E, W, U, P bool
		M                string
		q, debug, showV  bool
	)
	fs := flag.NewFlagSet("ysign", flag.ExitOnError)
	fs.StringVar(&k, "k", "", "Path to private key or p12 file")
	fs.StringVar(&k, "pkey", "", "Path to private key or p12 file")
	fs.Var(&m, "m", "Path to provisioning profile (repeat for extensions)")
	fs.Var(&m, "prov", "Path to provisioning profile (repeat for extensions)")
	fs.StringVar(&c, "c", "", "Path to certificate file (PEM or DER)")
	fs.StringVar(&c, "cert", "", "Path to certificate file (PEM or DER)")
	fs.BoolVar(&a, "a", false, "Ad-hoc signature (no certificate)")
	fs.BoolVar(&a, "adhoc", false, "Ad-hoc signature (no certificate)")
	fs.BoolVar(&f, "f", false, "Force sign without cache")
	fs.BoolVar(&f, "force", false, "Force sign without cache")
	fs.StringVar(&o, "o", "", "Output ipa path")
	fs.StringVar(&o, "output", "", "Output ipa path")
	fs.StringVar(&p, "p", "", "Password for private key or p12 file")
	fs.StringVar(&p, "password", "", "Password for private key or p12 file")
	fs.StringVar(&b, "b", "", "New bundle identifier")
	fs.StringVar(&b, "bundle_id", "", "New bundle identifier")
	fs.StringVar(&n, "n", "", "New bundle display name")
	fs.StringVar(&n, "bundle_name", "", "New bundle display name")
	fs.StringVar(&r, "r", "", "New bundle version")
	fs.StringVar(&r, "bundle_version", "", "New bundle version")
	fs.StringVar(&e, "e", "", "New entitlements plist file")
	fs.StringVar(&e, "entitlements", "", "New entitlements plist file")
	fs.StringVar(&icon, "I", "", "New app icon (PNG)")
	fs.StringVar(&icon, "icon", "", "New app icon (PNG)")
	fs.IntVar(&z, "z", 6, "Compression level for output ipa (0-9)")
	fs.IntVar(&z, "zip_level", 6, "Compression level for output ipa (0-9)")
	fs.Var(&l, "l", "Dylib to inject (repeatable)")
	fs.Var(&l, "dylib", "Dylib to inject (repeatable)")
	fs.Var(&d, "D", "Dylib to remove (repeatable)")
	fs.Var(&d, "rm_dylib", "Dylib to remove (repeatable)")
	fs.Var(&w, "w", "Inject dylib as weak (repeatable)")
	fs.Var(&w, "weak", "Inject dylib as weak (repeatable)")
	fs.BoolVar(&install, "i", false, "Install via ideviceinstaller after signing")
	fs.BoolVar(&install, "install", false, "Install via ideviceinstaller after signing")
	fs.StringVar(&t, "t", "", "Temp folder for intermediate files")
	fs.StringVar(&t, "temp_folder", "", "Temp folder for intermediate files")
	fs.BoolVar(&sha256Only, "2", false, "Use SHA256-only code directory")
	fs.BoolVar(&sha256Only, "sha256_only", false, "Use SHA256-only code directory")
	fs.BoolVar(&check, "C", false, "Check certificate / signature")
	fs.BoolVar(&check, "check", false, "Check certificate / signature")
	fs.StringVar(&metadata, "x", "", "Extract metadata and icon to directory")
	fs.StringVar(&metadata, "metadata", "", "Extract metadata and icon to directory")
	fs.BoolVar(&R, "R", false, "Remove provisioning profile after signing")
	fs.BoolVar(&R, "rm_provision", false, "Remove provisioning profile after signing")
	fs.BoolVar(&S, "S", false, "Enable UISupportsDocumentBrowser / UIFileSharingEnabled")
	fs.BoolVar(&S, "enable_docs", false, "Enable UISupportsDocumentBrowser / UIFileSharingEnabled")
	fs.StringVar(&M, "M", "", "Set MinimumOSVersion in Info.plist")
	fs.StringVar(&M, "min_version", "", "Set MinimumOSVersion in Info.plist")
	fs.BoolVar(&E, "E", false, "Remove all app extensions (PlugIns)")
	fs.BoolVar(&E, "rm_extensions", false, "Remove all app extensions (PlugIns)")
	fs.BoolVar(&W, "W", false, "Remove watch app")
	fs.BoolVar(&W, "rm_watch", false, "Remove watch app")
	fs.BoolVar(&U, "U", false, "Remove UISupportedDevices")
	fs.BoolVar(&U, "rm_uisd", false, "Remove UISupportedDevices")
	fs.BoolVar(&P, "P", false, "Also inject dylibs into extensions")
	fs.BoolVar(&P, "inject_extensions", false, "Also inject dylibs into extensions")
	fs.BoolVar(&q, "q", false, "Quiet operation")
	fs.BoolVar(&q, "quiet", false, "Quiet operation")
	fs.BoolVar(&debug, "d", false, "Keep intermediate files and print the work directory")
	fs.BoolVar(&debug, "debug", false, "Keep intermediate files and print the work directory")
	fs.BoolVar(&showV, "v", false, "Show version")
	fs.BoolVar(&showV, "version", false, "Show version")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `ysign - fast cross-platform iOS code signing tool (zsign-compatible)

Usage: ysign [-options] [-k privkey.pem] [-m dev.prov] [-o output.ipa] file|folder

Options:
  -k, --pkey           Path to private key or p12 file
  -m, --prov           Path to provisioning profile (repeat for extensions)
  -c, --cert           Path to certificate file (PEM or DER)
  -a, --adhoc          Perform ad-hoc signature only
  -d, --debug          Keep intermediate files and print the work directory
  -f, --force          Force sign without cache
  -o, --output         Path to output ipa file
  -p, --password       Password for private key or p12 file
  -b, --bundle_id      New bundle identifier
  -n, --bundle_name    New bundle display name
  -r, --bundle_version New bundle version
  -e, --entitlements   New entitlements file
  -I, --icon           New app icon (PNG)
  -z, --zip_level      Compression level (0-9)
  -l, --dylib          Dylib to inject (repeatable)
  -D, --rm_dylib       Dylib to remove (repeatable)
  -w, --weak           Inject dylib as weak (repeatable)
  -i, --install        Install via ideviceinstaller after signing
  -t, --temp_folder    Temp folder for intermediate files
  -2, --sha256_only    Force SHA256-only code directory
  -C, --check          Check certificate / signature
  -x, --metadata       Extract metadata and icon to directory
  -R, --rm_provision   Remove provisioning profile after signing
  -S, --enable_docs    Enable UISupportsDocumentBrowser / UIFileSharingEnabled
  -M, --min_version    Set MinimumOSVersion in Info.plist
  -E, --rm_extensions  Remove all app extensions (PlugIns)
  -W, --rm_watch       Remove watch app
  -U, --rm_uisd        Remove UISupportedDevices
  -P, --inject_extensions Also inject dylibs into extensions
  -q, --quiet          Quiet operation
  -v, --version        Show version
  -h, --help           Show help
`)
	}
	fs.Parse(os.Args[1:])
	if showV {
		fmt.Printf("ysign %s\n", version)
		return
	}
	args := fs.Args()
	if len(args) < 1 {
		fs.Usage()
		os.Exit(2)
	}
	input := args[0]

	// Check mode. When signing is also requested (e.g. -C -k ... -m ... -o ...),
	// verify the certificate / signature first, then continue to sign.
	if check {
		report, err := inspect.CheckFile(input, p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "check:", err)
			os.Exit(1)
		}
		fmt.Println(report)
		if k == "" && !a {
			return
		}
	}

	// Metadata mode.
	if metadata != "" {
		appDir, err := resolveAppDir(input, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "metadata:", err)
			os.Exit(1)
		}
		msg, err := inspect.ExtractMetadata(appDir, metadata)
		if err != nil {
			fmt.Fprintln(os.Stderr, "metadata:", err)
			os.Exit(1)
		}
		fmt.Println(msg)
		return
	}

	// Sign mode.
	var signer *signing.Signer
	if !a {
		if k == "" {
			fmt.Fprintln(os.Stderr, "error: signing requires -k (p12/pem key); use -a for ad-hoc or -C to check")
			os.Exit(2)
		}
		var err error
		if strings.HasSuffix(strings.ToLower(k), ".p12") || strings.HasSuffix(strings.ToLower(k), ".pfx") {
			signer, err = signing.LoadP12(k, p)
		} else if c != "" {
			signer, err = signing.LoadPEM(k, c)
		} else {
			fmt.Fprintln(os.Stderr, "error: -k key needs a matching -c cert file (or use a .p12)")
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "load identity:", err)
			os.Exit(1)
		}
	}

	cacheDir := t
	if cacheDir == "" {
		cd, _ := os.MkdirTemp("", "ysign-cache-")
		cacheDir = cd
	}

	workDir, cleanup, err := makeWorkDir(t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "workdir:", err)
		os.Exit(1)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "debug: workdir=%s (kept)\n", workDir)
	} else {
		defer cleanup()
	}

	appDir, err := resolveAppDir(input, workDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	opts := &resign.Options{
		BundleID:           b,
		BundleName:         n,
		BundleVersion:      r,
		MinOSVersion:       M,
		EntitlementsFile:   e,
		IconFile:           icon,
		AdHoc:              a,
		Force:              f,
		Quiet:              q,
		CacheDir:           cacheDir,
		ForceSHA256:        sha256Only,
		EnableDocs:         S,
		RemoveExtensions:   E,
		RemoveWatch:        W,
		RemoveUISD:         U,
		RemoveProvision:    R,
		Signer:             signer,
		InjectDylibs:       l,
		RemoveDylibs:       d,
		WeakDylibs:         w,
		InjectToExtensions: P,
		ExtProfiles:        m,
	}
	if err := resign.Resign(appDir, opts); err != nil {
		fmt.Fprintln(os.Stderr, "resign:", err)
		os.Exit(1)
	}

	// Repack to ipa.
	out := o
	if out == "" {
		base := filepath.Base(appDir)
		base = strings.TrimSuffix(base, ".app")
		out = base + "-ysign.ipa"
	}
	if z < 0 {
		z = 0
	}
	if z > 9 {
		z = 9
	}
	zipRoot := workDir
	if err := ipautil.ZipDir(zipRoot, out, z); err != nil {
		fmt.Fprintln(os.Stderr, "repack:", err)
		os.Exit(1)
	}
	if !q {
		// Print "Signed OK" for drop-in compatibility with scripts that grep the
		// output (e.g. PHP strstr($out, "Signed OK")) — this is what most
		// production sign-portal deployments of zsign rely on.
		fmt.Printf("Signed OK: %s\n", out)
	}
	if install {
		if err := runInstall(out); err != nil {
			fmt.Fprintln(os.Stderr, "install:", err)
		}
	}
}

// makeWorkDir returns a working directory and a cleanup function.
func makeWorkDir(t string) (string, func(), error) {
	if t != "" {
		if err := os.MkdirAll(t, 0o755); err != nil {
			return "", nil, err
		}
		return t, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "ysign-work-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// resolveAppDir produces a .app bundle path ready for signing. For a .ipa it
// unpacks into workDir and returns the Payload/*.app path. For a .app dir it
// copies into workDir/Payload. For a Payload dir it finds the .app inside.
func resolveAppDir(input, workDir string) (string, error) {
	low := strings.ToLower(input)
	switch {
	case strings.HasSuffix(low, ".ipa"):
		if workDir == "" {
			return "", fmt.Errorf("workdir required for ipa input")
		}
		return ipautil.UnzipIPA(input, workDir)
	case strings.HasSuffix(low, ".app"):
		if workDir == "" {
			return input, nil // operate in place
		}
		target := filepath.Join(workDir, "Payload", filepath.Base(input))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		if err := copyDir(input, target); err != nil {
			return "", err
		}
		return target, nil
	default:
		// A directory containing Payload/xxx.app.
		if workDir == "" {
			return findAppInDir(input)
		}
		target := filepath.Join(workDir, "Payload")
		if err := copyDir(input, target); err != nil {
			return "", err
		}
		return findAppInDir(target)
	}
}

func findAppInDir(dir string) (string, error) {
	payload := filepath.Join(dir, "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil {
		return "", fmt.Errorf("no Payload directory in %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".app") {
			return filepath.Join(payload, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no .app bundle under %s", payload)
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyFile(target, path)
	})
}

func copyFile(dst, src string) error {
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

func runInstall(ipa string) error {
	cmd := exec.Command("ideviceinstaller", "-i", ipa)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
