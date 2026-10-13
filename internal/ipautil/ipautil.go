// Package ipautil unpacks an IPA into a working directory and repacks it back.
package ipautil

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// UnzipIPA extracts src (an .ipa / zip) into dest. It returns the path to the
// .app bundle found inside (normally dest/Payload/xxx.app).
func UnzipIPA(src, dest string) (string, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", fmt.Errorf("open ipa: %w", err)
	}
	defer r.Close()

	var appPath string
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		// Zip-slip protection.
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)+string(os.PathSeparator)) {
			return "", fmt.Errorf("illegal path in archive: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		if err := extractFile(f, target); err != nil {
			return "", err
		}
		// Track the .app directory.
		if strings.HasSuffix(strings.ToLower(f.Name), ".app/") ||
			(filepath.Ext(f.Name) == "" && strings.Contains(f.Name, ".app/")) {
			// handled below
		}
	}

	// Locate the .app bundle.
	payload := filepath.Join(dest, "Payload")
	entries, err := os.ReadDir(payload)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".app") {
				appPath = filepath.Join(payload, e.Name())
				break
			}
		}
	}
	if appPath == "" {
		return "", errors.New("no .app bundle found under Payload/")
	}
	return appPath, nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return err
	}
	return nil
}

// ZipDir recursively zips the contents of rootDir into outZip, mirroring the
// directory structure. level (0-9) controls deflate compression; use -1 for the
// default. Used to produce a new .ipa from a working Payload dir.
func ZipDir(rootDir, outZip string, level int) error {
	out, err := os.Create(outZip)
	if err != nil {
		return err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()
	if level >= 0 && level <= 9 {
		zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, level)
		})
	}

	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			rel += "/"
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = rel
		if info.IsDir() {
			hdr.Name = rel
			hdr.SetMode(0755 | os.ModeDir)
		} else {
			hdr.Method = zip.Deflate
			// Match iOS expectations: main executable is 0755, others 0644.
			// Go's zip.FileInfoHeader on Windows produces 0666, which iOS rejects.
			base := filepath.Base(rel)
			ext := filepath.Ext(base)
			// Main executable: no extension, directly inside .app, and not PkgInfo
			if ext == "" && strings.HasSuffix(rel, ".app/"+base) && base != "PkgInfo" && base != "SignedByEsign" {
				hdr.SetMode(0755)
			} else {
				hdr.SetMode(0644)
			}
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
	return err
}
