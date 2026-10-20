// Package ipautil unpacks an IPA into a working directory and repacks it back.
package ipautil

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// UnzipIPA extracts src (an .ipa / zip) into dest. It returns the path to the
// .app bundle found inside (normally dest/Payload/xxx.app).
//
// Entries are extracted concurrently: each zip.File opens an independent
// section reader over the archive, so decompression and the writes to dest
// scale with the number of cores.
func UnzipIPA(src, dest string) (string, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", fmt.Errorf("open ipa: %w", err)
	}
	defer r.Close()

	type item struct {
		f      *zip.File
		target string
	}
	var items []item
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
		items = append(items, item{f: f, target: target})
	}

	if err := parallelFor(len(items), func(i int) error {
		return extractFile(items[i].f, items[i].target)
	}); err != nil {
		return "", err
	}

	// Locate the .app bundle.
	appPath := ""
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

// parallelFor runs fn(i) for i in [0,n) over a worker pool sized to the CPU
// count, returning the first error. It stops handing out new work once one
// call fails. Small workloads run inline.
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
					continue
				}
				if err := fn(i); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					cancel = true
					mu.Unlock()
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

// incompressibleExt lists asset types that are already compressed. Deflating
// them burns a lot of CPU for a rounding-error size win, so big files of these
// types are stored verbatim.
var incompressibleExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".heic": true, ".heif": true,
	".mp3": true, ".mp4": true, ".m4a": true, ".m4v": true, ".mov": true,
	".aac": true, ".wav": true, ".aiff": true, ".caf": true, ".flac": true,
	".zip": true, ".gz": true, ".bz2": true, ".xz": true, ".7z": true,
	".rar": true, ".br": true, ".woff": true, ".woff2": true, ".ttf": true,
	".otf": true, ".pdf": true,
}

// storeMinSize is the smallest file eligible for verbatim storage as an
// already-compressed asset.
const storeMinSize = 4 << 20

// spoolThreshold is the size above which a compressed entry is buffered in a
// temp file rather than in memory during the parallel compression pass.
const spoolThreshold = 1 << 20

// ZipDir recursively zips the contents of rootDir into outZip, mirroring the
// directory structure. level (0-9) controls deflate compression; use -1 for the
// default. Used to produce a new .ipa from a working Payload dir.
//
// The archive itself is a single sequential stream, but the expensive part --
// deflating each member -- is independent, so entries are compressed in
// parallel into per-entry buffers first and only then written out in order.
func ZipDir(rootDir, outZip string, level int) error {
	type entry struct {
		path  string
		rel   string
		info  os.FileInfo
		isDir bool
	}
	var entries []entry
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
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
		// Skip dot-entries at the archive root (e.g. the .ysign-cache dir);
		// an ipa may only carry Payload/ and friends.
		if strings.HasPrefix(rel, ".") && !strings.Contains(rel, "/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			// No directory entries in the archive: that matches zsign's
			// layout, and installd's zip handling is happiest without them.
			return nil
		}
		entries = append(entries, entry{path: path, rel: rel, info: info, isDir: false})
		return nil
	})
	if err != nil {
		return err
	}

	// --- Pass 1: compress every file member in parallel ---
	type prepared struct {
		hdr     *zip.FileHeader
		path    string // source file, needed again for stored entries
		buf     []byte // compressed bytes spooled in RAM
		tmpPath string // ...or the spool file when the entry is large
		isDir   bool
	}
	preparedEntries := make([]prepared, len(entries))
	spoolDir, err := os.MkdirTemp("", "ysign-zip")
	if err != nil {
		return err
	}
	defer os.RemoveAll(spoolDir)

	if err := parallelFor(len(entries), func(i int) error {
		e := entries[i]
		hdr, err := zip.FileInfoHeader(e.info)
		if err != nil {
			return err
		}
		hdr.Name = e.rel
		if e.isDir {
			hdr.SetMode(0755 | os.ModeDir)
			preparedEntries[i] = prepared{hdr: hdr, isDir: true}
			return nil
		}
		// iOS needs 0755 on executables (main binary, nested framework
		// binaries, dylibs) and 0644 on everything else. The on-disk mode
		// carries no permission bits on Windows, so decide from the Mach-O
		// magic rather than from the file name.
		if isExecutableFile(e.path, e.info) {
			hdr.SetMode(0755)
		} else {
			hdr.SetMode(0644)
		}
		// Already-compressed assets are stored verbatim: deflating them costs
		// real CPU time and gains almost nothing.
		if e.info.Size() >= storeMinSize &&
			incompressibleExt[strings.ToLower(filepath.Ext(e.path))] {
			hdr.Method = zip.Store
			preparedEntries[i] = prepared{hdr: hdr, path: e.path}
			return nil
		}

		hdr.Method = zip.Deflate
		src, err := os.Open(e.path)
		if err != nil {
			return err
		}
		defer src.Close()
		crc := crc32.NewIEEE()
		var dst io.Writer
		var tmp *os.File
		var mem bytes.Buffer
		if e.info.Size() > spoolThreshold {
			tmp, err = os.CreateTemp(spoolDir, "z")
			if err != nil {
				return err
			}
			defer tmp.Close()
			dst = tmp
		} else {
			mem.Grow(int(e.info.Size()) + 64)
			dst = &mem
		}
		fw, err := flate.NewWriter(dst, level)
		if err != nil {
			return err
		}
		if _, err := io.Copy(io.MultiWriter(fw, crc), src); err != nil {
			return err
		}
		if err := fw.Close(); err != nil {
			return err
		}
		hdr.CRC32 = crc.Sum32()
		var csize uint64
		if tmp != nil {
			st, err := tmp.Stat()
			if err != nil {
				return err
			}
			csize = uint64(st.Size())
		} else {
			csize = uint64(mem.Len())
		}
		// Deflating an already-compressed asset can grow it (PNG, media);
		// fall back to storing the original bytes verbatim instead.
		if csize >= uint64(e.info.Size()) {
			hdr.Method = zip.Store
			hdr.CRC32 = 0
			hdr.CompressedSize64 = 0
			preparedEntries[i] = prepared{hdr: hdr, path: e.path}
			return nil
		}
		// CreateRaw needs the final sizes up front.
		hdr.CompressedSize64 = csize
		if tmp != nil {
			preparedEntries[i] = prepared{hdr: hdr, path: e.path, tmpPath: tmp.Name()}
			return nil
		}
		preparedEntries[i] = prepared{hdr: hdr, path: e.path, buf: mem.Bytes()}
		return nil
	}); err != nil {
		return err
	}

	// --- Pass 2: write the members out in walk order ---
	out, err := os.Create(outZip)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	for _, p := range preparedEntries {
		var w io.Writer
		if p.isDir {
			if _, err := zw.CreateHeader(p.hdr); err != nil {
				_ = zw.Close()
				return err
			}
			continue
		}
		if p.hdr.Method == zip.Store {
			// Let the zip writer copy the bytes and compute the CRC itself.
			w, err = zw.CreateHeader(p.hdr)
		} else {
			// Bytes are already deflated; hand them over verbatim.
			w, err = zw.CreateRaw(p.hdr)
		}
		if err != nil {
			_ = zw.Close()
			return err
		}
		if p.hdr.Method == zip.Store || p.tmpPath != "" {
			src := p.path
			if p.tmpPath != "" {
				src = p.tmpPath
			}
			f, err := os.Open(src)
			if err != nil {
				_ = zw.Close()
				return err
			}
			_, err = io.Copy(w, f)
			f.Close()
			if err != nil {
				_ = zw.Close()
				return err
			}
			continue
		}
		if _, err := w.Write(p.buf); err != nil {
			_ = zw.Close()
			return err
		}
	}
	// Close writes the central directory; its error must be reported, otherwise
	// a truncated archive is reported as a successful repack.
	return zw.Close()
}

// isExecutableFile reports whether path should be stored with the executable
// bit set: any Mach-O image (thin or fat), plus whatever the filesystem
// already marks executable (meaningful on Unix).
func isExecutableFile(path string, info os.FileInfo) bool {
	if info.IsDir() {
		return false
	}
	if info.Mode().Perm()&0o111 != 0 {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return isMachOMagic(magic)
}

func isMachOMagic(m [4]byte) bool {
	be := binary.BigEndian.Uint32(m[:])
	if be == 0xcafebabe || be == 0xcafebabf { // fat
		return true
	}
	switch binary.LittleEndian.Uint32(m[:]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}
