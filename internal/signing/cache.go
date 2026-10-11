package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// DiskCache is a simple content-addressed key/value cache on disk, used to
// make repeated re-signing fast: unchanged Mach-O page hashes and unchanged
// CodeDirectory CMS signatures are reused instead of recomputed.
type DiskCache struct {
	dir string
}

// NewDiskCache creates (if needed) a cache directory.
func NewDiskCache(dir string) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &DiskCache{dir: dir}, nil
}

// Key computes a cache key for a payload.
func Key(payload []byte) string {
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:])
}

// Get returns the cached value for key, or ok=false.
func (c *DiskCache) Get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(c.dir, key))
	if err != nil {
		return nil, false
	}
	return data, true
}

// Set stores value under key.
func (c *DiskCache) Set(key string, value []byte) error {
	if c == nil {
		return nil
	}
	tmp := filepath.Join(c.dir, key+".tmp")
	if err := os.WriteFile(tmp, value, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.dir, key))
}

// Purge deletes all cached entries.
func (c *DiskCache) Purge() error {
	if c == nil {
		return nil
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(c.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
