// Package plistutil wraps plist read/write for Info.plist and entitlements.
package plistutil

import (
	"bytes"
	"errors"
	"fmt"

	"howett.net/plist"
)

// Decode parses a plist (XML or binary) into a generic map.
func Decode(data []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode plist: %w", err)
	}
	return m, nil
}

// EncodeXML serializes a map to an XML plist (UTF-8, with XML header).
func EncodeXML(m map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := plist.NewEncoder(&buf)
	enc.Indent("\t")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encode plist: %w", err)
	}
	return buf.Bytes(), nil
}

// GetString returns a string value at key, or "" if missing/non-string.
func GetString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetInt returns an int64 value at key (plist integers decode as uint64 or int).
func GetInt(m map[string]interface{}, key string) int64 {
	switch v := m[key].(type) {
	case uint64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

// Set sets a value at key, returning an error if the key exists with a
// different type (to avoid silently mangling Info.plist).
func Set(m map[string]interface{}, key string, value interface{}) {
	m[key] = value
}

// ReadBundleID pulls CFBundleIdentifier from an Info.plist map.
func ReadBundleID(info map[string]interface{}) string {
	return GetString(info, "CFBundleIdentifier")
}

// ReadBundleName pulls CFBundleName from an Info.plist map.
func ReadBundleName(info map[string]interface{}) string {
	if v := GetString(info, "CFBundleName"); v != "" {
		return v
	}
	return GetString(info, "CFBundleDisplayName")
}

// SetBundleID replaces CFBundleIdentifier.
func SetBundleID(info map[string]interface{}, bundleID string) error {
	if bundleID == "" {
		return errors.New("bundle id must not be empty")
	}
	Set(info, "CFBundleIdentifier", bundleID)
	return nil
}
