// Package plistutil wraps plist read/write for Info.plist and entitlements.
package plistutil

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

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

// EncodeXML serializes a map to an XML plist in the exact CFPropertyList
// (plutil) style that Apple's codesign and zsign produce: the root element is
// NOT indented, children are indented one tab per level, <data> payloads are
// placed on their own line, and dictionary keys are emitted in ASCII order.
func EncodeXML(m map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	if err := writeValue(&buf, m, 0); err != nil {
		return nil, err
	}
	buf.WriteString("</plist>\n")
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v interface{}, depth int) error {
	ind := strings.Repeat("\t", depth)
	switch t := v.(type) {
	case map[string]interface{}:
		if len(t) == 0 {
			buf.WriteString(ind + "<dict/>\n")
			return nil
		}
		buf.WriteString(ind + "<dict>\n")
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteString(ind + "\t<key>" + escapeXML(k) + "</key>\n")
			if err := writeValue(buf, t[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteString(ind + "</dict>\n")
	case []interface{}:
		if len(t) == 0 {
			buf.WriteString(ind + "<array/>\n")
			return nil
		}
		buf.WriteString(ind + "<array>\n")
		for _, e := range t {
			if err := writeValue(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteString(ind + "</array>\n")
	case []string:
		if len(t) == 0 {
			buf.WriteString(ind + "<array/>\n")
			return nil
		}
		buf.WriteString(ind + "<array>\n")
		for _, e := range t {
			buf.WriteString(ind + "\t<string>" + escapeXML(e) + "</string>\n")
		}
		buf.WriteString(ind + "</array>\n")
	case string:
		buf.WriteString(ind + "<string>" + escapeXML(t) + "</string>\n")
	case bool:
		if t {
			buf.WriteString(ind + "<true/>\n")
		} else {
			buf.WriteString(ind + "<false/>\n")
		}
	case uint64:
		buf.WriteString(ind + "<integer>" + strconv.FormatUint(t, 10) + "</integer>\n")
	case int:
		buf.WriteString(ind + "<integer>" + strconv.Itoa(t) + "</integer>\n")
	case int64:
		buf.WriteString(ind + "<integer>" + strconv.FormatInt(t, 10) + "</integer>\n")
	case float64:
		// plutil prints integral reals without a trailing .0? It prints them as
		// e.g. <real>1000</real> (integral) or <real>1000.5</real>.
		buf.WriteString(ind + "<real>" + formatReal(t) + "</real>\n")
	case []byte:
		b64 := base64.StdEncoding.EncodeToString(t)
		buf.WriteString(ind + "<data>\n" + ind + "\t" + b64 + "\n" + ind + "</data>\n")
	default:
		return fmt.Errorf("unsupported plist value type %T", v)
	}
	return nil
}

func formatReal(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
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

// Set replaces the value at key.
func Set(m map[string]interface{}, key string, value interface{}) {
	m[key] = value
}

// Remove deletes key (and its value) from the plist map.
func Remove(m map[string]interface{}, key string) {
	delete(m, key)
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
