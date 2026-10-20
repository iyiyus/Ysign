package signing

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"howett.net/plist"
)

// Provision represents a parsed .mobileprovision profile.
type Provision struct {
	UUID                  string
	Name                  string
	TeamIdentifiers       []string
	AppIdentifierPrefixes []string
	ExpirationDate        time.Time
	ProvisionsAllDevices  bool
	ProvisionedDevices    []string
	Entitlements          map[string]interface{}
	DeveloperCertificates []*x509.Certificate
	// AppIdentifier is prefix.bundleID as encoded in the profile.
	AppIdentifier string
}

// ParseProvision parses a DER-encoded mobileprovision (a CMS SignedData whose
// content is an XML plist).
func ParseProvision(der []byte) (*Provision, error) {
	content, err := ParseCMSContent(der)
	if err != nil {
		return nil, fmt.Errorf("parse mobileprovision CMS: %w", err)
	}
	var m map[string]interface{}
	if _, err := plist.Unmarshal(content, &m); err != nil {
		return nil, fmt.Errorf("decode mobileprovision plist: %w", err)
	}
	p := &Provision{}
	if v, ok := m["UUID"]; ok {
		p.UUID, _ = v.(string)
	}
	if v, ok := m["Name"]; ok {
		p.Name, _ = v.(string)
	}
	p.TeamIdentifiers = toStringSlice(m["TeamIdentifier"])
	p.AppIdentifierPrefixes = toStringSlice(m["ApplicationIdentifierPrefix"])
	if v, ok := m["ExpirationDate"]; ok {
		if t, ok := v.(time.Time); ok {
			p.ExpirationDate = t
		}
	}
	if v, ok := m["ProvisionsAllDevices"]; ok {
		p.ProvisionsAllDevices = toBool(v)
	}
	p.ProvisionedDevices = toStringSlice(m["ProvisionedDevices"])
	if v, ok := m["Entitlements"]; ok {
		if d, ok := v.(map[string]interface{}); ok {
			p.Entitlements = d
		}
	}
	if v, ok := m["DeveloperCertificates"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if b, ok := item.([]byte); ok {
					if cert, err := x509.ParseCertificate(b); err == nil {
						p.DeveloperCertificates = append(p.DeveloperCertificates, cert)
					}
				}
			}
		}
	}
	// AppIdentifier is the full sealed id ("TEAMID.com.example.app"); fall back
	// to the bare prefix when the profile carries no entitlements.
	if ai, ok := p.Entitlements["application-identifier"].(string); ok && ai != "" {
		p.AppIdentifier = ai
	} else if len(p.AppIdentifierPrefixes) > 0 {
		p.AppIdentifier = p.AppIdentifierPrefixes[0]
	}
	return p, nil
}

func toStringSlice(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

func toBool(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

// TeamID returns the first team identifier, or "".
func (p *Provision) TeamID() string {
	if len(p.TeamIdentifiers) > 0 {
		return p.TeamIdentifiers[0]
	}
	return ""
}

// AppIDPrefix returns the application identifier prefix, or "".
func (p *Provision) AppIDPrefix() string {
	if len(p.AppIdentifierPrefixes) > 0 {
		return p.AppIdentifierPrefixes[0]
	}
	return ""
}

// Expired reports whether the profile has expired.
func (p *Provision) Expired(now time.Time) bool {
	return !p.ExpirationDate.IsZero() && now.After(p.ExpirationDate)
}

// HasDevice returns true if the profile provisions the given UDID.
func (p *Provision) HasDevice(udid string) bool {
	if p.ProvisionsAllDevices {
		return true
	}
	for _, d := range p.ProvisionedDevices {
		if strings.EqualFold(d, udid) {
			return true
		}
	}
	return false
}

// AllowedEntitlements returns the entitlement keys the profile permits.
func (p *Provision) AllowedEntitlements() map[string]interface{} {
	return p.Entitlements
}
