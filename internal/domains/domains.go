// Package domains answers "is this host part of the store or a third party?".
package domains

import (
	"net"
	"net/url"
	"strings"
)

// Two-label public suffixes common in the stores this tool targets. A full Public Suffix
// List would be more exact; this covers Latin America, the US and Europe well enough that
// "www.coto.com.ar" and "static.coto.com.ar" are recognized as the same site.
var twoLabelSuffixes = map[string]bool{
	"com.ar": true, "gob.ar": true, "net.ar": true, "org.ar": true,
	"com.br": true, "net.br": true, "org.br": true,
	"com.mx": true, "com.co": true, "com.pe": true, "com.uy": true, "com.py": true, "com.bo": true, "com.ec": true, "com.ve": true,
	"co.uk": true, "org.uk": true, "com.au": true, "co.nz": true, "co.jp": true, "com.es": true,
	"com.cn": true, "co.za": true, "co.in": true,
}

// Registrable returns the registrable part of a host: "static.coto.com.ar" becomes "coto.com.ar".
// IP addresses are returned unchanged.
func Registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return host
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	lastTwo := strings.Join(labels[len(labels)-2:], ".")
	if twoLabelSuffixes[lastTwo] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return lastTwo
}

// Host extracts the lowercase hostname of a URL, or "" if there is none.
func Host(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// IsIP reports whether a host is a literal IP address.
func IsIP(host string) bool { return net.ParseIP(strings.Trim(host, "[]")) != nil }

// Scope decides which hosts belong to a store.
type Scope struct {
	firstParty map[string]bool
	allowed    map[string]bool
}

// NewScope builds a scope from the store's page URLs plus an explicit allowlist of domains.
func NewScope(pages, allow []string) *Scope {
	s := &Scope{firstParty: map[string]bool{}, allowed: map[string]bool{}}
	for _, p := range pages {
		if h := Host(p); h != "" {
			s.firstParty[Registrable(h)] = true
		}
	}
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			s.allowed[Registrable(a)] = true
		}
	}
	return s
}

// FirstParty reports whether the host belongs to the store itself.
func (s *Scope) FirstParty(host string) bool {
	return host != "" && s.firstParty[Registrable(host)]
}

// Allowed reports whether the host is the store itself or on its explicit allowlist.
func (s *Scope) Allowed(host string) bool {
	if host == "" {
		return true // relative URLs stay on the page's own origin
	}
	r := Registrable(host)
	return s.firstParty[r] || s.allowed[r]
}

// Trusted is Allowed plus the widely used providers in KnownGood. Behavioral rules use it,
// so sending analytics to Google is not reported as data leaving the store.
func (s *Scope) Trusted(host string) bool {
	return s.Allowed(host) || IsKnownGood(host)
}
