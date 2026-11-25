// Package model holds the types shared by every layer of the scanner.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Severity orders findings from purely informational to an active attack.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "unknown"
}

// ParseSeverity converts a name back into a Severity. Unknown names map to Info.
func ParseSeverity(name string) Severity {
	for i, n := range severityNames {
		if strings.EqualFold(n, name) {
			return Severity(i)
		}
	}
	return Info
}

// MarshalText makes severities readable in JSON and YAML.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText is the inverse of MarshalText.
func (s *Severity) UnmarshalText(b []byte) error {
	*s = ParseSeverity(string(b))
	return nil
}

// Layer names which detection layer produced a finding.
type Layer string

const (
	LayerStatic   Layer = "static"
	LayerRuntime  Layer = "runtime"
	LayerBaseline Layer = "baseline"
	LayerIntel    Layer = "intel"
	LayerPosture  Layer = "posture"
)

// Finding is one thing the scanner wants a human to look at.
type Finding struct {
	Layer    Layer    `json:"layer"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Target   string   `json:"target"`
	PageURL  string   `json:"page_url"`
	Location string   `json:"location"` // where on the page: "inline script #2", "onerror of <img>", a script URL...
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Evidence string   `json:"evidence,omitempty"` // a short, truncated snippet; never executed, always escaped on output
	New      bool     `json:"new"`                // not seen in this target's recent scans
}

// Fingerprint identifies a finding across scans so the same issue is not reported as new every night.
func (f Finding) Fingerprint() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		string(f.Layer), f.Rule, f.Target, f.PageURL, f.Location, f.Evidence,
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

// BaselineKey decides whether a finding is new compared with the previous scan. Unlike
// Fingerprint it ignores the evidence snippet and the parts of URLs that change on every
// deploy (cache-busters, content hashes, build numbers), so a provider shipping a new
// build of the same script does not turn every one of its findings into a "new" one.
//
// Bundler chunks (Next.js, webpack) are a special case: every deploy renames them and the
// browser loads a different subset on each visit, so the file name means nothing. For those
// the key is the chunk directory plus the evidence with minified identifiers blanked out:
// the same code in a renamed chunk is the same finding, new code is a new one.
func (f Finding) BaselineKey() string {
	loc := StableURLs(stripDiscovery(f.Location))
	parts := []string{string(f.Layer), f.Rule, f.Target, StableURLs(f.PageURL), loc}
	if dir, ok := BuildChunkDir(loc); ok {
		parts[4] = dir
		parts = append(parts, minifiedShape(f.Evidence))
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

// Directories where bundlers put content-hashed chunks with throwaway names.
var chunkDirs = []string{"/_next/static/", "/chunks/", "/static/js/", "/_nuxt/", "/build/assets/"}

// BuildChunkDir returns the directory of a bundler chunk URL ("https://cdn/_next/static/chunks/"),
// or false when the location is not one.
func BuildChunkDir(loc string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Host == "" || !strings.HasSuffix(u.Path, ".js") {
		return "", false
	}
	for _, d := range chunkDirs {
		if strings.Contains(u.Path, d) {
			return u.Scheme + "://" + u.Host + u.Path[:strings.LastIndexByte(u.Path, '/')+1], true
		}
	}
	return "", false
}

// Identifiers of one to three characters are what minifiers produce, and they change on
// every build; numbers change too.
var reShortIdent = regexp.MustCompile(`\b[A-Za-z_$][A-Za-z0-9_$]{0,2}\b|\d+`)

func minifiedShape(evidence string) string {
	return reShortIdent.ReplaceAllString(evidence, "_")
}

// Discovery-method prefixes on a Location: the same script seen in the static HTML, after the
// browser ran, or inside an iframe is one finding, so the prefix must not change the key.
var discoveryPrefixes = []string{"runtime-loaded ", "browser version of ", "iframe "}

func stripDiscovery(loc string) string {
	for _, p := range discoveryPrefixes {
		if strings.HasPrefix(loc, p) {
			return loc[len(p):]
		}
	}
	return loc
}

var (
	reURLInText = regexp.MustCompile(`https?://[^\s"'<>]+`)
	reURLToken  = regexp.MustCompile(`[A-Za-z0-9]+`)
	reDigits    = regexp.MustCompile(`[0-9]`)
)

// Query parameters that only bust caches or record build versions.
var volatileParams = map[string]bool{
	"cb": true, "gtm": true, "_": true, "t": true, "ts": true, "rnd": true, "random": true,
	"cachebust": true, "cachebuster": true, "nocache": true, "build": true, "hash": true,
}

// StableURLs rewrites every URL in s into a form that survives redeploys: volatile query
// parameters are dropped, and path or query tokens that look like hashes or build numbers
// (8+ characters with at least 2 digits, e.g. "e85a87e594b0", "m202610270101") become "*".
func StableURLs(s string) string {
	return reURLInText.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		u.Fragment = ""
		stable := stableTokens(u.Path)
		hashed := stable != u.Path
		u.Path = stable
		u.RawPath = ""
		if hashed && strings.HasSuffix(u.Path, ".js") {
			// A content-addressed file (asset-<hash>.js) is identified by its path. Query
			// parameters on it list bundle contents or versions that change with every deploy,
			// as on VTEX's "asset-<hash>.min.js?files=app@1.2.3,..." bundles.
			u.RawQuery = ""
			return u.String()
		}
		q := u.Query()
		for k, vs := range q {
			if volatileParams[strings.ToLower(k)] {
				q.Del(k)
				continue
			}
			for i := range vs {
				vs[i] = stableTokens(vs[i])
			}
		}
		u.RawQuery = q.Encode() // Encode sorts keys, so parameter order does not matter either
		return u.String()
	})
}

func stableTokens(s string) string {
	s = reVersionRun.ReplaceAllString(s, "*") // 1.2.3-style versions bump on every provider release
	s = reURLToken.ReplaceAllStringFunc(s, func(tok string) string {
		// 20+ characters is a random token whatever it contains (signed tag-gateway paths).
		if len(tok) >= 20 || len(tok) >= 8 && len(reDigits.FindAllStringIndex(tok, 3)) >= 2 {
			return "*"
		}
		return tok
	})
	// "bSuJ2xBC8cHT21-c68JXN31m" becomes "*-*": one build ID, so one placeholder.
	return reStarRun.ReplaceAllString(s, "*")
}

var (
	reStarRun    = regexp.MustCompile(`\*(?:[-_~]\*)+`)
	reVersionRun = regexp.MustCompile(`\d+(?:\.\d+)+`)
)

// Script is a piece of JavaScript found on a page, wherever it came from.
type Script struct {
	PageURL  string `json:"page_url"`
	Location string `json:"location"` // "inline #1", "external", "onerror of <img>", "runtime-injected"
	Src      string `json:"src,omitempty"`
	Content  string `json:"-"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
}

// NewScript computes the hash and size of a script's content.
func NewScript(pageURL, location, src, content string) Script {
	sum := sha256.Sum256([]byte(content))
	return Script{
		PageURL:  pageURL,
		Location: location,
		Src:      src,
		Content:  content,
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     len(content),
	}
}

// Key is how a script is matched against the previous scan: external scripts by URL,
// inline ones by page and position.
func (s Script) Key() string {
	if s.Src != "" {
		return "src:" + s.Src
	}
	return fmt.Sprintf("inline:%s#%s", s.PageURL, s.Location)
}

// Scan is the result of scanning one target once.
type Scan struct {
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Pages      []string  `json:"pages"`
	Scripts    []Script  `json:"scripts"`
	Domains    []string  `json:"domains"` // every third-party domain the pages talked to
	Findings   []Finding `json:"findings"`
	Errors     []string  `json:"errors,omitempty"`
}

// MaxSeverity is the worst finding in the scan, or -1 when there are none.
func (s Scan) MaxSeverity() Severity {
	max := Severity(-1)
	for _, f := range s.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// Truncate shortens evidence so reports stay readable and never carry a whole payload.
func Truncate(s string, n int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
