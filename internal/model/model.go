// Package model holds the types shared by every layer of the scanner.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	New      bool     `json:"new"`                // not present in the previous scan of this target
}

// Fingerprint identifies a finding across scans so the same issue is not reported as new every night.
func (f Finding) Fingerprint() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		string(f.Layer), f.Rule, f.Target, f.PageURL, f.Location, f.Evidence,
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

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
