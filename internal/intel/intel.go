// Package intel judges third-party domains by reputation rather than behavior: known-bad
// lists, names that imitate trusted providers, and how recently a domain was registered.
package intel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

// Checker is safe for concurrent use; RDAP answers are cached for the whole run.
type Checker struct {
	blocklist map[string]string // registrable domain → source of the listing
	rdap      *http.Client
	rdapBase  string
	ageCheck  bool

	mu    sync.Mutex
	cache map[string]ageResult
}

type ageResult struct {
	registered time.Time
	err        error
}

// Options configures a Checker.
type Options struct {
	BlocklistFiles []string // one domain per line; "#" comments and hosts-file format both accepted
	CheckAge       bool
	RDAPBase       string // default https://rdap.org/domain/
	HTTPClient     *http.Client
}

// New loads blocklists and prepares the RDAP client.
func New(o Options) (*Checker, error) {
	c := &Checker{blocklist: map[string]string{}, ageCheck: o.CheckAge, cache: map[string]ageResult{}}
	c.rdap = o.HTTPClient
	if c.rdap == nil {
		c.rdap = &http.Client{Timeout: 8 * time.Second}
	}
	c.rdapBase = o.RDAPBase
	if c.rdapBase == "" {
		c.rdapBase = "https://rdap.org/domain/"
	}
	for _, f := range o.BlocklistFiles {
		if err := c.loadBlocklist(f); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Checker) loadBlocklist(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening blocklist: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		d := fields[len(fields)-1] // hosts-file lines look like "127.0.0.1 bad.example"
		if d == "localhost" || domains.IsIP(d) {
			continue
		}
		c.blocklist[domains.Registrable(d)] = path
	}
	return sc.Err()
}

// BlocklistSize is the number of distinct domains loaded.
func (c *Checker) BlocklistSize() int { return len(c.blocklist) }

// Check evaluates every third-party domain a target talked to.
func (c *Checker) Check(ctx context.Context, target string, thirdParty []string, scope *domains.Scope) []model.Finding {
	var out []model.Finding
	add := func(rule string, sev model.Severity, host, title, detail string) {
		out = append(out, model.Finding{
			Layer: model.LayerIntel, Rule: rule, Severity: sev, Target: target,
			Location: host, Title: title, Detail: detail, Evidence: host,
		})
	}
	for _, host := range thirdParty {
		reg := domains.Registrable(host)
		if src, bad := c.blocklist[reg]; bad {
			add("blocklisted-domain", model.Critical, host, host+" is on a malware blocklist",
				fmt.Sprintf("Listed in %s. Any code or data exchanged with this domain should be treated as hostile.", src))
			continue
		}
		if scope.Allowed(host) || domains.IsKnownGood(host) {
			continue
		}
		if like := Lookalike(reg); like != "" {
			add("lookalike-domain", model.High, host, host+" imitates "+like,
				"The name is one or two characters away from a provider stores trust, or wraps its name in extra words. "+
					"Attackers register these so the domain blends into a page's network log.")
		}
		if tld := suspiciousTLD(reg); tld != "" {
			add("cheap-tld", model.Low, host, host+" uses a TLD favored by abuse",
				"."+tld+" domains cost almost nothing and are overrepresented in malware feeds. Not proof of anything on its own.")
		}
		if c.ageCheck {
			if when, err := c.registered(ctx, reg); err == nil && !when.IsZero() {
				age := time.Since(when)
				switch {
				case age < 30*24*time.Hour:
					add("new-domain-age", model.High, host, fmt.Sprintf("%s was registered %d days ago", host, int(age.Hours()/24)),
						"Skimmer infrastructure is typically registered days before an attack and abandoned after.")
				case age < 180*24*time.Hour:
					add("young-domain", model.Medium, host, fmt.Sprintf("%s is less than six months old", host),
						"Registered "+when.Format("2006-01-02")+". Young domains deserve a second look when they receive data from a store.")
				}
			}
		}
	}
	return out
}

// registered asks RDAP for the registration date. Failures are cached and treated as unknown.
func (c *Checker) registered(ctx context.Context, domain string) (time.Time, error) {
	c.mu.Lock()
	if r, ok := c.cache[domain]; ok {
		c.mu.Unlock()
		return r.registered, r.err
	}
	c.mu.Unlock()

	t, err := c.queryRDAP(ctx, domain)
	c.mu.Lock()
	c.cache[domain] = ageResult{t, err}
	c.mu.Unlock()
	return t, err
}

func (c *Checker) queryRDAP(ctx context.Context, domain string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.rdapBase+domain, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := c.rdap.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("rdap %s: status %d", domain, resp.StatusCode)
	}
	var body struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return time.Time{}, err
	}
	for _, e := range body.Events {
		if e.Action == "registration" {
			return time.Parse(time.RFC3339, e.Date)
		}
	}
	return time.Time{}, nil
}

var cheapTLDs = map[string]bool{
	"top": true, "xyz": true, "icu": true, "click": true, "buzz": true, "cyou": true, "rest": true,
	"monster": true, "sbs": true, "cfd": true, "bond": true, "quest": true, "zip": true, "mov": true,
}

func suspiciousTLD(reg string) string {
	i := strings.LastIndexByte(reg, '.')
	if i < 0 {
		return ""
	}
	if tld := reg[i+1:]; cheapTLDs[tld] {
		return tld
	}
	return ""
}

// Lookalike returns the trusted domain that reg imitates, or "".
func Lookalike(reg string) string {
	if domains.IsKnownGood(reg) {
		return ""
	}
	name := label(reg)
	norm := normalize(name)
	for _, good := range domains.KnownGood {
		g := domains.Registrable(good)
		gname := label(g)
		if len(gname) < 5 {
			continue // short names like "wa" or "vtex" collide with too many legitimate words
		}
		if name == gname {
			return g // same name under another TLD: google-analytics.top
		}
		if norm == normalize(gname) {
			return g // homoglyph swap: rn→m, 0→o, 1→l...
		}
		if d := levenshtein(name, gname); d > 0 && d <= 2 && len(name) >= 6 {
			return g
		}
		// "googletagmanager-cdn", "cdn-jquery": the brand plus decoration.
		if len(gname) >= 6 && name != gname && strings.Contains(strings.ReplaceAll(name, "-", ""), strings.ReplaceAll(gname, "-", "")) {
			return g
		}
	}
	return ""
}

// label is the part of a registrable domain before its suffix: "google-analytics" for
// "google-analytics.com", "mercadopago" for "mercadopago.com.ar".
func label(reg string) string {
	return strings.SplitN(reg, ".", 2)[0]
}

var homoglyphs = strings.NewReplacer("rn", "m", "vv", "w", "0", "o", "1", "l", "3", "e", "5", "s", "i", "l", "-", "")

func normalize(s string) string { return homoglyphs.Replace(strings.ToLower(s)) }

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr := make([]int, len(rb)+1)
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(rb)]
}
