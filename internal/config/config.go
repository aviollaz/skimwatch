// Package config loads the list of stores to scan.
package config

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/goccy/go-yaml"
)

// Kinds of target.
const (
	// KindStore is an online store: home, product and checkout-entry pages.
	KindStore = "store"
	// KindSharedCheckout is a payment or subscription form that many merchants embed, such
	// as a processor's hosted card form or a platform's checkout. One compromise there
	// reaches every merchant at once (PaperCut, 2026: one script tag in a shared card form,
	// 80 newspapers), so these targets are held to a stricter baseline.
	KindSharedCheckout = "shared-checkout"
)

// Target is one store or shared checkout. Pages are the URLs worth watching: the home page,
// a product page and the checkout entry point are where skimmers usually live.
type Target struct {
	Name  string   `yaml:"name"`
	Kind  string   `yaml:"kind"` // KindStore (default) or KindSharedCheckout
	Pages []string `yaml:"pages"`
	// Domains the store legitimately loads code from (its CDN, payment provider...).
	// Third-party domains outside this list are reported for review.
	Allow []string `yaml:"allow"`
	// For shared checkouts: the merchants known to embed this form. Findings name them,
	// so a report says who is affected and whom to notify.
	UsedBy []string `yaml:"used_by"`
}

// Shared reports whether the target is a form many merchants embed.
func (t Target) Shared() bool { return t.Kind == KindSharedCheckout }

// Settings tune how politely and how deeply the scanner works.
type Settings struct {
	UserAgent      string        `yaml:"user_agent"`
	RequestDelay   time.Duration `yaml:"request_delay"`  // minimum gap between requests to the same host
	Timeout        time.Duration `yaml:"timeout"`        // per request
	MaxBodyBytes   int64         `yaml:"max_body_bytes"` // larger responses are truncated
	RuntimeWait    time.Duration `yaml:"runtime_wait"`   // how long the browser watches each page
	Concurrency    int           `yaml:"concurrency"`    // targets scanned in parallel
	RespectRobots  bool          `yaml:"respect_robots"`
	CheckDomainAge bool          `yaml:"check_domain_age"` // RDAP lookups for unfamiliar third-party domains
}

// Config is the whole targets file.
type Config struct {
	Settings Settings `yaml:"settings"`
	Targets  []Target `yaml:"targets"`
}

// Defaults are deliberately slow: this tool watches stores, it must never load them.
func Defaults() Settings {
	return Settings{
		UserAgent:      "skimwatch/0.1 (+https://github.com/aviollaz/skimwatch; passive security monitor)",
		RequestDelay:   2 * time.Second,
		Timeout:        20 * time.Second,
		MaxBodyBytes:   5 << 20,
		RuntimeWait:    8 * time.Second,
		Concurrency:    2,
		RespectRobots:  true,
		CheckDomainAge: true,
	}
}

// Load reads and validates a targets file, filling unset settings with defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg := &Config{Settings: Defaults()}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	d := Defaults()
	s := &c.Settings
	if s.UserAgent == "" {
		s.UserAgent = d.UserAgent
	}
	if s.RequestDelay <= 0 {
		s.RequestDelay = d.RequestDelay
	}
	if s.Timeout <= 0 {
		s.Timeout = d.Timeout
	}
	if s.MaxBodyBytes <= 0 {
		s.MaxBodyBytes = d.MaxBodyBytes
	}
	if s.RuntimeWait <= 0 {
		s.RuntimeWait = d.RuntimeWait
	}
	if s.Concurrency <= 0 {
		s.Concurrency = d.Concurrency
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("config has no targets")
	}
	seen := map[string]bool{}
	for i, t := range c.Targets {
		if t.Name == "" {
			return fmt.Errorf("target %d has no name", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
		switch t.Kind {
		case "":
			c.Targets[i].Kind = KindStore
		case KindStore, KindSharedCheckout:
		default:
			return fmt.Errorf("target %q: unknown kind %q (want %q or %q)", t.Name, t.Kind, KindStore, KindSharedCheckout)
		}
		if len(t.Pages) == 0 {
			return fmt.Errorf("target %q has no pages", t.Name)
		}
		for _, p := range t.Pages {
			u, err := url.Parse(p)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("target %q: invalid page URL %q", t.Name, p)
			}
		}
	}
	return nil
}
