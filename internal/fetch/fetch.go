// Package fetch is a deliberately polite HTTP client: one request at a time per host,
// a fixed delay between them, robots.txt respected and response sizes capped.
package fetch

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Response is what the analyzers need from an HTTP response.
type Response struct {
	URL       string // final URL, after redirects
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
	Redirects []string // every URL visited on the way, in order
}

// Fetcher is safe for concurrent use.
type Fetcher struct {
	client    *http.Client
	userAgent string
	delay     time.Duration
	maxBytes  int64
	robots    bool

	mu    sync.Mutex
	hosts map[string]*hostState
}

type hostState struct {
	mu       sync.Mutex // serializes requests to one host
	last     time.Time
	rules    *robotsRules
	rulesErr error
	fetched  bool
}

// Options configures a Fetcher.
type Options struct {
	UserAgent     string
	Delay         time.Duration
	Timeout       time.Duration
	MaxBodyBytes  int64
	RespectRobots bool
	Transport     http.RoundTripper // nil means the default; tests inject their own
}

// New builds a Fetcher.
func New(o Options) *Fetcher {
	f := &Fetcher{
		userAgent: o.UserAgent,
		delay:     o.Delay,
		maxBytes:  o.MaxBodyBytes,
		robots:    o.RespectRobots,
		hosts:     map[string]*hostState{},
	}
	f.client = &http.Client{
		Timeout:   o.Timeout,
		Transport: o.Transport,
	}
	return f
}

// ErrDisallowed is returned when robots.txt forbids a URL.
type ErrDisallowed struct{ URL string }

func (e ErrDisallowed) Error() string { return "robots.txt disallows " + e.URL }

func (f *Fetcher) host(u *url.URL) *hostState {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := u.Scheme + "://" + u.Host
	h, ok := f.hosts[key]
	if !ok {
		h = &hostState{}
		f.hosts[key] = h
	}
	return h
}

// Get fetches a URL, waiting its turn for the host and honoring robots.txt.
func (f *Fetcher) Get(ctx context.Context, rawURL string) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", rawURL, err)
	}
	h := f.host(u)
	h.mu.Lock()
	defer h.mu.Unlock()

	if f.robots {
		if !h.fetched {
			h.rules, h.rulesErr = f.loadRobots(ctx, h, u)
			h.fetched = true
		}
		// An unreadable robots.txt is treated as "allow all", which is what crawlers conventionally do.
		if h.rules != nil && !h.rules.allowed(u.EscapedPath()) {
			return nil, ErrDisallowed{rawURL}
		}
	}
	return f.do(ctx, h, rawURL, f.maxBytes)
}

func (f *Fetcher) wait(ctx context.Context, h *hostState) error {
	if h.last.IsZero() {
		return nil
	}
	gap := time.Until(h.last.Add(f.delay))
	if gap <= 0 {
		return nil
	}
	t := time.NewTimer(gap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (f *Fetcher) do(ctx context.Context, h *hostState, rawURL string, maxBytes int64) (*Response, error) {
	if err := f.wait(ctx, h); err != nil {
		return nil, err
	}
	defer func() { h.last = time.Now() }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("Accept", "text/html,application/javascript,*/*;q=0.8")

	var chain []string
	client := *f.client
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		chain = append(chain, r.URL.String())
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	truncated := int64(len(body)) > maxBytes
	if truncated {
		body = body[:maxBytes]
	}
	return &Response{
		URL:       resp.Request.URL.String(),
		Status:    resp.StatusCode,
		Header:    resp.Header,
		Body:      body,
		Truncated: truncated,
		Redirects: chain,
	}, nil
}

func (f *Fetcher) loadRobots(ctx context.Context, h *hostState, u *url.URL) (*robotsRules, error) {
	robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"
	resp, err := f.do(ctx, h, robotsURL, 512<<10) // robots.txt has its own cap, independent of page limits
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, nil
	}
	return parseRobots(string(resp.Body), f.userAgent), nil
}

// robotsRules is a minimal robots.txt implementation: longest matching prefix wins,
// Allow beats Disallow on ties. Wildcards are not supported; they are rare in the
// paths this tool fetches (pages and scripts).
type robotsRules struct {
	allow    []string
	disallow []string
}

func (r *robotsRules) allowed(path string) bool {
	if path == "" {
		path = "/"
	}
	best, verdict := -1, true
	for _, p := range r.disallow {
		if p != "" && strings.HasPrefix(path, p) && len(p) > best {
			best, verdict = len(p), false
		}
	}
	for _, p := range r.allow {
		if strings.HasPrefix(path, p) && len(p) >= best {
			best, verdict = len(p), true
		}
	}
	return verdict
}

// parseRobots keeps the group for our user agent if there is one, otherwise the "*" group.
func parseRobots(body, userAgent string) *robotsRules {
	agentToken := strings.ToLower(strings.SplitN(userAgent, "/", 2)[0])
	groups := map[string]*robotsRules{}
	var current []string
	lastWasAgent := false
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "user-agent":
			if !lastWasAgent {
				current = nil
			}
			agent := strings.ToLower(val)
			current = append(current, agent)
			if groups[agent] == nil {
				groups[agent] = &robotsRules{}
			}
			lastWasAgent = true
		case "allow", "disallow":
			lastWasAgent = false
			for _, a := range current {
				if key == "allow" {
					groups[a].allow = append(groups[a].allow, val)
				} else {
					groups[a].disallow = append(groups[a].disallow, val)
				}
			}
		default:
			lastWasAgent = false
		}
	}
	if g, ok := groups[agentToken]; ok {
		return g
	}
	if g, ok := groups["*"]; ok {
		return g
	}
	return &robotsRules{}
}
