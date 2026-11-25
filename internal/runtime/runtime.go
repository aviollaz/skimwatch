// Package runtime loads pages in a real headless browser and watches what their code
// actually does: every request, every script added after load, every eval, every input
// listener. It then types canary values into the page's forms and checks whether they
// leave the browser.
package runtime

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

//go:embed instrument.js
var instrumentJS string

// Canary values are typed into forms. They are fake but shaped like the real thing, so
// skimmers that validate input (Luhn checks, length checks) still take them. 4111... is
// the standard Visa test number; no real card or account can be affected.
const (
	CanaryCard     = "4111111111111111"
	CanaryCVV      = "917"
	CanaryEmail    = "canary.skimwatch@example.invalid"
	CanaryPassword = "Skimwatch-Canary-7Q"
	// Every other text field gets a neutral marker instead of the card number, so a search
	// box whose autocomplete calls a third-party provider is not mistaken for card theft.
	CanaryText = "skimwatchcanarytext"
)

// Request is one network request the page made.
type Request struct {
	URL       string
	Method    string
	Type      string
	Body      string
	Initiator string // the script that caused it, when the browser knows
}

// Event is something the instrumentation script observed.
type Event struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	Source string `json:"source"`
}

// Script is code the browser executed that may not be in the static HTML.
type Script struct {
	URL     string
	Content string
}

// Result is everything observed on one page.
type Result struct {
	PageURL   string
	FinalURL  string
	Requests  []Request
	Sockets   []string // WebSocket URLs
	Frames    []string // data sent over WebSockets
	Scripts   []Script
	Events    []Event
	NonNative []string // browser APIs replaced by page code

	CardFields  int      // payment card inputs the page showed
	Hovered     int      // pay buttons the pointer was moved over
	WebRTCPeers []string // public IPs and hosts the page set up WebRTC connections with
}

// Browser owns one headless Chrome process shared by every page of a scan.
type Browser struct {
	ctx    context.Context
	cancel context.CancelFunc
	ua     string
}

// BrowserOptions configures the headless Chrome process.
type BrowserOptions struct {
	ExecPath  string // empty lets chromedp find Chrome
	UserAgent string
	NoSandbox bool   // required when running as root in many containers
	HostRules string // Chrome --host-resolver-rules, used by tests to map fake domains to a local server
	NoProxy   bool
}

// NewBrowser starts Chrome.
func NewBrowser(parent context.Context, o BrowserOptions) (*Browser, error) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.UserAgent(o.UserAgent), chromedp.Flag("disable-gpu", true))
	if o.ExecPath != "" {
		opts = append(opts, chromedp.ExecPath(o.ExecPath))
	}
	if o.NoSandbox {
		opts = append(opts, chromedp.NoSandbox)
	}
	if o.HostRules != "" {
		opts = append(opts, chromedp.Flag("host-resolver-rules", o.HostRules))
	}
	if o.NoProxy {
		opts = append(opts, chromedp.Flag("no-proxy-server", true))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(ctx); err != nil {
		cancel()
		allocCancel()
		return nil, fmt.Errorf("starting browser: %w", err)
	}
	return &Browser{ctx: ctx, cancel: func() { cancel(); allocCancel() }, ua: o.UserAgent}, nil
}

// Close stops Chrome.
func (b *Browser) Close() { b.cancel() }

// Visit loads one page in a fresh tab, waits, fills canaries, waits again and reports.
func (b *Browser) Visit(ctx context.Context, pageURL string, wait time.Duration) (*Result, error) {
	tab, cancel := chromedp.NewContext(b.ctx)
	defer cancel()
	tab, cancelTimeout := context.WithTimeout(tab, wait*3+30*time.Second)
	defer cancelTimeout()
	stop := context.AfterFunc(ctx, cancel) // honor the caller's cancellation too
	defer stop()

	res := &Result{PageURL: pageURL}
	var filled struct {
		Filled int `json:"filled"`
		Card   int `json:"card"`
	}
	var buttons []struct{ X, Y float64 }
	var mu sync.Mutex
	scriptIDs := map[network.RequestID]string{}

	chromedp.ListenTarget(tab, func(ev any) {
		mu.Lock()
		defer mu.Unlock()
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			r := Request{URL: e.Request.URL, Method: e.Request.Method, Type: string(e.Type), Initiator: initiatorURL(e.Initiator)}
			for _, part := range e.Request.PostDataEntries {
				if raw, err := base64.StdEncoding.DecodeString(part.Bytes); err == nil {
					r.Body += string(raw)
				} else {
					r.Body += part.Bytes
				}
			}
			res.Requests = append(res.Requests, r)
			if e.Type == network.ResourceTypeScript {
				scriptIDs[e.RequestID] = e.Request.URL
			}
		case *network.EventWebSocketCreated:
			res.Sockets = append(res.Sockets, e.URL)
		case *network.EventWebSocketFrameSent:
			if e.Response != nil && len(res.Frames) < 200 {
				res.Frames = append(res.Frames, e.Response.PayloadData)
			}
		}
	})

	err := chromedp.Run(tab,
		network.Enable(),
		chromedp.ActionFunc(func(c context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(instrumentJS).Do(c)
			return err
		}),
		chromedp.Navigate(pageURL),
		chromedp.Sleep(wait),
		chromedp.Evaluate(fillCanariesJS, &filled),
		// Some skimmers only wake up when the buyer is about to pay: PaperCut ran when the
		// pointer went over the pay button. Move a real (trusted) pointer over each one.
		// Nothing is ever clicked.
		chromedp.Evaluate(payButtonsJS, &buttons),
		chromedp.ActionFunc(func(c context.Context) error {
			for _, b := range buttons {
				for _, p := range [][2]float64{{2, 2}, {b.X, b.Y}} {
					if err := input.DispatchMouseEvent(input.MouseMoved, p[0], p[1]).Do(c); err != nil {
						return err
					}
				}
				res.Hovered++
				if err := chromedp.Sleep(400 * time.Millisecond).Do(c); err != nil {
					return err
				}
			}
			return nil
		}),
		chromedp.Sleep(wait/2+time.Second),
		chromedp.Location(&res.FinalURL),
		chromedp.Evaluate(`JSON.parse(JSON.stringify(window.__skimwatch || []))`, &res.Events),
		chromedp.Evaluate(nonNativeJS, &res.NonNative),
	)
	res.CardFields = filled.Card
	res.WebRTCPeers = webrtcPeers(res.Events)
	if err != nil {
		return res, fmt.Errorf("visiting %s: %w", pageURL, err)
	}

	// Fetch the bodies of every script the browser ran, including ones injected at runtime.
	mu.Lock()
	ids := make(map[network.RequestID]string, len(scriptIDs))
	for k, v := range scriptIDs {
		ids[k] = v
	}
	mu.Unlock()
	for id, u := range ids {
		var body []byte
		if err := chromedp.Run(tab, chromedp.ActionFunc(func(c context.Context) error {
			var e error
			body, e = network.GetResponseBody(id).Do(c)
			return e
		})); err == nil {
			res.Scripts = append(res.Scripts, Script{URL: u, Content: string(body)})
		}
	}
	return res, nil
}

func initiatorURL(in *network.Initiator) string {
	if in == nil {
		return ""
	}
	if in.Stack != nil {
		for _, f := range in.Stack.CallFrames {
			if f.URL != "" {
				return f.URL
			}
		}
	}
	return in.URL
}

// fillCanariesJS types fake values into every visible field, firing the events skimmers
// listen for. Submission is blocked by the instrumentation script.
const fillCanariesJS = `(() => {
  const pick = (el) => {
    const hint = [el.name, el.id, el.autocomplete, el.placeholder, el.type].join(" ").toLowerCase();
    if (/cvv|cvc|csc|security|cc-csc|codigo/.test(hint)) return "` + CanaryCVV + `";
    if (/card|cc-number|tarjeta|numero/.test(hint)) return "` + CanaryCard + `";
    if (el.type === "email" || /mail/.test(hint)) return "` + CanaryEmail + `";
    if (el.type === "password") return "` + CanaryPassword + `";
    if (el.type === "text" || el.type === "tel" || el.type === "search" || el.type === "") return "` + CanaryText + `";
    return null;
  };
  let n = 0, card = 0;
  for (const el of document.querySelectorAll("input, textarea")) {
    if (el.type === "hidden" || el.disabled || el.readOnly) continue;
    const v = pick(el);
    if (v === null) continue;
    if (v === "` + CanaryCard + `") card++;
    el.focus();
    el.value = v;
    for (const t of ["keydown", "keyup", "input", "change", "blur"]) el.dispatchEvent(new Event(t, { bubbles: true }));
    n++;
  }
  return { filled: n, card: card };
})()`

// payButtonsJS finds buttons that look like "pay", "buy" or "subscribe", plus the submit
// buttons of any form with card fields, scrolls each into view and returns its center.
const payButtonsJS = `(() => {
  const words = /pagar|pag[aá]|abonar|comprar|confirm|finaliz|suscrib|subscri|checkout|pay|buy|order|place|submit|continuar/i;
  const out = [], seen = new Set();
  const add = (el) => {
    if (seen.has(el) || out.length >= 6) return;
    seen.add(el);
    el.scrollIntoView({ block: "center" });
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return;
    out.push({ X: r.left + r.width / 2, Y: r.top + r.height / 2 });
  };
  for (const f of document.forms) {
    const card = [...f.elements].some((e) => /card|cc-number|tarjeta|cvv|cvc/i.test([e.name, e.id, e.autocomplete].join(" ")));
    if (!card) continue;
    for (const b of f.querySelectorAll("button, input[type=submit], input[type=button]")) add(b);
  }
  for (const b of document.querySelectorAll("button, input[type=submit], input[type=button], [role=button], a")) {
    const label = [b.textContent, b.value, b.getAttribute("aria-label"), b.id, b.className].join(" ");
    if (words.test(label)) add(b);
  }
  return out;
})()`

// nonNativeJS lists security-relevant browser APIs that page code has replaced.
const nonNativeJS = `(() => {
  const isNative = (f) => typeof f === "function" && /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(f));
  const checks = {
    "window.fetch": window.fetch,
    "XMLHttpRequest.prototype.open": XMLHttpRequest.prototype.open,
    "XMLHttpRequest.prototype.send": XMLHttpRequest.prototype.send,
    "navigator.sendBeacon": navigator.sendBeacon,
    "WebSocket": window.WebSocket,
  };
  return Object.entries(checks).filter(([, f]) => f && !isNative(f)).map(([k]) => k);
})()`

// Analyze turns observations into findings. Canary leaks are the strongest evidence the
// tool can produce: a card number typed into the page appeared in a request to another host.
func Analyze(r *Result, target string, scope *domains.Scope) []model.Finding {
	var out []model.Finding
	add := func(rule string, sev model.Severity, loc, title, detail, evidence string) {
		out = append(out, model.Finding{
			Layer: model.LayerRuntime, Rule: rule, Severity: sev, Target: target, PageURL: r.PageURL,
			Location: loc, Title: title, Detail: detail, Evidence: model.Truncate(evidence, 240),
		})
	}

	for _, req := range r.Requests {
		host := domains.Host(req.URL)
		if scope.Allowed(host) || strings.HasPrefix(req.URL, "data:") {
			continue
		}
		which := leakedCanary(req.URL + "\n" + req.Body)
		if which == "" {
			continue
		}
		sev := model.High
		switch which {
		case "card number":
			sev = model.Critical
		case "form text":
			sev = model.Low // search boxes and address autocompletes legitimately send what you type
		}
		by := req.Initiator
		if by == "" {
			by = "unknown script"
		}
		add("canary-exfiltration", sev, by, "Typed "+which+" was sent to "+host,
			fmt.Sprintf("The scanner typed a fake %s into the page. Moments later %s sent it to %s, a host outside the store. "+
				"This is direct evidence of data theft, not a heuristic.", which, by, host),
			req.Method+" "+req.URL)
	}
	for _, f := range r.Frames {
		if which := leakedCanary(f); which != "" {
			add("canary-websocket", model.Critical, "WebSocket", "Typed "+which+" was sent over a WebSocket",
				"A fake value typed by the scanner left the page through a WebSocket.", f)
		}
	}
	cardPage := r.CardFields > 0
	for _, e := range r.Events {
		if e.Kind != "webrtc-send" {
			continue
		}
		src := e.Source
		switch which := leakedCanary(e.Detail); {
		case which != "":
			add("canary-webrtc", model.Critical, src, "Typed "+which+" was sent over a WebRTC data channel",
				"The scanner typed a fake "+which+" into the page and "+src+" pushed it through a WebRTC data channel. "+
					"That traffic goes straight to a peer as UDP, invisible to CSP and to HTTP monitoring. "+
					"This is direct evidence of data theft, the same technique as the 2026 PaperCut skimmer.", e.Detail)
		case !scope.Trusted(domains.Host(src)):
			sev := model.Medium
			if cardPage {
				sev = model.High
			}
			add("webrtc-data-sent", sev, src, "Page sends data over a WebRTC data channel",
				"Code from "+src+" sent data through a data channel. Stores almost never need this; on a payment page "+
					"it is the exfiltration channel of choice for skimmers that want to stay out of the network log.", e.Detail)
		}
	}
	if len(r.WebRTCPeers) > 0 {
		var untrusted []string
		for _, p := range r.WebRTCPeers {
			if !scope.Trusted(p) {
				untrusted = append(untrusted, p)
			}
		}
		if len(untrusted) > 0 {
			sev := model.Medium
			if cardPage {
				sev = model.High
			}
			add("webrtc-peer-external", sev, "WebRTC", "WebRTC connection set up with "+untrusted[0],
				"The page configured a WebRTC peer, relay or candidate at "+strings.Join(untrusted, ", ")+". "+
					"Fraud-detection scripts use public STUN servers from known providers; an unknown server or bare IP "+
					"is a channel the attacker controls.", strings.Join(untrusted, ", "))
		}
	}

	for _, s := range r.Sockets {
		if host := domains.Host(s); !scope.Trusted(host) {
			add("websocket-external", model.Medium, s, "WebSocket to an outside host",
				"Stores rarely need a live socket to an unknown host. Skimmers use them because they bypass some monitoring.", s)
		}
	}

	if fh := domains.Host(r.FinalURL); r.FinalURL != "" && !scope.Allowed(fh) && !strings.HasPrefix(r.FinalURL, "chrome-error") {
		add("runtime-redirect", model.High, "navigation", "Page sent the browser to "+fh,
			"Loading the page ended on a host outside the store. Unless this is an expected login or region redirect, it is a hijack.",
			r.PageURL+" → "+r.FinalURL)
	}

	for _, api := range r.NonNative {
		add("api-replaced", model.Medium, api, api+" was replaced by page code",
			"The page swapped a built-in network API for its own function. Monitoring tools do this; so do skimmers. "+
				"Combine with the static findings to see which script did it.", api)
	}

	for _, e := range r.Events {
		switch e.Kind {
		case "listener":
			if isCardListener(e.Detail) && !scope.Trusted(domains.Host(e.Source)) && e.Source != "inline" {
				add("card-listener-external", model.High, e.Source, "Outside script listens to a card field",
					"A script from "+domains.Host(e.Source)+" attached a listener to a payment input: "+e.Detail, e.Detail)
			}
		case "blocked-submit":
			// Expected: the scanner blocks submissions. Not a finding.
		}
	}
	return out
}

var (
	reICEURL   = regexp.MustCompile(`(?i)\b(?:stun|turns?):([a-z0-9.-]+|\[[0-9a-f:]+\])`)
	reCandAddr = regexp.MustCompile(`(?i)candidate:\S+ \d+ \w+ \d+ (\S+) \d+ typ`)
	reConnAddr = regexp.MustCompile(`(?m)^c=IN IP[46] (\S+)`)
)

// webrtcPeers lists the public addresses a page configured as WebRTC servers or peers.
// mDNS names (.local) and private ranges are the browser's own and are skipped.
func webrtcPeers(events []Event) []string {
	seen := map[string]bool{}
	var out []string
	addPeer := func(h string) {
		h = strings.ToLower(strings.Trim(h, "[]"))
		if h == "" || seen[h] || strings.HasSuffix(h, ".local") || h == "0.0.0.0" {
			return
		}
		if ip := net.ParseIP(h); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, e := range events {
		switch e.Kind {
		case "webrtc-peer":
			for _, m := range reICEURL.FindAllStringSubmatch(e.Detail, 20) {
				addPeer(m[1])
			}
		case "webrtc-remote":
			for _, m := range reCandAddr.FindAllStringSubmatch(e.Detail, 50) {
				addPeer(m[1])
			}
			for _, m := range reConnAddr.FindAllStringSubmatch(e.Detail, 10) {
				addPeer(m[1])
			}
		}
	}
	return out
}

func isCardListener(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "cc-") || strings.Contains(d, "card") || strings.Contains(d, "cvv") ||
		strings.Contains(d, "cvc") || strings.Contains(d, "tarjeta")
}

// EvaluatedCode returns code the page passed to eval or Function at runtime: the decoded
// form of whatever was hidden, ready for static analysis.
func EvaluatedCode(r *Result) []Event {
	var out []Event
	for _, e := range r.Events {
		if e.Kind == "eval" || e.Kind == "function" {
			out = append(out, e)
		}
	}
	return out
}

var b64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// leakedCanary looks for any canary in a request, raw or in the encodings skimmers use.
func leakedCanary(s string) string {
	candidates := []string{s}
	if u, err := url.QueryUnescape(s); err == nil {
		candidates = append(candidates, u)
	}
	for _, tok := range b64Token.FindAllString(s, 100) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(tok); err == nil {
				candidates = append(candidates, string(b))
			}
		}
	}
	for _, c := range candidates {
		switch {
		case strings.Contains(c, CanaryCard):
			return "card number"
		case strings.Contains(c, CanaryEmail):
			return "email"
		case strings.Contains(c, CanaryPassword):
			return "password"
		case strings.Contains(strings.ToLower(c), CanaryText):
			return "form text"
		}
	}
	return ""
}
