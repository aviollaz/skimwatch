package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

func TestLookalike(t *testing.T) {
	cases := map[string]string{
		"google-analytlcs.com":     "google-analytics.com",
		"googletagrnanager.com":    "googletagmanager.com",
		"google-analytics.top":     "google-analytics.com",
		"googletagmanager-cdn.com": "googletagmanager.com",
		"rnercadopago.com":         "mercadopago.com",
		"mercadopago.com.ar":       "",
		"mystore.com.ar":           "",
		"stripe.network":           "",
		// The providers' own secondary domains, reported as imitations by the nightly scan.
		"googletagservices.com": "",
		"withgoogle.com":        "",
		"hotjar.io":             "",
		"tiktokw.us":            "",
	}
	for in, want := range cases {
		if got := Lookalike(in); got != want {
			t.Errorf("%s: want %q, got %q", in, want, got)
		}
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	bl := filepath.Join(dir, "bl.txt")
	os.WriteFile(bl, []byte("# test\n0.0.0.0 evil-cdn.example\npolyfill.io\n"), 0o644)

	young := time.Now().Add(-5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	rdap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fresh-collector.top" {
			w.Write([]byte(`{"events":[{"eventAction":"registration","eventDate":"` + young + `"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer rdap.Close()

	c, err := New(Options{BlocklistFiles: []string{bl}, CheckAge: true, RDAPBase: rdap.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	scope := domains.NewScope([]string{"https://www.store.com.ar/"}, nil)
	got := map[string]model.Severity{}
	for _, f := range c.Check(context.Background(), "t",
		[]string{"cdn.polyfill.io", "evil-cdn.example", "fresh-collector.top", "www.google-analytics.com", "static.store.com.ar"}, scope) {
		got[f.Rule+" "+f.Location] = f.Severity
	}
	want := map[string]model.Severity{
		"blocklisted-domain cdn.polyfill.io":  model.Critical,
		"blocklisted-domain evil-cdn.example": model.Critical,
		"new-domain-age fresh-collector.top":  model.High,
		"cheap-tld fresh-collector.top":       model.Low,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("want %s=%s, got %v", k, v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected extra findings: %v", got)
	}
}

// PaperCut (2026) published two server IPs and one attacker repository on jsDelivr.
// Neither fits a domain blocklist: the IPs have no name and the CDN is legitimate.
func TestIPAndURLIndicators(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.txt")
	os.WriteFile(bl, []byte("89.116.171.109\ncdn.jsdelivr.net/gh/fs82g9omml/\nhttps://github.com/fs82g9omml/\n"), 0o644)
	c, err := New(Options{BlocklistFiles: []string{bl}})
	if err != nil {
		t.Fatal(err)
	}
	scope := domains.NewScope([]string{"https://www.diario.com.ar/"}, nil)
	got := map[string]model.Severity{}
	for _, f := range c.Check(context.Background(), "t", []string{"89.116.171.109", "203.0.113.7", "cdn.jsdelivr.net"}, scope) {
		got[f.Rule+" "+f.Location] = f.Severity
	}
	if got["blocklisted-domain 89.116.171.109"] != model.Critical {
		t.Errorf("listed IP should be critical, got %v", got)
	}
	if got["bare-ip-host 203.0.113.7"] != model.Medium {
		t.Errorf("unlisted bare IP should be medium, got %v", got)
	}
	if _, ok := got["blocklisted-domain cdn.jsdelivr.net"]; ok {
		t.Error("a URL indicator must not blocklist the whole CDN")
	}

	urls := []string{
		"https://cdn.jsdelivr.net/gh/FS82G9OMML/alianet@main/jQuery.1.3.1.js",
		"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
	}
	fs := c.CheckURLs("t", "https://pay.example/form", urls)
	if len(fs) != 1 || fs[0].Severity != model.Critical || fs[0].Location != urls[0] {
		t.Errorf("want one critical match on the attacker repo, got %+v", fs)
	}
}
