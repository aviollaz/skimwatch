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
