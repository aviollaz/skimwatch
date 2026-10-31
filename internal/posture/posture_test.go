package posture

import (
	"net/http"
	"testing"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/static"
)

func ruleSet(h http.Header, doc *static.Document) map[string]bool {
	page := "https://shop.example.com/"
	out := map[string]bool{}
	for _, f := range Check("t", page, h, doc, domains.NewScope([]string{page}, nil)) {
		out[f.Rule] = true
	}
	return out
}

func TestPosture(t *testing.T) {
	doc := &static.Document{ExternalJS: []static.ExternalScript{
		{URL: "https://cdn.other.com/lib.js"},
		{URL: "https://cdn.other.com/pinned.js", Integrity: "sha384-abc"},
		{URL: "https://shop.example.com/app.js"},
	}}
	bare := ruleSet(http.Header{}, doc)
	for _, r := range []string{"no-csp", "no-hsts", "no-frame-protection", "no-sri"} {
		if !bare[r] {
			t.Errorf("missing %s on a page with no headers: %v", r, bare)
		}
	}

	strong := http.Header{}
	strong.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
	strong.Set("Strict-Transport-Security", "max-age=63072000")
	if got := ruleSet(strong, nil); len(got) != 0 {
		t.Errorf("a strict policy should raise nothing, got %v", got)
	}

	weak := http.Header{}
	weak.Set("Content-Security-Policy", "script-src * 'unsafe-eval'")
	if !ruleSet(weak, nil)["weak-csp"] {
		t.Error("wildcard script-src should be reported as weak")
	}
}
