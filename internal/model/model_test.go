package model

import "testing"

func TestStableURLs(t *testing.T) {
	// Pairs of locations from consecutive nightly scans that must count as the same script.
	same := [][2]string{
		{"runtime-loaded https://script.hotjar.com/modules.e85a87e594b0aace33cf.js",
			"runtime-loaded https://script.hotjar.com/modules.47ae0ae40a423a71e31f.js"},
		{"runtime-loaded https://securepubads.g.doubleclick.net/pagead/managed/js/gpt/m202610270101/pubads_impl.js?cb=122881924",
			"runtime-loaded https://securepubads.g.doubleclick.net/pagead/managed/js/gpt/m202611030101/pubads_impl.js?cb=122882097"},
		{"runtime-loaded https://www.googletagmanager.com/gtag/js?id=AW-10996412706&cx=c&gtm=4e6as1",
			"runtime-loaded https://www.googletagmanager.com/gtag/js?gtm=4e6b31&cx=c&id=AW-10996412706"},
		{"runtime-loaded https://www.gstatic.com/recaptcha/releases/bSuJ2xBC8cFy7pM4Z3Hu9boH/recaptcha__es_419.js",
			"runtime-loaded https://www.gstatic.com/recaptcha/releases/bSuJ2xBC8cHT21-c68JXN31m/recaptcha__es_419.js"},
		{"runtime-loaded https://analytics.tiktok.com/i18n/pixel/static/main.MTJjYzk1MmQ1MA.js",
			"runtime-loaded https://analytics.tiktok.com/i18n/pixel/static/main.MTJjYzk1MmQ1MQ.js"},
	}
	for _, p := range same {
		if a, b := StableURLs(p[0]), StableURLs(p[1]); a != b {
			t.Errorf("should match:\n  %s\n  %s", a, b)
		}
	}

	// Different scripts must stay different.
	different := [][2]string{
		{"https://cdn.example.com/checkout.js", "https://cdn.example.com/payment.js"},
		{"https://www.googletagmanager.com/gtm.js?id=GTM-TMWBWNM", "https://www.googletagmanager.com/gtm.js?id=GTM-53LM5RF"},
		{"https://shop.example/a.js", "https://evil.example/a.js"},
	}
	for _, p := range different {
		if StableURLs(p[0]) == StableURLs(p[1]) {
			t.Errorf("should differ: %s vs %s", p[0], p[1])
		}
	}
}

func TestBaselineKeyIgnoresEvidence(t *testing.T) {
	a := Finding{Layer: LayerStatic, Rule: "skimmer-pattern", Target: "vea", Location: "https://x.example/a.js", Evidence: "one"}
	b := a
	b.Evidence = "two"
	if a.BaselineKey() != b.BaselineKey() {
		t.Error("evidence should not affect the baseline key")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("evidence should still distinguish findings for deduplication")
	}
}
