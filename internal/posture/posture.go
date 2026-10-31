// Package posture reports missing defenses. None of these are attacks; they are the
// protections that would have limited one. A strict Content-Security-Policy, for example,
// would have stopped the Vea skimmer from sending data anywhere.
package posture

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
	"github.com/aviollaz/skimwatch/internal/static"
)

// Check inspects one page's response headers and script tags.
func Check(target, pageURL string, h http.Header, doc *static.Document, scope *domains.Scope) []model.Finding {
	var out []model.Finding
	add := func(rule string, sev model.Severity, title, detail, evidence string) {
		out = append(out, model.Finding{
			Layer: model.LayerPosture, Rule: rule, Severity: sev, Target: target, PageURL: pageURL,
			Location: "response headers", Title: title, Detail: detail, Evidence: model.Truncate(evidence, 240),
		})
	}

	if strings.HasPrefix(pageURL, "http://") {
		add("no-https", model.Medium, "Page served over plain HTTP",
			"Anything on the network path can read or modify the page, including injecting a skimmer.", pageURL)
	}

	csp := h.Get("Content-Security-Policy")
	switch {
	case csp == "":
		add("no-csp", model.Low, "No Content-Security-Policy",
			"A CSP with connect-src and script-src limits where code can load from and send data to. "+
				"It is the main browser-side defense against skimmers.", "")
	default:
		dirs := parseCSP(csp)
		script := firstNonEmpty(dirs["script-src"], dirs["default-src"])
		var weak []string
		if script == "" {
			weak = append(weak, "no script-src")
		}
		for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:"} {
			if containsToken(script, bad) {
				if bad == "'unsafe-inline'" && (strings.Contains(script, "'nonce-") || strings.Contains(script, "'sha")) {
					continue // ignored by browsers when a nonce or hash is present
				}
				weak = append(weak, "script-src "+bad)
			}
		}
		if firstNonEmpty(dirs["connect-src"], dirs["default-src"]) == "" {
			weak = append(weak, "no connect-src (data can be sent anywhere)")
		}
		if len(weak) > 0 {
			add("weak-csp", model.Info, "Content-Security-Policy is permissive",
				"The policy exists but would not stop an injected script: "+strings.Join(weak, "; ")+".", csp)
		}
	}

	if strings.HasPrefix(pageURL, "https://") && h.Get("Strict-Transport-Security") == "" {
		add("no-hsts", model.Low, "No HSTS header",
			"Without Strict-Transport-Security, a visitor's first request can be downgraded to HTTP and tampered with.", "")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		add("no-frame-protection", model.Info, "Page can be framed by any site",
			"Neither X-Frame-Options nor CSP frame-ancestors is set, which allows clickjacking.", "")
	}

	if doc != nil {
		var missing []string
		for _, s := range doc.ExternalJS {
			if s.Integrity == "" && !scope.Allowed(domains.Host(s.URL)) {
				missing = append(missing, s.URL)
			}
		}
		if len(missing) > 0 {
			add("no-sri", model.Info, fmt.Sprintf("%d third-party script(s) without Subresource Integrity", len(missing)),
				"Without an integrity hash, the browser runs whatever the third party serves today. SRI is not possible for "+
					"scripts that change constantly (tag managers), but static libraries should have it.",
				strings.Join(missing, ", "))
		}
	}
	return out
}

func parseCSP(csp string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(csp, ";") {
		f := strings.Fields(strings.TrimSpace(part))
		if len(f) == 0 {
			continue
		}
		m[strings.ToLower(f[0])] = strings.Join(f[1:], " ") + " "
	}
	return m
}

func containsToken(list, tok string) bool {
	for _, f := range strings.Fields(list) {
		if f == tok {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
