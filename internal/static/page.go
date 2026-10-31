package static

import (
	"fmt"
	"strings"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

// AnalyzePage runs every HTML-level check plus the JS checks on code embedded in the page.
// External scripts are analyzed separately, once their content has been fetched.
func AnalyzePage(doc *Document, target, pageURL string, scope *domains.Scope) []model.Finding {
	var out []model.Finding
	ctx := func(loc string) Context {
		return Context{Target: target, PageURL: pageURL, Location: loc, Scope: scope}
	}
	add := func(rule string, sev model.Severity, loc, title, detail, evidence string) {
		out = append(out, model.Finding{
			Layer: model.LayerStatic, Rule: rule, Severity: sev, Target: target, PageURL: pageURL,
			Location: loc, Title: title, Detail: detail, Evidence: model.Truncate(evidence, 240),
		})
	}

	for _, s := range doc.InlineJS {
		out = append(out, AnalyzeJS(s.Code, ctx(s.Location))...)
	}
	for _, s := range append(append([]Snippet{}, doc.Handlers...), doc.JSURLs...) {
		found := AnalyzeJS(s.Code, ctx(s.Location))
		out = append(out, found...)
		// Event handlers are tiny by nature. A long one is code that someone pasted into
		// a field that ends up rendered as HTML (a product description, a review...).
		if len(s.Code) > 400 && len(found) == 0 {
			add("long-handler", model.Medium, s.Location, "Unusually long inline event handler",
				fmt.Sprintf("%d characters of code in an attribute. Handlers are normally one call; long ones are a sign of injected content.", len(s.Code)),
				s.Code)
		}
	}

	for _, f := range doc.Iframes {
		host := domains.Host(f.URL)
		if scope.Trusted(host) {
			continue
		}
		if f.Hidden {
			add("hidden-iframe", model.High, "iframe "+f.URL, "Invisible iframe to an outside host",
				"A zero-size or hidden frame loading "+host+" can run code, phish or redirect without the visitor seeing it.", f.URL)
		}
	}
	for _, target := range doc.MetaRefresh {
		host := domains.Host(target)
		if !scope.Trusted(host) {
			add("meta-refresh-external", model.High, "<meta http-equiv=refresh>", "Page redirects visitors to an outside host",
				"A meta refresh sends every visitor to "+host+". On a store this is almost always a compromise.", target)
		}
	}
	for _, f := range doc.Forms {
		host := domains.Host(f.Action)
		if f.HasCardFields && !scope.Trusted(host) {
			add("card-form-external", model.High, "form action "+f.Action, "Card form posts to an outside host",
				"A form with payment fields submits to "+host+". Unless that is the store's payment provider (add it to the allowlist), card data is leaving.",
				f.Action)
		}
	}
	pageHTTPS := strings.HasPrefix(pageURL, "https://")
	for _, s := range doc.ExternalJS {
		host := domains.Host(s.URL)
		switch {
		case domains.IsIP(host):
			add("script-from-ip", model.High, s.URL, "Script loaded from a bare IP address",
				"Legitimate providers serve code from named domains and CDNs. A raw IP is typical of attacker infrastructure.", s.URL)
		case pageHTTPS && strings.HasPrefix(s.URL, "http://"):
			add("script-over-http", model.Medium, s.URL, "Script loaded over plain HTTP",
				"Anyone on the network path can replace this script. Browsers block it on HTTPS pages, but its presence means the page is misconfigured.", s.URL)
		}
	}
	return out
}
