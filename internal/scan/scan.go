// Package scan runs every layer over every target and assembles the results.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aviollaz/skimwatch/internal/baseline"
	"github.com/aviollaz/skimwatch/internal/config"
	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/fetch"
	"github.com/aviollaz/skimwatch/internal/intel"
	"github.com/aviollaz/skimwatch/internal/model"
	"github.com/aviollaz/skimwatch/internal/posture"
	"github.com/aviollaz/skimwatch/internal/runtime"
	"github.com/aviollaz/skimwatch/internal/static"
	"github.com/aviollaz/skimwatch/internal/store"
)

// Scanner wires the layers together. Browser may be nil to skip the runtime layer.
type Scanner struct {
	Config  *config.Config
	Fetcher *fetch.Fetcher
	Browser *runtime.Browser
	Intel   *intel.Checker
	Store   store.Store
	Log     *slog.Logger
}

// Run scans every target, a few at a time, and returns one Scan per target.
func (s *Scanner) Run(ctx context.Context) []*model.Scan {
	targets := s.Config.Targets
	results := make([]*model.Scan, len(targets))
	sem := make(chan struct{}, s.Config.Settings.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.scanTarget(ctx, t)
		}()
	}
	wg.Wait()
	return results
}

func (s *Scanner) scanTarget(ctx context.Context, t config.Target) *model.Scan {
	log := s.Log.With("target", t.Name)
	sc := &model.Scan{Target: t.Name, StartedAt: time.Now().UTC()}
	scope := domains.NewScope(t.Pages, t.Allow)
	thirdParty := map[string]bool{}
	staticScripts := map[string]string{} // URL → hash of what a plain HTTP client received
	var findings []model.Finding

	noteHost := func(h string) {
		if h != "" && !scope.Allowed(h) {
			thirdParty[h] = true
		}
	}
	analyzeScript := func(pageURL, location, src, content string) {
		sc.Scripts = append(sc.Scripts, model.NewScript(pageURL, location, src, content))
		fs := static.AnalyzeJS(content, static.Context{
			Target: t.Name, PageURL: pageURL, Location: location, Scope: scope,
		})
		if fromKnownProvider(src, scope) {
			capSeverity(fs, model.Medium)
		}
		findings = append(findings, fs...)
	}

	for _, page := range t.Pages {
		log.Info("fetching page", "url", page)
		resp, err := s.Fetcher.Get(ctx, page)
		if err != nil {
			sc.Errors = append(sc.Errors, err.Error())
			log.Warn("page failed", "url", page, "err", err)
			continue
		}
		sc.Pages = append(sc.Pages, resp.URL)
		if h := domains.Host(resp.URL); !scope.Allowed(h) {
			findings = append(findings, model.Finding{
				Layer: model.LayerStatic, Rule: "http-redirect-external", Severity: model.High, Target: t.Name, PageURL: page,
				Location: "HTTP redirect", Title: "Page redirects to " + h,
				Detail:   "Requesting the store's page ended on a host outside the store.",
				Evidence: strings.Join(append([]string{page}, resp.Redirects...), " → "),
			})
		}
		if resp.Status >= 400 {
			sc.Errors = append(sc.Errors, fmt.Sprintf("%s returned HTTP %d", page, resp.Status))
		}

		doc, err := static.ParseHTML(resp.Body, resp.URL)
		if err != nil {
			sc.Errors = append(sc.Errors, err.Error())
			continue
		}
		findings = append(findings, static.AnalyzePage(doc, t.Name, resp.URL, scope)...)
		findings = append(findings, posture.Check(t.Name, resp.URL, resp.Header, doc, scope)...)

		for _, in := range doc.InlineJS {
			analyzeScript(resp.URL, in.Location, "", in.Code)
		}
		for _, h := range doc.Handlers {
			sc.Scripts = append(sc.Scripts, model.NewScript(resp.URL, h.Location, "", h.Code)) // analyzed by AnalyzePage
		}
		for _, f := range doc.Iframes {
			noteHost(domains.Host(f.URL))
		}
		cardPage := t.Shared() || hasCardForm(doc)
		var loaded []string
		for _, f := range doc.Iframes {
			loaded = append(loaded, f.URL)
		}
		for _, ext := range doc.ExternalJS {
			loaded = append(loaded, ext.URL)
			findings = append(findings, userHostedScript(t.Name, resp.URL, ext.URL, cardPage)...)
		}
		findings = append(findings, s.Intel.CheckURLs(t.Name, resp.URL, loaded)...)
		for _, ext := range doc.ExternalJS {
			noteHost(domains.Host(ext.URL))
			if _, done := staticScripts[ext.URL]; done {
				continue
			}
			r, err := s.Fetcher.Get(ctx, ext.URL)
			if err != nil {
				sc.Errors = append(sc.Errors, err.Error())
				staticScripts[ext.URL] = ""
				continue
			}
			content := string(r.Body)
			staticScripts[ext.URL] = model.NewScript("", "", "", content).SHA256
			analyzeScript(resp.URL, ext.URL, ext.URL, content)
		}

		if s.Browser != nil {
			findings = append(findings, s.runtimeLayer(ctx, t.Name, resp.URL, cardPage, scope, staticScripts, noteHost, analyzeScript, log)...)
		}
	}

	findings = append(findings, s.Intel.Check(ctx, t.Name, sortedKeys(thirdParty), scope)...)
	sc.Domains = sortedKeys(thirdParty)

	prev, err := s.Store.Previous(ctx, t.Name)
	if err != nil {
		sc.Errors = append(sc.Errors, "loading previous scan: "+err.Error())
	}
	findings = append(findings, baseline.Compare(prev, sc, scope, t.Shared())...)

	if t.Shared() && len(t.UsedBy) > 0 {
		note := " This form is shared: what affects it affects " + strings.Join(t.UsedBy, ", ") + "."
		for i := range findings {
			if findings[i].Severity >= model.Medium {
				findings[i].Detail += note
			}
		}
	}
	sc.Findings = dedupe(findings)
	markNew(sc.Findings, prev)
	sort.SliceStable(sc.Findings, func(i, j int) bool { return sc.Findings[i].Severity > sc.Findings[j].Severity })
	sc.FinishedAt = time.Now().UTC()

	if err := s.Store.Save(ctx, sc); err != nil {
		sc.Errors = append(sc.Errors, "saving scan: "+err.Error())
		log.Error("saving scan failed", "err", err)
	}
	log.Info("target done", "findings", len(sc.Findings), "max", sc.MaxSeverity(), "errors", len(sc.Errors))
	return sc
}

func (s *Scanner) runtimeLayer(
	ctx context.Context, target, pageURL string, cardPage bool, scope *domains.Scope, staticScripts map[string]string,
	noteHost func(string), analyzeScript func(pageURL, location, src, content string), log *slog.Logger,
) []model.Finding {
	log.Info("loading page in browser", "url", pageURL)
	res, err := s.Browser.Visit(ctx, pageURL, s.Config.Settings.RuntimeWait)
	if err != nil {
		log.Warn("browser visit failed", "url", pageURL, "err", err)
		return []model.Finding{{
			Layer: model.LayerRuntime, Rule: "runtime-error", Severity: model.Info, Target: target, PageURL: pageURL,
			Location: "browser", Title: "Runtime analysis incomplete", Detail: err.Error(),
		}}
	}
	out := runtime.Analyze(res, target, scope)
	var urls []string
	for _, r := range res.Requests {
		noteHost(domains.Host(r.URL))
		urls = append(urls, r.URL)
		if r.Type == "Script" {
			if _, inHTML := staticScripts[r.URL]; !inHTML {
				out = append(out, userHostedScript(target, pageURL, r.URL, cardPage || res.CardFields > 0)...)
			}
		}
	}
	out = append(out, s.Intel.CheckURLs(target, pageURL, urls)...)
	for _, peer := range res.WebRTCPeers {
		noteHost(peer) // bare IPs and relay hosts go through the blocklist and reputation checks
	}
	for _, ws := range res.Sockets {
		noteHost(domains.Host(ws))
	}
	for _, sc := range res.Scripts {
		hash := model.NewScript("", "", "", sc.Content).SHA256
		prevHash, fetched := staticScripts[sc.URL]
		switch {
		case !fetched:
			// Not in the HTML: added at runtime by another script. Analyze it like any other.
			staticScripts[sc.URL] = hash
			analyzeScript(pageURL, "runtime-loaded "+sc.URL, sc.URL, sc.Content)
		case prevHash != "" && prevHash != hash && !scope.Allowed(domains.Host(sc.URL)) && !domains.IsKnownGood(domains.Host(sc.URL)):
			// Same URL, different code depending on who asks: a classic way to hide from scanners.
			out = append(out, model.Finding{
				Layer: model.LayerRuntime, Rule: "cloaked-script", Severity: model.Medium, Target: target, PageURL: pageURL,
				Location: sc.URL, Title: "Script differs between the browser and a plain request",
				Detail: "The server sent different code to the browser than to a direct HTTP request. Some CDNs vary " +
					"responses legitimately, but skimmers use this to show clean code to scanners. The browser's version was analyzed too.",
				Evidence: prevHash[:16] + " → " + hash[:16],
			})
			analyzeScript(pageURL, "browser version of "+sc.URL, "", sc.Content)
		}
	}
	for _, e := range runtime.EvaluatedCode(res) {
		out = append(out, static.AnalyzeJS(e.Detail, static.Context{
			Target: target, PageURL: pageURL, Location: "code evaluated at runtime by " + e.Source, Scope: scope,
		})...)
	}
	return out
}

// fromKnownProvider reports whether a script is served by a widely used provider (Google,
// Meta, Hotjar, TikTok, VTEX...) rather than by the store or an unknown host. Their tracking
// libraries read forms and send data out by design, which is exactly what the skimmer rules
// look for. Hosts on the store's allowlist are excluded: that is the store's own code, the
// usual place for injected skimmers. So are Google Tag Manager containers, which hold code
// the store (or whoever gets into its GTM account) configures, and have hosted real skimmers.
func fromKnownProvider(src string, scope *domains.Scope) bool {
	host := domains.Host(src)
	if host == "" || scope.Allowed(host) || !domains.IsKnownGood(host) {
		return false
	}
	if _, userCode := domains.ParseUserCode(src); userCode {
		return false // jsDelivr is trusted; whoever pushed this file to GitHub or npm is not
	}
	return !(domains.Registrable(host) == "googletagmanager.com" && strings.Contains(src, "/gtm.js"))
}

// hasCardForm reports whether the page asks for payment card data.
func hasCardForm(doc *static.Document) bool {
	for _, f := range doc.Forms {
		if f.HasCardFields {
			return true
		}
	}
	return false
}

// userHostedScript judges a script served by a public CDN out of someone's repository or
// package. Pinned npm versions are everywhere and stay quiet; code from a personal GitHub
// account, a moving ref or a file named after a library it is not, is reported, and more
// loudly on pages that take card numbers.
func userHostedScript(target, pageURL, src string, cardPage bool) []model.Finding {
	uc, ok := domains.ParseUserCode(src)
	if !ok {
		return nil
	}
	fake := uc.ImpersonatedLibrary()
	var sev model.Severity
	var why []string
	switch {
	case uc.Service == "github":
		sev = model.Medium
		why = append(why, "it is served straight from the GitHub account "+uc.Account()+", which anyone can create")
	case uc.Mutable:
		sev = model.Low
		why = append(why, "it is an npm package without a pinned version")
	case fake == "":
		return nil
	default:
		sev = model.Low
	}
	if uc.Mutable && uc.Service == "github" {
		why = append(why, "the ref "+orLatest(uc.Ref)+" can be changed to new code at any time under the same URL")
		sev++
	}
	if fake != "" {
		why = append(why, "the file is named like "+fake+" but does not come from "+fake+"'s official account")
		sev++
	}
	if cardPage {
		why = append(why, "the page asks for card data")
		sev++
	}
	if sev > model.Critical {
		sev = model.Critical
	}
	return []model.Finding{{
		Layer: model.LayerStatic, Rule: "user-hosted-script", Severity: sev, Target: target, PageURL: pageURL,
		Location: src, Title: "Script loaded from a personal " + uc.Service + " repository: " + uc.Account(),
		Detail: "Public CDNs like jsDelivr serve whatever their users publish, so the CDN's reputation says nothing " +
			"about this file. Flagged because " + strings.Join(why, "; ") + ". The 2026 PaperCut skimmer was loaded " +
			"exactly this way, as a fake jQuery from a throwaway GitHub account. Confirm the store owns this repository " +
			"and pin it to a commit with Subresource Integrity, or self-host it.",
		Evidence: src,
	}}
}

func orLatest(ref string) string {
	if ref == "" {
		return "(none, so the latest)"
	}
	return "@" + ref
}

// capSeverity keeps findings in the report but below max, so a provider's own library
// does not fail the nightly run. Integrity changes still surface through the baseline layer.
func capSeverity(fs []model.Finding, max model.Severity) {
	for i := range fs {
		if fs[i].Severity > max {
			fs[i].Severity = max
			fs[i].Detail += " Severity lowered: this script is served by a widely used provider, " +
				"and its own tracking code matches these patterns legitimately."
		}
	}
}

func dedupe(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		k := f.Fingerprint()
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func markNew(fs []model.Finding, prev *model.Scan) {
	old := map[string]bool{}
	if prev != nil {
		for _, f := range prev.Findings {
			old[f.BaselineKey()] = true
		}
	}
	for i := range fs {
		fs[i].New = !old[fs[i].BaselineKey()]
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
