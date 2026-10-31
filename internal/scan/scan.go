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
		findings = append(findings, static.AnalyzeJS(content, static.Context{
			Target: t.Name, PageURL: pageURL, Location: location, Scope: scope,
		})...)
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
			findings = append(findings, s.runtimeLayer(ctx, t.Name, resp.URL, scope, staticScripts, noteHost, analyzeScript, log)...)
		}
	}

	findings = append(findings, s.Intel.Check(ctx, t.Name, sortedKeys(thirdParty), scope)...)
	sc.Domains = sortedKeys(thirdParty)

	prev, err := s.Store.Previous(ctx, t.Name)
	if err != nil {
		sc.Errors = append(sc.Errors, "loading previous scan: "+err.Error())
	}
	findings = append(findings, baseline.Compare(prev, sc, scope)...)

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
	ctx context.Context, target, pageURL string, scope *domains.Scope, staticScripts map[string]string,
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
	for _, r := range res.Requests {
		noteHost(domains.Host(r.URL))
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
			old[f.Fingerprint()] = true
		}
	}
	for i := range fs {
		fs[i].New = !old[fs[i].Fingerprint()]
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
