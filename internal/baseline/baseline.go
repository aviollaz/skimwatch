// Package baseline compares a scan with the previous one. Supply-chain attacks replace a
// trusted script with a malicious version that may look clean in isolation; the change
// itself is the signal.
package baseline

import (
	"fmt"
	"sort"

	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/model"
)

// Compare reports scripts and domains that appeared or changed since the previous scan.
// A nil previous scan means this is the first one: it becomes the baseline and nothing is reported.
func Compare(prev *model.Scan, curr *model.Scan, scope *domains.Scope) []model.Finding {
	if prev == nil {
		return nil
	}
	var out []model.Finding
	add := func(rule string, sev model.Severity, page, loc, title, detail, evidence string) {
		out = append(out, model.Finding{
			Layer: model.LayerBaseline, Rule: rule, Severity: sev, Target: curr.Target, PageURL: page,
			Location: loc, Title: title, Detail: detail, Evidence: evidence,
		})
	}

	before := map[string]model.Script{}
	inlineBefore := map[string]bool{}
	for _, s := range prev.Scripts {
		if s.Src != "" {
			before[s.Key()] = s
		} else {
			inlineBefore[s.SHA256] = true
		}
	}

	reported := map[string]bool{}
	for _, s := range curr.Scripts {
		if s.Src == "" {
			if !inlineBefore[s.SHA256] && !reported[s.SHA256] {
				reported[s.SHA256] = true
				add("inline-script-changed", model.Info, s.PageURL, s.Location, "New or changed inline script",
					"Inline code differs from the last scan. Normal after a deploy; worth a look if nothing was deployed.",
					fmt.Sprintf("sha256 %s, %d bytes", s.SHA256[:16], s.Size))
			}
			continue
		}
		if reported[s.Key()] {
			continue
		}
		reported[s.Key()] = true
		host := domains.Host(s.Src)
		old, existed := before[s.Key()]
		switch {
		case !existed && scope.Allowed(host):
			add("new-script", model.Info, s.PageURL, s.Src, "New first-party script", "A script from the store's own domains appeared since the last scan.", s.Src)
		case !existed:
			sev := model.Medium
			if domains.IsKnownGood(host) {
				sev = model.Low
			}
			add("new-third-party-script", sev, s.PageURL, s.Src, "New script from "+host,
				"A third-party script appeared since the last scan. Confirm someone at the store added it on purpose.", s.Src)
		case old.SHA256 != s.SHA256 && !scope.Allowed(host) && !domains.IsKnownGood(host):
			add("third-party-script-changed", model.Medium, s.PageURL, s.Src, "Third-party script changed: "+host,
				fmt.Sprintf("Same URL, different content (%d → %d bytes). This is exactly how supply-chain attacks such as the "+
					"2024 polyfill.io compromise reached thousands of sites. Review the diff.", old.Size, s.Size),
				fmt.Sprintf("%s → %s", old.SHA256[:16], s.SHA256[:16]))
		case old.SHA256 != s.SHA256:
			add("script-changed", model.Info, s.PageURL, s.Src, "Script content changed",
				"A first-party or well-known provider script was updated. Usually a routine release.",
				fmt.Sprintf("%s → %s", old.SHA256[:16], s.SHA256[:16]))
		}
	}

	known := map[string]bool{}
	for _, d := range prev.Domains {
		known[d] = true
	}
	var fresh []string
	for _, d := range curr.Domains {
		if !known[d] {
			fresh = append(fresh, d)
		}
	}
	sort.Strings(fresh)
	for _, d := range fresh {
		sev := model.Low
		if domains.IsKnownGood(d) {
			sev = model.Info
		}
		add("new-domain", sev, "", d, "Pages now talk to "+d,
			"A third-party domain the pages did not contact in the previous scan.", d)
	}
	return out
}
