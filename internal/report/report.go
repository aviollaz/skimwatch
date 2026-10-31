// Package report renders scans as a single self-contained HTML page.
// Evidence is attacker-controlled text, so it goes through html/template's escaping and is
// never placed in a script, style or URL context.
package report

import (
	_ "embed"
	"html/template"
	"io"
	"time"

	"github.com/aviollaz/skimwatch/internal/model"
)

//go:embed report.html.tmpl
var tmplSrc string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sev": func(s model.Severity) string { return s.String() },
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
}).Parse(tmplSrc))

type targetView struct {
	Scan   *model.Scan
	Counts [5]int
	Max    string
}

type view struct {
	Generated time.Time
	Targets   []targetView
	Totals    [5]int
	NewCount  int
}

// Write renders every scan into one page.
func Write(w io.Writer, scans []*model.Scan) error {
	v := view{Generated: time.Now().UTC()}
	for _, s := range scans {
		if s == nil {
			continue
		}
		tv := targetView{Scan: s, Max: "clean"}
		for _, f := range s.Findings {
			tv.Counts[f.Severity]++
			v.Totals[f.Severity]++
			if f.New && f.Severity >= model.Medium {
				v.NewCount++
			}
		}
		if m := s.MaxSeverity(); m >= 0 {
			tv.Max = m.String()
		}
		v.Targets = append(v.Targets, tv)
	}
	return tmpl.Execute(w, v)
}
