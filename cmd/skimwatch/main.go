// Command skimwatch watches online stores for client-side attacks: card skimmers,
// malicious redirects, cryptominers and compromised third-party scripts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aviollaz/skimwatch/internal/config"
	"github.com/aviollaz/skimwatch/internal/domains"
	"github.com/aviollaz/skimwatch/internal/fetch"
	"github.com/aviollaz/skimwatch/internal/intel"
	"github.com/aviollaz/skimwatch/internal/model"
	"github.com/aviollaz/skimwatch/internal/report"
	"github.com/aviollaz/skimwatch/internal/runtime"
	"github.com/aviollaz/skimwatch/internal/scan"
	"github.com/aviollaz/skimwatch/internal/static"
	"github.com/aviollaz/skimwatch/internal/store"
)

const usage = `skimwatch: client-side attack monitor for online stores

Usage:
  skimwatch scan    -config targets.yaml [flags]   scan every target and write a report
  skimwatch analyze [-url page-url] FILE...        analyze local .js or .html files offline

Run "skimwatch scan -h" for scan flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "scan":
		code = runScan(os.Args[2:])
	case "analyze":
		code = runAnalyze(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	os.Exit(code)
}

// Exit codes are the CI contract: 0 nothing new at or above -fail-on, 1 new findings, 2 the scan could not run.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "targets.yaml", "targets file")
	dbURL := fs.String("db", os.Getenv("DATABASE_URL"), "Postgres URL for scan history (default $DATABASE_URL); empty uses -state")
	stateDir := fs.String("state", ".skimwatch", "directory for scan history when no database is configured")
	reportPath := fs.String("report", "report.html", "HTML report output")
	jsonPath := fs.String("json", "", "optional JSON output with every finding")
	chrome := fs.String("chrome", os.Getenv("SKIMWATCH_CHROME"), "Chrome/Chromium binary (default: autodetect)")
	noBrowser := fs.Bool("no-browser", false, "skip the runtime layer")
	noSandbox := fs.Bool("no-sandbox", false, "run Chrome without its sandbox (needed in some containers)")
	failOn := fs.String("fail-on", "high", "exit 1 when a NEW finding is at or above this severity (critical, high, medium, low, info, none)")
	var blocklists multiFlag
	fs.Var(&blocklists, "blocklist", "domain blocklist file (repeatable); data/blocklist.txt is used when present")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		return 2
	}
	st := cfg.Settings

	if len(blocklists) == 0 {
		if _, err := os.Stat(filepath.Join("data", "blocklist.txt")); err == nil {
			blocklists = append(blocklists, filepath.Join("data", "blocklist.txt"))
		}
	}
	checker, err := intel.New(intel.Options{BlocklistFiles: blocklists, CheckAge: st.CheckDomainAge})
	if err != nil {
		log.Error("intel", "err", err)
		return 2
	}
	log.Info("blocklist loaded", "domains", checker.BlocklistSize())

	var history store.Store
	if *dbURL != "" {
		history, err = store.NewPostgresStore(ctx, *dbURL)
	} else {
		history, err = store.NewFileStore(*stateDir)
	}
	if err != nil {
		log.Error("store", "err", err)
		return 2
	}
	defer history.Close()

	var browser *runtime.Browser
	if !*noBrowser {
		browser, err = runtime.NewBrowser(ctx, runtime.BrowserOptions{ExecPath: *chrome, UserAgent: st.UserAgent, NoSandbox: *noSandbox})
		if err != nil {
			log.Error("browser unavailable; rerun with -no-browser to skip the runtime layer", "err", err)
			return 2
		}
		defer browser.Close()
	}

	s := &scan.Scanner{
		Config: cfg,
		Fetcher: fetch.New(fetch.Options{
			UserAgent: st.UserAgent, Delay: st.RequestDelay, Timeout: st.Timeout,
			MaxBodyBytes: st.MaxBodyBytes, RespectRobots: st.RespectRobots,
		}),
		Browser: browser,
		Intel:   checker,
		Store:   history,
		Log:     log,
	}
	scans := s.Run(ctx)

	if err := writeFile(*reportPath, func(f *os.File) error { return report.Write(f, scans) }); err != nil {
		log.Error("report", "err", err)
		return 2
	}
	log.Info("report written", "path", *reportPath)
	if *jsonPath != "" {
		if err := writeFile(*jsonPath, func(f *os.File) error {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			return enc.Encode(scans)
		}); err != nil {
			log.Error("json", "err", err)
			return 2
		}
	}

	if *failOn == "none" {
		return 0
	}
	threshold := model.ParseSeverity(*failOn)
	newBad := 0
	for _, sc := range scans {
		for _, f := range sc.Findings {
			if f.New && f.Severity >= threshold {
				newBad++
				log.Warn("new finding", "target", f.Target, "severity", f.Severity, "title", f.Title, "where", f.Location)
			}
		}
	}
	if newBad > 0 {
		log.Warn("scan found new problems", "count", newBad, "threshold", threshold)
		return 1
	}
	return 0
}

// runAnalyze is the offline mode: paste a suspicious script or saved page into a file and
// get the static layer's verdict without touching the network.
func runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	pageURL := fs.String("url", "https://store.invalid/", "URL the file was taken from (decides which hosts count as first party)")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "analyze: give at least one .js or .html file")
		return 2
	}
	scope := domains.NewScope([]string{*pageURL}, nil)
	worst := model.Severity(-1)
	for _, path := range fs.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		var findings []model.Finding
		if strings.HasSuffix(strings.ToLower(path), ".js") {
			findings = static.AnalyzeJS(string(raw), static.Context{Target: path, PageURL: *pageURL, Location: path, Scope: scope})
		} else {
			doc, err := static.ParseHTML(raw, *pageURL)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			findings = static.AnalyzePage(doc, path, *pageURL, scope) // includes inline scripts and handlers
		}
		fmt.Printf("== %s: %d finding(s)\n", path, len(findings))
		for _, f := range findings {
			if f.Severity > worst {
				worst = f.Severity
			}
			fmt.Printf("  [%-8s] %s\n             %s\n", f.Severity, f.Title, f.Location)
			if f.Evidence != "" {
				fmt.Printf("             evidence: %s\n", model.Truncate(f.Evidence, 120))
			}
		}
	}
	if worst >= model.High {
		return 1
	}
	return 0
}

func writeFile(path string, fn func(*os.File) error) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return errors.Join(fn(f), f.Close())
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
