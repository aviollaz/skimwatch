package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "targets.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.RequestDelay != 3*time.Second || cfg.Settings.RuntimeWait != 8*time.Second {
		t.Errorf("durations not parsed: %+v", cfg.Settings)
	}
	if cfg.Settings.Timeout != Defaults().Timeout {
		t.Errorf("unset settings should keep defaults, got %v", cfg.Settings.Timeout)
	}
	if len(cfg.Targets) == 0 || len(cfg.Targets[0].Allow) == 0 {
		t.Errorf("targets not parsed: %+v", cfg.Targets)
	}
}

func TestRejectsBadConfig(t *testing.T) {
	for name, body := range map[string]string{
		"no targets":   "settings: {}\n",
		"bad url":      "targets:\n  - name: a\n    pages: [ftp://x]\n",
		"duplicate":    "targets:\n  - name: a\n    pages: [https://a.com]\n  - name: a\n    pages: [https://b.com]\n",
		"missing name": "targets:\n  - pages: [https://a.com]\n",
	} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
