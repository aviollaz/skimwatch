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
		"bad kind":     "targets:\n  - name: a\n    kind: bank\n    pages: [https://a.com]\n",
	} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestKinds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(`targets:
  - name: shop
    pages: [https://shop.example]
  - name: form
    kind: shared-checkout
    pages: [https://pay.example/form]
    used_by: [diario-a, diario-b]
`), 0o644)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets[0].Kind != KindStore || cfg.Targets[0].Shared() {
		t.Errorf("kind should default to store, got %q", cfg.Targets[0].Kind)
	}
	if !cfg.Targets[1].Shared() || len(cfg.Targets[1].UsedBy) != 2 {
		t.Errorf("shared checkout not parsed: %+v", cfg.Targets[1])
	}
}
