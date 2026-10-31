package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aviollaz/skimwatch/internal/model"
)

func sample(target string, at time.Time, sev model.Severity) *model.Scan {
	return &model.Scan{
		Target: target, StartedAt: at, FinishedAt: at.Add(time.Second),
		Scripts:  []model.Script{model.NewScript("https://s.example/", "external", "https://cdn.example/a.js", "var a=1")},
		Findings: []model.Finding{{Layer: model.LayerStatic, Rule: "r", Severity: sev, Target: target, Title: "t", Evidence: "e"}},
	}
}

func exercise(t *testing.T, s Store) {
	ctx := context.Background()
	prev, err := s.Previous(ctx, "shop")
	if err != nil || prev != nil {
		t.Fatalf("empty store should return nil, got %v %v", prev, err)
	}
	t0 := time.Now().UTC().Truncate(time.Second)
	if err := s.Save(ctx, sample("shop", t0, model.Low)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, sample("shop", t0.Add(time.Hour), model.Critical)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Previous(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.StartedAt.Equal(t0.Add(time.Hour)) || got.Findings[0].Severity != model.Critical {
		t.Fatalf("Previous should return the latest scan, got %+v", got)
	}
	if got.Scripts[0].SHA256 == "" {
		t.Error("script hashes must survive a round trip")
	}
}

func TestFileStore(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
}

// Set SKIMWATCH_TEST_DB to a throwaway database to run this.
func TestPostgresStore(t *testing.T) {
	url := os.Getenv("SKIMWATCH_TEST_DB")
	if url == "" {
		t.Skip("SKIMWATCH_TEST_DB not set")
	}
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.pool.Exec(ctx, "TRUNCATE scans CASCADE")
	exercise(t, s)

	// The same finding twice keeps the date it was first seen.
	var first, latest time.Time
	if err := s.pool.QueryRow(ctx, `SELECT MIN(first_seen), MAX(first_seen) FROM findings WHERE target='shop'`).Scan(&first, &latest); err != nil {
		t.Fatal(err)
	}
	if !first.Equal(latest) {
		t.Errorf("first_seen should be stable across scans: %v vs %v", first, latest)
	}
	// Applying the schema again must be harmless.
	if _, err := NewPostgresStore(ctx, url); err != nil {
		t.Errorf("schema should be idempotent: %v", err)
	}
}
