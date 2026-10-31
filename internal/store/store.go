// Package store persists scans so each run can be compared with the previous one.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aviollaz/skimwatch/internal/model"
)

// Store keeps the history of scans.
type Store interface {
	// Previous returns the most recent stored scan for a target, or nil if there is none.
	Previous(ctx context.Context, target string) (*model.Scan, error)
	// Save records a finished scan.
	Save(ctx context.Context, s *model.Scan) error
	Close() error
}

// FileStore keeps the latest scan of each target as a JSON file. Good for local runs.
type FileStore struct{ dir string }

// NewFileStore creates the directory if needed.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func (f *FileStore) path(target string) string {
	return filepath.Join(f.dir, unsafeChars.ReplaceAllString(target, "_")+".json")
}

// Previous implements Store.
func (f *FileStore) Previous(_ context.Context, target string) (*model.Scan, error) {
	raw, err := os.ReadFile(f.path(target))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s model.Scan
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("reading previous scan of %s: %w", target, err)
	}
	return &s, nil
}

// Save implements Store. It writes to a temp file first so a crash never leaves a half-written baseline.
func (f *FileStore) Save(_ context.Context, s *model.Scan) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path(s.Target) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(s.Target))
}

// Close implements Store.
func (f *FileStore) Close() error { return nil }
