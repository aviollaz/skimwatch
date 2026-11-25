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
	"time"

	"github.com/aviollaz/skimwatch/internal/model"
)

// Store keeps the history of scans.
type Store interface {
	// Previous returns the most recent stored scan for a target, or nil if there is none.
	Previous(ctx context.Context, target string) (*model.Scan, error)
	// Seen returns the baseline keys of every finding in the target's scans that started at
	// or after since. A finding is only "new" if it is absent from all of them: the browser
	// loads a different set of scripts on each visit, so comparing with just the previous
	// night made the same findings flap in and out and fail the run again and again.
	Seen(ctx context.Context, target string, since time.Time) (map[string]bool, error)
	// Save records a finished scan.
	Save(ctx context.Context, s *model.Scan) error
	Close() error
}

// FileStore keeps the latest scan of each target as a JSON file, plus the baseline keys it
// has seen and when. Good for local runs.
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

func (f *FileStore) seenPath(target string) string {
	return filepath.Join(f.dir, unsafeChars.ReplaceAllString(target, "_")+".seen.json")
}

func (f *FileStore) readSeen(target string) (map[string]time.Time, error) {
	raw, err := os.ReadFile(f.seenPath(target))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]time.Time{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]time.Time{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("reading seen findings of %s: %w", target, err)
	}
	return m, nil
}

// Seen implements Store.
func (f *FileStore) Seen(_ context.Context, target string, since time.Time) (map[string]bool, error) {
	m, err := f.readSeen(target)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k, at := range m {
		if !at.Before(since) {
			out[k] = true
		}
	}
	return out, nil
}

// Save implements Store. It writes to a temp file first so a crash never leaves a half-written baseline.
func (f *FileStore) Save(_ context.Context, s *model.Scan) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(f.path(s.Target), raw); err != nil {
		return err
	}
	seen, err := f.readSeen(s.Target)
	if err != nil {
		return err
	}
	for _, fd := range s.Findings {
		if k := fd.BaselineKey(); s.StartedAt.After(seen[k]) {
			seen[k] = s.StartedAt
		}
	}
	for k, at := range seen {
		if s.StartedAt.Sub(at) > 90*24*time.Hour {
			delete(seen, k) // keep the file small; no window is ever this long
		}
	}
	raw, err = json.Marshal(seen)
	if err != nil {
		return err
	}
	return writeAtomic(f.seenPath(s.Target), raw)
}

func writeAtomic(path string, raw []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Close implements Store.
func (f *FileStore) Close() error { return nil }
