package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aviollaz/skimwatch/internal/model"
)

// The schema is idempotent and applied on every start, so a fresh database needs no setup.
// Findings get their own table so they can be queried ("every critical finding this month")
// without parsing JSON; scripts stay inside the scan document because they are only read back
// as a whole, by the baseline layer.
const schema = `
CREATE TABLE IF NOT EXISTS scans (
	id          BIGSERIAL PRIMARY KEY,
	target      TEXT        NOT NULL,
	started_at  TIMESTAMPTZ NOT NULL,
	finished_at TIMESTAMPTZ NOT NULL,
	max_severity TEXT,
	document    JSONB       NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_target_started ON scans (target, started_at DESC);

CREATE TABLE IF NOT EXISTS findings (
	id          BIGSERIAL PRIMARY KEY,
	scan_id     BIGINT      NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	target      TEXT        NOT NULL,
	fingerprint TEXT        NOT NULL,
	layer       TEXT        NOT NULL,
	rule        TEXT        NOT NULL,
	severity    TEXT        NOT NULL,
	page_url    TEXT,
	location    TEXT,
	title       TEXT        NOT NULL,
	detail      TEXT,
	evidence    TEXT,
	first_seen  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_target_fp ON findings (target, fingerprint);
CREATE INDEX IF NOT EXISTS findings_severity ON findings (severity);
`

// PostgresStore keeps the full history in Postgres (Neon in production).
type PostgresStore struct{ pool *pgxpool.Pool }

// NewPostgresStore connects and ensures the schema exists.
func NewPostgresStore(ctx context.Context, url string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Previous implements Store.
func (p *PostgresStore) Previous(ctx context.Context, target string) (*model.Scan, error) {
	var raw []byte
	err := p.pool.QueryRow(ctx,
		`SELECT document FROM scans WHERE target = $1 ORDER BY started_at DESC LIMIT 1`, target).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s model.Scan
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save implements Store. A finding keeps the date it was first seen, so the report can
// separate new problems from ones that have been open for weeks.
func (p *PostgresStore) Save(ctx context.Context, s *model.Scan) error {
	doc, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var id int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO scans (target, started_at, finished_at, max_severity, document) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		s.Target, s.StartedAt, s.FinishedAt, s.MaxSeverity().String(), doc).Scan(&id); err != nil {
		return fmt.Errorf("saving scan: %w", err)
	}
	for _, f := range s.Findings {
		_, err := tx.Exec(ctx, `
			INSERT INTO findings (scan_id, target, fingerprint, layer, rule, severity, page_url, location, title, detail, evidence, first_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
				COALESCE((SELECT MIN(first_seen) FROM findings WHERE target = $2 AND fingerprint = $3), $12))`,
			id, f.Target, f.Fingerprint(), string(f.Layer), f.Rule, f.Severity.String(), f.PageURL, f.Location,
			f.Title, f.Detail, f.Evidence, s.StartedAt)
		if err != nil {
			return fmt.Errorf("saving finding: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Close implements Store.
func (p *PostgresStore) Close() error {
	p.pool.Close()
	return nil
}
