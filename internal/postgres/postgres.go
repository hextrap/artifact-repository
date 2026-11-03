// Package postgres opens the artifact repository's Postgres database and
// applies its schema migrations.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// migrations returns the embedded migrations ordered by their numeric
// prefix (0001_initial.sql is version 1).
func migrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil {
			return nil, fmt.Errorf("migration %s: name must start with a number", e.Name())
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// advisoryLockKey serializes migrations across replicas starting together.
const advisoryLockKey = 0x68787472 // "hxtr"

// Migrate applies pending migrations, each in its own transaction.
func Migrate(ctx context.Context, db *sql.DB) error {
	ms, err := migrations()
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryLockKey)

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS artifact_schema_migrations (
		version    integer     PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var current int
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM artifact_schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifact_schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

// Open connects, verifies the connection and migrates the schema. Errors
// never include the URL, which may contain a password.
func Open(ctx context.Context, url string) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("database: invalid database_url")
	}
	db.SetMaxOpenConns(20)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: connecting: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	return db, nil
}
