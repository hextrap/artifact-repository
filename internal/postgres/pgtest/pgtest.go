// Package pgtest gives tests an isolated, migrated Postgres schema when
// HEXTRAP_TEST_POSTGRES_URL is set, e.g.
//
//	HEXTRAP_TEST_POSTGRES_URL=postgres://postgres@localhost/test?sslmode=disable go test ./pkg/artifact/...
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/postgres"
)

const EnvVar = "HEXTRAP_TEST_POSTGRES_URL"

func Enabled() bool { return os.Getenv(EnvVar) != "" }

// URL returns a connection URL whose search_path is a fresh schema, dropped
// when the test ends. It skips the test when Postgres isn't configured.
func URL(t *testing.T) string {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		t.Skipf("set %s to run Postgres tests", EnvVar)
	}
	admin, err := sql.Open("postgres", base)
	require.NoError(t, err)

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	schema := "hextrap_test_" + hex.EncodeToString(b)
	_, err = admin.ExecContext(context.Background(), `CREATE SCHEMA `+schema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})

	u, err := url.Parse(base)
	require.NoError(t, err, "%s must be a postgres:// URL", EnvVar)
	q := u.Query()
	q.Set("search_path", schema) // lib/pq sends unknown params as run-time settings
	u.RawQuery = q.Encode()
	return u.String()
}

// DB returns a migrated database on a fresh schema (see URL).
func DB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := postgres.Open(context.Background(), URL(t))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() }) // runs before URL's schema drop
	return db
}
