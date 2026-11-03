package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMigrationsAreNumberedContiguously(t *testing.T) {
	r := require.New(t)
	ms, err := migrations()
	r.NoError(err)
	r.NotEmpty(ms)
	for i, m := range ms {
		r.Equal(i+1, m.version, "migration %s", m.name)
		r.NotEmpty(strings.TrimSpace(m.sql), m.name)
	}
}

func TestMigrationsOnlyTouchArtifactTables(t *testing.T) {
	// In cloud mode the schema shares a database with the Django app.
	ms, err := migrations()
	require.NoError(t, err)
	for _, m := range ms {
		for _, line := range strings.Split(m.sql, "\n") {
			l := strings.ToUpper(strings.TrimSpace(line))
			for _, stmt := range []string{"CREATE TABLE ", "CREATE INDEX ", "CREATE UNIQUE INDEX ", "ALTER TABLE ", "DROP TABLE "} {
				if strings.HasPrefix(l, stmt) {
					require.Contains(t, l, "ARTIFACT_", "%s: %s", m.name, line)
				}
			}
		}
	}
}

func TestOpenFailsFastWhenUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Open(ctx, "postgres://hextrap@127.0.0.1:1/hextrap?sslmode=disable&connect_timeout=2")
	require.Error(t, err)
}

func TestOpenDoesNotLeakPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Open(ctx, "postgres://hextrap:s3cret@127.0.0.1:1/hextrap?sslmode=disable&connect_timeout=2")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "s3cret")
}
