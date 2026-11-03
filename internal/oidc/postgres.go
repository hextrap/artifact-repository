package oidc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"hextrap.io/artifacts/internal/identity"
)

// PostgresSessions shares browser sessions across replicas. Only a SHA-256
// of each session ID is stored, so a database leak doesn't expose live
// sessions.
type PostgresSessions struct {
	db *sql.DB
}

func NewPostgresSessions(db *sql.DB) *PostgresSessions {
	return &PostgresSessions{db: db}
}

func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (s *PostgresSessions) Create(p identity.Principal, expires time.Time) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	id := randomString(32)
	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO artifact_sessions (id_hash, principal, expires_at) VALUES ($1, $2, $3)`, hashID(id), string(b), expires)
	return id, err
}

func (s *PostgresSessions) Get(id string, now time.Time) (identity.Principal, bool) {
	var raw []byte
	var expires time.Time
	err := s.db.QueryRowContext(context.Background(),
		`SELECT principal, expires_at FROM artifact_sessions WHERE id_hash = $1`, hashID(id)).Scan(&raw, &expires)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("loading session", "err", err)
		}
		return identity.Principal{}, false
	}
	if !now.Before(expires) {
		s.Delete(id)
		return identity.Principal{}, false
	}
	var p identity.Principal
	if err := json.Unmarshal(raw, &p); err != nil {
		slog.Error("decoding session", "err", err)
		return identity.Principal{}, false
	}
	return p, true
}

func (s *PostgresSessions) Delete(id string) {
	if _, err := s.db.ExecContext(context.Background(), `DELETE FROM artifact_sessions WHERE id_hash = $1`, hashID(id)); err != nil {
		slog.Error("deleting session", "err", err)
	}
}

func (s *PostgresSessions) DeleteExpired(now time.Time) error {
	_, err := s.db.ExecContext(context.Background(), `DELETE FROM artifact_sessions WHERE expires_at <= $1`, now)
	return err
}
