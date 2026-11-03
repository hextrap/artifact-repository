package tokens

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lib/pq"
)

// where renders the filter as SQL with placeholders numbered from start.
func (f Filter) where(start int) (string, []any, error) {
	if f.Tenant == "" {
		return "", nil, ErrUnscopedFilter
	}
	var conds []string
	var args []any
	add := func(col, val string) {
		if val != "" {
			args = append(args, val)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, start+len(args)-1))
		}
	}
	add("tenant", f.Tenant)
	add("kind", string(f.Kind))
	add("id", f.ID)
	add("subject", f.Subject)
	add("repo", f.Repo)
	return strings.Join(conds, " AND "), args, nil
}

// PostgresStore implements Store on the schema in pkg/artifact/postgres.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const recordColumns = `id, hash, tenant, kind, subject, email, groups, name, repo, created_by, created_at, expires_at, revoked`

func scanRecord(sc interface{ Scan(...any) error }) (Record, error) {
	var r Record
	var groups []string
	err := sc.Scan(&r.ID, &r.Hash, &r.Tenant, &r.Kind, &r.Subject, &r.Email, pq.Array(&groups), &r.Name, &r.Repo,
		&r.CreatedBy, &r.CreatedAt, &r.ExpiresAt, &r.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	if len(groups) > 0 {
		r.Groups = groups
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	return r, nil
}

func groupsArray(groups []string) any {
	if groups == nil {
		groups = []string{}
	}
	return pq.Array(groups)
}

func (s *PostgresStore) Create(r Record) error {
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO artifact_tokens (`+recordColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		r.ID, r.Hash, r.Tenant, string(r.Kind), r.Subject, r.Email, groupsArray(r.Groups), r.Name, r.Repo,
		r.CreatedBy, r.CreatedAt, r.ExpiresAt, r.Revoked)
	return err
}

func (s *PostgresStore) ByHash(hash string) (Record, error) {
	return scanRecord(s.db.QueryRowContext(context.Background(),
		`SELECT `+recordColumns+` FROM artifact_tokens WHERE hash = $1`, hash))
}

func (s *PostgresStore) List(f Filter) ([]Record, error) {
	where, args, err := f.where(1)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+recordColumns+` FROM artifact_tokens WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Revoke(f Filter) (int, error) {
	where, args, err := f.where(1)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(context.Background(), `UPDATE artifact_tokens SET revoked = true WHERE `+where, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *PostgresStore) UpdateIdentity(f Filter, email string, groups []string) error {
	where, args, err := f.where(3)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(context.Background(), `UPDATE artifact_tokens SET email = $1, groups = $2 WHERE `+where,
		append([]any{email, groupsArray(slices.Clone(groups))}, args...)...)
	return err
}

var _ Store = (*PostgresStore)(nil)
