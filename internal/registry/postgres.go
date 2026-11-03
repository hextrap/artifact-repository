package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/rbac"
)

// PostgresStore implements Store on the schema in pkg/artifact/postgres.
// Unique constraints, not application checks, enforce that versions and
// filenames are never reused, so concurrent replicas can't race past them.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// mapError turns constraint violations into registry errors.
func mapError(err error) error {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return err
	}
	switch pqErr.Code {
	case "23505": // unique_violation
		switch pqErr.Constraint {
		case "artifact_repos_pkey":
			return ErrExists
		case "artifact_versions_pkey":
			return ErrVersionExists
		case "artifact_filenames_pkey":
			return ErrFileExists
		}
	case "23503": // foreign_key_violation: the repository doesn't exist
		return ErrNotFound
	}
	return err
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *PostgresStore) tx(fn func(ctx context.Context, tx *sql.Tx) error) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		tx.Rollback()
		return mapError(err)
	}
	return mapError(tx.Commit())
}

func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// --- Repositories ---

const repoColumns = `tenant, name, format, type, anonymous_read, delete_grace_ns, created_at, created_by, upstream`

func scanRepo(sc interface{ Scan(...any) error }) (Repo, error) {
	var r Repo
	var grace int64
	if err := sc.Scan(&r.Tenant, &r.Name, &r.Format, &r.Type, &r.AnonymousRead, &grace, &r.CreatedAt, &r.CreatedBy, &r.Upstream); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Repo{}, ErrNotFound
		}
		return Repo{}, err
	}
	r.DeleteGrace = time.Duration(grace)
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func (s *PostgresStore) CreateRepo(r Repo, admin rbac.Grant) error {
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifact_repos (`+repoColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.Tenant, r.Name, r.Format, r.Type, r.AnonymousRead, int64(r.DeleteGrace), r.CreatedAt, r.CreatedBy, r.Upstream); err != nil {
			return err
		}
		return insertGrants(ctx, tx, r.Tenant, r.Name, []rbac.Grant{admin})
	})
}

func (s *PostgresStore) GetRepo(tenant, name string) (Repo, error) {
	return scanRepo(s.db.QueryRowContext(context.Background(),
		`SELECT `+repoColumns+` FROM artifact_repos WHERE tenant = $1 AND name = $2`, tenant, name))
}

func (s *PostgresStore) ListRepos(tenant string) ([]Repo, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT `+repoColumns+` FROM artifact_repos WHERE tenant = $1 ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Repo
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateRepo(r Repo) error {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE artifact_repos SET anonymous_read = $3, delete_grace_ns = $4 WHERE tenant = $1 AND name = $2`,
		r.Tenant, r.Name, r.AnonymousRead, int64(r.DeleteGrace))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func lockRepo(ctx context.Context, tx *sql.Tx, tenant, name string) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM artifact_repos WHERE tenant = $1 AND name = $2 FOR UPDATE`, tenant, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *PostgresStore) DeleteRepo(tenant, name string) error {
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		if err := lockRepo(ctx, tx, tenant, name); err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM artifact_versions
			WHERE tenant = $1 AND repo = $2 AND purged_at IS NULL)`, tenant, name).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrRepoNotEmpty
		}
		// Grants, versions, files, filenames and tags cascade.
		_, err := tx.ExecContext(ctx, `DELETE FROM artifact_repos WHERE tenant = $1 AND name = $2`, tenant, name)
		return err
	})
}

// --- Grants ---

func readGrants(ctx context.Context, q querier, tenant, repo string) ([]rbac.Grant, error) {
	rows, err := q.QueryContext(ctx, `SELECT subject_kind, subject, role FROM artifact_grants
		WHERE tenant = $1 AND repo = $2 ORDER BY position`, tenant, repo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []rbac.Grant{}
	for rows.Next() {
		var g rbac.Grant
		if err := rows.Scan(&g.SubjectKind, &g.Subject, &g.Role); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func insertGrants(ctx context.Context, tx *sql.Tx, tenant, repo string, grants []rbac.Grant) error {
	for i, g := range grants {
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifact_grants (tenant, repo, position, subject_kind, subject, role)
			VALUES ($1, $2, $3, $4, $5, $6)`, tenant, repo, i, g.SubjectKind, g.Subject, int(g.Role)); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) Grants(tenant, repo string) ([]rbac.Grant, error) {
	if _, err := s.GetRepo(tenant, repo); err != nil {
		return nil, err
	}
	return readGrants(context.Background(), s.db, tenant, repo)
}

func (s *PostgresStore) UpdateGrants(tenant, repo string, fn func([]rbac.Grant) ([]rbac.Grant, error)) error {
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		// The row lock serializes concurrent grant changes, which the
		// last-admin check depends on.
		if err := lockRepo(ctx, tx, tenant, repo); err != nil {
			return err
		}
		current, err := readGrants(ctx, tx, tenant, repo)
		if err != nil {
			return err
		}
		updated, err := fn(current)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM artifact_grants WHERE tenant = $1 AND repo = $2`, tenant, repo); err != nil {
			return err
		}
		return insertGrants(ctx, tx, tenant, repo, updated)
	})
}

// --- Versions ---

const versionColumns = `seq, tenant, repo, package, version, display_name, manifest, publisher,
	published_at, yanked, yank_reason, deleted_at, purged_at, source, origin`

func scanVersion(sc interface{ Scan(...any) error }) (int64, Version, error) {
	var seq int64
	var v Version
	var manifest []byte
	var deleted, purged sql.NullTime
	err := sc.Scan(&seq, &v.Tenant, &v.Repo, &v.Package, &v.Version, &v.DisplayName, &manifest, &v.Publisher,
		&v.PublishedAt, &v.Yanked, &v.YankReason, &deleted, &purged, &v.Source, &v.Origin)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, Version{}, ErrNotFound
	}
	if err != nil {
		return 0, Version{}, err
	}
	v.Manifest = manifest
	v.PublishedAt = v.PublishedAt.UTC()
	v.DeletedAt, v.PurgedAt = timePtr(deleted), timePtr(purged)
	return seq, v, nil
}

// queryVersions loads versions matching where (in insertion order) with
// their files.
func queryVersions(ctx context.Context, q querier, where string, args ...any) ([]Version, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+versionColumns+` FROM artifact_versions WHERE `+where+` ORDER BY seq`, args...)
	if err != nil {
		return nil, err
	}
	var seqs []int64
	var out []Version
	for rows.Next() {
		seq, v, err := scanVersion(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		seqs = append(seqs, seq)
		out = append(out, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	files, err := loadFiles(ctx, q, seqs)
	if err != nil {
		return nil, err
	}
	for i, seq := range seqs {
		out[i].Files = files[seq]
	}
	return out, nil
}

func loadFiles(ctx context.Context, q querier, seqs []int64) (map[int64][]File, error) {
	out := map[int64][]File{}
	if len(seqs) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT version_seq, filename, digest, size, attrs FROM artifact_files
		WHERE version_seq = ANY($1) ORDER BY version_seq, position`, pq.Array(seqs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var f File
		var attrs []byte
		if err := rows.Scan(&seq, &f.Filename, &f.Digest, &f.Size, &attrs); err != nil {
			return nil, err
		}
		if len(attrs) > 0 {
			if err := json.Unmarshal(attrs, &f.Attrs); err != nil {
				return nil, err
			}
		}
		out[seq] = append(out[seq], f)
	}
	return out, rows.Err()
}

func insertFiles(ctx context.Context, tx *sql.Tx, v Version, seq int64, startPos int, files []File) error {
	for i, f := range files {
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifact_filenames (tenant, repo, package, filename)
			VALUES ($1, $2, $3, $4)`, v.Tenant, v.Repo, v.Package, f.Filename); err != nil {
			return err
		}
		if err := insertFileRow(ctx, tx, seq, startPos+i, f); err != nil {
			return err
		}
	}
	return nil
}

func insertVersion(ctx context.Context, tx *sql.Tx, v Version, onConflictDoNothing bool) error {
	q := `INSERT INTO artifact_versions (tenant, repo, package, version, display_name, manifest, publisher,
		published_at, yanked, yank_reason, deleted_at, purged_at, source, origin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	if onConflictDoNothing {
		q += ` ON CONFLICT ON CONSTRAINT artifact_versions_pkey DO NOTHING`
	}
	_, err := tx.ExecContext(ctx, q, v.Tenant, v.Repo, v.Package, v.Version, v.DisplayName, nullBytes(v.Manifest),
		v.Publisher, v.PublishedAt, v.Yanked, v.YankReason, nullTime(v.DeletedAt), nullTime(v.PurgedAt), v.Source, v.Origin)
	return err
}

func versionWhere() string {
	return `tenant = $1 AND repo = $2 AND package = $3 AND version = $4`
}

func (s *PostgresStore) CreateVersion(v Version, tags map[string]string) error {
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		if err := insertVersion(ctx, tx, v, false); err != nil {
			return err
		}
		var seq int64
		if err := tx.QueryRowContext(ctx, `SELECT seq FROM artifact_versions WHERE `+versionWhere(),
			v.Tenant, v.Repo, v.Package, v.Version).Scan(&seq); err != nil {
			return err
		}
		if err := insertFiles(ctx, tx, v, seq, 0, v.Files); err != nil {
			return err
		}
		for tag, ver := range tags {
			if err := setDistTag(ctx, tx, v.Tenant, v.Repo, v.Package, tag, ver); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *PostgresStore) AddFiles(init Version, files []File) error {
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		// Claim the filenames first: a reused filename is reported as such
		// even when the version is also gone.
		for _, f := range files {
			if _, err := tx.ExecContext(ctx, `INSERT INTO artifact_filenames (tenant, repo, package, filename)
				VALUES ($1, $2, $3, $4)`, init.Tenant, init.Repo, init.Package, f.Filename); err != nil {
				return err
			}
		}
		if err := insertVersion(ctx, tx, init, true); err != nil {
			return err
		}
		seq, v, err := scanVersion(tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM artifact_versions WHERE `+
			versionWhere()+` FOR UPDATE`, init.Tenant, init.Repo, init.Package, init.Version))
		if err != nil {
			return err
		}
		if !v.Visible() {
			return ErrVersionExists
		}
		var next int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(position) + 1, 0) FROM artifact_files WHERE version_seq = $1`,
			seq).Scan(&next); err != nil {
			return err
		}
		for i, f := range files {
			if err := insertFileRow(ctx, tx, seq, next+i, f); err != nil {
				return err
			}
		}
		return nil
	})
}

func insertFileRow(ctx context.Context, tx *sql.Tx, seq int64, pos int, f File) error {
	var attrs any
	if f.Attrs != nil {
		b, err := json.Marshal(f.Attrs)
		if err != nil {
			return err
		}
		attrs = string(b)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO artifact_files (version_seq, position, filename, digest, size, attrs)
		VALUES ($1, $2, $3, $4, $5, $6)`, seq, pos, f.Filename, string(f.Digest), f.Size, attrs)
	return err
}

func (s *PostgresStore) UpdateVersion(key VersionKey, fn func(*Version) error) (Version, error) {
	var out Version
	err := s.tx(func(ctx context.Context, tx *sql.Tx) error {
		seq, v, err := scanVersion(tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM artifact_versions WHERE `+
			versionWhere()+` FOR UPDATE`, key.Tenant, key.Repo, key.Package, key.Version))
		if err != nil {
			return err
		}
		files, err := loadFiles(ctx, tx, []int64{seq})
		if err != nil {
			return err
		}
		v.Files = files[seq]
		if err := fn(&v); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE artifact_versions SET yanked = $2, yank_reason = $3, deleted_at = $4, purged_at = $5
			WHERE seq = $1`, seq, v.Yanked, v.YankReason, nullTime(v.DeletedAt), nullTime(v.PurgedAt)); err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

func (s *PostgresStore) Versions(tenant, repo, pkg string) ([]Version, error) {
	return queryVersions(context.Background(), s.db, `tenant = $1 AND repo = $2 AND package = $3`, tenant, repo, pkg)
}

func (s *PostgresStore) RepoVersions(tenant, repo string) ([]Version, error) {
	return queryVersions(context.Background(), s.db, `tenant = $1 AND repo = $2`, tenant, repo)
}

func (s *PostgresStore) TrashedVersions() ([]Version, error) {
	return queryVersions(context.Background(), s.db, `deleted_at IS NOT NULL AND purged_at IS NULL`)
}

// --- Dist-tags ---

func (s *PostgresStore) DistTags(tenant, repo, pkg string) (map[string]string, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT tag, version FROM artifact_dist_tags
		WHERE tenant = $1 AND repo = $2 AND package = $3`, tenant, repo, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tag, version string
		if err := rows.Scan(&tag, &version); err != nil {
			return nil, err
		}
		out[tag] = version
	}
	return out, rows.Err()
}

func setDistTag(ctx context.Context, q querier, tenant, repo, pkg, tag, version string) error {
	_, err := q.ExecContext(ctx, `INSERT INTO artifact_dist_tags (tenant, repo, package, tag, version)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT ON CONSTRAINT artifact_dist_tags_pkey DO UPDATE SET version = EXCLUDED.version`,
		tenant, repo, pkg, tag, version)
	return err
}

func (s *PostgresStore) SetDistTag(tenant, repo, pkg, tag, version string) error {
	return mapError(setDistTag(context.Background(), s.db, tenant, repo, pkg, tag, version))
}

func (s *PostgresStore) RemoveDistTag(tenant, repo, pkg, tag string) error {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM artifact_dist_tags
		WHERE tenant = $1 AND repo = $2 AND package = $3 AND tag = $4`, tenant, repo, pkg, tag)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Storage ---

func (s *PostgresStore) DigestReferenced(d blob.Digest) (bool, error) {
	var used bool
	err := s.db.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM artifact_files f JOIN artifact_versions v ON v.seq = f.version_seq
		WHERE f.digest = $1 AND v.purged_at IS NULL)`, string(d)).Scan(&used)
	return used, err
}

func (s *PostgresStore) StorageUsed(tenant string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(f.size), 0)::bigint
		FROM artifact_files f JOIN artifact_versions v ON v.seq = f.version_seq
		WHERE v.tenant = $1 AND v.purged_at IS NULL`, tenant).Scan(&n)
	return n, err
}

// --- Audit ---

func (s *PostgresStore) AppendAudit(e AuditEntry) error {
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO artifact_audit
		(time, tenant, repo, actor, actor_kind, action, target, before, after, source_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		e.Time, e.Tenant, e.Repo, e.Actor, e.ActorKind, e.Action, e.Target, e.Before, e.After, e.SourceIP)
	return err
}

func (s *PostgresStore) Audit(tenant, repo string, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT time, tenant, repo, actor, actor_kind, action, target,
		before, after, source_ip FROM artifact_audit WHERE tenant = $1 AND repo = $2 ORDER BY id DESC LIMIT $3`,
		tenant, repo, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Tenant, &e.Repo, &e.Actor, &e.ActorKind, &e.Action, &e.Target,
			&e.Before, &e.After, &e.SourceIP); err != nil {
			return nil, err
		}
		e.Time = e.Time.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

var _ Store = (*PostgresStore)(nil)
