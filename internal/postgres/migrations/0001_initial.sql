-- Hosted repositories: metadata, access, audit, tokens and sessions.
-- Package files live in the blob store, referenced by digest.

CREATE TABLE artifact_repos (
    tenant         text        NOT NULL,
    name           text        NOT NULL,
    format         text        NOT NULL,
    type           text        NOT NULL,
    anonymous_read boolean     NOT NULL DEFAULT false,
    delete_grace_ns bigint     NOT NULL,
    created_at     timestamptz NOT NULL,
    created_by     text        NOT NULL,
    CONSTRAINT artifact_repos_pkey PRIMARY KEY (tenant, name)
);

CREATE TABLE artifact_grants (
    tenant       text    NOT NULL,
    repo         text    NOT NULL,
    position     integer NOT NULL,
    subject_kind text    NOT NULL,
    subject      text    NOT NULL,
    role         integer NOT NULL,
    CONSTRAINT artifact_grants_pkey PRIMARY KEY (tenant, repo, position),
    CONSTRAINT artifact_grants_repo_fkey FOREIGN KEY (tenant, repo)
        REFERENCES artifact_repos (tenant, name) ON DELETE CASCADE
);

CREATE TABLE artifact_versions (
    seq          bigserial   NOT NULL,
    tenant       text        NOT NULL,
    repo         text        NOT NULL,
    package      text        NOT NULL,
    version      text        NOT NULL,
    display_name text        NOT NULL,
    manifest     bytea,
    publisher    text        NOT NULL,
    published_at timestamptz NOT NULL,
    yanked       boolean     NOT NULL DEFAULT false,
    yank_reason  text        NOT NULL DEFAULT '',
    deleted_at   timestamptz,
    purged_at    timestamptz,
    CONSTRAINT artifact_versions_pkey PRIMARY KEY (tenant, repo, package, version),
    CONSTRAINT artifact_versions_seq_key UNIQUE (seq),
    CONSTRAINT artifact_versions_repo_fkey FOREIGN KEY (tenant, repo)
        REFERENCES artifact_repos (tenant, name) ON DELETE CASCADE
);
CREATE INDEX artifact_versions_trash_idx ON artifact_versions (deleted_at)
    WHERE deleted_at IS NOT NULL AND purged_at IS NULL;

CREATE TABLE artifact_files (
    version_seq bigint  NOT NULL,
    position    integer NOT NULL,
    filename    text    NOT NULL,
    digest      text    NOT NULL,
    size        bigint  NOT NULL,
    attrs       jsonb,
    CONSTRAINT artifact_files_pkey PRIMARY KEY (version_seq, position),
    CONSTRAINT artifact_files_version_fkey FOREIGN KEY (version_seq)
        REFERENCES artifact_versions (seq) ON DELETE CASCADE
);
CREATE INDEX artifact_files_digest_idx ON artifact_files (digest);

-- Every filename ever used for a package, so none is ever reused, even
-- after its version is purged.
CREATE TABLE artifact_filenames (
    tenant   text NOT NULL,
    repo     text NOT NULL,
    package  text NOT NULL,
    filename text NOT NULL,
    CONSTRAINT artifact_filenames_pkey PRIMARY KEY (tenant, repo, package, filename),
    CONSTRAINT artifact_filenames_repo_fkey FOREIGN KEY (tenant, repo)
        REFERENCES artifact_repos (tenant, name) ON DELETE CASCADE
);

CREATE TABLE artifact_dist_tags (
    tenant  text NOT NULL,
    repo    text NOT NULL,
    package text NOT NULL,
    tag     text NOT NULL,
    version text NOT NULL,
    CONSTRAINT artifact_dist_tags_pkey PRIMARY KEY (tenant, repo, package, tag),
    CONSTRAINT artifact_dist_tags_repo_fkey FOREIGN KEY (tenant, repo)
        REFERENCES artifact_repos (tenant, name) ON DELETE CASCADE
);

-- No foreign key: the audit trail outlives deleted repositories.
CREATE TABLE artifact_audit (
    id         bigserial   PRIMARY KEY,
    time       timestamptz NOT NULL,
    tenant     text        NOT NULL,
    repo       text        NOT NULL,
    actor      text        NOT NULL,
    actor_kind text        NOT NULL,
    action     text        NOT NULL,
    target     text        NOT NULL,
    before     text        NOT NULL DEFAULT '',
    after      text        NOT NULL DEFAULT '',
    source_ip  text        NOT NULL DEFAULT ''
);
CREATE INDEX artifact_audit_repo_idx ON artifact_audit (tenant, repo, id DESC);

-- Only a SHA-256 of each token is stored.
CREATE TABLE artifact_tokens (
    id         text        PRIMARY KEY,
    hash       text        NOT NULL,
    tenant     text        NOT NULL,
    kind       text        NOT NULL,
    subject    text        NOT NULL DEFAULT '',
    email      text        NOT NULL DEFAULT '',
    groups     text[]      NOT NULL DEFAULT '{}',
    name       text        NOT NULL DEFAULT '',
    repo       text        NOT NULL DEFAULT '',
    created_by text        NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked    boolean     NOT NULL DEFAULT false,
    CONSTRAINT artifact_tokens_hash_key UNIQUE (hash)
);
CREATE INDEX artifact_tokens_subject_idx ON artifact_tokens (tenant, kind, subject);
CREATE INDEX artifact_tokens_repo_idx ON artifact_tokens (tenant, kind, repo);

-- Browser sessions, keyed by a SHA-256 of the cookie value.
CREATE TABLE artifact_sessions (
    id_hash    text        PRIMARY KEY,
    principal  jsonb       NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX artifact_sessions_expires_idx ON artifact_sessions (expires_at);
