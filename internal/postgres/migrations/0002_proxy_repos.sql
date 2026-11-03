-- Proxy repositories cache packages from an upstream registry; versions
-- record whether they were published here or cached from upstream.

ALTER TABLE artifact_repos ADD COLUMN upstream text NOT NULL DEFAULT '';
ALTER TABLE artifact_versions ADD COLUMN source text NOT NULL DEFAULT 'published';
ALTER TABLE artifact_versions ADD COLUMN origin text NOT NULL DEFAULT '';
