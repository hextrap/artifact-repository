# Hextrap Artifact Repository

Package repositories for npm, PyPI, Maven, Cargo, Go modules and container images, hosted and proxied, with role-based access control, an audit log and rate limiting. One binary, `hextrap-artifacts`. Design: `docs/artifact-repository-plan.md` in the hextrap repo.

## Quick start

```bash
cp config.example.yaml config.yaml
printf '%s' 'a long password' | hextrap-artifacts hash-password   # paste the output into config.yaml
hextrap-artifacts -config config.yaml
```

Then open http://localhost:8080, sign in as `admin`, and create an access token. Each repository's Setup tab shows the client configuration for it.

[`config.example.yaml`](config.example.yaml) is the whole minimal setup: one admin user and a storage location. [`config.full.example.yaml`](config.full.example.yaml) documents every setting. Both are loaded by the test suite, so they stay in sync with what the binary accepts. As shipped, the minimal example has a placeholder instead of a password hash, so it won't start with a default password.

## Sign-in

Either, not both:

- **Local users**: `users` (username and `password_hash` from `hextrap-artifacts hash-password`) and `admins` (usernames). Only hashes are stored (PBKDF2-SHA256, 600,000 iterations). Sign-in attempts are throttled per IP and per username (10 per 15 minutes), whatever `rate_limit` says.
- **OIDC**: an `oidc` block with your identity provider, plus `admin_groups` and/or `admin_emails`. Requires `public_url`; register `<public_url>/auth/callback` as the redirect URI.

Admins have Admin on every repository and are set only in the config file, so nobody can be locked out from inside the app.

Package clients (npm, pip, uv, twine, mvn, cargo, go, docker) use access tokens created after signing in, never passwords.

### Behind an authenticating proxy (oauth2-proxy, Pomerium, Cloudflare Access)

You don't need one: configure `oidc` with the same identity provider and the repository handles sign-in itself, including groups.

If policy requires every internal app to sit behind your auth proxy, exempt the package-client and API paths. Package clients can't do a browser login. They send an access token on every request, and the repository checks it:

```
/npm/  /pypi/  /maven/  /cargo/  /go/  /v2/  /api/
```

Leave the rest (the UI and `/auth/`) behind the proxy. Users then sign in twice: once at the proxy and once in the repository, usually without a prompt the second time if both use the same identity provider.

The repository ignores identity headers set by a proxy (`X-Forwarded-User`, `X-Forwarded-Email` and the like). Every user still signs in to the repository itself, so a proxy can restrict who reaches the UI but can't grant access.

## Editions

The default build is the **self-hosted edition**: one tenant. It refuses multi-tenant settings (`tenant_domain`, `oidc.tenant_claim`) at startup. The **cloud edition** (`go build -tags cloud`) is what hextrap runs; it adds subdomain tenants and requires OIDC, Postgres and S3. `make artifact-repo` tests and builds both.

The process makes outbound connections only to the OIDC issuer (if configured), the S3 endpoint, the ECS credentials endpoint (169.254.170.2, on ECS), Postgres (if configured) and the configured proxy upstreams. Nothing is sent to hextrap unless `hextrap_firewall` is configured.

## Proxy repositories

A proxy repository caches packages from an upstream registry. Point the client at it like any repository:

- Project indexes are fetched from upstream (cached for 5 minutes) with download links rewritten to hextrap.
- The first download of a file fetches it, checks it against the hash upstream declared, and stores it. Go modules are also checked against the Go checksum database (sum.golang.org), and container manifests and layers against their digests. Later downloads come from storage (`X-Hextrap-Cache: hit`), even if upstream is down. Concurrent requests for the same file share one download.
- Each package and version records where it came from: the UI and API show **Cached from pypi.org** or **Published**.
- Proxies are read-only. Deleting a cached version blocks it from being fetched again.
- Upstreams are limited to `upstreams` in the config file (defaults: pypi.org, registry.npmjs.org, Maven Central, index.crates.io, proxy.golang.org, Docker Hub), so repository creators can't point the server at other addresses.

### Policy: the hextrap firewall

This repository has no policy engine of its own. To block malware, typosquats and too-new releases, and to apply allow and deny lists, connect proxy repositories to a hextrap firewall (paid hextrap): add a `hextrap_firewall` credential to the config (see `config.full.example.yaml`), then choose the firewall as a repository's upstream in its Settings tab. It becomes the default upstream for new PyPI, npm, Go and Cargo proxies.

- Downloads go through the firewall with its credential, which is sent to the firewall's hosts and nowhere else. Download links that point at the public registry are rewritten to the firewall, so nothing is fetched around it.
- A blocked download fails with 403 and a message naming the hextrap firewall. It is never served from the cache instead.
- Cached files are checked with the firewall again before they're served (an allow is reused for 5 minutes), so a package denied after it was cached stops installing and every install shows in the hextrap dashboard. If the firewall is unreachable, cached files keep serving: they were allowed when cached.
- Without a firewall, a self-hosted proxy caches unchecked: the UI marks it **No policy** and its packages **Unchecked**. The cloud edition requires a firewall for every proxy repository.
- The firewall doesn't support Maven or container images yet.

## Formats

| Format | Hosted (publish) | Proxy (default upstream) | Client URL |
|---|---|---|---|
| npm | `npm publish` | registry.npmjs.org | `/npm/<repo>/` |
| PyPI | `twine upload`, `uv publish` | pypi.org | `/pypi/<repo>/simple/` |
| Maven | `mvn deploy`, Gradle | Maven Central | `/maven/<repo>/` |
| Cargo | `cargo publish` | index.crates.io | `sparse+/cargo/<repo>/index/` |
| Go modules | no (Go has no publish command) | proxy.golang.org | `GOPROXY=/go/<repo>` |
| Container images | `docker push` | Docker Hub | `<host>/<repo>/<image>:<tag>` |

Container images are pushed and pulled as `<host>/<repo>/<image>`. Each manifest is a version (named by its digest) and tags point at manifests. A manifest can only reference layers already in its repository or uploaded to it, so knowing a digest never grants access to content. Layers shared by several images count toward the storage quota once per image. Uploaded layers that no manifest references within 24 hours are removed.

## Storage

### Package files

- **`storage.s3`** is the supported store, and the only one the cloud edition allows. Files are content-addressed at `<prefix>sha256/<aa>/<bb>/<sha256>`; identical content is stored once.
- Credentials come from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, or the ECS task role.
- The IAM policy needs `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `<bucket>/<prefix>*` and `s3:ListBucket` on the bucket (without it S3 answers 403 instead of 404 for missing objects and uploads fail). With `aws:kms`, also `kms:GenerateDataKey` and `kms:Decrypt` on the key.
- Startup checks the bucket is reachable and fails fast if not.
- **`storage.filesystem`** is for testing: self-hosted only, and it logs a warning at startup.

### Metadata

- **Without `database_url`** (default): metadata and tokens are snapshot files in `data_dir`; sessions are in memory (users sign in again after a restart). Single node only.
- **With `database_url`**: metadata, tokens and sessions live in Postgres. The schema (tables prefixed `artifact_`) is created and migrated automatically at startup; replicas starting together take an advisory lock. Pass the URL through `HEXTRAP_DATABASE_URL` to keep the password out of the config file.
- **Multiple replicas** need Postgres and S3. Rate limits are counted per replica until the Redis limiter lands.

## Use

1. Sign in, then select **Create access token**. The page shows `.npmrc` / `pip.conf` snippets for your repositories.
2. Create repositories and manage access with the API (`/api/v1/...`). The creator of a repository is its first Admin.

```bash
# npm
npm config set registry https://repo.example.com/npm/<repo>/
npm config set //repo.example.com/npm/<repo>/:_authToken <token>
npm publish

# pip / uv
pip install --index-url https://__token__:<token>@repo.example.com/pypi/<repo>/simple/ <pkg>
twine upload --repository-url https://repo.example.com/pypi/<repo>/ -u __token__ -p <token> dist/*
uv publish --publish-url https://repo.example.com/pypi/<repo>/ -u __token__ -p <token>
```

CI: an Admin creates a repo-scoped service token (`POST /api/v1/repos/<repo>/service-tokens` with `{"name": "...", "role": "developer"}`). Service tokens can be Reader, Developer or Maintainer, never Admin.

## Roles

| | Reader | Developer | Maintainer | Admin |
|---|:-:|:-:|:-:|:-:|
| Install | ✓ | ✓ | ✓ | ✓ |
| Publish | | ✓ | ✓ | ✓ |
| Yank / deprecate, dist-tags | | | ✓ | ✓ |
| Delete, restore, purge | | | | ✓ |
| Settings, access, audit log | | | | ✓ |

Grants go to users (local username, or OIDC `sub` or verified email), IdP groups, or service tokens. The last Admin of a repository can't be removed.

## API

| Method | Path | |
|---|---|---|
| GET | `/api/v1/me` | Current identity and `edition` (`self-hosted` or `cloud`) |
| GET | `/api/v1/upstreams` | Allowed proxy upstreams per format: `[{"url", "firewall"}]`, firewalls first |
| GET, POST | `/api/v1/tokens` | Personal tokens (POST requires a browser session) |
| DELETE | `/api/v1/tokens/{id}` | Revoke |
| GET, POST | `/api/v1/repos` | List / create `{"name", "format", "type": "hosted"\|"proxy", "upstream"}`; formats `npm`, `pypi`, `maven`, `cargo`, `go`, `oci` |
| GET, PATCH, DELETE | `/api/v1/repos/{repo}` | PATCH `{"anonymous_read", "delete_grace_days", "upstream"}` (switching a proxy's upstream keeps its cache); repo responses include `firewall`; DELETE requires empty repo |
| GET, PUT | `/api/v1/repos/{repo}/grants` | PUT `{"subject_kind": "user"\|"group"\|"service_token", "subject", "role"}` |
| DELETE | `/api/v1/repos/{repo}/grants?subject_kind=&subject=` | |
| GET | `/api/v1/repos/{repo}/packages`, `/versions?package=` | |
| POST | `/api/v1/repos/{repo}/versions/{yank\|unyank\|delete\|restore\|purge}` | `{"package", "version", "reason", "confirm": "pkg@version"}` |
| GET | `/api/v1/repos/{repo}/trash`, `/audit?limit=` | |
| GET, POST, DELETE | `/api/v1/repos/{repo}/service-tokens[/{id}]` | |
| GET | `/api/v1/usage` | Tenant storage used |

## Development

```bash
go test ./...              # self-hosted edition
go test -tags cloud ./...  # cloud edition

# Also run the registry, token and session suites against Postgres
# (each test gets its own schema, dropped afterwards):
HEXTRAP_TEST_POSTGRES_URL=postgres://postgres@localhost/test?sslmode=disable go test ./...
```

Code lives in `internal/` (`blob`, `config`, `edition`, `formats/{npm,pypi,maven,cargo,gomod,oci}`, `upstream`, `identity`, `localauth`, `oidc`, `postgres`, `ratelimit`, `rbac`, `registry`, `server`, `snapshot`, `tokens`) and `cmd/hextrap-artifacts/`.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Release archives also include `THIRD_PARTY_NOTICES` with the licenses of the modules compiled into the binary.
