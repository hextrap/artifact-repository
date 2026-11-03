// Command hextrap-artifacts serves the Hextrap artifact repository.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"hextrap.io/artifacts/internal/blob"
	"hextrap.io/artifacts/internal/config"
	"hextrap.io/artifacts/internal/edition"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/localauth"
	"hextrap.io/artifacts/internal/oidc"
	"hextrap.io/artifacts/internal/postgres"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/server"
	"hextrap.io/artifacts/internal/tokens"
)

// version is stamped in by release builds:
//
//	go build -ldflags "-X main.version=0.1.0"
var version = "dev"

func versionString() string {
	return fmt.Sprintf("hextrap-artifacts %s (%s)", version, edition.Name)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := hashPassword(os.Stdin, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}
	configPath := flag.String("config", "/etc/hextrap-artifacts/config.yaml", "config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:\n  hextrap-artifacts [-config file]   serve the repository\n  hextrap-artifacts -version          print the version\n  hextrap-artifacts hash-password     read a password on stdin, print its hash for users[].password_hash")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(versionString())
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		slog.Error("exiting", "err", err)
		stop()
		os.Exit(1)
	}
}

const minPasswordLen = 8

// hashPassword reads a password (one line) and prints the value for a
// user's password_hash. The input is echoed on a terminal, so prefer piping:
//
//	printf '%s' "$PASSWORD" | hextrap-artifacts hash-password
func hashPassword(in io.Reader, out, prompt io.Writer) error {
	fmt.Fprint(prompt, "Password: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	fmt.Fprintln(prompt)
	password := strings.TrimRight(line, "\r\n")
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	h, err := localauth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, h)
	return err
}

type app struct {
	handler  http.Handler
	registry *registry.Service
	tokens   *tokens.Manager
	sessions sessionStore
	close    func()
}

type sessionStore interface {
	oidc.Sessions
	DeleteExpired(now time.Time) error
}

type stores struct {
	registry registry.Store
	tokens   tokens.Store
	sessions sessionStore
	close    func()
}

// openStores uses Postgres when database_url is set, which is required to
// run more than one replica; otherwise files under the data directory.
func openStores(ctx context.Context, cfg config.Config) (stores, error) {
	if cfg.DatabaseURL != "" {
		db, err := postgres.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return stores{}, err
		}
		return stores{
			registry: registry.NewPostgresStore(db),
			tokens:   tokens.NewPostgresStore(db),
			sessions: oidc.NewPostgresSessions(db),
			close:    func() { db.Close() },
		}, nil
	}
	reg, err := registry.NewFileStore(filepath.Join(cfg.DataDir, "registry.db"))
	if err != nil {
		return stores{}, err
	}
	tok, err := tokens.NewFileStore(filepath.Join(cfg.DataDir, "tokens.db"))
	if err != nil {
		return stores{}, err
	}
	return stores{registry: reg, tokens: tok, sessions: oidc.NewMemorySessions(), close: func() {}}, nil
}

// openBlobStore returns the configured package file store. S3 is checked
// at startup so bad credentials or bucket policy fail before serving.
func openBlobStore(ctx context.Context, cfg config.Config, now func() time.Time) (blob.Store, error) {
	if cfg.Storage.Filesystem != "" {
		slog.Warn("storage.filesystem is for testing only; use storage.s3 for real use",
			"path", cfg.Storage.Filesystem)
		return blob.NewFilesystem(cfg.Storage.Filesystem)
	}
	// No overall timeout: uploads and downloads can be large. Requests are
	// bounded by their contexts instead.
	client := &http.Client{}
	creds, err := blob.DefaultCredentials(client, now)
	if err != nil {
		return nil, err
	}
	s, err := blob.NewS3(*cfg.Storage.S3, creds, client, now, "")
	if err != nil {
		return nil, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := s.Check(checkCtx); err != nil {
		return nil, err
	}
	return s, nil
}

// loginFlow is the sign-in method: OIDC or local users.
type loginFlow interface {
	http.Handler
	Authenticate(r *http.Request) (identity.Principal, bool)
}

func signIn(ctx context.Context, cfg config.Config, sessions oidc.Sessions, tok *tokens.Manager,
	client *http.Client, now func() time.Time, clientIP func(*http.Request) string) (loginFlow, error) {
	if cfg.OIDC != nil {
		provider, err := oidc.NewProvider(ctx, cfg.OIDC.Config, client, now)
		if err != nil {
			return nil, err
		}
		return oidc.NewFlow(provider, sessions, cfg.Tenant, tok.RefreshUser), nil
	}
	users, err := localauth.NewUsers(cfg.Users)
	if err != nil {
		return nil, err
	}
	flow := localauth.NewFlow(users, sessions, cfg.Tenant, cfg.PublicURL, now, tok.RefreshUser)
	flow.ClientIP = clientIP
	return flow, nil
}

// requestBaseURL builds links from the request when public_url is unset.
func requestBaseURL(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil || (trustProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// build wires the repository from config.
func build(ctx context.Context, cfg config.Config, client *http.Client, now func() time.Time) (*app, error) {
	// Config validation already enforces this; checked again here so no other
	// path can start a self-hosted build in multi-tenant mode.
	if cfg.MultiTenant() && !edition.MultiTenant {
		return nil, errors.New("tenant_domain: multi-tenant mode is only available in hextrap cloud")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	blobs, err := openBlobStore(ctx, cfg, now)
	if err != nil {
		return nil, fmt.Errorf("blob store: %w", err)
	}
	st, err := openStores(ctx, cfg)
	if err != nil {
		return nil, err
	}
	reg := registry.New(st.registry, blobs, now, registry.QuotaFunc(func(string) int64 { return cfg.StorageQuotaBytes }))
	for format, list := range cfg.Upstreams.ByFormat() {
		reg.AllowUpstreams(registry.Format(format), *list...)
	}
	var firewalls []server.Firewall
	if fw := cfg.HextrapFirewall; fw != nil {
		for format, url := range fw.URLs {
			reg.AllowFirewall(registry.Format(format), url)
			firewalls = append(firewalls, server.Firewall{URL: url, Username: fw.Username, Password: fw.Password})
		}
	}
	if edition.MultiTenant {
		reg.RequireFirewall() // the hosted product never caches unchecked
	}
	tok := tokens.NewManager(st.tokens, now)

	clientIP := server.RemoteAddrIP
	if cfg.TrustProxyHeaders {
		clientIP = server.ForwardedForIP
	}
	flow, err := signIn(ctx, cfg, st.sessions, tok, client, now, clientIP)
	if err != nil {
		st.close()
		return nil, err
	}

	tenant, baseURL := server.SingleTenant(cfg.Tenant), func(*http.Request) string { return cfg.PublicURL }
	switch {
	case cfg.MultiTenant():
		tenant = server.SubdomainTenant(cfg.TenantDomain)
		scheme, _, _ := strings.Cut(cfg.PublicURL, "://")
		baseURL = func(r *http.Request) string { return scheme + "://" + r.Host }
	case cfg.PublicURL == "":
		baseURL = func(r *http.Request) string { return requestBaseURL(r, cfg.TrustProxyHeaders) }
	}
	guard := ratelimit.NewGuard(ratelimit.StaticConfig(cfg.RateLimit), ratelimit.NewMemory(now),
		ratelimit.WithAlert(func(err error) { slog.Error("rate limiter", "err", err) }))

	h := server.New(server.Options{
		Registry: reg, Tokens: tok, Sessions: flow, Auth: flow, Admins: cfg.InstanceAdmins(),
		Guard: guard, Tenant: tenant, BaseURL: baseURL, ClientIP: clientIP, GoChecksumDB: cfg.Upstreams.GoChecksumDB,
		Firewalls: firewalls,
	})
	return &app{handler: h, registry: reg, tokens: tok, sessions: st.sessions, close: st.close}, nil
}

func run(ctx context.Context, cfg config.Config) error {
	a, err := build(ctx, cfg, &http.Client{Timeout: 15 * time.Second}, time.Now)
	if err != nil {
		return fmt.Errorf("starting: %w", err)
	}
	defer a.close()

	// Purge soft-deleted versions whose grace period has passed, and
	// expired sessions.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if n, err := a.registry.PurgeExpired(ctx); err != nil {
				slog.Error("purging expired versions", "err", err)
			} else if n > 0 {
				slog.Info("purged expired versions", "count", n)
			}
			if err := a.sessions.DeleteExpired(time.Now()); err != nil {
				slog.Error("deleting expired sessions", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Uploads and downloads can be large; no overall read/write timeout.
		IdleTimeout: 120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("serving artifact repository", "version", version, "edition", edition.Name, "listen", cfg.Listen, "public_url", cfg.PublicURL)
		if cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
