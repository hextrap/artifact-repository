package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/config"
	"hextrap.io/artifacts/internal/identity"
	"hextrap.io/artifacts/internal/registry"
	"hextrap.io/artifacts/internal/upstream/upstreamtest"
)

// fakePyPIFirewall serves one wheel through a fake hextrap firewall.
func fakePyPIFirewall(t *testing.T) (*upstreamtest.Firewall, string) {
	wheel := []byte("WHEEL")
	sum := sha256.Sum256(wheel)
	mux := http.NewServeMux()
	mux.HandleFunc("/simple/demo/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		json.NewEncoder(w).Encode(map[string]any{"files": []map[string]any{{
			"filename": "demo-1.0-py3-none-any.whl", "url": "/packages/demo-1.0-py3-none-any.whl",
			"hashes": map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}}})
	})
	mux.HandleFunc("/packages/demo-1.0-py3-none-any.whl", func(w http.ResponseWriter, r *http.Request) { w.Write(wheel) })
	fw := upstreamtest.NewFirewall(mux)
	srv := httptest.NewServer(fw)
	t.Cleanup(srv.Close)
	return fw, srv.URL
}

func TestBuildConnectsTheFirewall(t *testing.T) {
	r := require.New(t)
	fw, url := fakePyPIFirewall(t)
	cfg := localConfig(t.TempDir())
	cfg.HextrapFirewall = &config.FirewallConfig{Username: upstreamtest.Username, Password: upstreamtest.Password,
		URLs: map[string]string{"pypi": url}}
	cfg.Upstreams.PyPI = []string{"https://pypi.org"}
	app, err := build(context.Background(), cfg, http.DefaultClient, time.Now)
	r.NoError(err)
	r.Equal([]string{url, "https://pypi.org"}, app.registry.Upstreams()[registry.FormatPyPI], "the firewall is the default")

	admin := identity.Principal{Tenant: "default", Kind: identity.KindUser, Subject: "admin"}
	r.NoError(app.registry.CreateRepo(context.Background(), admin, registry.RepoInput{
		Name: "pypi", Format: registry.FormatPyPI, Type: registry.TypeProxy, AnonymousRead: true}))
	get := func() int {
		rec := httptest.NewRecorder()
		app.handler.ServeHTTP(rec, httptest.NewRequest("GET", "/pypi/pypi/files/demo/demo-1.0-py3-none-any.whl", nil))
		return rec.Code
	}
	r.Equal(200, get())
	r.Equal(1, fw.Hits("/packages/demo-1.0-py3-none-any.whl"), "fetched through the firewall with its credentials")

	fw.Block("/packages/demo-1.0-py3-none-any.whl")
	app2, err := build(context.Background(), cfg, http.DefaultClient, time.Now) // a fresh process: no remembered allow
	r.NoError(err)
	app = app2
	r.Equal(http.StatusForbidden, get())
}
