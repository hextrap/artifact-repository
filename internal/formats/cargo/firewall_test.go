package cargo

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/upstream"
	"hextrap.io/artifacts/internal/upstream/upstreamtest"
)

const serdeDownload = "/cargo/crates-io/api/v1/crates/serde/1.0.201/download"

func newFirewallEnv(t *testing.T) (*fakeCratesIO, *env) {
	f := newFakeCratesIO(t)
	f.firewall = upstreamtest.NewFirewall(f.registry)
	return f, newEnvWith(t, f.srv.URL, true)
}

func TestFirewallCrateDownload(t *testing.T) {
	r := require.New(t)
	f, e := newFirewallEnv(t)
	code, body, _ := e.do("GET", serdeDownload, "reader", nil)
	r.Equal(200, code, body)
	r.Equal("SERDE-201", body)
	r.Equal(1, f.firewall.Hits("/dl/serde/1.0.201/download"))
	r.Equal(int32(0), f.count("HEAD /dl/serde/1.0.201/download"),
		"no HEAD for a publish date: the firewall applies soak time, and a HEAD would log a second install")
}

func TestFirewallBlockedCrate(t *testing.T) {
	r := require.New(t)
	f, e := newFirewallEnv(t)
	f.firewall.Block("/dl/serde/1.0.201/download")
	code, body, _ := e.do("GET", serdeDownload, "reader", nil)
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "hextrap firewall")
}

func TestFirewallRechecksCachedCrates(t *testing.T) {
	r := require.New(t)
	f, e := newFirewallEnv(t)
	code, _, _ := e.do("GET", serdeDownload, "reader", nil)
	r.Equal(200, code)

	f.firewall.Block("/dl/serde/1.0.201/download")
	e.advance(upstream.IndexTTL + time.Second)
	code, body, _ := e.do("GET", serdeDownload, "reader", nil)
	r.Equal(http.StatusForbidden, code, body)

	f.firewall.SetDown(true)
	e.advance(upstream.IndexTTL + time.Second)
	code, _, _ = e.do("GET", serdeDownload, "reader", nil)
	r.Equal(200, code, "served from the cache while the firewall is down")
}
