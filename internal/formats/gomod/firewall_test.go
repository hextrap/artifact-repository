package gomod

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	tomlZip     = "/github.com/!burnt!sushi/toml/@v/v1.4.0.zip"
	tomlZipPath = "/go/goproxy" + tomlZip
)

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func TestFirewallZipDownload(t *testing.T) {
	r := require.New(t)
	e := newEnvWith(t, true)
	code, body, _ := e.get(tomlZipPath, "reader")
	r.Equal(200, code, body)
	r.Equal(1, e.up.firewall.Hits(tomlZip))
}

func TestFirewallBlockedZip(t *testing.T) {
	r := require.New(t)
	e := newEnvWith(t, true)
	e.up.firewall.Block(tomlZip)
	code, body, _ := e.get(tomlZipPath, "reader")
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "hextrap firewall")
}

func TestFirewallRechecksCachedZips(t *testing.T) {
	r := require.New(t)
	e := newEnvWith(t, true)
	code, _, _ := e.get(tomlZipPath, "reader")
	r.Equal(200, code)

	e.up.firewall.Block(tomlZip)
	e.advance(upstream.IndexTTL + time.Second)
	code, body, _ := e.get(tomlZipPath, "reader")
	r.Equal(http.StatusForbidden, code, body)

	// .mod and .info aren't subject to policy at the firewall.
	modPath := "/go/goproxy/github.com/!burnt!sushi/toml/@v/v1.4.0.mod"
	code, _, _ = e.get(modPath, "reader")
	r.Equal(200, code)

	e.up.firewall.SetDown(true)
	e.advance(upstream.IndexTTL + time.Second)
	code, _, _ = e.get(tomlZipPath, "reader")
	r.Equal(200, code, "served from the cache while the firewall is down")
}
