package npm

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	leftPad     = "/left-pad/-/left-pad-1.3.0.tgz"
	leftPadPath = "/npm/proxy" + leftPad
)

// publicNPM stands in for registry.npmjs.org, where packuments from the
// firewall still link their tarballs.
func publicNPM(t *testing.T, e *proxyEnv) *atomic.Int32 {
	var hits atomic.Int32
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(e.up.tarballs[r.URL.Path])
	}))
	t.Cleanup(public.Close)
	e.up.tarballBase = public.URL
	return &hits
}

func TestFirewallTarballsGoThroughTheFirewall(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	publicHits := publicNPM(t, e)
	code, body, _ := e.do("GET", leftPadPath, "reader", nil)
	r.Equal(200, code, string(body))
	r.Equal("LEFTPAD-1.3.0", string(body))
	r.Equal(int32(0), publicHits.Load(), "not fetched around the firewall")
	r.Equal(1, e.up.firewall.Hits(leftPad))
}

func TestFirewallBlockedTarball(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	e.up.firewall.Block(leftPad)
	code, body, _ := e.do("GET", leftPadPath, "reader", nil)
	r.Equal(http.StatusForbidden, code)
	r.Contains(string(body), "hextrap firewall")
}

func TestFirewallRechecksCachedTarballs(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	code, _, _ := e.do("GET", leftPadPath, "reader", nil)
	r.Equal(200, code)

	e.up.firewall.Block(leftPad)
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()
	code, body, _ := e.do("GET", leftPadPath, "reader", nil)
	r.Equal(http.StatusForbidden, code, string(body))

	e.up.firewall.SetDown(true)
	e.mu.Lock()
	e.clock = e.clock.Add(upstream.IndexTTL + time.Second)
	e.mu.Unlock()
	code, _, _ = e.do("GET", leftPadPath, "reader", nil)
	r.Equal(200, code, "served from the cache while the firewall is down")
}
