package pypi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/upstream"
)

const (
	fwWheel     = "requests-2.32.3-py3-none-any.whl"
	fwWheelPath = "/pypi/proxy/files/requests/" + fwWheel
)

func TestFirewallDownloadsThroughTheFirewall(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	code, body, hdr := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code, body)
	r.Equal("WHEEL-BYTES", body)
	r.Equal("miss", hdr.Get("X-Hextrap-Cache"))
	r.Equal(1, e.up.firewall.Hits("/packages/"+fwWheel), "the firewall saw the download")
}

func TestFirewallBlockReachesTheClient(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	e.up.firewall.Block("/packages/" + fwWheel)
	code, body, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(http.StatusForbidden, code)
	r.Contains(body, "hextrap firewall")
	versions, _ := e.svc.Versions(context.Background(), principals["admin"], "proxy", "requests")
	r.Empty(versions, "nothing cached")
}

func TestFirewallRechecksCachedFiles(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	code, _, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code)

	code, _, hdr := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code)
	r.Equal("hit", hdr.Get("X-Hextrap-Cache"))

	// Denied after it was cached: the cached copy stops installing once the
	// last allow expires.
	e.up.firewall.Block("/packages/" + fwWheel)
	e.advance(upstream.IndexTTL + time.Second)
	code, body, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(http.StatusForbidden, code, body)
	r.Contains(body, "hextrap firewall")
}

func TestFirewallDownServesCachedFiles(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	code, _, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code)

	e.up.firewall.SetDown(true)
	e.advance(upstream.IndexTTL + time.Second)
	code, body, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code, "allowed when cached; the firewall being down doesn't break installs")
	r.Equal("WHEEL-BYTES", body)
}

func TestFirewallMetadataFilesArentRechecked(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	code, _, _ := e.get(fwWheelPath+".metadata", "reader", "")
	r.Equal(200, code)
	// The firewall passes metadata through without policy, so a check
	// would say nothing.
	before := e.up.firewall.Hits("/packages/" + fwWheel + ".metadata")
	e.advance(upstream.IndexTTL + time.Second)
	code, _, _ = e.get(fwWheelPath+".metadata", "reader", "")
	r.Equal(200, code)
	r.Equal(before, e.up.firewall.Hits("/packages/"+fwWheel+".metadata"))
}

func TestFirewallDownloadsDontGoAroundIt(t *testing.T) {
	r := require.New(t)
	e := newProxyEnvWith(t, true)
	// The index links files to the public file host, as pypi.org does.
	var publicHits atomic.Int32
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits.Add(1)
		w.Write([]byte("WHEEL-BYTES"))
	}))
	defer public.Close()
	e.up.fileBase = public.URL
	code, body, _ := e.get(fwWheelPath, "reader", "")
	r.Equal(200, code, body)
	r.Equal(int32(0), publicHits.Load(), "fetched through the firewall, not the public host")
	r.Equal(1, e.up.firewall.Hits("/packages/"+fwWheel))
}
