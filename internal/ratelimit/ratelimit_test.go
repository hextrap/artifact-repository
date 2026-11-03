package ratelimit_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/ratelimit"
	"hextrap.io/artifacts/internal/ratelimit/limitertest"
)

func TestMemoryLimiterContract(t *testing.T) {
	limitertest.Run(t, func(t *testing.T, clock func() time.Time) ratelimit.Limiter {
		return ratelimit.NewMemory(clock)
	})
}

func enabledConfig() ratelimit.Config {
	cfg := ratelimit.DefaultConfig()
	cfg.Enabled = true
	cfg.Tenant = ratelimit.Limit{Rate: 10, Burst: 100}
	cfg.PrincipalShare = 0.5
	cfg.Anonymous = ratelimit.Limit{Rate: 1, Burst: 10}
	return cfg
}

func newGuard(clock *limitertest.FakeClock, cfg ratelimit.Config) *ratelimit.Guard {
	return ratelimit.NewGuard(ratelimit.StaticConfig(cfg), ratelimit.NewMemory(clock.Now))
}

func TestGuardTenantIsolation(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	g := newGuard(limitertest.NewFakeClock(), enabledConfig())

	// Exhaust tenant A using several principals so the per-principal cap isn't what trips.
	for i := 0; ; i++ {
		d := g.Check(ctx, ratelimit.Request{Tenant: "a", Principal: string(rune('p' + i%3)), Op: ratelimit.OpRead})
		if !d.Allowed {
			r.Equal("tenant", d.Scope)
			break
		}
		r.Less(i, 1000)
	}
	d := g.Check(ctx, ratelimit.Request{Tenant: "b", Principal: "p", Op: ratelimit.OpRead})
	r.True(d.Allowed, "tenant B must be unaffected by tenant A")
}

func TestGuardPrincipalShare(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	g := newGuard(limitertest.NewFakeClock(), enabledConfig())

	allowed := 0
	for i := 0; i < 200; i++ {
		if g.Check(ctx, ratelimit.Request{Tenant: "a", Principal: "runaway", Op: ratelimit.OpRead}).Allowed {
			allowed++
		}
	}
	r.Equal(50, allowed, "one principal gets half the tenant burst")

	d := g.Check(ctx, ratelimit.Request{Tenant: "a", Principal: "other", Op: ratelimit.OpRead})
	r.True(d.Allowed, "another principal in the same tenant still works")
}

func TestGuardCostWeights(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	g := newGuard(limitertest.NewFakeClock(), enabledConfig())

	count := func(op ratelimit.Op, principal string) int {
		n := 0
		for g.Check(ctx, ratelimit.Request{Tenant: principal, Principal: principal, Op: op}).Allowed {
			n++
		}
		return n
	}
	r.Equal(50, count(ratelimit.OpRead, "t1"))
	r.Equal(50, count(ratelimit.OpDownload, "t2"))
	r.Equal(10, count(ratelimit.OpUpstreamMiss, "t3"))
	r.Equal(5, count(ratelimit.OpPublish, "t4"))
	r.Equal(10, count(ratelimit.OpAuth, "t5"))
}

func TestGuardAnonymousLimitedPerIP(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	g := newGuard(limitertest.NewFakeClock(), enabledConfig())

	n := 0
	for g.Check(ctx, ratelimit.Request{Tenant: "a", IP: "1.1.1.1", Op: ratelimit.OpRead}).Allowed {
		n++
	}
	r.Equal(10, n)
	r.True(g.Check(ctx, ratelimit.Request{Tenant: "a", IP: "2.2.2.2", Op: ratelimit.OpRead}).Allowed)
	r.True(g.Check(ctx, ratelimit.Request{Tenant: "a", Principal: "u", Op: ratelimit.OpRead}).Allowed,
		"authenticated traffic is not limited by anonymous IP buckets")
}

func TestGuardDisabledAllowsEverything(t *testing.T) {
	g := newGuard(limitertest.NewFakeClock(), ratelimit.DefaultConfig())
	for i := 0; i < 100000; i++ {
		require.True(t, g.Check(context.Background(), ratelimit.Request{Tenant: "a", Principal: "u", Op: ratelimit.OpPublish}).Allowed)
	}
}

func TestDefaultConfigIsDisabled(t *testing.T) {
	require.False(t, ratelimit.DefaultConfig().Enabled, "self-hosted default is off")
}

// A fresh `npm ci` of a 3,000-package lockfile (metadata + tarball per
// package, ~1,000 req/s) must not throttle on the lowest paid cloud tier.
func TestLowestPaidTierAllowsLargeLockfileInstall(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	clock := limitertest.NewFakeClock()
	cfg, ok := ratelimit.Tiers["team"]
	r.True(ok)
	g := ratelimit.NewGuard(ratelimit.StaticConfig(cfg), ratelimit.NewMemory(clock.Now))

	for i := 0; i < 3000; i++ {
		for _, op := range []ratelimit.Op{ratelimit.OpRead, ratelimit.OpDownload} {
			d := g.Check(ctx, ratelimit.Request{Tenant: "acme", Principal: "ci", Op: op})
			r.True(d.Allowed, "throttled at package %d", i)
			clock.Advance(time.Millisecond)
		}
	}
}

type failingLimiter struct{}

func (failingLimiter) AllowAll(context.Context, []ratelimit.Check) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("redis: connection refused")
}

func TestGuardFailsOpenToFallback(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	clock := limitertest.NewFakeClock()
	var alerts []error
	g := ratelimit.NewGuard(ratelimit.StaticConfig(enabledConfig()), failingLimiter{},
		ratelimit.WithFallback(ratelimit.NewMemory(clock.Now), 2),
		ratelimit.WithAlert(func(err error) { alerts = append(alerts, err) }))

	allowed := 0
	for i := 0; i < 200; i++ {
		if g.Check(ctx, ratelimit.Request{Tenant: "a", Principal: "u", Op: ratelimit.OpRead}).Allowed {
			allowed++
		}
	}
	r.Equal(25, allowed, "fallback uses limit / replica count")
	r.NotEmpty(alerts)
}

func TestGuardWithoutFallbackFailsOpen(t *testing.T) {
	g := ratelimit.NewGuard(ratelimit.StaticConfig(enabledConfig()), failingLimiter{})
	require.True(t, g.Check(context.Background(), ratelimit.Request{Tenant: "a", Principal: "u", Op: ratelimit.OpRead}).Allowed)
}

type countingSource struct {
	cfg   ratelimit.Config
	calls int
}

func (s *countingSource) ConfigFor(string) ratelimit.Config {
	s.calls++
	return s.cfg
}

func TestCachedConfigPicksUpChangesAfterTTL(t *testing.T) {
	r := require.New(t)
	clock := limitertest.NewFakeClock()
	src := &countingSource{cfg: enabledConfig()}
	cached := ratelimit.NewCachedConfig(src, time.Minute, clock.Now)

	r.Equal(float64(100), cached.ConfigFor("a").Tenant.Burst)
	src.cfg.Tenant.Burst = 500
	r.Equal(float64(100), cached.ConfigFor("a").Tenant.Burst, "still cached")
	clock.Advance(61 * time.Second)
	r.Equal(float64(500), cached.ConfigFor("a").Tenant.Burst)
	r.Equal(2, src.calls)
}

func TestWriteHeaders(t *testing.T) {
	r := require.New(t)
	w := httptest.NewRecorder()
	ratelimit.WriteHeaders(w, ratelimit.Decision{
		Allowed:    false,
		Scope:      "tenant",
		Limit:      ratelimit.Limit{Rate: 10, Burst: 100},
		Remaining:  0,
		RetryAfter: 1500 * time.Millisecond,
	})
	r.Equal("2", w.Header().Get("Retry-After"), "rounded up to whole seconds")
	r.Equal(`"tenant";q=100;w=10`, w.Header().Get("RateLimit-Policy"))
	r.Equal(`"tenant";r=0;t=2`, w.Header().Get("RateLimit"))
}
