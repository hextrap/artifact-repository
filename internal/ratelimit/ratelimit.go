// Package ratelimit implements per-tenant, per-principal and per-IP rate
// limiting using GCRA (a token-bucket equivalent that stores one timestamp
// per key).
package ratelimit

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Limit allows Rate cost units per second with bursts of up to Burst units.
type Limit struct {
	Rate  float64 `yaml:"rate"`
	Burst float64 `yaml:"burst"`
}

func (l Limit) scale(f float64) Limit {
	return Limit{Rate: l.Rate * f, Burst: l.Burst * f}
}

// Check is one bucket a request must fit in.
type Check struct {
	Scope string // "tenant", "principal", "anonymous"; reported back in Decision
	Key   string
	Cost  float64
	Limit Limit
}

type Decision struct {
	Allowed bool
	// Scope and Limit describe the denying bucket, or the tightest one when allowed.
	Scope      string
	Limit      Limit
	Remaining  float64
	RetryAfter time.Duration // when denied
	Reset      time.Duration // until the bucket is full again
}

// Limiter checks a request against several buckets atomically: it is
// charged to all of them or, if any would be exceeded, to none.
type Limiter interface {
	AllowAll(ctx context.Context, checks []Check) (Decision, error)
}

// Memory is an in-process Limiter, for self-hosted and single-replica use.
type Memory struct {
	mu    sync.Mutex
	now   func() time.Time
	tat   map[string]int64 // theoretical arrival time, unix nanos
	calls int
}

func NewMemory(now func() time.Time) *Memory {
	return &Memory{now: now, tat: map[string]int64{}}
}

const sweepEvery = 4096

func (m *Memory) AllowAll(_ context.Context, checks []Check) (Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UnixNano()

	m.calls++
	if m.calls%sweepEvery == 0 {
		// A key whose TAT has passed is a full bucket; forgetting it is equivalent.
		for k, t := range m.tat {
			if t <= now {
				delete(m.tat, k)
			}
		}
	}

	newTATs := make([]int64, len(checks))
	var denied, tightest *Decision
	for i, c := range checks {
		d, newTAT := gcra(now, m.tat[c.Key], c)
		newTATs[i] = newTAT
		if !d.Allowed {
			if denied == nil || d.RetryAfter > denied.RetryAfter {
				denied = &d
			}
			continue
		}
		if tightest == nil || d.Remaining < tightest.Remaining {
			tightest = &d
		}
	}
	if denied != nil {
		return *denied, nil
	}
	for i, c := range checks {
		m.tat[c.Key] = newTATs[i]
	}
	if tightest == nil {
		return Decision{Allowed: true}, nil
	}
	return *tightest, nil
}

// gcra evaluates one check against a key's stored TAT and returns the TAT to
// store if the request is allowed. A Redis implementation must use the same
// arithmetic (in its Lua script) to pass limitertest.
func gcra(now, tat int64, c Check) (Decision, int64) {
	interval := float64(time.Second) / c.Limit.Rate // nanos per unit
	tolerance := int64(c.Limit.Burst * interval)
	if tat < now {
		tat = now
	}
	newTAT := tat + int64(math.Round(c.Cost*interval))
	d := Decision{Scope: c.Scope, Limit: c.Limit}
	if newTAT-now > tolerance {
		d.RetryAfter = time.Duration(newTAT - tolerance - now)
		d.Reset = time.Duration(tat - now)
		d.Remaining = math.Max(0, math.Floor(float64(tolerance-(tat-now))/interval))
		return d, tat
	}
	d.Allowed = true
	d.Reset = time.Duration(newTAT - now)
	d.Remaining = float64(tolerance-(newTAT-now)) / interval
	return d, newTAT
}

// Op classifies a request for costing.
type Op string

const (
	OpRead         Op = "read"          // metadata/index served from cache
	OpDownload     Op = "download"      // package file
	OpUpstreamMiss Op = "upstream_miss" // charged in addition when a proxy repo fetches upstream
	OpPublish      Op = "publish"
	OpAuth         Op = "auth"
)

type Config struct {
	Enabled bool  `yaml:"enabled"`
	Tenant  Limit `yaml:"tenant"`
	// PrincipalShare is the fraction of the tenant limit one user or token may use.
	PrincipalShare float64        `yaml:"principal_share"`
	Anonymous      Limit          `yaml:"anonymous"`
	Costs          map[Op]float64 `yaml:"costs"`
}

func DefaultCosts() map[Op]float64 {
	return map[Op]float64{
		OpRead:         1,
		OpDownload:     1,
		OpUpstreamMiss: 5,
		OpPublish:      10,
		OpAuth:         5,
	}
}

// DefaultConfig is the self-hosted default: limiting off.
func DefaultConfig() Config {
	return Config{
		Enabled:        false,
		Tenant:         Limit{Rate: 200, Burst: 50000},
		PrincipalShare: 0.5,
		Anonymous:      Limit{Rate: 5, Burst: 200},
		Costs:          DefaultCosts(),
	}
}

// Tiers are the cloud plan defaults. Bursts are sized for large lockfile
// installs, which are normal traffic.
var Tiers = map[string]Config{
	"free":       {Enabled: true, Tenant: Limit{Rate: 10, Burst: 4000}, PrincipalShare: 0.5, Anonymous: Limit{Rate: 2, Burst: 100}, Costs: DefaultCosts()},
	"team":       {Enabled: true, Tenant: Limit{Rate: 50, Burst: 20000}, PrincipalShare: 0.5, Anonymous: Limit{Rate: 5, Burst: 200}, Costs: DefaultCosts()},
	"enterprise": {Enabled: true, Tenant: Limit{Rate: 200, Burst: 100000}, PrincipalShare: 0.5, Anonymous: Limit{Rate: 10, Burst: 500}, Costs: DefaultCosts()},
}

type ConfigSource interface {
	ConfigFor(tenant string) Config
}

type StaticConfig Config

func (s StaticConfig) ConfigFor(string) Config { return Config(s) }

// CachedConfig caches another source's per-tenant config for ttl.
type CachedConfig struct {
	src     ConfigSource
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]cachedEntry
}

type cachedEntry struct {
	cfg     Config
	fetched time.Time
}

func NewCachedConfig(src ConfigSource, ttl time.Duration, now func() time.Time) *CachedConfig {
	return &CachedConfig{src: src, ttl: ttl, now: now, entries: map[string]cachedEntry{}}
}

func (c *CachedConfig) ConfigFor(tenant string) Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e, ok := c.entries[tenant]; ok && now.Sub(e.fetched) < c.ttl {
		return e.cfg
	}
	cfg := c.src.ConfigFor(tenant)
	c.entries[tenant] = cachedEntry{cfg: cfg, fetched: now}
	return cfg
}

type Request struct {
	Tenant    string
	Principal string // empty for anonymous requests
	IP        string
	Op        Op
}

type Guard struct {
	source   ConfigSource
	primary  Limiter
	fallback Limiter
	replicas int
	alert    func(error)
}

type Option func(*Guard)

// WithFallback is used when the primary limiter errors (e.g. Redis down),
// with limits divided across replicas since each replica counts alone.
func WithFallback(l Limiter, replicas int) Option {
	return func(g *Guard) {
		g.fallback = l
		g.replicas = max(replicas, 1)
	}
}

func WithAlert(f func(error)) Option {
	return func(g *Guard) { g.alert = f }
}

func NewGuard(source ConfigSource, primary Limiter, opts ...Option) *Guard {
	g := &Guard{source: source, primary: primary, replicas: 1, alert: func(error) {}}
	for _, o := range opts {
		o(g)
	}
	return g
}

func (g *Guard) checks(cfg Config, req Request, scale float64) []Check {
	cost, ok := cfg.Costs[req.Op]
	if !ok {
		cost = 1
	}
	tenant := cfg.Tenant.scale(scale)
	checks := []Check{{Scope: "tenant", Key: "t:" + req.Tenant, Cost: cost, Limit: tenant}}
	if req.Principal != "" {
		checks = append(checks, Check{Scope: "principal", Key: "p:" + req.Tenant + ":" + req.Principal, Cost: cost, Limit: tenant.scale(cfg.PrincipalShare)})
	} else {
		checks = append(checks, Check{Scope: "anonymous", Key: "a:" + req.Tenant + ":" + req.IP, Cost: cost, Limit: cfg.Anonymous.scale(scale)})
	}
	return checks
}

// Check charges the request and reports whether it may proceed. It never
// fails closed: if limiting is unavailable, requests are allowed.
func (g *Guard) Check(ctx context.Context, req Request) Decision {
	cfg := g.source.ConfigFor(req.Tenant)
	if !cfg.Enabled {
		return Decision{Allowed: true}
	}
	d, err := g.primary.AllowAll(ctx, g.checks(cfg, req, 1))
	if err == nil {
		return d
	}
	g.alert(fmt.Errorf("rate limiter unavailable, failing open: %w", err))
	if g.fallback == nil {
		return Decision{Allowed: true}
	}
	d, err = g.fallback.AllowAll(ctx, g.checks(cfg, req, 1/float64(g.replicas)))
	if err != nil {
		return Decision{Allowed: true}
	}
	return d
}

func ceilSeconds(d time.Duration) int64 {
	return int64(math.Ceil(d.Seconds()))
}

// WriteHeaders sets Retry-After (when denied) and the IETF draft
// RateLimit-Policy / RateLimit headers.
func WriteHeaders(w http.ResponseWriter, d Decision) {
	if d.Scope == "" || d.Limit.Rate == 0 {
		return
	}
	window := int64(math.Ceil(d.Limit.Burst / d.Limit.Rate))
	w.Header().Set("RateLimit-Policy", fmt.Sprintf(`%q;q=%d;w=%d`, d.Scope, int64(d.Limit.Burst), window))
	reset := d.Reset
	if !d.Allowed {
		reset = d.RetryAfter
		w.Header().Set("Retry-After", strconv.FormatInt(ceilSeconds(d.RetryAfter), 10))
	}
	w.Header().Set("RateLimit", fmt.Sprintf(`%q;r=%d;t=%d`, d.Scope, int64(d.Remaining), ceilSeconds(reset)))
}
