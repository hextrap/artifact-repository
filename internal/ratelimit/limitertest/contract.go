// Package limitertest is the shared contract every ratelimit.Limiter
// implementation (in-memory, Redis) must pass.
package limitertest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"hextrap.io/artifacts/internal/ratelimit"
)

// FakeClock is a manually advanced clock.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewFakeClock() *FakeClock {
	return &FakeClock{now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// Run exercises a Limiter. newLimiter must return a fresh limiter driven by clock.
func Run(t *testing.T, newLimiter func(t *testing.T, clock func() time.Time) ratelimit.Limiter) {
	ctx := context.Background()
	lim := ratelimit.Limit{Rate: 10, Burst: 20} // 10 units/s, burst 20

	check := func(key string, cost float64) ratelimit.Check {
		return ratelimit.Check{Scope: "tenant", Key: key, Cost: cost, Limit: lim}
	}

	t.Run("allows up to burst then denies", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		for i := 0; i < 20; i++ {
			d, err := l.AllowAll(ctx, []ratelimit.Check{check("a", 1)})
			r.NoError(err)
			r.True(d.Allowed, "request %d", i)
		}
		d, err := l.AllowAll(ctx, []ratelimit.Check{check("a", 1)})
		r.NoError(err)
		r.False(d.Allowed)
		r.Equal("tenant", d.Scope)
		r.Equal(100*time.Millisecond, d.RetryAfter)
	})

	t.Run("refills at rate", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		d, err := l.AllowAll(ctx, []ratelimit.Check{check("a", 20)})
		r.NoError(err)
		r.True(d.Allowed)

		d, _ = l.AllowAll(ctx, []ratelimit.Check{check("a", 5)})
		r.False(d.Allowed)
		r.Equal(500*time.Millisecond, d.RetryAfter)

		c.Advance(500 * time.Millisecond)
		d, _ = l.AllowAll(ctx, []ratelimit.Check{check("a", 5)})
		r.True(d.Allowed)
	})

	t.Run("cost is weighted", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		for i := 0; i < 4; i++ {
			d, _ := l.AllowAll(ctx, []ratelimit.Check{check("a", 5)})
			r.True(d.Allowed)
		}
		d, _ := l.AllowAll(ctx, []ratelimit.Check{check("a", 1)})
		r.False(d.Allowed)
	})

	t.Run("keys are independent", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		d, _ := l.AllowAll(ctx, []ratelimit.Check{check("a", 20)})
		r.True(d.Allowed)
		d, _ = l.AllowAll(ctx, []ratelimit.Check{check("a", 1)})
		r.False(d.Allowed)
		d, _ = l.AllowAll(ctx, []ratelimit.Check{check("b", 20)})
		r.True(d.Allowed)
	})

	t.Run("all-or-nothing across checks", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		small := ratelimit.Check{Scope: "principal", Key: "p", Cost: 1, Limit: ratelimit.Limit{Rate: 1, Burst: 1}}

		d, _ := l.AllowAll(ctx, []ratelimit.Check{check("t", 1), small})
		r.True(d.Allowed)
		// Principal is exhausted; the tenant must not be charged for the denied request.
		for i := 0; i < 5; i++ {
			d, _ = l.AllowAll(ctx, []ratelimit.Check{check("t", 1), small})
			r.False(d.Allowed)
			r.Equal("principal", d.Scope)
		}
		d, _ = l.AllowAll(ctx, []ratelimit.Check{check("t", 19)})
		r.True(d.Allowed, "tenant budget should be untouched by denied requests")
	})

	t.Run("reports remaining for the tightest scope", func(t *testing.T) {
		r := require.New(t)
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		small := ratelimit.Check{Scope: "principal", Key: "p", Cost: 1, Limit: ratelimit.Limit{Rate: 1, Burst: 5}}
		d, _ := l.AllowAll(ctx, []ratelimit.Check{check("t", 1), small})
		r.True(d.Allowed)
		r.Equal("principal", d.Scope)
		r.InDelta(4, d.Remaining, 0.001)
	})

	t.Run("cost above burst is never allowed", func(t *testing.T) {
		c := NewFakeClock()
		l := newLimiter(t, c.Now)
		d, err := l.AllowAll(ctx, []ratelimit.Check{check("a", 21)})
		require.NoError(t, err)
		require.False(t, d.Allowed)
	})
}
