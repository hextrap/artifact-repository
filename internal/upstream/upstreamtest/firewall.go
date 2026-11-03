// Package upstreamtest fakes a hextrap firewall in front of a format's fake
// upstream registry, answering the way codeproxy does.
package upstreamtest

import (
	"net/http"
	"sync"
)

// The credentials the fake firewall accepts.
const (
	Username = "fw-user"
	Password = "fw-pass"
)

// Firewall requires Basic auth, answers blocked paths with "400 blocking
// rule", and otherwise passes requests to the registry behind it.
type Firewall struct {
	next    http.Handler
	mu      sync.Mutex
	blocked map[string]bool
	down    bool
	hits    map[string]int
}

func NewFirewall(next http.Handler) *Firewall {
	return &Firewall{next: next, blocked: map[string]bool{}, hits: map[string]int{}}
}

// Block makes the firewall refuse requests for path.
func (f *Firewall) Block(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[path] = true
}

// SetDown makes every request fail with 503.
func (f *Firewall) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// Hits counts the authenticated requests for path.
func (f *Firewall) Hits(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *Firewall) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	down, blocked := f.down, f.blocked[r.URL.Path]
	f.mu.Unlock()
	if down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if u, p, ok := r.BasicAuth(); !ok || u != Username || p != Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.mu.Unlock()
	if blocked {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("blocking rule"))
		return
	}
	f.next.ServeHTTP(w, r)
}
