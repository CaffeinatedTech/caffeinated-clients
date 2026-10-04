package auth

import (
	"sync"
	"time"
)

// Rate limiting policy for login and TOTP attempts (F1.9). The counters live
// in memory: a single instance, so no shared store is needed.
const (
	rateWindow     = 15 * time.Minute
	rateMaxFailure = 5
	rateBaseLock   = 30 * time.Second
	rateMaxLock    = time.Hour
)

// Limiter is a small per-key failure limiter with exponential backoff. The
// zero value is not usable; call NewLimiter.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	windowStart time.Time
	failures    int
	lockedUntil time.Time
}

// NewLimiter returns an empty Limiter.
func NewLimiter() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket)}
}

// Allow reports whether an attempt for key may proceed, and if not, how long
// to wait. Keys are caller-defined (e.g. "ip:1.2.3.4", "user:adam").
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || now.Sub(b.windowStart) > rateWindow {
		return true, 0
	}
	if now.Before(b.lockedUntil) {
		return false, b.lockedUntil.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt and starts or extends a lock once the failure
// threshold is crossed.
func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 1024 {
		l.evictLocked(now)
	}
	b := l.buckets[key]
	if b == nil || now.Sub(b.windowStart) > rateWindow {
		b = &bucket{windowStart: now}
		l.buckets[key] = b
	}
	b.failures++
	if b.failures >= rateMaxFailure {
		lock := rateBaseLock << (b.failures - rateMaxFailure)
		if lock > rateMaxLock || lock <= 0 {
			lock = rateMaxLock
		}
		b.lockedUntil = now.Add(lock)
	}
}

// Reset clears a key's failures, e.g. after a successful authentication.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *Limiter) evictLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.windowStart) > rateWindow && now.After(b.lockedUntil) {
			delete(l.buckets, k)
		}
	}
}
