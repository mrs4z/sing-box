// Package ratelimit provides per-user bandwidth limiting for proxy connections.
package ratelimit

import (
	"net"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// LimitedConn wraps a net.Conn with DOWNLOAD-ONLY bandwidth limiting.
//
// Only Write — bytes the server sends to the peer, i.e. the client's
// download — is shaped. Read (the client's upload) flows through
// untouched: the LTE quota and the post-cap throttle are about
// outgoing-from-server traffic only; uploads are free.
//
// Uses a token bucket algorithm — see Limiter.wait for refill details.
type LimitedConn struct {
	net.Conn
	limiter   *Limiter
	allowedFn func(host string) bool // optional: bypass limiter for whitelisted destinations
	destHost  string
}

// Limiter implements a simple token bucket rate limiter.
type Limiter struct {
	mu        sync.Mutex
	rate      int       // bytes per second
	tokens    int       // available tokens
	maxTokens int       // max burst (= rate, i.e. 1 second worth)
	lastFill  time.Time // last time tokens were refilled
}

// NewLimiter creates a rate limiter with the given bytes-per-second limit.
func NewLimiter(bytesPerSecond int) *Limiter {
	return &Limiter{
		rate:      bytesPerSecond,
		tokens:    bytesPerSecond, // start with full bucket
		maxTokens: bytesPerSecond,
		lastFill:  time.Now(),
	}
}

// wait blocks until n tokens are available, returns number of tokens consumed.
func (l *Limiter) wait(n int) int {
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.lastFill)
		if elapsed > 0 {
			refill := int(elapsed.Seconds() * float64(l.rate))
			if refill > 0 {
				l.tokens += refill
				if l.tokens > l.maxTokens {
					l.tokens = l.maxTokens
				}
				l.lastFill = now
			}
		}

		if l.tokens > 0 {
			take := n
			if take > l.tokens {
				take = l.tokens
			}
			l.tokens -= take
			l.mu.Unlock()
			return take
		}
		l.mu.Unlock()
		// Wait for tokens to refill — 50ms granularity
		time.Sleep(50 * time.Millisecond)
	}
}

// NewLimitedConn wraps a connection with bandwidth limiting.
// If allowedFn is set and returns true for the destination, the limiter is bypassed.
func NewLimitedConn(conn net.Conn, limiter *Limiter, destHost string, allowedFn func(string) bool) *LimitedConn {
	return &LimitedConn{
		Conn:      conn,
		limiter:   limiter,
		allowedFn: allowedFn,
		destHost:  destHost,
	}
}

func (c *LimitedConn) Read(b []byte) (int, error) {
	// Uploads (client → server) are NOT rate-limited. The product
	// spec is "limit applies only to outgoing traffic from the server",
	// which corresponds to LimitedConn.Write. Read passes straight
	// through to the underlying connection.
	return c.Conn.Read(b)
}

func (c *LimitedConn) Write(b []byte) (int, error) {
	// Bypass limiter for whitelisted destinations
	if c.allowedFn != nil && c.destHost != "" && c.allowedFn(c.destHost) {
		return c.Conn.Write(b)
	}

	written := 0
	for written < len(b) {
		remaining := len(b) - written
		allowed := c.limiter.wait(remaining)
		n, err := c.Conn.Write(b[written : written+allowed])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Unwrap returns the underlying connection (for sing-box compatibility).
func (c *LimitedConn) Unwrap() net.Conn {
	return c.Conn
}

// Upstream returns the underlying connection (for bufio compatibility).
func (c *LimitedConn) Upstream() any {
	return c.Conn
}

// LimitedPacketConn wraps a PacketConn with bandwidth limiting.
type LimitedPacketConn struct {
	N.PacketConn
	limiter   *Limiter
	allowedFn func(string) bool
	destHost  string
}

// NewLimitedPacketConn wraps a packet connection with bandwidth limiting.
func NewLimitedPacketConn(conn N.PacketConn, limiter *Limiter, destHost string, allowedFn func(string) bool) *LimitedPacketConn {
	return &LimitedPacketConn{
		PacketConn: conn,
		limiter:    limiter,
		allowedFn:  allowedFn,
		destHost:   destHost,
	}
}
