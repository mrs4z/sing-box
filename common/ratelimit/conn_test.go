package ratelimit

import "testing"

func TestSetRate(t *testing.T) {
	l := NewLimiter(100)
	if l.rate != 100 || l.maxTokens != 100 {
		t.Fatalf("unexpected initial state: rate=%d max=%d", l.rate, l.maxTokens)
	}

	l.SetRate(50)
	if l.rate != 50 || l.maxTokens != 50 {
		t.Fatalf("rate not updated: rate=%d max=%d", l.rate, l.maxTokens)
	}
	if l.tokens > 50 {
		t.Fatalf("tokens must be clamped to new max, got %d", l.tokens)
	}

	// Non-positive rates are ignored (callers drop the limiter instead).
	l.SetRate(0)
	if l.rate != 50 {
		t.Fatalf("SetRate(0) must be a no-op, got rate=%d", l.rate)
	}

	l.SetRate(1000)
	if l.rate != 1000 || l.maxTokens != 1000 {
		t.Fatalf("rate not raised: rate=%d max=%d", l.rate, l.maxTokens)
	}
}
