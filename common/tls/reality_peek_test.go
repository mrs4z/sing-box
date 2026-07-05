//go:build with_utls

package tls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// captureClientHello returns the raw bytes crypto/tls emits as the first
// ClientHello flight for the given SNI.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		defer close(done)
		_, _ = io.Copy(&buf, server) // drains until the client pipe closes
	}()
	c := tls.Client(client, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS13})
	_ = client.SetDeadline(time.Now().Add(time.Second))
	// Handshake never completes (no server), but the ClientHello is written
	// before it blocks/errors — that's all we need.
	_ = c.Handshake()
	_ = client.Close()
	<-done
	return buf.Bytes()
}

func TestParseClientHelloSNI(t *testing.T) {
	for _, want := range []string{"github.com", "www.microsoft.com", "www.cloudflare.com"} {
		raw := captureClientHello(t, want)
		if len(raw) == 0 {
			t.Fatalf("no ClientHello captured for %s", want)
		}
		pc := &peekConn{Conn: &staticConn{data: raw}}
		got, err := parseClientHelloSNI(pc)
		if err != nil {
			t.Fatalf("parse SNI for %s: %v", want, err)
		}
		if got != want {
			t.Fatalf("SNI = %q, want %q", got, want)
		}
	}
}

// TestPeekConnReplaysExactBytes is the safety-critical invariant: whatever the
// sniffer consumed must be replayed byte-identically to the real handshake, or
// REALITY would read a truncated ClientHello and every connection would break.
func TestPeekConnReplaysExactBytes(t *testing.T) {
	raw := captureClientHello(t, "github.com")
	extra := []byte("APPLICATION-DATA-AFTER-HELLO")
	full := append(append([]byte{}, raw...), extra...)

	pc := &peekConn{Conn: &staticConn{data: full}}
	sni, err := parseClientHelloSNI(pc)
	if err != nil || sni != "github.com" {
		t.Fatalf("sniff: sni=%q err=%v", sni, err)
	}
	// Reading pc from the start must yield the ENTIRE original stream: the
	// peeked ClientHello bytes replayed first, then the untouched remainder.
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("peekConn replay mismatch: got %d bytes, want %d", len(got), len(full))
	}
}

func TestPeekClientHelloFailOpen(t *testing.T) {
	// Garbage that is not a TLS ClientHello must not panic and must still replay
	// every consumed byte (fail-open to the legacy handshake).
	junk := []byte("\x16\x03\x01\x00\x05HELLOnot-really-tls")
	sni, pc := peekClientHelloSNI(&staticConn{data: junk})
	if sni != "" {
		t.Fatalf("expected empty SNI on junk, got %q", sni)
	}
	got, _ := io.ReadAll(pc)
	if !bytes.Equal(got, junk) {
		t.Fatalf("fail-open must replay all bytes: got %d want %d", len(got), len(junk))
	}
}

// staticConn is a net.Conn that serves a fixed byte slice then EOF.
type staticConn struct {
	net.Conn
	data []byte
	pos  int
}

func (c *staticConn) Read(b []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(b, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *staticConn) Close() error { return nil }
