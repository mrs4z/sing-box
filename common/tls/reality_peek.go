//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
)

// Multi-decoy REALITY (Potok custom). The upstream REALITY server always dials
// one fixed decoy (RealityConfig.Dest) BEFORE reading the ClientHello, so a
// decoy that flaps unreachable from the box hangs every handshake — including
// authorized clients — until an operator reinstalls with a new SNI. To make
// that self-healing and seamless, we accept a POOL of decoys, peek the SNI the
// client actually sent, and steer the dial to THAT decoy (its cert matches the
// SNI, so masquerade toward scanners is preserved). Clients carry the pool and
// retry the next decoy when one is unreachable — no reinstall, no dropped
// sessions. This lives entirely in our wrapper; the vendored utls is untouched.

// realityDestContextKey carries the per-connection decoy dial target chosen from
// the peeked ClientHello SNI. RealityConfig.DialContext reads it and dials that
// instead of the fixed Config.Dest.
type realityDestContextKey struct{}

// destFromContext returns the per-connection decoy override, if any.
func destFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(realityDestContextKey{}).(string)
	return v, ok && v != ""
}

// withDest returns ctx carrying an explicit decoy dial target.
func withDest(ctx context.Context, dest string) context.Context {
	return context.WithValue(ctx, realityDestContextKey{}, dest)
}

// peekConn buffers the bytes consumed while sniffing the ClientHello and
// replays them on the first Reads, so the underlying REALITY handshake reads the
// exact same stream. Everything after the buffer passes straight through.
type peekConn struct {
	net.Conn
	buf []byte // already-read bytes not yet replayed
}

func (c *peekConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// readN reads exactly n bytes from conn into the peek buffer and returns them.
func (c *peekConn) readN(n int) ([]byte, error) {
	start := len(c.buf)
	for len(c.buf)-start < n {
		tmp := make([]byte, n-(len(c.buf)-start))
		read, err := c.Conn.Read(tmp)
		if read > 0 {
			c.buf = append(c.buf, tmp[:read]...)
		}
		if err != nil {
			return nil, err
		}
	}
	return c.buf[start : start+n], nil
}

var errNotClientHello = errors.New("reality: not a TLS 1.x ClientHello")

// peekClientHelloSNI reads the leading TLS record from conn, extracts the SNI
// from the ClientHello, and returns a peekConn that will replay those bytes to
// the real handshake. On any parse failure it returns a peekConn that has still
// buffered whatever it read, so the caller can hand it to the normal handshake
// unchanged (fail-open — never worse than the legacy path).
func peekClientHelloSNI(conn net.Conn) (string, *peekConn) {
	pc := &peekConn{Conn: conn}
	sni, err := parseClientHelloSNI(pc)
	if err != nil {
		return "", pc
	}
	return sni, pc
}

// parseClientHelloSNI parses just enough of the TLS record + ClientHello to pull
// the server_name extension. It reads through pc.readN so consumed bytes are
// buffered for replay. Deliberately strict and allocation-light; any deviation
// returns errNotClientHello and the caller falls back to legacy behavior.
func parseClientHelloSNI(pc *peekConn) (string, error) {
	// TLS record header: type(1)=handshake(22), version(2), length(2).
	hdr, err := pc.readN(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 22 {
		return "", errNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 42 || recLen > 16384 {
		return "", errNotClientHello
	}
	body, err := pc.readN(recLen)
	if err != nil {
		return "", err
	}
	return sniFromHandshake(body)
}

// sniFromHandshake walks a ClientHello handshake body and returns the SNI.
func sniFromHandshake(b []byte) (string, error) {
	// Handshake header: type(1)=client_hello(1), length(3).
	if len(b) < 4 || b[0] != 1 {
		return "", errNotClientHello
	}
	p := b[4:] // handshake body
	// legacy_version(2) + random(32)
	if len(p) < 34 {
		return "", errNotClientHello
	}
	p = p[34:]
	// session_id
	if len(p) < 1 {
		return "", errNotClientHello
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", errNotClientHello
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return "", errNotClientHello
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < csLen {
		return "", errNotClientHello
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return "", errNotClientHello
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", errNotClientHello
	}
	p = p[cmLen:]
	// extensions
	if len(p) < 2 {
		return "", errNotClientHello
	}
	extTotal := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < extTotal {
		return "", errNotClientHello
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < extLen {
			return "", errNotClientHello
		}
		if extType == 0 { // server_name
			return parseSNIExtension(p[:extLen])
		}
		p = p[extLen:]
	}
	return "", errNotClientHello
}

// parseSNIExtension pulls the first host_name from a server_name extension body.
func parseSNIExtension(b []byte) (string, error) {
	// ServerNameList: list_length(2), then entries: type(1), name_length(2), name.
	if len(b) < 2 {
		return "", errNotClientHello
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < listLen {
		return "", errNotClientHello
	}
	b = b[:listLen]
	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if len(b) < nameLen {
			return "", errNotClientHello
		}
		if nameType == 0 { // host_name
			return string(b[:nameLen]), nil
		}
		b = b[nameLen:]
	}
	return "", errNotClientHello
}
