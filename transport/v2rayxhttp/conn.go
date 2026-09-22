package v2rayxhttp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var _ net.Conn = (*clientConn)(nil)

// clientConn is one XHTTP session presented as a net.Conn: reads drain the
// streaming downlink response, writes are cut into numbered uplink requests.
type clientConn struct {
	ctx       context.Context
	cancel    context.CancelFunc
	client    *Client
	sessionID string
	reader    io.ReadCloser

	// Uploads run concurrently — the server puts them back in order by seq —
	// so `seq` is handed out under the lock and `inflight` bounds how many
	// requests may be outstanding at once.
	writeMu  sync.Mutex
	seq      int64
	inflight chan struct{}

	errMu     sync.Mutex
	writeErr  error
	closeOnce sync.Once
}

func newClientConn(ctx context.Context, cancel context.CancelFunc, client *Client, sessionID string, reader io.ReadCloser) *clientConn {
	return &clientConn{
		ctx:       ctx,
		cancel:    cancel,
		client:    client,
		sessionID: sessionID,
		reader:    reader,
		inflight:  make(chan struct{}, client.maxInflight),
	}
}

func (c *clientConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *clientConn) Write(b []byte) (int, error) {
	if err := c.err(); err != nil {
		return 0, err
	}
	written := 0
	for len(b) > 0 {
		size := len(b)
		if size > c.client.maxUpload {
			size = c.client.maxUpload
		}
		// The caller owns b and may reuse it the moment Write returns, while
		// the request is still in flight — so the chunk is copied.
		chunk := make([]byte, size)
		copy(chunk, b[:size])
		b = b[size:]

		c.writeMu.Lock()
		seq := c.seq
		c.seq++
		c.writeMu.Unlock()

		select {
		case c.inflight <- struct{}{}:
		case <-c.ctx.Done():
			return written, io.ErrClosedPipe
		}
		go func() {
			defer func() { <-c.inflight }()
			if err := c.upload(seq, chunk); err != nil {
				c.setErr(err)
				c.cancel()
			}
		}()
		written += size
	}
	return written, nil
}

// upload sends one chunk. The payload travels in the body for a POST, or split
// across X-Data-N headers when the CDN in front only proxies GET.
func (c *clientConn) upload(seq int64, payload []byte) error {
	request, err := c.client.newRequest(c.ctx, c.client.uplinkMethod, c.sessionID, strconv.FormatInt(seq, 10))
	if err != nil {
		return err
	}
	if c.client.headerUplink {
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		for i := 0; len(encoded) > 0; i++ {
			size := c.client.chunkSize
			if size > len(encoded) {
				size = len(encoded)
			}
			request.Header.Set(fmt.Sprintf("%s-%d", c.client.dataKey, i), encoded[:size])
			encoded = encoded[size:]
		}
	} else {
		request.Body = io.NopCloser(newBytesReader(payload))
		request.ContentLength = int64(len(payload))
	}

	response, err := c.client.transport.RoundTrip(request)
	if err != nil {
		return E.Cause(err, "v2ray-xhttp: upload seq ", seq)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return E.New("v2ray-xhttp: upload seq ", seq, " rejected: ", response.Status)
	}
	return nil
}

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.reader.Close()
	})
	return nil
}

func (c *clientConn) err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.writeErr
}

func (c *clientConn) setErr(err error) {
	c.errMu.Lock()
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.errMu.Unlock()
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}.TCPAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.client.serverAddr.TCPAddr()
}

// Deadlines are meaningless for a session spread over independent HTTP
// requests; cancellation happens through the connection context instead.
func (c *clientConn) SetDeadline(time.Time) error      { return nil }
func (c *clientConn) SetReadDeadline(time.Time) error  { return nil }
func (c *clientConn) SetWriteDeadline(time.Time) error { return nil }

// bytesReader is a minimal io.Reader over a byte slice — bytes.Reader would do,
// but keeping the type local avoids pulling the caller's buffer semantics into
// the request body path by accident.
type bytesReader struct {
	data []byte
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(b []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.data)
	r.data = r.data[n:]
	return n, nil
}
