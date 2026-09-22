// Package v2rayxhttp speaks Xray's XHTTP transport (packet-up mode) as a
// CLIENT. It exists because sing-box has no XHTTP of its own and our servers
// moved to Xray: an XHTTP inbound behind a CDN is the one transport that still
// gets through networks where REALITY and plain TLS to a flagged IP are cut.
//
// Wire protocol, as implemented by the Xray server we talk to
// (transport/internet/splithttp):
//
//	downlink  GET  <path>/<session>?x_padding=…   → 200, body streams forever
//	uplink    POST <path>/<session>/<seq>          → body carries the chunk
//	          GET  <path>/<session>/<seq>          → chunk rides in X-Data-N
//	                                                 headers, base64url, when
//	                                                 the CDN in front refuses
//	                                                 anything but GET/HEAD
//
// The server reassembles the uplink by `seq`, so requests may fly in parallel
// and arrive out of order — which is exactly how throughput is won: waiting for
// each upload's response would cap a connection at one chunk per round trip.
//
// Only packet-up is implemented. stream-up / stream-one need a request body
// that stays open for the life of the connection, which no CDN we front with
// will proxy, and "auto" is ambiguous on the wire.
package v2rayxhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

const (
	// Chunk size the uplink splits writes at. Xray's own default is 1 MB for a
	// body upload; with the payload in headers a CDN's header budget decides,
	// and 64 KB measured best against Yandex Cloud CDN (5.8-18.9 MB/s, where
	// 16 KB gave 0.8 MB/s).
	defaultMaxEachPostBytes = 1000000
	defaultHeaderPostBytes  = 65536

	// Padding length range, matching Xray's default: the server REJECTS a
	// request whose x_padding falls outside its own range with 400.
	defaultPaddingMin = 100
	defaultPaddingMax = 1000

	// Base64url chunk per X-Data-N header. Xray's default for header placement.
	defaultHeaderChunkSize = 3500

	// Uploads in flight at once. Ordering is restored server-side by seq, so
	// this only bounds memory and connection pressure.
	defaultMaxInflightUploads = 8

	defaultUplinkDataKey = "X-Data"
)

// Client dials XHTTP connections against one server.
type Client struct {
	ctx        context.Context
	transport  http.RoundTripper
	requestURL url.URL
	host       string
	headers    http.Header
	serverAddr M.Socksaddr

	maxUpload    int
	padMin       int
	padMax       int
	uplinkMethod string
	headerUplink bool
	dataKey      string
	chunkSize    int
	maxInflight  int
}

// NewClient builds the transport. `tlsConfig` is required in practice — our
// inbounds are real-cert TLS and every CDN terminates HTTPS — but plaintext
// h2c is kept working for local tests.
func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.Mode != "" && options.Mode != "packet-up" {
		return nil, E.New("v2ray-xhttp: unsupported mode: ", options.Mode, " (only packet-up is implemented)")
	}

	var transport http.RoundTripper
	var requestURL url.URL
	if tlsConfig == nil {
		requestURL.Scheme = "http"
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}
	} else {
		requestURL.Scheme = "https"
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
		tlsDialer := tls.NewDialer(dialer, tlsConfig)
		transport = &http2.Transport{
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     10 * time.Second,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
			},
		}
	}
	requestURL.Host = serverAddr.String()
	requestURL.Path = normalizePath(options.Path)

	host := options.Host
	if host == "" && tlsConfig != nil {
		host = tlsConfig.ServerName()
	}
	if host == "" {
		host = serverAddr.AddrString()
	}

	padMin, padMax, err := parseRange(options.XPaddingBytes, defaultPaddingMin, defaultPaddingMax)
	if err != nil {
		return nil, E.Cause(err, "v2ray-xhttp: parse xPaddingBytes")
	}

	headerUplink := strings.EqualFold(options.UplinkDataPlacement, "header")
	uplinkMethod := strings.ToUpper(options.UplinkHTTPMethod)
	switch uplinkMethod {
	case "":
		uplinkMethod = http.MethodPost
	case http.MethodPost:
	case http.MethodGet:
		// A GET carrying a body is dropped by every middlebox worth fronting
		// with, so the payload has to move into headers.
		headerUplink = true
	default:
		return nil, E.New("v2ray-xhttp: unsupported uplinkHTTPMethod: ", options.UplinkHTTPMethod)
	}

	maxUpload := options.ScMaxEachPostBytes
	if maxUpload <= 0 {
		if headerUplink {
			maxUpload = defaultHeaderPostBytes
		} else {
			maxUpload = defaultMaxEachPostBytes
		}
	}
	chunkSize := options.UplinkChunkSize
	if chunkSize <= 0 {
		chunkSize = defaultHeaderChunkSize
	}
	dataKey := options.UplinkDataKey
	if dataKey == "" {
		dataKey = defaultUplinkDataKey
	}
	maxInflight := options.MaxConcurrentUploads
	if maxInflight <= 0 {
		maxInflight = defaultMaxInflightUploads
	}

	return &Client{
		ctx:          ctx,
		transport:    transport,
		requestURL:   requestURL,
		host:         host,
		headers:      options.Headers.Build(),
		serverAddr:   serverAddr,
		maxUpload:    maxUpload,
		padMin:       padMin,
		padMax:       padMax,
		uplinkMethod: uplinkMethod,
		headerUplink: headerUplink,
		dataKey:      dataKey,
		chunkSize:    chunkSize,
		maxInflight:  maxInflight,
	}, nil
}

// DialContext opens one XHTTP session: a streaming GET for the downlink, plus
// the bookkeeping the uplink requests need.
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}

	// The downlink request outlives this call, so it must not inherit the dial
	// context (which is cancelled as soon as the dial returns).
	connCtx, cancel := context.WithCancel(c.ctx)

	request, err := c.newRequest(connCtx, http.MethodGet, sessionID, "")
	if err != nil {
		cancel()
		return nil, err
	}
	response, err := c.transport.RoundTrip(request)
	if err != nil {
		cancel()
		return nil, E.Cause(err, "v2ray-xhttp: open downlink")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		cancel()
		return nil, E.New("v2ray-xhttp: unexpected downlink status: ", response.Status)
	}

	return newClientConn(connCtx, cancel, c, sessionID, response.Body), nil
}

func (c *Client) Close() error {
	if transport, ok := c.transport.(*http2.Transport); ok {
		transport.CloseIdleConnections()
	}
	if transport, ok := c.transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// newRequest builds one XHTTP request: <path>/<session>[/<seq>] plus the
// x_padding the server validates.
func (c *Client) newRequest(ctx context.Context, method, sessionID, seq string) (*http.Request, error) {
	requestURL := c.requestURL
	requestURL.Path = requestURL.Path + sessionID
	if seq != "" {
		requestURL.Path = requestURL.Path + "/" + seq
	}
	padding, err := randomPadding(c.padMin, c.padMax)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("x_padding", padding)
	requestURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header = c.headers.Clone()
	if request.Header == nil {
		request.Header = http.Header{}
	}
	request.Host = c.host
	return request, nil
}

// normalizePath mirrors Xray's GetNormalizedPath: leading and trailing slash,
// so session and seq can simply be appended.
func normalizePath(path string) string {
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path += "/"
	}
	return path
}

// parseRange reads "N" or "N-M" (Xray's range syntax), falling back to the
// given defaults when empty.
func parseRange(value string, defaultMin, defaultMax int) (int, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultMin, defaultMax, nil
	}
	from, to, found := strings.Cut(value, "-")
	minValue, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil {
		return 0, 0, E.New("invalid range: ", value)
	}
	if !found {
		return minValue, minValue, nil
	}
	maxValue, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil {
		return 0, 0, E.New("invalid range: ", value)
	}
	if maxValue < minValue {
		return 0, 0, E.New("invalid range: ", value)
	}
	return minValue, maxValue, nil
}

func randomPadding(minLen, maxLen int) (string, error) {
	length := minLen
	if maxLen > minLen {
		delta, err := rand.Int(rand.Reader, big.NewInt(int64(maxLen-minLen+1)))
		if err != nil {
			return "", err
		}
		length += int(delta.Int64())
	}
	if length <= 0 {
		return "", nil
	}
	return strings.Repeat("X", length), nil
}

func newSessionID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", E.Cause(err, "v2ray-xhttp: generate session id")
	}
	return hex.EncodeToString(id[:]), nil
}
