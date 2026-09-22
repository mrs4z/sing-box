package v2rayxhttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The wire protocol lives in Xray, not in a spec, so the only test that proves
// this transport is one that talks to a real Xray inbound. The inbound is
// configured exactly the way our agent renders it (uplinkDataPlacement auto +
// a wide header budget), which makes this a guard for that contract too.
//
//	SINGBOX_XHTTP_INTEGRATION=1 [SINGBOX_XRAY_BIN=/path/to/xray] \
//	  go test ./transport/v2rayxhttp -run AgainstXray -v
func TestAgainstXray(t *testing.T) {
	if os.Getenv("SINGBOX_XHTTP_INTEGRATION") != "1" {
		t.Skip("set SINGBOX_XHTTP_INTEGRATION=1 to run against a local xray")
	}
	binary := os.Getenv("SINGBOX_XRAY_BIN")
	if binary == "" {
		binary = "/tmp/xray-darwin"
	}
	if _, err := os.Stat(binary); err != nil {
		if resolved, lookErr := exec.LookPath("xray"); lookErr == nil {
			binary = resolved
		} else {
			t.Skip("xray executable not found; set SINGBOX_XRAY_BIN")
		}
	}

	echoAddr := startEchoServer(t)
	const path = "/p9k2"

	for _, tc := range []struct {
		name    string
		options option.V2RayXHTTPOptions
	}{
		{
			name:    "body uplink (POST)",
			options: option.V2RayXHTTPOptions{Path: path, Mode: "packet-up", ScMaxEachPostBytes: 4096},
		},
		{
			// What a CDN that proxies only GET/HEAD forces us into.
			name: "header uplink (GET)",
			options: option.V2RayXHTTPOptions{
				Path: path, Mode: "packet-up",
				UplinkHTTPMethod:    "GET",
				UplinkDataPlacement: "header",
				ScMaxEachPostBytes:  4096,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := startXray(t, binary, path, echoAddr)
			serverAddr := M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", port))

			client, err := v2rayxhttp.NewClient(context.Background(), N.SystemDialer, serverAddr, tc.options, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			conn, err := client.DialContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			// Two writes, the second big enough to be split across several
			// numbered uploads — which also proves the server reassembles by
			// seq rather than by arrival order.
			payloads := [][]byte{[]byte("hello xhttp"), make([]byte, 10000)}
			for i := range payloads[1] {
				payloads[1][i] = byte(i % 251)
			}
			for _, payload := range payloads {
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				echoed := make([]byte, len(payload))
				if err = readFull(conn, echoed, 10*time.Second); err != nil {
					t.Fatal(err)
				}
				if string(echoed) != string(payload) {
					t.Fatalf("echo mismatch: got %d bytes, first diff at %d", len(echoed), firstDiff(echoed, payload))
				}
			}
		})
	}
}

// startEchoServer returns the address of a TCP server that echoes everything.
func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// startXray runs an XHTTP inbound that forwards everything to `target`,
// shaped the way our agent renders inbounds.
func startXray(t *testing.T, binary, path, target string) int {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var targetPort int
	fmt.Sscanf(portStr, "%d", &targetPort)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "xhttp-in", "listen": "127.0.0.1", "port": port,
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": host, "port": targetPort, "network": "tcp"},
			"streamSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"path": path, "mode": "packet-up",
					"uplinkDataPlacement":  "auto",
					"serverMaxHeaderBytes": 262144,
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	configPath := filepath.Join(t.TempDir(), "xray.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binary, "run", "-c", configPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitForPort(t, port)
	return port
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("xray did not listen on %d", port)
}

func readFull(conn net.Conn, buffer []byte, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, buffer)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timed out reading %d bytes", len(buffer))
	}
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return len(a)
}

// TestVLESSOverXHTTPAgainstXray is the shape our Android client will actually
// run: sing-box's own VLESS outbound carrying traffic over this transport into
// an Xray VLESS inbound. It proves the option plumbing (config → transport)
// as well as the wire protocol.
func TestVLESSOverXHTTPAgainstXray(t *testing.T) {
	if os.Getenv("SINGBOX_XHTTP_INTEGRATION") != "1" {
		t.Skip("set SINGBOX_XHTTP_INTEGRATION=1 to run against a local xray")
	}
	binary := os.Getenv("SINGBOX_XRAY_BIN")
	if binary == "" {
		binary = "/tmp/xray-darwin"
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skip("xray executable not found; set SINGBOX_XRAY_BIN")
	}

	const (
		path = "/p9k2"
		uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	)
	echoAddr := startEchoServer(t)
	port := startXrayVLESS(t, binary, path, uuid)

	options := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)},
		UUID:          uuid,
		Transport: &option.V2RayTransportOptions{
			Type: "xhttp",
			XHTTPOptions: option.V2RayXHTTPOptions{
				Path: path, Mode: "packet-up",
				UplinkHTTPMethod:    "GET",
				UplinkDataPlacement: "header",
				ScMaxEachPostBytes:  4096,
			},
		},
	}
	outbound, err := vless.NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "xhttp-test", options)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte("vless over xhttp over a GET uplink")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if err = readFull(conn, echoed, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != string(payload) {
		t.Fatalf("echo mismatch: %q", echoed)
	}
}

// startXrayVLESS runs a VLESS inbound over XHTTP; traffic leaves through
// freedom, so the outbound's requested destination is dialed for real.
func startXrayVLESS(t *testing.T, binary, path, uuid string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "vless-in", "listen": "127.0.0.1", "port": port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": uuid}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"path": path, "mode": "packet-up",
					"uplinkDataPlacement":  "auto",
					"serverMaxHeaderBytes": 262144,
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	configPath := filepath.Join(t.TempDir(), "xray-vless.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", configPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitForPort(t, port)
	return port
}
