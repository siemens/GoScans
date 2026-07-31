/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package banner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the banner package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-banner-test-*")
	if errTmpDir != nil {
		panic(errTmpDir)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}

// test_startBannerServer starts a local TCP server that writes a fixed banner on each connection.
// The server is shut down via t.Cleanup. Returns the host and port of the listener.
func test_startBannerServer(t *testing.T) (string, int) {

	t.Helper()

	// Listen on a random loopback port
	ln, errLn := net.Listen("tcp", "127.0.0.1:0")
	if errLn != nil {
		t.Fatalf("test_startBannerServer() could not start listener: %v", errLn)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Accept connections in background and write a banner response
	go func() {
		for {
			accepted, errAccepted := ln.Accept()
			if errAccepted != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				// Read the trigger byte the client sends before replying, so the
				// connection stays open long enough for the client to read our response.
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.0\r\n"))
			}(accepted)
		}
	}()

	// Return host and port
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// test_closedPort allocates a random free port on the given network, immediately closes the listener,
// and returns the address so callers can use a guaranteed-refused endpoint.
func test_closedPort(t *testing.T, network string) string {

	t.Helper()

	// Allocate and immediately release a port on the given network
	if network == "tcp" {
		ln, errLn := net.Listen("tcp", "127.0.0.1:0")
		if errLn != nil {
			t.Fatalf("test_closedPort() could not allocate tcp port: %v", errLn)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}

	// UDP path
	ln, errLn := net.ListenPacket("udp", "127.0.0.1:0")
	if errLn != nil {
		t.Fatalf("test_closedPort() could not allocate udp port: %v", errLn)
	}
	addr := ln.LocalAddr().String()
	_ = ln.Close()
	return addr
}

// TestNewScanner verifies that NewScanner returns an error for invalid protocols and invalid target formats.
func TestNewScanner(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	// Prepare and run test cases
	type args struct {
		logger   utils.Logger
		target   string
		port     int
		protocol string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid-ipv4-tcp",
			args: args{
				logger:   testLogger,
				target:   "192.0.2.1",
				port:     443,
				protocol: "tcp",
			},
			wantErr: false,
		},
		{
			name: "valid-ipv4-udp",
			args: args{
				logger:   testLogger,
				target:   "192.0.2.1",
				port:     443,
				protocol: "udp",
			},
			wantErr: false,
		},
		{
			name: "valid-ipv6",
			args: args{
				logger:   testLogger,
				target:   "2001:db8::1",
				port:     443,
				protocol: "tcp",
			},
			wantErr: false,
		},
		{
			name: "valid-hostname",
			args: args{
				logger:   testLogger,
				target:   "host.domain.tld",
				port:     443,
				protocol: "tcp",
			},
			wantErr: false,
		},
		{
			name: "invalid-cidr-range",
			args: args{
				logger:   testLogger,
				target:   "192.0.2.0/24",
				port:     443,
				protocol: "tcp",
			},
			wantErr: true,
		},
		{
			name: "invalid-protocol",
			args: args{
				logger:   testLogger,
				target:   "192.0.2.1",
				port:     443,
				protocol: "abc",
			},
			wantErr: true,
		},
		{
			name: "empty-target",
			args: args{
				logger:   testLogger,
				target:   "",
				port:     443,
				protocol: "tcp",
			},
			wantErr: true,
		},
		{
			name: "whitespace-target",
			args: args{
				logger:   testLogger,
				target:   "   ",
				port:     443,
				protocol: "tcp",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNew := NewScanner(tt.args.logger, tt.args.target, tt.args.port, tt.args.protocol, dialTimeout, receiveTimeout)
			if (errNew != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNew, tt.wantErr)
				return
			}
		})
	}
}

// TestScanner_Run_HappyPath verifies that Run returns StatusCompleted and no exception when the target is reachable.
func TestScanner_Run_HappyPath(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 2 * time.Second
	receiveTimeout := 2 * time.Second

	// Start a local banner server so the test requires no external network access
	host, port := test_startBannerServer(t)

	// Initialize the banner scanner
	scan, errScan := NewScanner(testLogger, host, port, "tcp", dialTimeout, receiveTimeout)
	if errScan != nil {
		t.Fatalf("NewScanner() error = '%v'", errScan)
	}

	// Launch scan and verify result
	result := scan.Run()
	if result.Exception {
		t.Errorf("Scanner.Run() exception = 'true', want = 'false'; status = '%v'", result.Status)
		return
	}
	if result.Status != utils.StatusCompleted {
		t.Errorf("Scanner.Run() status = '%v', want = '%v'", result.Status, utils.StatusCompleted)
		return
	}
	if len(result.Data.Plain) == 0 {
		t.Errorf("Scanner.Run() result.Data.Plain length = '0', want = 'non-zero'")
	}
}

// TestScanner_Run_NotReachable verifies that Run returns StatusNotReachable when the endpoint cannot be dialed.
func TestScanner_Run_NotReachable(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 100 * time.Millisecond
	receiveTimeout := 100 * time.Millisecond

	// Allocate and immediately close a TCP port so connection is refused
	closedAddr := test_closedPort(t, "tcp")
	tcpAddr, errTcpAddr := net.ResolveTCPAddr("tcp", closedAddr)
	if errTcpAddr != nil {
		t.Fatalf("could not parse closed address: %v", errTcpAddr)
	}

	// Initialize the banner scanner
	scan, errScan := NewScanner(testLogger, tcpAddr.IP.String(), tcpAddr.Port, "tcp", dialTimeout, receiveTimeout)
	if errScan != nil {
		t.Fatalf("NewScanner() error = '%v'", errScan)
	}

	// Launch scan and verify result
	result := scan.Run()
	if result.Exception {
		t.Errorf("Scanner.Run() exception = 'true', want = 'false'")
		return
	}
	if result.Status != utils.StatusNotReachable {
		t.Errorf("Scanner.Run() status = '%v', want = '%v'", result.Status, utils.StatusNotReachable)
	}
}

// TestScanner_Run_UdpNotReachable verifies that Run handles UDP endpoints that are not reachable gracefully.
func TestScanner_Run_UdpNotReachable(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 100 * time.Millisecond
	receiveTimeout := 100 * time.Millisecond

	// Allocate and immediately release a UDP port
	closedAddr := test_closedPort(t, "udp")
	udpAddr, errUdpAddr := net.ResolveUDPAddr("udp", closedAddr)
	if errUdpAddr != nil {
		t.Fatalf("could not parse closed udp address: %v", errUdpAddr)
	}

	// Initialize scanner
	scan, errScan := NewScanner(testLogger, udpAddr.IP.String(), udpAddr.Port, "udp", dialTimeout, receiveTimeout)
	if errScan != nil {
		t.Fatalf("NewScanner() error = '%v'", errScan)
	}

	// Launch scan; UDP path should complete without exception
	result := scan.Run()
	if result.Exception {
		t.Errorf("Scanner.Run() exception = 'true', want = 'false'")
	}
}

// TestScanner_UpdateResultMap verifies the storage and skip behaviour for different response/error combinations.
func TestScanner_UpdateResultMap(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	// Prepare and run test cases
	type args struct {
		res         map[string][]byte
		triggerName string
		response    []byte
		err         error
	}
	tests := []struct {
		name      string
		args      args
		wantKey   bool   // whether the map should contain the trigger key after the call
		wantValue []byte // expected stored value when wantKey is true
	}{
		{
			name: "non-empty-response-no-error",
			args: args{
				res:         make(map[string][]byte),
				triggerName: "plain",
				response:    []byte("SSH-2.0-OpenSSH_8.0"),
				err:         nil,
			},
			wantKey:   true,
			wantValue: []byte("SSH-2.0-OpenSSH_8.0"),
		},
		{
			name: "leading-trailing-whitespace-is-trimmed",
			args: args{
				res:         make(map[string][]byte),
				triggerName: "plain",
				response:    []byte("  banner data  "),
				err:         nil,
			},
			wantKey:   true,
			wantValue: []byte("banner data"),
		},
		{
			name: "error-response-not-stored",
			args: args{
				res:         make(map[string][]byte),
				triggerName: "ssl",
				response:    []byte("some bytes"),
				err:         fmt.Errorf("connection refused"),
			},
			wantKey: false,
		},
		{
			name: "empty-response-not-stored",
			args: args{
				res:         make(map[string][]byte),
				triggerName: "telnet",
				response:    []byte{},
				err:         nil,
			},
			wantKey: false,
		},
		{
			name: "whitespace-only-response-not-stored",
			args: args{
				res:         make(map[string][]byte),
				triggerName: "http",
				response:    []byte("   \t\n   "),
				err:         nil,
			},
			wantKey: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Build scanner to call the method under test
			s, errS := NewScanner(testLogger, "192.0.2.1", 80, "tcp", dialTimeout, receiveTimeout)
			if errS != nil {
				t.Fatalf("NewScanner() error = '%v'", errS)
			}

			// Execute and verify result map state
			s.updateResultMap(tt.args.res, tt.args.triggerName, tt.args.response, tt.args.err)
			got, ok := tt.args.res[tt.args.triggerName]
			if tt.wantKey {
				if !ok {
					t.Errorf("updateResultMap() key '%v' absent, want = 'present'", tt.args.triggerName)
					return
				}
				if !reflect.DeepEqual(got, tt.wantValue) {
					t.Errorf("updateResultMap() value = '%v', want = '%v'", got, tt.wantValue)
				}
			} else {
				if ok {
					t.Errorf("updateResultMap() key '%v' present with value '%v', want = 'absent'", tt.args.triggerName, got)
				}
			}
		})
	}
}

// TestSendPlain_InvalidAddress verifies that sendPlain returns an error for unresolvable hostnames.
func TestSendPlain_InvalidAddress(t *testing.T) {

	// Prepare test variables
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	// Prepare and run test cases
	tests := []struct {
		name     string
		address  string
		port     int
		protocol string
		trigger  string
	}{
		{
			name:     "invalid-hostname-tcp",
			address:  "invalid.invalid",
			port:     53,
			protocol: "tcp",
			trigger:  triggerLinux,
		},
		{
			name:     "invalid-hostname-udp",
			address:  "invalid.invalid",
			port:     53,
			protocol: "udp",
			trigger:  triggerLinux,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Call and verify an error is returned
			_, errSend := sendPlain(tt.address, tt.port, tt.protocol, tt.trigger, dialTimeout, receiveTimeout)
			if errSend == nil {
				t.Errorf("sendPlain() error = 'nil', want error for unresolvable hostname")
			}
		})
	}
}

// TestSendPlain_ReturnsDataFromServer verifies that sendPlain reads response bytes from a local HTTP server.
func TestSendPlain_ReturnsDataFromServer(t *testing.T) {

	// Start a local HTTP server that returns a fixed response body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "banner-response")
	}))
	t.Cleanup(srv.Close)

	// Parse host and port from server listener address
	host, portStr, errSplit := net.SplitHostPort(srv.Listener.Addr().String())
	if errSplit != nil {
		t.Fatalf("could not parse server address: %v", errSplit)
	}
	var port int
	if _, errScan := fmt.Sscanf(portStr, "%d", &port); errScan != nil {
		t.Fatalf("could not parse port: %v", errScan)
	}

	// Build an HTTP trigger for this host and send it via sendPlain
	req := fmt.Sprintf(triggerHttp, host)
	resp, errResp := sendPlain(host, port, "tcp", req, 5*time.Second, 5*time.Second)
	if errResp != nil {
		t.Errorf("sendPlain() error = '%v', want = 'nil'", errResp)
		return
	}
	if len(resp) == 0 {
		t.Errorf("sendPlain() response length = '0', want = 'non-zero'")
	}
}

// TestSendPlain_ConnectionRefused verifies that sendPlain returns an error when the port is closed.
func TestSendPlain_ConnectionRefused(t *testing.T) {

	// Allocate and immediately close a TCP port
	closedAddr := test_closedPort(t, "tcp")
	tcpAddr, errTcpAddr := net.ResolveTCPAddr("tcp", closedAddr)
	if errTcpAddr != nil {
		t.Fatalf("could not parse address: %v", errTcpAddr)
	}

	// Call and verify an error is returned
	_, errSend := sendPlain(tcpAddr.IP.String(), tcpAddr.Port, "tcp", triggerLinux, 100*time.Millisecond, 100*time.Millisecond)
	if errSend == nil {
		t.Errorf("sendPlain() error = 'nil', want error for refused connection")
	}
}

// TestSendSsl_ReturnsDataFromServer verifies that sendSsl reads response bytes from a local TLS HTTP server.
func TestSendSsl_ReturnsDataFromServer(t *testing.T) {

	// Start a local TLS server; sendSsl uses InsecureTlsConfigFactory which skips cert verification
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls-banner-response")
	}))
	t.Cleanup(srv.Close)

	// Parse host and port from server listener address
	host, portStr, errSplit := net.SplitHostPort(srv.Listener.Addr().String())
	if errSplit != nil {
		t.Fatalf("could not parse server address: %v", errSplit)
	}
	var port int
	if _, errScan := fmt.Sscanf(portStr, "%d", &port); errScan != nil {
		t.Fatalf("could not parse port: %v", errScan)
	}

	// Build an HTTP trigger so the TLS server processes the request and replies with HTTP bytes
	req := fmt.Sprintf(triggerHttp, host)
	resp, errResp := sendSsl(host, port, req, 5*time.Second, 5*time.Second)
	if errResp != nil {
		t.Errorf("sendSsl() error = '%v', want = 'nil'", errResp)
		return
	}
	if len(resp) == 0 {
		t.Errorf("sendSsl() response length = '0', want = 'non-zero'")
	}
}

// TestSendSsl_ConnectionRefused verifies that sendSsl returns an error when the TLS port is closed.
func TestSendSsl_ConnectionRefused(t *testing.T) {

	// Allocate and immediately close a TCP port
	closedAddr := test_closedPort(t, "tcp")
	tcpAddr, errTcpAddr := net.ResolveTCPAddr("tcp", closedAddr)
	if errTcpAddr != nil {
		t.Fatalf("could not parse address: %v", errTcpAddr)
	}

	// Call and verify an error is returned
	_, errSend := sendSsl(tcpAddr.IP.String(), tcpAddr.Port, triggerLinux, 100*time.Millisecond, 100*time.Millisecond)
	if errSend == nil {
		t.Errorf("sendSsl() error = 'nil', want error for refused connection")
	}
}

// TestSendTelnet_ConnectionRefused verifies that sendTelnet returns an error when the port is closed.
func TestSendTelnet_ConnectionRefused(t *testing.T) {

	// Allocate and immediately close a TCP port
	closedAddr := test_closedPort(t, "tcp")
	tcpAddr, errTcpAddr := net.ResolveTCPAddr("tcp", closedAddr)
	if errTcpAddr != nil {
		t.Fatalf("could not parse address: %v", errTcpAddr)
	}

	// Prepare and run test cases for both trigger modes
	tests := []struct {
		name      string
		isWindows bool
	}{
		{name: "windows-trigger", isWindows: true},
		{name: "linux-trigger", isWindows: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errSend := sendTelnet(tcpAddr.IP.String(), tcpAddr.Port, tt.isWindows, 100*time.Millisecond, 100*time.Millisecond)
			if errSend == nil {
				t.Errorf("sendTelnet() error = 'nil', want error for refused connection")
			}
		})
	}
}

// TestSendTelnet_ReturnsDataFromServer verifies that sendTelnet reads response bytes from a raw TCP server.
func TestSendTelnet_ReturnsDataFromServer(t *testing.T) {

	// Start a raw TCP server that writes a banner on connect (simulates a telnet-capable service)
	host, port := test_startBannerServer(t)

	// Prepare and run test cases for both trigger modes
	tests := []struct {
		name      string
		isWindows bool
	}{
		{name: "windows-trigger", isWindows: true},
		{name: "linux-trigger", isWindows: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, errResp := sendTelnet(host, port, tt.isWindows, 2*time.Second, 2*time.Second)
			if errResp != nil {
				t.Errorf("sendTelnet() error = '%v', want = 'nil'", errResp)
				return
			}
			if len(resp) == 0 {
				t.Errorf("sendTelnet() response length = '0', want = 'non-zero'")
			}
		})
	}
}

// TestSendPlain_IPv6Address verifies that sendPlain correctly formats an IPv6 address and returns an error for an unreachable host rather than a parse error.
func TestSendPlain_IPv6Address(t *testing.T) {

	// Use a loopback IPv6 address on a port that will be refused so we get a dial error, not a parse/format error
	closedAddr := test_closedPort(t, "tcp")
	tcpAddr, errTcpAddr := net.ResolveTCPAddr("tcp", closedAddr)
	if errTcpAddr != nil {
		t.Fatalf("could not parse closed address: %v", errTcpAddr)
	}

	// Use the IPv6 loopback instead of the IPv4 address returned by test_closedPort
	_, errSend := sendPlain("::1", tcpAddr.Port, "tcp", triggerLinux, 100*time.Millisecond, 100*time.Millisecond)
	if errSend == nil {
		t.Errorf("sendPlain() error = 'nil', want error for refused IPv6 connection")
		return
	}

	// Verify the error is a network dial error, not an address-format error
	if socketErrorType(errSend) != "dial" {
		t.Errorf("sendPlain() error type = '%v', want = 'dial' (got address-format or unexpected error: %v)", socketErrorType(errSend), errSend)
	}
}

// TestSendPlain_TruncatesAtNullByte verifies that sendPlain stops the response buffer at the first null byte.
func TestSendPlain_TruncatesAtNullByte(t *testing.T) {

	// Start a server that sends a banner followed by null bytes (typical binary protocol response)
	ln, errLn := net.Listen("tcp", "127.0.0.1:0")
	if errLn != nil {
		t.Fatalf("could not start listener: %v", errLn)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, errConn := ln.Accept()
			if errConn != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				// Write banner text followed by a null byte and then more bytes that must be stripped
				_, _ = c.Write([]byte("HELLO\x00SHOULD_NOT_APPEAR"))
			}(conn)
		}
	}()

	// Parse host and port
	addr := ln.Addr().(*net.TCPAddr)

	// Call sendPlain and verify null-byte truncation
	resp, errResp := sendPlain(addr.IP.String(), addr.Port, "tcp", triggerLinux, 2*time.Second, 2*time.Second)
	if errResp != nil {
		t.Fatalf("sendPlain() error = '%v', want = 'nil'", errResp)
	}
	if string(resp) != "HELLO" {
		t.Errorf("sendPlain() response = '%s', want = 'HELLO'", resp)
	}
}

// TestSocketErrorType verifies that socketErrorType returns the correct operation string or empty for non-socket errors.
func TestSocketErrorType(t *testing.T) {

	// Allocate a free TCP port then close it so connection attempts are refused immediately
	closedAddr := test_closedPort(t, "tcp")

	// Prepare and run test cases
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil-error",
			err:  nil,
			want: "",
		},
		{
			name: "non-net-error",
			err:  fmt.Errorf("some generic error"),
			want: "",
		},
		{
			name: "dial-error-from-refused-port",
			err: func() error {
				// Dial a closed port to produce a real *net.OpError with Op=="dial"
				_, errDial := net.DialTimeout("tcp", closedAddr, 500*time.Millisecond)
				return errDial
			}(),
			want: "dial",
		},
		{
			name: "read-write-error-non-dial-op",
			err:  &net.OpError{Op: "read", Err: io.EOF},
			want: "read",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := socketErrorType(tt.err); got != tt.want {
				t.Errorf("socketErrorType() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
