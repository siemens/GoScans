/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
	gossh "golang.org/x/crypto/ssh"
)

// TestMain initializes the test environment and runs all tests in the ssh package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-ssh-test-*")
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

// test_startSshServer starts an in-process SSH server on a random available port.
// The server rejects all authentication while advertising the specified supported methods.
// Password, public-key, and keyboard-interactive callbacks reject every attempt so that
// getAuthenticationMethods can extract the method list from the resulting error message.
func test_startSshServer(t *testing.T, allowPassword, allowPublicKey, allowKeyboardInteractive, allowNone bool) string {
	t.Helper()

	// Generate a fresh RSA host key for each test server
	hostKey, errHostKey := rsa.GenerateKey(rand.Reader, 2048)
	if errHostKey != nil {
		t.Fatalf("test_startSshServer() rsa.GenerateKey error = '%v'", errHostKey)
	}
	signer, errSigner := gossh.NewSignerFromKey(hostKey)
	if errSigner != nil {
		t.Fatalf("test_startSshServer() NewSignerFromKey error = '%v'", errSigner)
	}

	// Configure the server with only the requested auth methods
	serverConfig := &gossh.ServerConfig{
		NoClientAuth: allowNone,
	}
	serverConfig.AddHostKey(signer)
	if allowPassword {
		serverConfig.PasswordCallback = func(_ gossh.ConnMetadata, _ []byte) (*gossh.Permissions, error) {
			return nil, fmt.Errorf("password authentication rejected")
		}
	}
	if allowPublicKey {
		serverConfig.PublicKeyCallback = func(_ gossh.ConnMetadata, _ gossh.PublicKey) (*gossh.Permissions, error) {
			return nil, fmt.Errorf("public key authentication rejected")
		}
	}
	if allowKeyboardInteractive {
		serverConfig.KeyboardInteractiveCallback = func(_ gossh.ConnMetadata, _ gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			return nil, fmt.Errorf("keyboard-interactive authentication rejected")
		}
	}

	// Bind to a random port on loopback
	listener, errListener := net.Listen("tcp", "127.0.0.1:0")
	if errListener != nil {
		t.Fatalf("test_startSshServer() net.Listen error = '%v'", errListener)
	}

	// Accept connections and run the SSH handshake; auth will always be rejected
	go func() {
		for {
			conn, errConn := listener.Accept()
			if errConn != nil {
				return
			}
			go func(c net.Conn) {
				_, _, _, _ = gossh.NewServerConn(c, serverConfig)
				_ = c.Close()
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = listener.Close() })

	// Return nil as everything went fine
	return listener.Addr().String()
}

// test_buildValidKexInitPacket constructs a minimal valid SSH kexInit binary packet suitable for readPacket.
func test_buildValidKexInitPacket(t *testing.T) []byte {
	t.Helper()

	// Build a kexInitMsg with representative algorithm values
	msg := kexInitMsg{
		KexAlgos:                []string{"curve25519-sha256"},
		ServerHostKeyAlgos:      []string{"ssh-ed25519"},
		CiphersClientServer:     []string{"aes256-gcm@openssh.com"},
		CiphersServerClient:     []string{"aes256-gcm@openssh.com"},
		MACsClientServer:        []string{"hmac-sha2-256"},
		MACsServerClient:        []string{"hmac-sha2-256"},
		CompressionClientServer: []string{"none"},
		CompressionServerClient: []string{"none"},
	}

	// Marshal produces a byte slice starting with the msgKexInit type byte (0x14)
	payload := gossh.Marshal(msg)

	// Build the binary SSH packet: 5-byte prefix then payload then padding
	const paddingLen = 4
	packetLen := uint32(1 + len(payload) + paddingLen) // 1 for the padding_length field itself

	var prefix [prefixLen]byte
	binary.BigEndian.PutUint32(prefix[0:4], packetLen)
	prefix[4] = paddingLen

	var buf bytes.Buffer
	buf.Write(prefix[:])
	buf.Write(payload)
	buf.Write(make([]byte, paddingLen))

	// Return nil as everything went fine
	return buf.Bytes()
}

// errReadWriter is a ReadWriter whose Write always fails, used to test write-error paths in exchangeVersions.
type errReadWriter struct{}

func (e *errReadWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated write error")
}

func (e *errReadWriter) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read error")
}

// TestNewScanner verifies that NewScanner accepts valid targets and rejects invalid ones.
func TestNewScanner(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:    "valid-ipv4",
			target:  "192.0.2.1",
			wantErr: false,
		},
		{
			name:    "valid-hostname",
			target:  "host.domain.tld",
			wantErr: false,
		},
		{
			// Regression: NewScanner must trim whitespace before validating so that
			// "  192.0.2.1  " (with surrounding spaces) is accepted rather than rejected.
			name:    "whitespace-trimmed",
			target:  "  192.0.2.1  ",
			wantErr: false,
		},
		{
			name:    "empty-target",
			target:  "",
			wantErr: true,
		},
		{
			name:    "cidr-not-valid",
			target:  "192.0.2.0/24",
			wantErr: true,
		},
		{
			name:    "address-with-port",
			target:  "192.0.2.1:22",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, errScanner := NewScanner(testLogger, tt.target, 22, 5*time.Second)
			if (errScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errScanner, tt.wantErr)
				return
			}
			if errScanner == nil && scanner == nil {
				t.Errorf("NewScanner() = 'nil', want = 'non-nil scanner'")
			}
		})
	}
}

// TestSetContext verifies that SetContext stores a context on first call and ignores subsequent calls.
func TestSetContext(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	scanner, errScanner := NewScanner(testLogger, "192.0.2.1", 22, 5*time.Second)
	if errScanner != nil {
		t.Fatalf("NewScanner() error = '%v'", errScanner)
	}

	// Verify context is nil before any SetContext call
	if scanner.contextInner != nil {
		t.Errorf("SetContext() initial contextInner = '%v', want = 'nil'", scanner.contextInner)
	}

	// Set context for the first time
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	scanner.SetContext(ctx1)

	// Verify first context was stored
	if scanner.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner after first call = '%v', want = '%v'", scanner.contextInner, ctx1)
	}

	// Attempt to overwrite with a second context; must be ignored
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	scanner.SetContext(ctx2)

	// Verify second call had no effect
	if scanner.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner after second call = '%v', want = '%v' (must remain unchanged)", scanner.contextInner, ctx1)
	}
}

// TestKeyboardInteractiveChallenge verifies that challenge returns an empty-string slice the same length as the question list.
func TestKeyboardInteractiveChallenge(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name      string
		questions []string
		wantLen   int
	}{
		{
			name:      "no-questions",
			questions: []string{},
			wantLen:   0,
		},
		{
			name:      "single-question",
			questions: []string{"Password:"},
			wantLen:   1,
		},
		{
			name:      "multiple-questions",
			questions: []string{"Password:", "OTP:"},
			wantLen:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := keyboardInteractive(map[string]string{})
			got, errGot := cr.challenge("user", "instruction", tt.questions, nil)
			if errGot != nil {
				t.Errorf("challenge() error = '%v', want = 'nil'", errGot)
				return
			}

			// Verify length matches question count
			if len(got) != tt.wantLen {
				t.Errorf("challenge() len = '%v', want = '%v'", len(got), tt.wantLen)
			}

			// Verify all answers are empty strings
			for i, answer := range got {
				if answer != "" {
					t.Errorf("challenge() answer[%d] = '%v', want = ''", i, answer)
				}
			}
		})
	}
}

// TestFakeClient verifies that the FakeClient GSSAPI stub methods return their expected zero values.
func TestFakeClient(t *testing.T) {

	// Prepare unit test data
	client := &FakeClient{}

	// Verify InitSecContext returns empty token, false, and nil error
	outputToken, needContinue, errInit := client.InitSecContext("target", nil, false)
	if errInit != nil {
		t.Errorf("FakeClient.InitSecContext() error = '%v', want = 'nil'", errInit)
	}
	if len(outputToken) != 0 {
		t.Errorf("FakeClient.InitSecContext() outputToken = '%v', want = 'empty'", outputToken)
	}
	if needContinue {
		t.Errorf("FakeClient.InitSecContext() needContinue = 'true', want = 'false'")
	}

	// Verify GetMIC returns nil mic and nil error
	mic, errMic := client.GetMIC([]byte("data"))
	if errMic != nil {
		t.Errorf("FakeClient.GetMIC() error = '%v', want = 'nil'", errMic)
	}
	if mic != nil {
		t.Errorf("FakeClient.GetMIC() mic = '%v', want = 'nil'", mic)
	}

	// Verify DeleteSecContext returns nil
	errDelete := client.DeleteSecContext()
	if errDelete != nil {
		t.Errorf("FakeClient.DeleteSecContext() error = '%v', want = 'nil'", errDelete)
	}
}

// TestInfoFromErr verifies that infoFromErr extracts SSH negotiation parameters from error messages.
func TestInfoFromErr(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		errMsg error
	}
	tests := []struct {
		name       string
		args       args
		want       []string
		wantErrMsg string
		wantErr    bool
	}{
		{
			name:       "valid-algorithm-list",
			args:       args{errMsg: fmt.Errorf("ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [], server offered: [diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1]")},
			want:       []string{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"},
			wantErrMsg: "",
			wantErr:    false,
		},
		{
			name:       "single-algorithm",
			args:       args{errMsg: fmt.Errorf("server offered: [diffie-hellman-group14-sha1]")},
			want:       []string{"diffie-hellman-group14-sha1"},
			wantErrMsg: "",
			wantErr:    false,
		},
		{
			name:       "attempted-methods-format",
			args:       args{errMsg: fmt.Errorf("ssh: unable to authenticate, attempted methods [none password], no supported methods remain")},
			want:       []string{"none", "password"},
			wantErrMsg: "",
			wantErr:    false,
		},
		{
			name:       "nil-err-msg",
			args:       args{errMsg: nil},
			want:       []string{},
			wantErrMsg: "error message was nil",
			wantErr:    true,
		},
		{
			name:       "no-such-host",
			args:       args{errMsg: fmt.Errorf("dial tcp: lookup nosuchhost.domain.tld: no such host")},
			want:       []string{},
			wantErrMsg: "no such host",
			wantErr:    true,
		},
		{
			name:       "unrecognized-error-format",
			args:       args{errMsg: fmt.Errorf("the error message changed internally in the crypto package")},
			want:       []string{},
			wantErrMsg: "could not excerpt parameter from error message: the error message changed internally in the crypto package",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := infoFromErr(tt.args.errMsg)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("infoFromErr() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}

			// Verify security parameters on success
			if errGot == nil && !utils.Equals(got, tt.want) {
				t.Errorf("infoFromErr() = '%v', want = '%v'", got, tt.want)
			}

			// Verify error message on failure
			if errGot != nil && errGot.Error() != tt.wantErrMsg {
				t.Errorf("infoFromErr() error message = '%v', want = '%v'", errGot.Error(), tt.wantErrMsg)
			}
		})
	}
}

// TestReadVersion verifies that readVersion parses SSH version strings correctly from various byte sequences.
func TestReadVersion(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "crlf-terminated",
			input:   []byte("SSH-2.0-OpenSSH_8.0\r\n"),
			want:    []byte("SSH-2.0-OpenSSH_8.0"),
			wantErr: false,
		},
		{
			name:    "lf-terminated",
			input:   []byte("SSH-2.0-OpenSSH_8.0\n"),
			want:    []byte("SSH-2.0-OpenSSH_8.0"),
			wantErr: false,
		},
		{
			name:    "banner-then-version",
			input:   []byte("banner line\nSSH-2.0-OpenSSH_8.0\n"),
			want:    []byte("SSH-2.0-OpenSSH_8.0"),
			wantErr: false,
		},
		{
			name:    "empty-reader",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "overflow-no-newline",
			input:   bytes.Repeat([]byte("x"), maxVersionStringBytes),
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := readVersion(bytes.NewReader(tt.input))
			if (errGot != nil) != tt.wantErr {
				t.Errorf("readVersion() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("readVersion() = '%s', want = '%s'", got, tt.want)
			}
		})
	}
}

// TestExchangeVersions verifies that exchangeVersions sends the local version and returns the remote version.
func TestExchangeVersions(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name         string
		versionLine  []byte
		remoteData   []byte
		useErrWriter bool
		want         []byte
		wantErr      bool
	}{
		{
			name:        "valid-exchange",
			versionLine: []byte("SSH-2.0-GoScans"),
			remoteData:  []byte("SSH-2.0-OpenSSH_8.0\r\n"),
			want:        []byte("SSH-2.0-OpenSSH_8.0"),
			wantErr:     false,
		},
		{
			name:        "junk-char-in-version-line",
			versionLine: []byte("SSH-2.0-\x01GoScans"),
			remoteData:  []byte("SSH-2.0-OpenSSH_8.0\r\n"),
			want:        nil,
			wantErr:     true,
		},
		{
			name:         "write-error",
			versionLine:  []byte("SSH-2.0-GoScans"),
			useErrWriter: true,
			want:         nil,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rw io.ReadWriter
			if tt.useErrWriter {
				rw = &errReadWriter{}
			} else {
				buf := &bytes.Buffer{}
				buf.Write(tt.remoteData)
				rw = buf
			}
			got, errGot := exchangeVersions(rw, tt.versionLine)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("exchangeVersions() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("exchangeVersions() = '%s', want = '%s'", got, tt.want)
			}
		})
	}
}

// TestReadPacket verifies that readPacket correctly decodes SSH kexInit binary packets and rejects malformed input.
func TestReadPacket(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	scanner := &Scanner{logger: testLogger}

	// Prepare and run test cases
	tests := []struct {
		name    string
		input   func() []byte
		wantErr bool
	}{
		{
			name:    "valid-packet",
			input:   func() []byte { return test_buildValidKexInitPacket(t) },
			wantErr: false,
		},
		{
			name:    "empty-reader",
			input:   func() []byte { return []byte{} },
			wantErr: true,
		},
		{
			name: "length-too-small",
			input: func() []byte {
				// paddingLength=3, length=4 → length<=paddingLength+1 → 4<=4 → invalid
				var prefix [prefixLen]byte
				binary.BigEndian.PutUint32(prefix[0:4], 4)
				prefix[4] = 3
				return prefix[:]
			},
			wantErr: true,
		},
		{
			name: "length-too-large",
			input: func() []byte {
				var prefix [prefixLen]byte
				binary.BigEndian.PutUint32(prefix[0:4], maxPacket+1)
				prefix[4] = 0
				return prefix[:]
			},
			wantErr: true,
		},
		{
			name: "truncated-payload",
			input: func() []byte {
				// Prefix declares 100-byte payload but only 10 bytes are present
				var prefix [prefixLen]byte
				binary.BigEndian.PutUint32(prefix[0:4], 100)
				prefix[4] = 4
				var buf bytes.Buffer
				buf.Write(prefix[:])
				buf.Write(make([]byte, 10))
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "wrong-message-type",
			input: func() []byte {
				// First payload byte is 0x01, not msgKexInit (0x14)
				payload := make([]byte, 50)
				payload[0] = 0x01
				const paddingLen = 4
				packetLen := uint32(1 + len(payload) + paddingLen)
				var prefix [prefixLen]byte
				binary.BigEndian.PutUint32(prefix[0:4], packetLen)
				prefix[4] = paddingLen
				var buf bytes.Buffer
				buf.Write(prefix[:])
				buf.Write(payload)
				buf.Write(make([]byte, paddingLen))
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "corrupt-payload",
			input: func() []byte {
				// Type byte is correct but the remaining bytes are invalid for ssh.Unmarshal
				payload := make([]byte, 20)
				payload[0] = msgKexInit
				for i := 1; i < len(payload); i++ {
					payload[i] = 0xFF
				}
				const paddingLen = 4
				packetLen := uint32(1 + len(payload) + paddingLen)
				var prefix [prefixLen]byte
				binary.BigEndian.PutUint32(prefix[0:4], packetLen)
				prefix[4] = paddingLen
				var buf bytes.Buffer
				buf.Write(prefix[:])
				buf.Write(payload)
				buf.Write(make([]byte, paddingLen))
				return buf.Bytes()
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input()
			got, errGot := scanner.readPacket(bytes.NewReader(input))
			if (errGot != nil) != tt.wantErr {
				t.Errorf("readPacket() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if errGot == nil && got == nil {
				t.Errorf("readPacket() = 'nil', want = 'non-nil kexInitMsg'")
			}
		})
	}
}

// TestGetSecurityParameter verifies that getSecurityParameter extracts SSH algorithms from an in-process server.
func TestGetSecurityParameter(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name       string
		address    func(t *testing.T) string
		wantErr    bool
		wantFields bool
	}{
		{
			name:       "valid-server",
			address:    func(t *testing.T) string { return test_startSshServer(t, true, false, false, false) },
			wantErr:    false,
			wantFields: true,
		},
		{
			name:    "unreachable",
			address: func(_ *testing.T) string { return "127.0.0.1:1" },
			wantErr: true,
		},
		{
			name: "non-ssh-server",
			address: func(t *testing.T) string {
				t.Helper()

				// Start a plain TCP server returning non-SSH data
				listener, errListener := net.Listen("tcp", "127.0.0.1:0")
				if errListener != nil {
					t.Fatalf("net.Listen error = '%v'", errListener)
				}
				go func() {
					conn, errConn := listener.Accept()
					if errConn != nil {
						return
					}
					_, _ = conn.Write([]byte("not-an-ssh-server\r\n"))
					_ = conn.Close()
					_ = listener.Close()
				}()
				t.Cleanup(func() { _ = listener.Close() })
				return listener.Addr().String()
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &Scanner{
				logger:      testLogger,
				dialTimeout: 3 * time.Second,
			}
			results := &ResultData{}
			errGet := scanner.getSecurityParameter(tt.address(t), results)
			if (errGet != nil) != tt.wantErr {
				t.Errorf("getSecurityParameter() error = '%v', wantErr = '%v'", errGet, tt.wantErr)
				return
			}
			if tt.wantFields {
				if len(results.KeyExchangeAlgorithms) == 0 {
					t.Errorf("getSecurityParameter() KeyExchangeAlgorithms = '%v', want = 'non-empty'", results.KeyExchangeAlgorithms)
				}
				if results.ProtocolVersion == "" {
					t.Errorf("getSecurityParameter() ProtocolVersion = '', want = 'non-empty'")
				}
			}
		})
	}
}

// TestGetAuthenticationMethods verifies that getAuthenticationMethods detects server-supported auth methods via SSH dial.
func TestGetAuthenticationMethods(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name       string
		address    func(t *testing.T) string
		wantErr    bool
		acceptErr  bool
		wantMethod string
	}{
		{
			name:       "password-only",
			address:    func(t *testing.T) string { return test_startSshServer(t, true, false, false, false) },
			wantErr:    false,
			wantMethod: "password",
		},
		{
			name:       "publickey-only",
			address:    func(t *testing.T) string { return test_startSshServer(t, false, true, false, false) },
			wantErr:    false,
			wantMethod: "publickey",
		},
		{
			// DNS for invalid.invalid may time out (returning nil error + nil methods) or fail
			// with NXDOMAIN (returning an error) depending on the resolver. Accept either outcome.
			name:      "unreachable-host",
			address:   func(_ *testing.T) string { return "invalid.invalid:22" },
			wantErr:   false,
			acceptErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := &Scanner{
				logger:      testLogger,
				dialTimeout: 5 * time.Second,
				target:      "127.0.0.1",
			}
			got, errGot := scanner.getAuthenticationMethods(tt.address(t))
			if tt.wantErr && errGot == nil {
				t.Errorf("getAuthenticationMethods() error = nil, wantErr = true")
				return
			}
			if !tt.wantErr && !tt.acceptErr && errGot != nil {
				t.Errorf("getAuthenticationMethods() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if tt.wantMethod != "" && !slices.Contains(got, tt.wantMethod) {
				t.Errorf("getAuthenticationMethods() = '%v', want to contain = '%v'", got, tt.wantMethod)
			}
		})
	}
}

// TestScanner_Run_ValidServer verifies a full scan against an in-process SSH server completes successfully.
func TestScanner_Run_ValidServer(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Start in-process SSH server and extract its address components
	addr := test_startSshServer(t, true, false, false, false)
	host, portStr, errSplit := net.SplitHostPort(addr)
	if errSplit != nil {
		t.Fatalf("net.SplitHostPort() error = '%v'", errSplit)
	}
	port, errPort := strconv.Atoi(portStr)
	if errPort != nil {
		t.Fatalf("strconv.Atoi() error = '%v'", errPort)
	}

	// Run the full scanner against the in-process server
	scanner, errScanner := NewScanner(testLogger, host, port, 5*time.Second)
	if errScanner != nil {
		t.Fatalf("NewScanner() error = '%v'", errScanner)
	}
	result := scanner.Run(10 * time.Second)

	// Verify the scan completed without exception
	if result == nil {
		t.Fatalf("Run() result = 'nil', want = 'non-nil'")
	}
	if result.Exception {
		t.Errorf("Run() Exception = 'true', want = 'false'")
	}
	if result.Status != utils.StatusCompleted {
		t.Errorf("Run() Status = '%v', want = '%v'", result.Status, utils.StatusCompleted)
	}
}

// TestScanner_Run_NotReachable verifies that Run returns a non-exception status when the target hostname does not resolve.
// Depending on the resolver, DNS for a non-existent host may return NXDOMAIN (StatusNotReachable) or time out
// within the scan window (StatusDeadline). Both outcomes indicate the host is not reachable and are accepted.
func TestScanner_Run_NotReachable(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Run the scanner against a non-resolvable hostname
	scanner, errScanner := NewScanner(testLogger, "invalid.invalid", 22, 5*time.Second)
	if errScanner != nil {
		t.Fatalf("NewScanner() error = '%v'", errScanner)
	}
	result := scanner.Run(10 * time.Second)

	// Verify scan result is present with no exception
	if result == nil {
		t.Fatalf("Run() result = 'nil', want = 'non-nil'")
	}
	if result.Exception {
		t.Errorf("Run() Exception = 'true', want = 'false'")
	}

	// DNS behavior is resolver-dependent: NXDOMAIN → StatusNotReachable, timeout → StatusDeadline
	if result.Status != utils.StatusNotReachable && result.Status != utils.StatusDeadline {
		t.Errorf("Run() Status = '%v', want = '%v' or '%v'", result.Status, utils.StatusNotReachable, utils.StatusDeadline)
	}
}

// TestScanner_Run_ContextCancelled verifies that Run returns StatusDeadline when the context is cancelled before execution.
func TestScanner_Run_ContextCancelled(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Use port 1 so the dial fails quickly with connection-refused rather than DNS failure
	scanner, errScanner := NewScanner(testLogger, "127.0.0.1", 1, 2*time.Second)
	if errScanner != nil {
		t.Fatalf("NewScanner() error = '%v'", errScanner)
	}

	// Pre-cancel the context before Run so ContextExpired fires after getAuthenticationMethods returns
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner.SetContext(ctx)

	result := scanner.Run(10 * time.Second)

	// Verify deadline status
	if result == nil {
		t.Fatalf("Run() result = 'nil', want = 'non-nil'")
	}
	if result.Exception {
		t.Errorf("Run() Exception = 'true', want = 'false'")
	}
	if result.Status != utils.StatusDeadline {
		t.Errorf("Run() Status = '%v', want = '%v'", result.Status, utils.StatusDeadline)
	}
}
