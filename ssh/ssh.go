/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package ssh implements a scan module for SSH host fingerprinting and authentication testing.
package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
	"golang.org/x/crypto/ssh"
)

// Label identifies the SSH scan module
const Label = "Ssh"

// Internal constants mirroring values from the upstream golang.org/x/crypto/ssh package.
const packageVersion = "SSH-2.0-Go" // ssh\transport.go
const maxVersionStringBytes = 255   // Maximum SSH identification string length
const prefixLen = 5                 // ssh\cipher.go
const maxPacket = 256 * 1024        // Maximum SSH packet size
const msgKexInit = 20               // ssh\messages.go

// errNoSuchHost identifies DNS failures for nonexistent hosts
var errNoSuchHost = fmt.Errorf("no such host")

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger) error {
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup() error {
	return nil
}

// ResultData holds all SSH security parameters collected during a scan.
type ResultData struct {
	AuthenticationMechanisms   []string
	KeyExchangeAlgorithms      []string
	ServerKeyAlgorithms        []string
	ServerEncryptionAlgorithms []string
	ServerMacAlgorithms        []string
	ServerCompressAlgorithms   []string
	UsesGuessedKeyExchange     bool
	ProtocolVersion            string
}

// Result wraps ResultData with a scan status and an exception flag for the caller to inspect.
type Result struct {
	Data      *ResultData
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// Scanner holds the target configuration and timeouts for a single SSH scan session.
type Scanner struct {
	Label       string
	Started     time.Time
	Finished    time.Time
	logger      utils.Logger
	target      string // Address to be scanned (might be IPv4, IPv6 or hostname)
	port        int
	dialTimeout time.Duration

	contextInner       context.Context    // Context for the scan, within which the scan should execute. Might optionally wrap an outer context. If outer context is cancelled, inner one should cancel too, but not the other way around.
	contextInnerCancel context.CancelFunc // Context cancel function of inner context, not impacting optional outer one.
}

// NewScanner validates the target and returns an initialised Scanner ready to run.
func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	dialTimeout time.Duration,
) (*Scanner, error) {

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

	// Check whether input target is valid
	if !utils.IsValidAddress(target) {
		return nil, fmt.Errorf("invalid target '%s'", target)
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		target,
		port,
		dialTimeout,
		nil,
		nil,
	}

	// Return scan struct
	return &scan, nil
}

// SetContext can be used to pass an existing context from outside.
// If timeout is supplied later when calling Run() the external context and the deadline context will be combined.
// Once set, the context cannot be changed anymore, because it might have been wrapped internally already.
func (s *Scanner) SetContext(ctx context.Context) {
	if s.contextInner == nil {
		s.contextInner = ctx
	}
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf("Unexpected error: %s", r)

			// Build error status from error message and formatted stacktrace
			errMsg := fmt.Sprintf("%s%s", r, utils.StacktraceIndented("\t"))

			// Return result set indicating exception
			res = &Result{
				nil,
				errMsg,
				true,
			}
		}
	}()

	// Set scan started flag
	s.Started = time.Now()

	// Create initial context
	contextInner := context.Background()

	// Replace context with external one if set
	if s.contextInner != nil {
		contextInner = s.contextInner
	}

	// Add timeout to context if desired
	var contextInnerCancel context.CancelFunc
	if timeout > 0 {
		contextInner, contextInnerCancel = context.WithTimeout(contextInner, timeout)
	}

	// Set context for scan
	s.contextInner = contextInner
	s.contextInnerCancel = contextInnerCancel

	// Execute scan logic
	s.logger.Infof("Started  scan of %s:%d.", s.target, s.port)
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.target, duration)

	// Return result set
	return res
}

// execute collects authentication methods and security parameters from the target and returns the aggregated result.
func (s *Scanner) execute() *Result {

	// Cleanup inner context if set
	if s.contextInnerCancel != nil {
		defer s.contextInnerCancel()
	}

	// The scan first gets the authentication parameters using the golang ssh package functions.
	// To get the other security parameter we implemented the first message exchange of the ssh handshake.

	// Declare result variable to be returned
	results := &ResultData{}

	// Prepare address
	address := net.JoinHostPort(s.target, strconv.Itoa(s.port))

	// Get authentication methods
	authMethods, errAuthMethods := s.getAuthenticationMethods(address)
	if errAuthMethods != nil {
		if errors.Is(errAuthMethods, errNoSuchHost) {
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		} else {
			s.logger.Debugf("Could not extract authentication methods: %s", errAuthMethods)
		}
	} else {

		// If no error occurred, safe authentication methods
		results.AuthenticationMechanisms = authMethods
	}

	// Check whether scan timeout is reached
	if utils.ContextExpired(s.contextInner) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
		}
	}

	// We initialize an ssh handshake to get the remaining security parameter
	errParameters := s.getSecurityParameter(address, results)
	if errParameters != nil {
		s.logger.Debugf("Could not get security parameters: %s", errParameters)
	}

	// Check whether scan timeout is reached
	if utils.ContextExpired(s.contextInner) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

// getAuthenticationMethods dials the target twice with empty credentials to enumerate the server's supported
// authentication methods, including a separate probe for gssapi-with-mic.
func (s *Scanner) getAuthenticationMethods(address string) ([]string, error) {

	// Use the Go SSH dial with empty credentials to provoke an error that lists the server's supported auth methods
	var authMethods []string
	answers := keyboardInteractive(map[string]string{})
	config := &ssh.ClientConfig{
		User: "",
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
			ssh.PublicKeys(),
			ssh.KeyboardInteractive(answers.challenge),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.dialTimeout,
	}

	// Dial with standard auth methods to collect the server-offered list from the resulting error
	sshConn, errSshConn := ssh.Dial("tcp", address, config)

	// If the connection succeeded with empty credentials, record "none" as the only method
	if errSshConn == nil {
		authMethods = []string{"none"}
		errClose := sshConn.Close()
		if errClose != nil {
			s.logger.Debugf("Could not close connection to %s: %s", s.target, errClose)
		}
	} else {
		var netErr net.Error
		if !errors.As(errSshConn, &netErr) || !netErr.Timeout() {

			// Extract the supported methods advertised by the server from the error message
			triedAuthMethods, errTriedAuthMethods := infoFromErr(errSshConn)
			if errTriedAuthMethods != nil {
				return nil, errTriedAuthMethods
			}

			// Go always tries "none" internally, but since empty-credential auth failed we exclude it
			authMethods = utils.RemoveFromSlice(triedAuthMethods, "none")
		}
	}

	// Probe gssapi-with-mic separately: Go may return an unusual error when the server does not support its
	// implementation, but if the error does not indicate that only "none" was attempted, the server offered the method
	config.Auth = []ssh.AuthMethod{ssh.GSSAPIWithMICAuthMethod(&FakeClient{}, "")}
	config.Timeout = s.dialTimeout
	sshConn, errSshConn = ssh.Dial("tcp", address, config)
	if errSshConn == nil {
		errClose2 := sshConn.Close()
		if errClose2 != nil {
			s.logger.Debugf("Could not close connection to %s: %s", s.target, errClose2)
		}
	} else {
		var netErr net.Error
		if !errors.As(errSshConn, &netErr) || !netErr.Timeout() {
			if errSshConn.Error() != "ssh: handshake failed: ssh: could not authenticate, attempted methods [none], no supported methods remain" {
				authMethods = append(authMethods, "gssapi-with-mic")
			}
		}
	}

	// Return nil as everything went fine
	return authMethods, nil
}

// keyboardInteractive is an empty keyboard-interactive responder used to probe all auth methods offered by the server.
type keyboardInteractive map[string]string

// challenge returns an empty answer for every question, satisfying the ssh.KeyboardInteractiveChallenge interface.
func (cr keyboardInteractive) challenge(user string, instruction string, questions []string, echos []bool) ([]string, error) {
	return make([]string, len(questions)), nil
}

// FakeClient is a stub GSSAPI client used to probe for GSSAPI authentication support during SSH scanning.
type FakeClient struct{}

// InitSecContext satisfies the ssh.GSSAPIClient interface by returning empty output, no continuation, and no error.
func (f *FakeClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	return
}

// GetMIC satisfies the ssh.GSSAPIClient interface by returning a nil MIC and no error.
func (f *FakeClient) GetMIC(micField []byte) ([]byte, error) {
	return nil, nil
}

// DeleteSecContext satisfies the ssh.GSSAPIClient interface by returning nil.
func (f *FakeClient) DeleteSecContext() error {
	return nil
}

// getSecurityParameter performs the first three steps of the SSH handshake to extract the server's protocol version
// and negotiated security algorithms, writing all discovered values into results.
func (s *Scanner) getSecurityParameter(address string, results *ResultData) error {

	// To get the security parameters we implement the first three steps of the SSH handshake: establish a connection,
	// perform the protocol version exchange, then read the server's kexInit message.

	// Establish a connection to target
	conn, errConn := net.DialTimeout("tcp", address, s.dialTimeout)
	if errConn != nil {
		return fmt.Errorf("could not establish tcp connection: %s", errConn)
	}
	defer func() {
		errClose := conn.Close()
		if errClose != nil {
			s.logger.Debugf("Could not close connection to %s: %s", address, errClose)
		}
	}()

	// Send our version string and read the server's version (TODO: add SSH 1.x support if needed)
	clientVersion := []byte(packageVersion)
	serverVersion, errServerVersion := exchangeVersions(conn, clientVersion)
	if errServerVersion != nil {
		return fmt.Errorf("could not get ssh protocol version: %s", errServerVersion)
	}
	results.ProtocolVersion = string(serverVersion)

	// Read the server's kexInit message, which contains all security algorithms
	otherInit, errOtherInit := s.readPacket(conn)
	if errOtherInit != nil {
		return fmt.Errorf("could not read handshake response: %s", errOtherInit)
	}

	// Populate result with negotiated algorithms
	results.KeyExchangeAlgorithms = otherInit.KexAlgos
	results.ServerCompressAlgorithms = otherInit.CompressionServerClient
	results.ServerEncryptionAlgorithms = otherInit.CiphersServerClient
	results.ServerKeyAlgorithms = otherInit.ServerHostKeyAlgos
	results.ServerMacAlgorithms = otherInit.MACsServerClient
	results.UsesGuessedKeyExchange = otherInit.FirstKexFollows

	// Return nil as everything went fine
	return nil
}

// infoFromErr extracts the SSH negotiation parameter list from an ssh.Dial error message.
// The error is expected to contain a bracket-enclosed list such as "[none publickey]".
func infoFromErr(err error) ([]string, error) {

	// Nil error is unexpected behavior
	if err == nil {
		return []string{}, fmt.Errorf("error message was nil")
	}
	errMsg := err.Error()

	// Check if the host is not reachable
	if strings.Contains(errMsg, errNoSuchHost.Error()) {
		return nil, errNoSuchHost
	}

	// Find start and end of the bracket-enclosed algorithm list
	start := strings.LastIndex(errMsg, "[")
	end := strings.LastIndex(errMsg, "]")

	// Return an error if no bracket pair was found, indicating an unrecognized error format
	if start == -1 || end == -1 {
		return nil, fmt.Errorf("could not excerpt parameter from error message: %s", errMsg)
	}

	// Split the space-separated algorithm names
	algStr := errMsg[start+1 : end]
	params := strings.Split(algStr, " ")

	return params, nil
}

// kexInitMsg mirrors the kexInitMsg struct from ssh\messages.go and is used to unmarshal the server's key exchange init packet.
type kexInitMsg struct {
	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}

// readPacket reads one SSH binary packet from r and unmarshals it as a kexInitMsg. It is a leaner version of
// (s *streamPacketCipher) readPacket from ssh\cipher.go.
func (s *Scanner) readPacket(r io.Reader) (*kexInitMsg, error) {

	var prefix [prefixLen]byte
	var packetData []byte
	var otherInit = &kexInitMsg{}

	// Read prefix to find out the padding length
	if _, errReadFull := io.ReadFull(r, prefix[:]); errReadFull != nil {
		return nil, errReadFull
	}

	// Get message length and padding length from prefix
	length := binary.BigEndian.Uint32(prefix[0:4])
	paddingLength := uint32(prefix[4])

	// Check message length
	if length <= paddingLength+1 {
		return nil, fmt.Errorf("ssh: invalid packet length, packet too small")
	}
	if length > maxPacket {
		return nil, fmt.Errorf("ssh: invalid packet length, packet too large")
	}

	// Read payload
	packetData = make([]byte, length-1)
	if _, errReadFull := io.ReadFull(r, packetData); errReadFull != nil {
		return nil, errReadFull
	}

	// Check if we got the right message type
	if packetData[0] != msgKexInit {
		return nil, fmt.Errorf("ssh: first packet should be msgKexInit")
	}

	// Trim padding
	packetData = packetData[:length-paddingLength-1]

	// Unmarshal to kexInitMsg
	if errUnmarshal := ssh.Unmarshal(packetData, otherInit); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	// Return the unmarshaled key exchange message from the target
	return otherInit, nil
}

// The following two functions are copied from ssh\transport.go.

// exchangeVersions sends versionLine to rw and reads back the remote side's version string.
// versionLine must be US-ASCII, start with "SSH-2.0-", and must not include a newline.
func exchangeVersions(rw io.ReadWriter, versionLine []byte) (them []byte, errThem error) {

	// Contrary to the RFC, we do not ignore lines that don't start with "SSH-2.0-" to remain compatible with
	// nonconforming servers.
	for _, c := range versionLine {
		// The spec disallows non US-ASCII chars, and
		// specifically forbids null chars.
		if c < 32 {
			return nil, fmt.Errorf("ssh: junk character in version line")
		}
	}
	if _, errThem = rw.Write(append(versionLine, '\r', '\n')); errThem != nil {
		return
	}

	them, errThem = readVersion(rw)
	return them, errThem
}

// readVersion reads the SSH version string as specified by RFC 4253, section 4.2.
func readVersion(r io.Reader) ([]byte, error) {

	var versionString = make([]byte, 0, 64)
	var ok bool
	var buf [1]byte

	for length := 0; length < maxVersionStringBytes; length++ {
		_, errReadFull := io.ReadFull(r, buf[:])
		if errReadFull != nil {
			return nil, errReadFull
		}
		// The RFC says that the version should be terminated with \r\n
		// but several SSH servers actually only send a \n.
		if buf[0] == '\n' {
			if !bytes.HasPrefix(versionString, []byte("SSH-")) {
				// RFC 4253 says we need to ignore all version string lines
				// except the one containing the SSH version (provided that
				// all the lines do not exceed 255 bytes in total).
				versionString = versionString[:0]
				continue
			}
			ok = true
			break
		}

		// non ASCII chars are disallowed, but we are lenient,
		// since Go doesn't use null-terminated strings.

		// The RFC allows a comment after a space, however,
		// all of it (version and comments) goes into the
		// session hash.
		versionString = append(versionString, buf[0])
	}

	if !ok {
		return nil, fmt.Errorf("ssh: overflow reading version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
	}
	return versionString, nil
}
