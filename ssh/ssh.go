/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/siemens/GoScans/utils"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"time"
)

const Label = "Ssh"

// constants used by go
const (
	packageVersion        = "SSH-2.0-Go" // ssh\transport.go
	maxVersionStringBytes = 255          // ""
	prefixLen             = 5            // ssh\cipher.go
	maxPacket             = 256 * 1024   // ""
	msgKexInit            = 20           // ssh\messages.go
)

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

type Result struct {
	Data      *ResultData
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

type Scanner struct {
	Label       string
	Started     time.Time
	Finished    time.Time
	logger      utils.Logger
	target      string // Address to be scanned (might be IPv4, IPv6 or hostname)
	port        int
	dialTimeout time.Duration
	deadline    time.Time // Time when the scanner has to abort
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port int,
	dialTimeout time.Duration,
) (*Scanner, error) {

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
		strings.TrimSpace(target),
		port,
		dialTimeout,
		time.Time{}, // zero time (no deadline yet set)
	}

	// Return scan struct
	return &scan, nil
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf(fmt.Sprintf("Unexpected error: %s", r))

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

	// Set scan started flag and calculate deadline
	s.Started = time.Now()
	s.deadline = time.Now().Add(timeout)
	s.logger.Infof("Started  scan of %s.", s.target)

	// Execute scan logic
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.target, duration)

	// Return result set
	return res
}

func (s *Scanner) execute() *Result {

	// The scan first gets the authentication parameters using the golang ssh package functions.
	// To get the other security parameter we implemented the first message exchange of the ssh handshake.

	// Declare result variable to be returned
	results := &ResultData{}

	// Prepare address
	address := fmt.Sprintf("%s:%d", s.target, s.port)

	// Get authentication methods
	authMethods, errAuth := s.getAuthenticationMethods(address)
	if errAuth != nil {
		if errors.Is(errAuth, errNoSuchHost) {
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		} else {
			s.logger.Debugf("Could not extract authentication methods: %s", errAuth)
		}
	} else {

		// If no error occurred, safe authentication methods
		results.AuthenticationMechanisms = authMethods
	}

	// Check whether scan timeout is reached
	if utils.DeadlineReached(s.deadline) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
		}
	}

	// We initialize a ssh handshake to get the remaining security parameter
	errParameters := s.getSecurityParameter(address, results)
	if errParameters != nil {
		s.logger.Debugf("Could not get security parameters: %s", errParameters)
	}

	// Check whether scan timeout is reached
	if utils.DeadlineReached(s.deadline) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			results,
			utils.StatusDeadline,
			false,
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

func (s *Scanner) getAuthenticationMethods(address string) ([]string, error) {

	// To get the authentication mechanisms we use the dial() function of the go ssh package and use empty credentials.

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
		Timeout:         s.dialTimeout, // Pass remaining time to the deadline as timeout
	}

	// Try to establish connection to target with empty authentication methods to get the error message with supported
	// methods by the server, this also checks for reachability of the target
	sshConn, err := ssh.Dial("tcp", address, config)

	// Check if ssh connection could be established with empty credentials (should not happen)
	// if yes, we add the none-method to the authentication mechanism
	if err == nil {
		authMethods = []string{"none"}
		err := sshConn.Close()
		if err != nil {
			s.logger.Debugf("Could not close connection to %s: %s", s.target, err)
		}
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() { // Check if the error was because the dial timed out.

		// Try to excerpt the supported methods from the error
		triedAuthMethods, err := infoFromErr(err)
		if err != nil {
			return nil, err
		}

		// golang tried the none method, so it adds it to the error message, but since the authentication with
		// empty credential failed, we remove it
		authMethods = utils.RemoveFromSlice(triedAuthMethods, "none")
	}

	// We test the gssapi-with-mic auth method separately because Go can give back an unusual error when the server does
	// not support Go's version of this mechanism, but we can still conclude that it supports gssapi-with-mic, if we
	// don't get the error that only the none method was tried, because this means it tried the gssapi-with-mic method,
	// because the servers offers it as an option
	config.Auth = []ssh.AuthMethod{ssh.GSSAPIWithMICAuthMethod(&FakeClient{}, "")}
	config.Timeout = s.dialTimeout
	sshConn, err = ssh.Dial("tcp", address, config)
	if err == nil {
		err := sshConn.Close()
		if err != nil {
			s.logger.Debugf("Could not close connection to %s: %s", s.target, err)
		}
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() { // Check if the error was because the dial timed out.
		if err.Error() != "ssh: handshake failed: ssh: could not authenticate, attempted methods [none], no supported methods remain" {
			authMethods = append(authMethods, "gssapi-with-mic")
		}
	}

	return authMethods, nil
}

// We need an empty Challenge for the ssh Client, to test all Auth methods of target
type keyboardInteractive map[string]string

func (cr keyboardInteractive) challenge(user string, instruction string, questions []string, echos []bool) ([]string, error) {
	return make([]string, len(questions)), nil
}

// We need to define a fake gssapi client in order to let Go test for this authentication method
type FakeClient struct{}

func (f *FakeClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	return
}

func (f *FakeClient) GetMIC(micField []byte) ([]byte, error) {
	return nil, nil
}

func (f *FakeClient) DeleteSecContext() error {
	return nil
}

func (s *Scanner) getSecurityParameter(address string, results *ResultData) error {
	// To get the security parameter of the target we implement the first three steps of the ssh handshake:
	// After we established a connection, we start the handshake with a protocol Version exchange and read the next two
	// responses which contain the target's protocol version and its security parameters.

	// Establish a connection to target
	conn, err := net.DialTimeout("tcp", address, s.dialTimeout)
	if err != nil {
		return fmt.Errorf("could not establish tcp connection: %s", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			s.logger.Debugf("Could not close connection to %s: %s", address, err)
		}
	}()

	// Start SSH Handshake
	// Version exchange
	clientVersion := []byte(packageVersion) // TODO check if we can support ssh version 1.x
	serverVersion, err := exchangeVersions(conn, clientVersion)
	if err != nil {
		return fmt.Errorf("could not get shh protocol version: %s", err)
	}
	results.ProtocolVersion = string(serverVersion)

	// Read targets Key exchange message, which contains all security algorithms we want
	otherInit, err := s.readPacket(conn)
	if err != nil {
		return fmt.Errorf("could not read handshake response: %s", err)
	}

	// Prepare result
	results.KeyExchangeAlgorithms = otherInit.KexAlgos
	results.ServerCompressAlgorithms = otherInit.CompressionServerClient
	results.ServerEncryptionAlgorithms = otherInit.CiphersServerClient
	results.ServerKeyAlgorithms = otherInit.ServerHostKeyAlgos
	results.ServerMacAlgorithms = otherInit.MACsServerClient
	results.UsesGuessedKeyExchange = otherInit.FirstKexFollows
	return nil
}

// Excerpts information (authentication method, kex algorithms...) from an error of ssh.Dial
// The err should have the form of "...server offered: [none publickey]..."
func infoFromErr(err error) ([]string, error) {

	// If no Error was sent, this is unexpected behavior
	if err == nil {
		return []string{}, fmt.Errorf("error message was nil")
	}
	errMsg := err.Error()

	// test if host is reachable
	if strings.Contains(errMsg, errNoSuchHost.Error()) {
		return nil, errNoSuchHost
	}

	// Find start and end of the algorithm list
	start := strings.LastIndex(errMsg, "[")
	end := strings.LastIndex(errMsg, "]")

	// If Error message changed in the future, send an error
	if strings.Contains(errMsg, "server offered") && start == -1 || end == -1 {
		return nil, fmt.Errorf("could not excerpt parameter from error message: %s", errMsg)
	}

	// Split the algorithms
	algStr := errMsg[start+1 : end]
	params := strings.Split(algStr, " ")

	return params, nil
}

// struct for ssh messages, copied from go's ssh\messages.go
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

// readPacket reads the target response to our ssh handshake initiation, leaner version of (s *streamPacketCipher) readPacket in ssh\cipher.go
func (s *Scanner) readPacket(r io.Reader) (*kexInitMsg, error) {
	var prefix [prefixLen]byte
	var packetData []byte
	otherInit := &kexInitMsg{}

	// Read prefix to find out the padding length
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
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
	if _, err := io.ReadFull(r, packetData); err != nil {
		return nil, err
	}

	// Check if we got the right message type
	if packetData[0] != msgKexInit {
		return nil, fmt.Errorf("ssh: first packet should be msgKexInit")
	}

	// Trim padding
	packetData = packetData[:length-paddingLength-1]

	// Unmarshal to kexInitMsg
	if err := ssh.Unmarshal(packetData, otherInit); err != nil {
		return nil, err
	}

	// Return the unmarshaled key exchange message from the target
	return otherInit, nil
}

// The following two functions are copied from ssh\transport.go

// Sends and receives a version line.  The versionLine string should
// be US ASCII, start with "SSH-2.0-", and should not include a
// newline. exchangeVersions returns the other side's version line.
func exchangeVersions(rw io.ReadWriter, versionLine []byte) (them []byte, err error) {
	// Contrary to the RFC, we do not ignore lines that don't
	// start with "SSH-2.0-" to make the library usable with
	// nonconforming servers.
	for _, c := range versionLine {
		// The spec disallows non US-ASCII chars, and
		// specifically forbids null chars.
		if c < 32 {
			return nil, fmt.Errorf("ssh: junk character in version line")
		}
	}
	if _, err = rw.Write(append(versionLine, '\r', '\n')); err != nil {
		return
	}

	them, err = readVersion(rw)
	return them, err
}

// Read version string as specified by RFC 4253, section 4.2.
func readVersion(r io.Reader) ([]byte, error) {
	versionString := make([]byte, 0, 64)
	var ok bool
	var buf [1]byte

	for length := 0; length < maxVersionStringBytes; length++ {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return nil, err
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
