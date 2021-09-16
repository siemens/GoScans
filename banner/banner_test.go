/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package banner

import (
	"fmt"
	"go-scans/utils"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
		{"valid-udp", args{testLogger, "google.com", 443, "udp"}, false},
		{"valid-hostname", args{testLogger, "google.com", 443, "tcp"}, false},
		{"valid-ipv4", args{testLogger, "192.168.0.1", 443, "tcp"}, false},
		{"valid-ipv6", args{testLogger, "1::", 443, "tcp"}, false},
		{"invalid-range", args{testLogger, "192.168.0.1/26", 443, "tcp"}, true},
		{"invalid-protocol", args{testLogger, "192.168.0.1", 443, "abc"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(tt.args.logger, tt.args.target, tt.args.port, tt.args.protocol, dialTimeout, receiveTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanner_Run(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	type args struct {
		logger utils.Logger
		target string
		port   int
	}
	tests := []struct {
		name string
		args args
	}{
		{"hostname", args{testLogger, "google.com", 443}},
		{"ip", args{testLogger, "172.217.10.46", 80}}, // google.com
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the banner scanner
			scan, err := NewScanner(tt.args.logger, tt.args.target, tt.args.port, "tcp", dialTimeout, receiveTimeout)
			if err != nil {
				t.Errorf("NewScanner() error = '%v'", err)
				return
			}

			// Launch scan
			result := scan.Run()

			// Evaluate result
			if result.Exception {
				t.Errorf("scan failed: %s", result.Status)
				return
			}

			// Output result
			fmt.Println("Status:", result.Status)
			fmt.Println("Data:", result.Data)
		})
	}
}

// Tests that are expected to run into the dial timeout. Currently all of them only timeout when establishing the SSL
// connection. We might want to cover the other protocols as well.
func TestScanner_TimeoutRun(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	type args struct {
		logger   utils.Logger
		target   string
		port     int
		protocol string
	}
	tests := []struct {
		name string
		args args
	}{
		{"tcp-1", args{testLogger, "10.61.168.56", 1720, "tcp"}},
		{"tcp-2", args{testLogger, "10.61.168.34", 1720, "tcp"}},
		{"tcp-3", args{testLogger, "10.61.168.48", 1720, "tcp"}},
		{"tcp-4", args{testLogger, "10.61.168.40", 1720, "tcp"}},
		{"tcp-5", args{testLogger, "10.61.168.59", 1720, "tcp"}},
		{"tcp-6", args{testLogger, "10.61.168.37", 1720, "tcp"}},
		{"tcp-7", args{testLogger, "10.61.168.36", 1720, "tcp"}},
		{"tcp-8", args{testLogger, "10.61.168.43", 1720, "tcp"}},
		{"tcp-9", args{testLogger, "10.61.168.50", 1720, "tcp"}},
		{"tcp-10", args{testLogger, "10.61.168.32", 1720, "tcp"}},
		{"tcp-11", args{testLogger, "10.61.168.51", 1720, "tcp"}},
		{"tcp-12", args{testLogger, "10.61.168.52", 1720, "tcp"}},
		{"tcp-13", args{testLogger, "10.61.168.42", 1720, "tcp"}},
		{"tcp-14", args{testLogger, "10.61.168.35", 1720, "tcp"}},

		{"udp-1", args{testLogger, "10.61.168.34", 1720, "udp"}},
		{"udp-2", args{testLogger, "10.61.168.56", 1720, "udp"}},
		{"udp-3", args{testLogger, "10.61.168.48", 1720, "udp"}},
		{"udp-4", args{testLogger, "10.61.168.40", 1720, "udp"}},
		{"udp-5", args{testLogger, "10.61.168.59", 1720, "udp"}},
		{"udp-6", args{testLogger, "10.61.168.37", 1720, "udp"}},
		{"udp-7", args{testLogger, "10.61.168.36", 1720, "udp"}},
		{"udp-8", args{testLogger, "10.61.168.43", 1720, "udp"}},
		{"udp-9", args{testLogger, "10.61.168.50", 1720, "udp"}},
		{"udp-10", args{testLogger, "10.61.168.32", 1720, "udp"}},
		{"udp-11", args{testLogger, "10.61.168.51", 1720, "udp"}},
		{"udp-12", args{testLogger, "10.61.168.52", 1720, "udp"}},
		{"udp-13", args{testLogger, "10.61.168.42", 1720, "udp"}},
		{"udp-14", args{testLogger, "10.61.168.35", 1720, "udp"}},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the banner scanner
			scan, err := NewScanner(tt.args.logger, tt.args.target, tt.args.port, tt.args.protocol, dialTimeout, receiveTimeout)
			if err != nil {
				t.Errorf("NewScanner() error = '%v'", err)
				return
			}

			// Launch scan
			result := scan.Run()

			// Evaluate result
			if result.Exception {
				t.Errorf("scan failed: %s", result.Status)
				return
			}

			// Output result
			fmt.Println("Status:", result.Status)
			fmt.Println("Data:", result.Data)
		})
	}
}

func TestScanner_UpdateResultMap(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	// Prepare and run test cases
	type fields struct {
		Label     string
		ChResults chan *Result
		Started   time.Time
		Finished  time.Time
		logger    utils.Logger
		target    string
		port      int
		protocol  string
	}
	f := fields{
		"test",
		make(chan *Result),
		time.Now(),
		time.Now(),
		testLogger,
		"localhost",
		80,
		"tcp",
	}
	type args struct {
		res         map[string][]byte
		triggerName string
		response    []byte
		err         error
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		shouldHold bool
	}{
		{"valid", f, args{make(map[string][]byte), "test", []byte("test response"), nil}, true},
		{"valid", f, args{make(map[string][]byte), "test", []byte("test response"), fmt.Errorf("something went wrong")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, errNew := NewScanner(testLogger, tt.fields.target, tt.fields.port, tt.fields.protocol, dialTimeout, receiveTimeout)
			if errNew != nil {
				t.Errorf("Scanner.updateResultMap(); Could not create Scanner.")
			} else {
				s.updateResultMap(tt.args.res, tt.args.triggerName, tt.args.response, tt.args.err)
				if got, ok := tt.args.res[tt.args.triggerName]; ok {
					if tt.shouldHold {
						if !reflect.DeepEqual(got, tt.args.response) {
							t.Errorf("Scanner.updateResultMap(); Map holds %v, want = '%v'", got, tt.args.response)
						}
					} else {
						t.Errorf("Scanner.updateResultMap(); Map should not hold key %v", tt.args.triggerName)
					}
				} else if !tt.shouldHold {
					t.Errorf("Scanner.updateResultMap(); Map does not hold key %v", tt.args.triggerName)
				}
			}
		})
	}
}

func TestSendPlain(t *testing.T) {

	// Prepare test variables
	dialTimeout := 5 * time.Second
	receiveTimeout := 5 * time.Second

	// Prepare and run test cases
	type args struct {
		address  string
		port     int
		protocol string
		trigger  string
	}
	tests := []struct {
		name      string
		args      args
		wantError string
	}{
		{"invalid-address-tcp", args{"invalid", 53, "tcp", triggerLinux}, "dial tcp: lookup invalid: no such host"},
		{"invalid-address-udp", args{"invalid", 53, "udp", triggerLinux}, "dial udp: lookup invalid: no such host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.args.trigger, "%s") {
				tt.args.trigger = fmt.Sprintf(tt.args.trigger, tt.args.address)
			}
			_, err := sendPlain(tt.args.address, tt.args.port, tt.args.protocol, tt.args.trigger, dialTimeout, receiveTimeout)
			if err != nil {
				if err.Error() != tt.wantError {
					t.Errorf("sendPlain() error type = '%v', want '%v'", err.Error(), tt.wantError)
				}
			}
		})
	}
}

func TestSocketErrorType(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{"connection-success1", "google.com", 443, ""},
		{"connection-success2", "8.8.8.8", 53, ""},
		{"connection-timeout1", "10.10.10.10", 443, "dial"},  // DIAL error because not existing
		{"connection-timeout2", "192.168.0.1", 4564, "dial"}, // DIAL error because host online but port closed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Resolve Address
			addr, errRes := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", tt.host, tt.port))
			if errRes != nil {
				t.Errorf("SocketErrorType() = could not execute test due to invalid input")
			}
			// Establish connection
			_, errDial := net.DialTCP("tcp", nil, addr)
			// Test error result
			if got := socketErrorType(errDial); got != tt.want {
				t.Errorf("SocketErrorType() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
