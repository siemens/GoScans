/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/discovery/ot"
	"github.com/siemens/GoScans/utils"
)

// mockDNSForward maps hostnames to the single IP the test resolver returns.
var mockDNSForward = map[string]string{
	"ccc.de":     "195.54.164.39",
	"www.ccc.de": "195.54.164.39",
}

// TestMain initializes the test environment and runs all tests in the discovery package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Replace DNS lookups with deterministic mocks so tests are network-independent.
	utils.OverrideDNS(
		func(host string) ([]net.IP, error) {
			if ip, ok := mockDNSForward[host]; ok {
				return []net.IP{net.ParseIP(ip)}, nil
			}
			return nil, &net.DNSError{Err: fmt.Sprintf("lookup %s: no such host", host), Name: host}
		},
		func(addr string) ([]string, error) {
			return nil, &net.DNSError{Err: fmt.Sprintf("lookup %s: no such host", addr), Name: addr}
		},
	)

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-discovery-test-*")
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

const nmapLfChar = "\n"
const testTarget = "127.0.0.1"

var testArgs = []string{
	"-PE",
	"-PP",
	"-PS21,22,25,23,80,111,179,443,445,1433,1521,3189,3306,3389,5800,5900,8000,8008,8080,8443",
	"-PA80,21000",
	"-sS",
	"-O",
	"--top-ports", "10",
	"-sV",
	"-T4",
	"--min-hostgroup", "64",
	"--randomize-hosts",
	"--host-timeout", "6h",
	"--max-retries", "2",
	"--script", "address-info,afp-serverinfo,ajp-auth,ajp-methods,amqp-info,auth-owners,backorifice-info,bitcoinrpc-info,cassandra-info,clock-skew,creds-summary,dns-nsid,dns-recursion,dns-service-discovery,epmd-info,finger,flume-master-info,freelancer-info,ftp-anon,ftp-bounce,ganglia-info,giop-info,gopher-ls,hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info,hbase-master-info,hbase-region-info,hddtemp-info,hnap-info,Http-auth,Http-cisco-anyconnect,Http-cors,Http-generator,Http-git,Http-open-proxy,Http-robots.txt,Http-svn-enum,Http-webdav-scan,ike-version,imap-capabilities,imap-ntlm-info,ip-https-discover,ipv6-node-info,irc-info,iscsi-info,jdwp-info,knx-gateway-info,maxdb-info,mongodb-databases,mongodb-info,ms-sql-info,ms-sql-ntlm-info,mysql-info,nat-pmp-info,nbstat,ncp-serverinfo,netbus-info,nntp-ntlm-info,openlookup-info,pop3-capabilities,pop3-ntlm-info,quake1-info,quake3-info,quake3-master-getservers,realvnc-auth-bypass,rmi-dumpregistry,rpcinfo,rtsp-methods,servicetags,sip-methods,smb-security-mode,smb-protocols,smtp-commands,smtp-ntlm-info,snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,socks-auth-info,socks-open-proxy,ssh-hostkey,sshv1,ssl-known-key,sstp-discover,telnet-ntlm-info,tls-nextprotoneg,upnp-info,ventrilo-info,vnc-info,wdb-version,weblogic-t3-info,wsdd-discover,x11-access,xmlrpc-methods,xmpp-info,vnc-title,acarsd-info,afp-showmount,ajp-headers,ajp-request,allseeingeye-info,bitcoin-getaddr,bitcoin-info,citrix-enum-apps,citrix-enum-servers-xml,citrix-enum-servers,coap-resources,couchdb-databases,couchdb-stats,daytime,db2-das-info,dict-info,drda-info,duplicates,gpsd-info,Http-affiliate-id,Http-apache-negotiation,Http-apache-server-status,Http-cross-domain-policy,Http-frontpage-login,Http-gitweb-projects-enum,Http-php-version,Http-qnap-nas-info,Http-vlcstreamer-ls,Http-vuln-cve2010-0738,Http-vmware-path-vuln,Http-vuln-cve2011-3192,Http-vuln-cve2014-2126,Http-vuln-cve2014-2127,Http-vuln-cve2014-2128,ip-forwarding,ipmi-cipher-zero,ipmi-version,membase-Http-info,memcached-info,mqtt-subscribe,msrpc-enum,ncp-enum-users,netbus-auth-bypass,nfs-ls,nfs-showmount,nfs-statfs,omp2-enum-targets,oracle-tns-version,rdp-enum-encryption,redis-info,rfc868-time,riak-Http-info,rsync-list-modules,rusers,smb-mbenum,ssh2-enum-algos,stun-info,telnet-encryption,tn3270-screen,versant-info,voldemort-info,vuze-dht-info,xdmcp-discover,supermicro-ipmi-conf,cccam-version,docker-version,enip-info,fox-info,iax2-version,jdwp-version,netbus-version,pcworx-info,s7-info,teamspeak2-version",
	"--script", "vmware-version,tls-ticketbleed,smb2-time,smb2-security-mode,smb2-capabilities,smb-vuln-ms17-010,smb-double-pulsar-backdoor,openwebnet-discovery,Http-vuln-cve2017-1001000,Http-security-headers,Http-cookie-flags,ftp-syst,cics-info",
}

// TestNewScanner verifies that NewScanner returns an error for invalid inputs and no error for valid configurations.
func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Prepare unit test data
	testLogger := utils.NewTestLogger()
	nmapBlacklist := []string{"20.20.20.2", "10.10.10.1"}
	nmapBlacklistFile := filepath.Join(testSettings.PathDataDir, "discovery", "blacklist_valid.txt")
	excludeDomains := []string{"cloudfront.net", "wildcard.cloudfront.net", "azurewebsites.net"}
	dialTimeout := 5 * time.Second

	// Initialize default scripts
	errInit := initDefaultScripts(testSettings.PathNmap)
	if errInit != nil {
		t.Errorf("Could not initialize default scripts: %s", errInit)
		return
	}

	// Prepare and run test cases
	type args struct {
		logger            utils.Logger
		target            string
		nmap              string
		nmapParameters    []string
		nmapVersionAll    bool
		nmapBlacklist     []string
		nmapBlacklistFile string
		ldapServer        string
		ldapDomain        string
		ldapUser          string
		ldapPassword      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid-basic",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: false,
		},
		{
			name:    "valid-no-args",
			args:    args{testLogger, testTarget, testSettings.PathNmap, []string{}, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: false,
		},
		{
			name:    "valid-no-versionall",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, false, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: false,
		},
		{
			name:    "invalid-ldap-url",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "https://sub.domain.tld", "", "", ""},
			wantErr: true,
		},
		{
			name:    "valid-ldap-url",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "sub.domain.tld", "", "", ""},
			wantErr: false,
		},
		{
			name:    "invalid-blacklist-path",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, "notexisting", "", "", "", ""},
			wantErr: true,
		},
		{
			name:    "invalid-target1",
			args:    args{testLogger, "", testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: true,
		},
		{
			name:    "invalid-target2",
			args:    args{testLogger, "invalid input", testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: true,
		},
		{
			name:    "invalid-nmap",
			args:    args{testLogger, testTarget, "notexisting", testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""},
			wantErr: true,
		},
		{
			name:    "invalid-credentials-set",
			args:    args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "some.domain", "", ""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNewScanner := NewScanner(tt.args.logger, []string{tt.args.target}, tt.args.nmap, tt.args.nmapParameters, tt.args.nmapVersionAll, tt.args.nmapBlacklist, tt.args.nmapBlacklistFile, []string{}, tt.args.ldapServer, tt.args.ldapDomain, tt.args.ldapUser, tt.args.ldapPassword, false, excludeDomains, dialTimeout)
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
				return
			}
		})
	}
}

// TestExtractHostData verifies that extractHostData correctly parses host information from an Nmap result.
func TestExtractHostData(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errIn := os.ReadFile(nmapXml)
	if errIn != nil {
		t.Errorf("Reading Nmap sample result failed: %s", errIn)
	}

	// Parse Nmap result
	scanResult := nmap.Run{}
	errParse := nmap.Parse(in, &scanResult)
	if errParse != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", errParse)
	}

	// Prepare and run test cases
	tests := []struct {
		name  string
		h     nmap.Host
		want  []string
		want1 []string
		want2 []string
		want3 time.Time
		want4 time.Duration
	}{
		{
			name:  "valid",
			h:     scanResult.Hosts[0],
			want:  []string{"host123.sub.domain.tld", "HOST123.sub.domain.tld"},
			want1: nil,
			want2: []string{"96% Microsoft Windows 7 SP1", "92% Microsoft Windows 8.1 Update 1", "92% Microsoft Windows Phone 7.5 or 8.0", "91% Microsoft Windows 7 or Windows Server 2008 R2", "91% Microsoft Windows Server 2008 R2", "91% Microsoft Windows Server 2008 R2 or Windows 8.1", "91% Microsoft Windows Server 2008 R2 SP1 or Windows 8", "91% Microsoft Windows 7", "91% Microsoft Windows 7 Professional or Windows 8", "91% Microsoft Windows 7 SP1 or Windows Server 2008 R2"},
			want3: time.Date(2019, 02, 21, 14, 32, 49, 0, &time.Location{}),
			want4: time.Second * 20776,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3, got4 := extractHostData(tt.h)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractHostData() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extractHostData() got1 = '%v', want1 = '%v'", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractHostData() got2 = '%v', want2 = '%v'", got2, tt.want2)
			}
			if !reflect.DeepEqual(got3, tt.want3) {
				t.Errorf("extractHostData() got3 = '%v', want3 = '%v'", got3, tt.want3)
			}
			if !reflect.DeepEqual(got4, tt.want4) {
				t.Errorf("extractHostData() got4 = '%v', want4 = '%v'", got4, tt.want4)
			}
		})
	}
}

// TestExtractPortData verifies that extractPortData correctly parses port service information from an Nmap result.
func TestExtractPortData(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errIn := os.ReadFile(nmapXml)
	if errIn != nil {
		t.Errorf("Reading Nmap sample result failed: %s", errIn)
	}

	// Parse Nmap result
	scanResult := nmap.Run{}
	errParse := nmap.Parse(in, &scanResult)
	if errParse != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", errParse)
	}

	// Define expected read data
	services := []Service{
		{
			445,
			"tcp",
			"microsoft-ds",
			"",
			"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds",
			"",
			"",
			"Windows",
			[]string{"cpe:/o:microsoft:windows"},
			"workgroup: SUB",
			"probed",
			118,
		},
		{
			3389,
			"tcp",
			"ms-wbt-server",
			"ssl",
			"",
			"",
			"",
			"",
			nil,
			"",
			"table",
			118,
		},
	}

	// Prepare and run test cases
	tests := []struct {
		name  string
		ports []nmap.Port
		want  []Service
		want1 []string
	}{
		{
			name:  "valid",
			ports: scanResult.Hosts[0].Ports,
			want:  services,
			want1: []string{"HOST123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := extractPortData(tt.ports)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractPortData() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extractPortData() got1 = '%v', want = '%v'", got1, tt.want1)
			}
		})
	}
}

// TestExtractHostScriptData verifies that extractHostScriptData correctly parses Nmap host script output.
func TestExtractHostScriptData(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errIn := os.ReadFile(nmapXml)
	if errIn != nil {
		t.Errorf("Reading Nmap sample result failed: %s", errIn)
	}

	// Parse Nmap result
	scanResult := nmap.Run{}
	errParse := nmap.Parse(in, &scanResult)
	if errParse != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", errParse)
	}

	// Define expected read data
	scripts := []Script{
		{"Host", -1, "", "clock-skew", "mean: -19m59s, deviation: 34m37s, median: 0s"},
		{"Host", -1, "", "msrpc-enum", "NT_STATUS_ACCESS_DENIED"},
		{"Host", -1, "", "smb-mbenum", nmapLfChar + "  ERROR: Call to Browser Service failed with status = 2184"},
		{"Host", -1, "", "smb-os-discovery", nmapLfChar + "  OS: Windows 7 Enterprise 7601 Service Pack 1 (Windows 7 Enterprise 6.1)" + nmapLfChar + "  OS CPE: cpe:/o:microsoft:windows_7::sp1" + nmapLfChar + "  Computer name: HOST123" + nmapLfChar + "  NetBIOS computer name: HOST123\\x00" + nmapLfChar + "  Domain name: sub.domain.tld" + nmapLfChar + "  Forest name: sub.domain.tld" + nmapLfChar + "  FQDN: HOST123.sub.domain.tld" + nmapLfChar + "  System time: 2019-02-21T15:38:29+01:00" + nmapLfChar},
		{"Host", -1, "", "smb-protocols", nmapLfChar + "  dialects: " + nmapLfChar + "    NT LM 0.12 (SMBv1) [dangerous, but default]" + nmapLfChar + "    2.02" + nmapLfChar + "    2.10"},
		{"Host", -1, "", "smb-security-mode", nmapLfChar + "  account_used: <blank>" + nmapLfChar + "  authentication_level: user" + nmapLfChar + "  challenge_response: supported" + nmapLfChar + "  message_signing: supported"},
		{"Host", -1, "", "smb2-capabilities", nmapLfChar + "  2.02: " + nmapLfChar + "    Distributed File System" + nmapLfChar + "  2.10: " + nmapLfChar + "    Distributed File System" + nmapLfChar + "    Leasing" + nmapLfChar + "    Multi-credit operations"},
		{"Host", -1, "", "smb2-security-mode", nmapLfChar + "  2.02: " + nmapLfChar + "    Message signing enabled but not required"},
		{"Host", -1, "", "smb2-time", nmapLfChar + "  date: 2019-02-21 15:38:33" + nmapLfChar + "  start_date: 2019-02-21 09:53:29"},
	}

	// Prepare and run test cases
	tests := []struct {
		name        string
		hostScripts []nmap.Script
		want        []Script
		want1       []string
		want2       string
	}{
		{
			name:        "valid",
			hostScripts: scanResult.Hosts[0].HostScripts,
			want:        scripts,
			want1:       []string{"HOST123.sub.domain.tld"},
			want2:       "Windows 7 Enterprise 7601 Service Pack 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := extractHostScriptData(tt.hostScripts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractHostScriptData() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extractHostScriptData() got1 = '%v', want = '%v'", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("extractHostScriptData() got2 = '%v', want = '%v'", got2, tt.want2)
			}
		})
	}
}

// TestExtractPortScriptData verifies that extractPortScriptData correctly parses Nmap port script output.
func TestExtractPortScriptData(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errIn := os.ReadFile(nmapXml)
	if errIn != nil {
		t.Errorf("Reading Nmap sample result failed: %s", errIn)
	}

	// Parse Nmap result
	scanResult := nmap.Run{}
	errParse := nmap.Parse(in, &scanResult)
	if errParse != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", errParse)
	}

	// Define expected read data
	scripts := []Script{
		{"port", 3389, "tcp", "rdp-enum-encryption", nmapLfChar + "  Security layer" + nmapLfChar + "    CredSSP: SUCCESS" + nmapLfChar},
		{"port", 3389, "tcp", "ssl-cert", "Subject: commonName=HOST123.sub.domain.tld" + nmapLfChar + "Issuer: commonName=HOST123.sub.domain.tld" + nmapLfChar + "Public Key type: rsa" + nmapLfChar + "Public Key bits: 2048" + nmapLfChar + "Signature Algorithm: sha1WithRSAEncryption" + nmapLfChar + "Not valid before: 2018-10-17T11:24:39" + nmapLfChar + "Not valid after:  2019-04-18T11:24:39" + nmapLfChar + "MD5:   58ce c5a4 eabb d148 6145 062d 42f3 303f" + nmapLfChar + "SHA-1: e2a1 89b5 ac66 63ba 506c d7ef 6222 4842 7b32 d432"},
	}

	// Prepare and run test cases
	tests := []struct {
		name  string
		ports []nmap.Port
		want  []Script
		want1 []string
		want2 []int
	}{
		{
			name:  "valid",
			ports: scanResult.Hosts[0].Ports,
			want:  scripts,
			want1: []string{"HOST123.sub.domain.tld"},
			want2: []int{3389},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := extractPortScriptData(tt.ports)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractPortScriptData() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extractPortScriptData() got1 = '%v', want = '%v'", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractPortScriptData() got2 = '%v', want = '%v'", got2, tt.want2)
			}
		})
	}
}

// TestDecideDnsName verifies that decideDnsName selects the correct forward-resolving hostname from the candidate list.
func TestDecideDnsName(t *testing.T) {

	// Prepare unit test data
	excludeDomains := []string{"cloudfront.net", "wildcard.cloudfront.net", "azurewebsites.net"}

	// Prepare and run test cases
	type args struct {
		hData      *Host
		chThrottle chan struct{}
		chResults  chan *Host
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want2 []string
	}{
		{
			name:  "domain-valid-forward",
			args:  args{&Host{Ip: "195.54.164.39", OtherNames: []string{"*.domain.tld", "ccc.de", "notexisting"}}, make(chan struct{}, 1), make(chan *Host)},
			want:  "ccc.de",
			want2: []string{"domain.tld", "wildcard.domain.tld", "notexisting"},
		},
		{
			name:  "domain-invalid",
			args:  args{&Host{Ip: "192.168.0.1", OtherNames: []string{"*.domain.tld", "www.cert.domain.tld", "cert.domain.tld", "notexisting"}}, make(chan struct{}, 1), make(chan *Host)},
			want:  "",
			want2: []string{"domain.tld", "cert.domain.tld", "wildcard.domain.tld", "www.cert.domain.tld", "notexisting"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Launch function asynchronously
			decideDnsName(tt.args.hData, []string{}, excludeDomains)

			// Check result
			if !reflect.DeepEqual(tt.args.hData.DnsName, tt.want) {
				t.Errorf("decideDnsName() DNS Name = '%v', want = '%v'", tt.args.hData.DnsName, tt.want)
			}
			if !reflect.DeepEqual(tt.args.hData.OtherNames, tt.want2) {
				t.Errorf("decideDnsName() Other Names = '%v', want2 = '%v'", tt.args.hData.OtherNames, tt.want2)
			}
		})
	}
}

// Test_sanitizeDnsNames verifies that sanitizeDnsNames deduplicates, lowercases, and excludes blocked domains.
func Test_sanitizeDnsNames(t *testing.T) {
	input := []string{"sub1.cert.domain.tld", "sub2.domain.tld", "SuB2.domain.tld", "nothing", "A", "sub.domain.tld", "", "", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "1::", "*.sub.domain.tld", "azurewebsites.net"}
	output := []string{"sub1.cert.domain.tld", "sub2.domain.tld", "nothing", "a", "sub.domain.tld", "wildcard.sub.domain.tld"}

	// Prepare and run test cases
	tests := []struct {
		name           string
		hostnames      []string
		excludeDomains []string
		want           []string
	}{
		{
			name:           "dedup-lowercase-excluded-domains",
			hostnames:      input,
			excludeDomains: []string{"cloudfront.net", "wildcard.cloudfront.net", "azurewebsites.net"},
			want:           output,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeDnsNames(tt.hostnames, tt.excludeDomains); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sanitizeDnsNames() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_orderDnsNames verifies that orderDnsNames returns hostnames in priority order matching the domain chain.
func Test_orderDnsNames(t *testing.T) {

	// Sample priority chain
	domainOrder := []string{
		"forrest1.domain.local",
		"domain.local",
		"other.local",
		"third-party.com",
	}

	// Define final output and order
	order := []string{
		"forrest1.domain.local", "host.forrest1.domain.local", "domain.local", "forrest2.domain.local", "forrest3.domain.local",
		"host.forrest3.domain.local", "other.local", "host.other.local", "host.third-party.com", "g.com", "google.com", "some.com", "some.de",
		"some4life.de", "some.geocities.com", "host.google.com", "some.hosting.com", "host.some.com",
		"anythingelse",
	}

	// Prepare and run test cases
	tests := []struct {
		name      string
		hostnames []string
		want      []string
	}{
		{name: "disorder0", hostnames: utils.Shuffle([]string{"forrest1.domain.local", "host.forrest1.domain.local"}), want: []string{"forrest1.domain.local", "host.forrest1.domain.local"}},
		{name: "disorder1", hostnames: utils.Shuffle([]string{"host.forrest1.domain.local", "domain.local"}), want: []string{"host.forrest1.domain.local", "domain.local"}},
		{name: "disorder2", hostnames: utils.Shuffle([]string{"domain.local", "forrest2.domain.local"}), want: []string{"domain.local", "forrest2.domain.local"}},
		{name: "disorder3", hostnames: utils.Shuffle([]string{"forrest2.domain.local", "forrest3.domain.local"}), want: []string{"forrest2.domain.local", "forrest3.domain.local"}},
		{name: "disorder4", hostnames: utils.Shuffle([]string{"forrest3.domain.local", "host.forrest3.domain.local"}), want: []string{"forrest3.domain.local", "host.forrest3.domain.local"}},
		{name: "disorder5", hostnames: utils.Shuffle([]string{"host.forrest3.domain.local", "other.local"}), want: []string{"host.forrest3.domain.local", "other.local"}},
		{name: "disorder6", hostnames: utils.Shuffle([]string{"other.local", "host.other.local"}), want: []string{"other.local", "host.other.local"}},
		{name: "disorder7", hostnames: utils.Shuffle([]string{"host.other.local", "host.third-party.com"}), want: []string{"host.other.local", "host.third-party.com"}},
		{name: "disorder8", hostnames: utils.Shuffle([]string{"host.third-party.com", "g.com"}), want: []string{"host.third-party.com", "g.com"}},
		{name: "disorder9", hostnames: utils.Shuffle([]string{"g.com", "google.com"}), want: []string{"g.com", "google.com"}},
		{name: "disorder10", hostnames: utils.Shuffle([]string{"google.com", "some.com"}), want: []string{"google.com", "some.com"}},
		{name: "disorder11", hostnames: utils.Shuffle([]string{"some.com", "some.de"}), want: []string{"some.com", "some.de"}},
		{name: "disorder12", hostnames: utils.Shuffle([]string{"some.de", "some4life.de"}), want: []string{"some.de", "some4life.de"}},
		{name: "disorder13", hostnames: utils.Shuffle([]string{"some4life.de", "host.google.com"}), want: []string{"some4life.de", "host.google.com"}},
		{name: "disorder14", hostnames: utils.Shuffle([]string{"host.google.com", "host.some.com"}), want: []string{"host.google.com", "host.some.com"}},
		{name: "disorder15", hostnames: utils.Shuffle([]string{"host.some.com", "some.geocities.com"}), want: []string{"some.geocities.com", "host.some.com"}},
		{name: "disorder16", hostnames: utils.Shuffle([]string{"some.geocities.com", "some.hosting.com"}), want: []string{"some.geocities.com", "some.hosting.com"}},
		{name: "disorder17", hostnames: utils.Shuffle([]string{"some.hosting.com", "anythingelse"}), want: []string{"some.hosting.com", "anythingelse"}},
		{name: "disorder18", hostnames: utils.Shuffle(order), want: order},
		{name: "disorder19", hostnames: utils.Shuffle([]string{"localhost", "hostname", "domain.com", "some.hosting.com", "anythingelse"}), want: []string{"domain.com", "some.hosting.com", "anythingelse", "hostname", "localhost"}},
		{name: "disorder20", hostnames: utils.Shuffle([]string{"abcde", "abcde.domain.tld", "abcde.domain2.tld"}), want: []string{"abcde.domain.tld", "abcde.domain2.tld", "abcde"}},

		// Prefer FQDNs over incomplete hostnames
		{name: "disorder21", hostnames: []string{"hostname", "hostname.domain.tld"}, want: []string{"hostname.domain.tld", "hostname"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orderDnsNames(tt.hostnames, domainOrder); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("orderDnsNames() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// Test_identifyDnsName verifies that identifyDnsName selects the hostname that forward-resolves to the given IP.
func Test_identifyDnsName(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		potentialHostnames []string
		expectedIp         string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 []string
	}{
		{
			name:  "invalid-ip",
			args:  args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, "invalid_ip"},
			want:  "",
			want1: []string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			name:  "empty-ip",
			args:  args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, ""},
			want:  "",
			want1: []string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			name:  "none-resolving",
			args:  args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, "10.10.10.10"},
			want:  "",
			want1: []string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			name:  "none-valid",
			args:  args{[]string{"domain.tld", "nothing", "with space", "sub.domain.tld"}, "10.10.10.10"},
			want:  "",
			want1: []string{"domain.tld", "nothing", "with space", "sub.domain.tld"},
		},
		{
			name:  "one-valid",
			args:  args{[]string{"ccc.de", "nothing", "www.ccc.de", "with space", "sub.ccc.de"}, "195.54.164.39"},
			want:  "ccc.de",
			want1: []string{"www.ccc.de", "nothing", "with space", "sub.ccc.de"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := identifyDnsName(tt.args.potentialHostnames, tt.args.expectedIp)
			if got != tt.want {
				t.Errorf("identifyDnsName() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("identifyDnsName() got1 = '%v', want1 = '%v'", got1, tt.want1)
			}
		})
	}
}

// TestAppendMissingOtHosts verifies that appendMissingOtHosts injects OT-only hosts and skips those whose MAC was
// already seen.
func TestAppendMissingOtHosts(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name      string
		hostsOt   []ot.Host
		seenMacs  map[string]struct{}
		initial   []*Host
		wantCount int
	}{
		{
			name:      "empty-ot-list",
			hostsOt:   []ot.Host{},
			seenMacs:  map[string]struct{}{},
			initial:   []*Host{},
			wantCount: 0,
		},
		{
			name:      "new-mac-appended",
			hostsOt:   []ot.Host{{MacAddress: "AA:BB:CC:DD:EE:FF", Ips: []string{"192.0.2.1"}}},
			seenMacs:  map[string]struct{}{},
			initial:   []*Host{},
			wantCount: 1,
		},
		{
			name:      "duplicate-mac-skipped",
			hostsOt:   []ot.Host{{MacAddress: "AA:BB:CC:DD:EE:FF", Ips: []string{"192.0.2.1"}}},
			seenMacs:  map[string]struct{}{"AA:BB:CC:DD:EE:FF": {}},
			initial:   []*Host{},
			wantCount: 0,
		},
		{
			name:      "empty-mac-always-appended",
			hostsOt:   []ot.Host{{MacAddress: "", Ips: []string{"192.0.2.2"}}},
			seenMacs:  map[string]struct{}{"": {}},
			initial:   []*Host{},
			wantCount: 1,
		},
		{
			name:      "identifier-falls-back-to-mac",
			hostsOt:   []ot.Host{{MacAddress: "BB:CC:DD:EE:FF:00"}},
			seenMacs:  map[string]struct{}{},
			initial:   []*Host{},
			wantCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendMissingOtHosts(testLogger, tt.hostsOt, tt.seenMacs, nil, tt.initial, nil, nil)
			if len(got) != tt.wantCount {
				t.Errorf("appendMissingOtHosts() len = '%v', want = '%v'", len(got), tt.wantCount)
			}
		})
	}

	// Verify that extra IPs from OT hosts are propagated to the injected discovery Host
	t.Run("other-ips-propagated", func(t *testing.T) {
		hostsOt := []ot.Host{{
			MacAddress: "AA:BB:CC:DD:EE:FF",
			Ips:        []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		}}
		got := appendMissingOtHosts(testLogger, hostsOt, map[string]struct{}{}, nil, []*Host{}, nil, nil)
		if len(got) != 1 {
			t.Fatalf("appendMissingOtHosts() len = %d, want 1", len(got))
		}
		if len(got[0].OtherIps) != 2 {
			t.Errorf("OtherIps len = %d, want 2", len(got[0].OtherIps))
		} else {
			if got[0].OtherIps[0] != "192.0.2.2" || got[0].OtherIps[1] != "192.0.2.3" {
				t.Errorf("OtherIps = %v, want [192.0.2.2 192.0.2.3]", got[0].OtherIps)
			}
		}
	})

	// Verify that all OT DNS names are passed through decideDnsName for sanitization and ordering.
	// OT station names (e.g. PROFINET name-of-station) typically don't resolve in DNS, so they
	// remain in OtherNames while DnsName stays empty.
	t.Run("dns-names-sanitized", func(t *testing.T) {
		hostsOt := []ot.Host{{
			MacAddress: "AA:BB:CC:DD:EE:FF",
			Ips:        []string{"192.0.2.1"},
			DnsNames:   []string{"plc-station-1", "plc-station-1.local", "alias-1"},
		}}
		got := appendMissingOtHosts(testLogger, hostsOt, map[string]struct{}{}, nil, []*Host{}, nil, nil)
		if len(got) != 1 {
			t.Fatalf("appendMissingOtHosts() len = %d, want 1", len(got))
		}
		if len(got[0].OtherNames) != 3 {
			t.Errorf("OtherNames len = %d, want 3", len(got[0].OtherNames))
		}
	})

	// Verify that when an OT host has multiple IPs and the first is already in nmap results,
	// the function picks an unseen IP as primary instead.
	t.Run("prefers-unseen-ip-as-primary", func(t *testing.T) {
		hostsOt := []ot.Host{{
			MacAddress: "AA:BB:CC:DD:EE:FF",
			Ips:        []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		}}
		seenIps := map[string]struct{}{"192.0.2.1": {}}
		got := appendMissingOtHosts(testLogger, hostsOt, map[string]struct{}{}, seenIps, []*Host{}, nil, nil)
		if len(got) != 1 {
			t.Fatalf("appendMissingOtHosts() len = %d, want 1", len(got))
		}
		if got[0].Ip != "192.0.2.2" {
			t.Errorf("Ip = %s, want 192.0.2.2 (first unseen)", got[0].Ip)
		}
		if len(got[0].OtherIps) != 2 {
			t.Errorf("OtherIps len = %d, want 2", len(got[0].OtherIps))
		}
	})

	// Verify fallback: when all IPs are already seen, Ips[0] is used as primary.
	t.Run("falls-back-to-first-ip-when-all-seen", func(t *testing.T) {
		hostsOt := []ot.Host{{
			MacAddress: "AA:BB:CC:DD:EE:FF",
			Ips:        []string{"192.0.2.1", "192.0.2.2"},
		}}
		seenIps := map[string]struct{}{"192.0.2.1": {}, "192.0.2.2": {}}
		got := appendMissingOtHosts(testLogger, hostsOt, map[string]struct{}{}, seenIps, []*Host{}, nil, nil)
		if len(got) != 1 {
			t.Fatalf("appendMissingOtHosts() len = %d, want 1", len(got))
		}
		if got[0].Ip != "192.0.2.1" {
			t.Errorf("Ip = %s, want 192.0.2.1 (fallback to first)", got[0].Ip)
		}
	})
}

// TestAllZero verifies that allZero returns true only when every byte in the slice is zero.
func TestAllZero(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    []byte
		want bool
	}{
		{
			name: "all-zeros",
			s:    []byte{0, 0, 0},
			want: true,
		},
		{
			name: "one-nonzero",
			s:    []byte{0, 1, 0},
			want: false,
		},
		{
			name: "empty-slice",
			s:    []byte{},
			want: true,
		},
		{
			name: "single-nonzero",
			s:    []byte{255},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allZero(tt.s); got != tt.want {
				t.Errorf("allZero() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestParseStringData verifies that parseStringData correctly reads numEntries and securityOffset from the header
// and collects the expected number of uint16 binding entries.
func TestParseStringData(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name           string
		data           []byte
		wantNumEntries int
		wantSecOffset  int
		wantArrayLen   int
	}{
		{
			name:           "zero-entries",
			data:           make([]byte, 16),
			wantNumEntries: 0,
			wantSecOffset:  0,
			wantArrayLen:   0,
		},
		{
			name: "one-entry",
			data: func() []byte {
				buf := make([]byte, 18)
				binary.LittleEndian.PutUint32(buf[8:12], 1)
				binary.LittleEndian.PutUint16(buf[14:16], 0)
				binary.LittleEndian.PutUint16(buf[16:18], 0xAB)
				return buf
			}(),
			wantNumEntries: 1,
			wantSecOffset:  0,
			wantArrayLen:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseStringData(tt.data)
			if got.bindingsNumEntries != tt.wantNumEntries {
				t.Errorf("parseStringData() bindingsNumEntries = '%v', want = '%v'", got.bindingsNumEntries, tt.wantNumEntries)
			}
			if got.bindingsSecurityOffset != tt.wantSecOffset {
				t.Errorf("parseStringData() bindingsSecurityOffset = '%v', want = '%v'", got.bindingsSecurityOffset, tt.wantSecOffset)
			}
			if len(got.bindingsStringArray) != tt.wantArrayLen {
				t.Errorf("parseStringData() bindingsStringArray len = '%v', want = '%v'", len(got.bindingsStringArray), tt.wantArrayLen)
			}
		})
	}
}

// TestUnique verifies that unique removes duplicate entries while preserving order.
func TestUnique(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "no-duplicates",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with-duplicates",
			input: []string{"a", "b", "a", "c", "b"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "all-same",
			input: []string{"x", "x", "x"},
			want:  []string{"x"},
		},
		{
			name:  "single-element",
			input: []string{"only"},
			want:  []string{"only"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.UniqueStrings(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unique() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
