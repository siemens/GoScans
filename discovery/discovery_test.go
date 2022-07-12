/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"github.com/Ullaakut/nmap/v2"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/discovery/active_directory"
	"github.com/siemens/GoScans/utils"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

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

func TestCheckSetup(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		nmapDir string
		nmap    string
		wantErr bool
	}{
		{"invalid", "notexisting.exe", "notexistingDir", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckSetup(tt.nmapDir, tt.nmap); (err != nil) != tt.wantErr {
				t.Errorf("CheckSetup() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestSetup(t *testing.T) {

	// Retrieve test settings
	testLogger := utils.NewTestLogger()
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare and run test cases
	tests := []struct {
		name    string
		nmapDir string
		nmap    string
		wantErr bool
	}{
		{"invalid-privileges", testSettings.PathNmapDir, testSettings.PathNmap, true}, // throws error without admin process privileges
		{"invalid-dir", testSettings.PathNmapDir, "notexistingDir", true},
		{"invalid-exe", "notexisting.exe", testSettings.PathNmap, true},
		{"invalid-all", "notexisting.exe", "notexistingDir", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Setup(testLogger, tt.nmapDir, tt.nmap); (err != nil) != tt.wantErr {
				t.Errorf("Setup() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	nmapBlacklist := []string{"20.20.20.2", "10.10.10.1"}
	nmapBlacklistFile := filepath.Join(testSettings.PathDataDir, "discovery", "blacklist_valid.txt")
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
		{"valid-basic", args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, false},
		{"valid-no-args", args{testLogger, testTarget, testSettings.PathNmap, []string{}, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, false},
		{"valid-no-versionall", args{testLogger, testTarget, testSettings.PathNmap, testArgs, false, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, false},
		{"valid-ldap-url", args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "https://sub.domain.tld", "", "", ""}, false},
		{"invalid-ldap-url", args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "sub.domain.tld", "", "", ""}, true},
		{"invalid-blacklist-path", args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, "notexisting", "", "", "", ""}, true},
		{"invalid-target1", args{testLogger, "", testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, true},
		{"invalid-target2", args{testLogger, "invalid input", testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, true},
		{"invalid-nmap", args{testLogger, testTarget, "notexisting", testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "", "", ""}, true},
		{"invalid-credentials-set", args{testLogger, testTarget, testSettings.PathNmap, testArgs, true, nmapBlacklist, nmapBlacklistFile, "", "some.domain", "", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(tt.args.logger, []string{tt.args.target}, tt.args.nmap, tt.args.nmapParameters, tt.args.nmapVersionAll, tt.args.nmapBlacklist, tt.args.nmapBlacklistFile, []string{}, tt.args.ldapServer, tt.args.ldapDomain, tt.args.ldapUser, tt.args.ldapPassword, dialTimeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

func TestExtractHostData(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, err := ioutil.ReadFile(nmapXml)
	if err != nil {
		t.Errorf("Rading Nmap sample result failed: %s", err)
	}

	// Parse Nmap result
	scanResult, err := nmap.Parse(in)
	if err != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", err)
	}

	// Some location in the CET timezone
	location, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Errorf("could not load location for test: %s", err)
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
			"valid",
			scanResult.Hosts[0],
			[]string{"host123.sub.domain.tld", "HOST123.sub.domain.tld"},
			[]string{},
			[]string{"96% Microsoft Windows 7 SP1", "92% Microsoft Windows 8.1 Update 1", "92% Microsoft Windows Phone 7.5 or 8.0", "91% Microsoft Windows 7 or Windows Server 2008 R2", "91% Microsoft Windows Server 2008 R2", "91% Microsoft Windows Server 2008 R2 or Windows 8.1", "91% Microsoft Windows Server 2008 R2 SP1 or Windows 8", "91% Microsoft Windows 7", "91% Microsoft Windows 7 Professional or Windows 8", "91% Microsoft Windows 7 SP1 or Windows Server 2008 R2"},
			time.Date(2019, 02, 21, 15, 32, 49, 0, location),
			time.Second * 20776,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, got3, got4 := extractHostData(tt.h)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractHostData() = '%v', want = '%v'", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("extractHostData() got3 = '%v', want3 = '%v'", got3, tt.want3)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractHostData() got1 = '%v', want1 = '%v'", got1, tt.want1)
			}
			if !reflect.DeepEqual(got3, tt.want3) {
				t.Errorf("extractHostData() got2 = '%v', want2 = '%v'", got2, tt.want2)
			}
			if !reflect.DeepEqual(got4, tt.want4) {
				t.Errorf("extractHostData() got3 = '%v', want3 = '%v'", got3, tt.want3)
			}
		})
	}
}

func TestExtractPortData(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, err := ioutil.ReadFile(nmapXml)
	if err != nil {
		t.Errorf("Rading Nmap sample result failed: %s", err)
	}

	// Parse Nmap result
	scanResult, err := nmap.Parse(in)
	if err != nil {
		t.Errorf("Parsing Nmap sample result failed: %s", err)
	}

	// Define expected read data
	services := []Service{
		{
			445,
			"tcp",
			"microsoft-ds",
			"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds",
			"",
			"",
			"Windows",
			"",
			[]string{"cpe:/o:microsoft:windows"},
			"workgroup: SUB",
			"probed",
			118,
		},
		{
			3389,
			"tcp",
			"ms-wbt-server",
			"",
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
		{"valid", scanResult.Hosts[0].Ports, services, []string{"HOST123"}},
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

func TestExtractHostScriptData(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errRead := ioutil.ReadFile(nmapXml)
	if errRead != nil {
		t.Errorf("Rading Nmap sample result failed: %s", errRead)
	}

	// Parse Nmap result
	scanResult, errParse := nmap.Parse(in)
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
		want        []string
		want1       string
		want2       []Script
	}{
		{"valid", scanResult.Hosts[0].HostScripts, []string{"HOST123.sub.domain.tld"}, "Windows 7 Enterprise 7601 Service Pack 1", scripts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := extractHostScriptData(tt.hostScripts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractHostScriptData() = '%v', want = '%v'", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("extractHostScriptData() got1 = '%v', want = '%v'", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractHostScriptData() got2 = '%v', want = '%v'", got2, tt.want2)
			}
		})
	}
}

func TestExtractPortScriptData(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	nmapXml := filepath.Join(testSettings.PathDataDir, "discovery", "host123.domain.tld.xml")

	// Read Nmap result form file
	in, errRead := ioutil.ReadFile(nmapXml)
	if errRead != nil {
		t.Errorf("Rading Nmap sample result failed: %s", errRead)
	}

	// Parse Nmap result
	scanResult, errParse := nmap.Parse(in)
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
		want  []string
		want1 []int
		want2 []Script
	}{
		{"valid", scanResult.Hosts[0].Ports, []string{"HOST123.sub.domain.tld"}, []int{3389}, scripts},
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

func TestPostprocessingSubmit(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	timeout := 10 * time.Second
	want := 5
	taskCnt := 0
	hPorts := make(map[string][]int)
	hPorts["127.0.0.1"] = []int{}
	hPorts["127.0.0.2"] = []int{443}
	hPorts["127.0.0.3"] = []int{443, 3389}
	hData := []Host{
		{
			"127.0.0.1",
			"localhost",
			[]string{"local"},
			[]string{},
			[]string{"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds"},
			"",
			time.Now().Add(timeout),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
		{
			"127.0.0.2",
			"localhost2",
			[]string{"local2"},
			[]string{},
			[]string{"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds"},
			"",
			time.Now().Add(timeout),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
		{
			"127.0.0.3",
			"localhost3",
			[]string{"local3"},
			[]string{},
			[]string{""},
			"",
			time.Now().Add(timeout),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
	}

	// Prepare slots and return channels
	chThrottleUser := make(chan struct{}, 20)
	chThrottleSans := make(chan struct{}, 50)
	chThrottleDns := make(chan struct{}, 20)
	chDoneUsers := make(chan *Host)
	chDoneSans := make(chan *Host)
	chDoneDns := make(chan *Host)

	// Submit data
	for _, h := range hData {
		taskCnt = postprocessingSubmit(
			testLogger,
			taskCnt,
			&h,
			[]string{},
			hPorts[h.Ip],
			dialTimeout,
			chThrottleUser,
			chThrottleSans,
			chThrottleDns,
			chDoneUsers,
			chDoneSans,
			chDoneDns,
		)
	}

	// Validate expected state
	if taskCnt != want {
		t.Errorf("postprocessingSubmit() = '%v', want = '%v'", taskCnt, want)
	}

	// Wait for expected results. If something went unepxected, this will block
	chToBeRead := []chan *Host{chDoneUsers, chDoneUsers, chDoneSans, chDoneSans, chDoneDns}
	if len(chToBeRead) != want {
		t.Errorf("postprocessingSubmit() %v results will be read, want = '%v'", len(chToBeRead), want)
	}
	for _, ch := range chToBeRead {
		<-ch
	}

	// Check if all channels are empty, as they should be now
	select {
	case _ = <-chDoneUsers:
		t.Errorf("postprocessingSubmit() User done channel not empty!")
	case _ = <-chDoneSans:
		t.Errorf("postprocessingSubmit() SANS done channel not empty!")
	case _ = <-chDoneDns:
		t.Errorf("postprocessingSubmit() DNS done channel not empty!")
	default:
	}
}

func TestPostprocessingComplete(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	dialTimeout := 5 * time.Second
	taskCnt := 0
	hPorts := make(map[string][]int)
	hPorts["127.0.0.1"] = []int{}
	hPorts["127.0.0.2"] = []int{443}
	hPorts["127.0.0.3"] = []int{443, 3389}
	hData := []Host{
		{
			"127.0.0.1",
			"localhost",
			[]string{"local"},
			[]string{},
			[]string{"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds"},
			"",
			time.Now(),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
		{
			"127.0.0.2",
			"localhost2",
			[]string{"local2"},
			[]string{},
			[]string{"Windows 7 Enterprise 7601 Service Pack 1 microsoft-ds"},
			"",
			time.Now(),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
		{
			"127.0.0.3",
			"localhost3",
			[]string{"local3"},
			[]string{},
			[]string{""},
			"",
			time.Now(),
			time.Minute,
			"",
			[]string{},
			[]string{},
			[]Service{},
			[]Script{},
			&active_directory.Ad{},
		},
	}

	// Prepare slots and return channels
	chThrottleUser := make(chan struct{}, 20)
	chThrottleSans := make(chan struct{}, 50)
	chThrottleDns := make(chan struct{}, 20)
	chDoneUsers := make(chan *Host)
	chDoneSans := make(chan *Host)
	chDoneDns := make(chan *Host)

	// Submit data
	for _, h := range hData {
		taskCnt = postprocessingSubmit(
			testLogger,
			taskCnt,
			&h,
			[]string{},
			hPorts[h.Ip],
			dialTimeout,
			chThrottleUser,
			chThrottleSans,
			chThrottleDns,
			chDoneUsers,
			chDoneSans,
			chDoneDns,
		)
	}

	// Check if postprocessing finishes
	postprocessingComplete(
		testLogger,
		&ldapConf{},
		taskCnt,
		[]string{},
		dialTimeout,
		chThrottleDns,
		chDoneUsers,
		chDoneSans,
		chDoneDns,
	)
}

func TestDecideDnsName(t *testing.T) {

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
		{"domain-valid-forward", args{&Host{Ip: "195.54.164.39", OtherNames: []string{"*.domain.tld", "ccc.de", "notexisting"}}, make(chan struct{}, 1), make(chan *Host)}, "ccc.de", []string{"domain.tld", "wildcard.domain.tld", "notexisting"}},
		{"domain-invalid", args{&Host{Ip: "192.168.0.1", OtherNames: []string{"*.domain.tld", "www.cert.domain.tld", "cert.domain.tld", "notexisting"}}, make(chan struct{}, 1), make(chan *Host)}, "", []string{"domain.tld", "cert.domain.tld", "wildcard.domain.tld", "www.cert.domain.tld", "notexisting"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Launch function asynchronously
			go decideDnsName(tt.args.hData, []string{}, tt.args.chThrottle, tt.args.chResults)

			// Check result sent via channel
			select {
			case updatedHost := <-tt.args.chResults:
				if !reflect.DeepEqual(updatedHost.DnsName, tt.want) {
					t.Errorf("decideDnsName() DNS Name = '%v', want = '%v'", updatedHost.DnsName, tt.want)
				}
				if !reflect.DeepEqual(updatedHost.OtherNames, tt.want2) {
					t.Errorf("decideDnsName() Other Names = '%v', want2 = '%v'", updatedHost.OtherNames, tt.want2)
				}
			}
		})
	}
}

func Test_sanitizeDnsNames(t *testing.T) {
	input := []string{"sub1.cert.domain.tld", "sub2.domain.tld", "SuB2.domain.tld", "nothing", "A", "sub.domain.tld", "", "", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "1::", "*.sub.domain.tld"}
	output := []string{"sub1.cert.domain.tld", "sub2.domain.tld", "nothing", "a", "sub.domain.tld", "wildcard.sub.domain.tld"}

	// Prepare and run test cases
	tests := []struct {
		name      string
		hostnames []string
		want      []string
	}{
		{"test1", input, output},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeDnsNames(tt.hostnames); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sanitizeDnsNames() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

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
		"some4life.de", "host.google.com", "host.some.com", "some.geocities.com", "some.hosting.com",
		"anythingelse",
	}

	// Prepare and run test cases
	tests := []struct {
		name      string
		hostnames []string
		want      []string
	}{
		{"disorder0", utils.Shuffle([]string{"forrest1.domain.local", "host.forrest1.domain.local"}), []string{"forrest1.domain.local", "host.forrest1.domain.local"}},
		{"disorder1", utils.Shuffle([]string{"host.forrest1.domain.local", "domain.local"}), []string{"host.forrest1.domain.local", "domain.local"}},
		{"disorder2", utils.Shuffle([]string{"domain.local", "forrest2.domain.local"}), []string{"domain.local", "forrest2.domain.local"}},
		{"disorder3", utils.Shuffle([]string{"forrest2.domain.local", "forrest3.domain.local"}), []string{"forrest2.domain.local", "forrest3.domain.local"}},
		{"disorder4", utils.Shuffle([]string{"forrest3.domain.local", "host.forrest3.domain.local"}), []string{"forrest3.domain.local", "host.forrest3.domain.local"}},
		{"disorder5", utils.Shuffle([]string{"host.forrest3.domain.local", "other.local"}), []string{"host.forrest3.domain.local", "other.local"}},
		{"disorder6", utils.Shuffle([]string{"other.local", "host.other.local"}), []string{"other.local", "host.other.local"}},
		{"disorder7", utils.Shuffle([]string{"host.other.local", "host.third-party.com"}), []string{"host.other.local", "host.third-party.com"}},
		{"disorder8", utils.Shuffle([]string{"host.third-party.com", "g.com"}), []string{"host.third-party.com", "g.com"}},
		{"disorder9", utils.Shuffle([]string{"g.com", "google.com"}), []string{"g.com", "google.com"}},
		{"disorder10", utils.Shuffle([]string{"google.com", "some.com"}), []string{"google.com", "some.com"}},
		{"disorder11", utils.Shuffle([]string{"some.com", "some.de"}), []string{"some.com", "some.de"}},
		{"disorder12", utils.Shuffle([]string{"some.de", "some4life.de"}), []string{"some.de", "some4life.de"}},
		{"disorder13", utils.Shuffle([]string{"some4life.de", "host.google.com"}), []string{"some4life.de", "host.google.com"}},
		{"disorder14", utils.Shuffle([]string{"host.google.com", "host.some.com"}), []string{"host.google.com", "host.some.com"}},
		{"disorder15", utils.Shuffle([]string{"host.some.com", "some.geocities.com"}), []string{"host.some.com", "some.geocities.com"}},
		{"disorder16", utils.Shuffle([]string{"some.geocities.com", "some.hosting.com"}), []string{"some.geocities.com", "some.hosting.com"}},
		{"disorder17", utils.Shuffle([]string{"some.hosting.com", "anythingelse"}), []string{"some.hosting.com", "anythingelse"}},
		{"disorder18", utils.Shuffle(order), order},
		{"disorder19", utils.Shuffle([]string{"localhost", "hostname", "domain.com", "some.hosting.com", "anythingelse"}), []string{"domain.com", "some.hosting.com", "anythingelse", "hostname", "localhost"}},

		// Prefer FQDNs over incomplete hostnames
		{"disorder20", []string{"hostname", "hostname.domain.tld"}, []string{"hostname.domain.tld", "hostname"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orderDnsNames(tt.hostnames, domainOrder); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("orderDnsNames() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

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
			"invalid-ip",
			args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, "invalid_ip"},
			"",
			[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			"empty-ip",
			args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, ""},
			"",
			[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			"none-resolving",
			args{[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"}, "10.10.10.10"},
			"",
			[]string{"something-not-existing.com", "nothing", "with space", "something-not-existing.domain.tld"},
		},
		{
			"none-valid",
			args{[]string{"domain.tld", "nothing", "with space", "sub.domain.tld"}, "10.10.10.10"},
			"",
			[]string{"domain.tld", "nothing", "with space", "sub.domain.tld"},
		},
		{
			"one-valid",
			args{[]string{"ccc.de", "nothing", "www.ccc.de", "with space", "sub.ccc.de"}, "195.54.164.39"},
			"ccc.de",
			[]string{"www.ccc.de", "nothing", "with space", "sub.ccc.de"},
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
