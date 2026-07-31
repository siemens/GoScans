/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ad

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/siemens/GoScans/utils"
)

// ldapConnectGssapi establishes an LDAP connection with GSSAPI (Kerberos) authentication
func ldapConnectGssapi(
	logger utils.Logger,
	ldapAddress string,
	ldapPort int,
	ldapDomain string,
	ldapUser string,
	ldapPassword string,
	dialTimeout time.Duration,
) (*ldap.Conn, error) {

	// Lookup reachable domain controller for the given domain
	dc, errDc := cache.GetDc(logger, ldapAddress)
	if errDc != nil {
		return nil, fmt.Errorf("could not find domain controller: %v", errDc)
	}

	// Set the found domain controller as the Service Principal Name
	logger.Debugf("Setting '%s' as Service Principal Name.", dc)
	spn := dc

	// Validate required options
	if ldapDomain == "" {
		return nil, fmt.Errorf("missing kerberos realm")
	}
	defaultRealm := strings.ToUpper(ldapDomain)

	// Open a standard LDAP connection
	conn, errConn := ldap.DialURL(
		fmt.Sprintf("ldap://%s:%d", spn, ldapPort),
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
	)
	if errConn != nil {
		logger.Debugf("LDAP connection failed: %s", errConn)
		return nil, errConn
	}

	// Set timeout for the connection
	conn.SetTimeout(dialTimeout)

	// Try to upgrade to TLS
	errTls := conn.StartTLS(utils.InsecureTlsConfigFactory()) // Insecure, because this is not a user interface, we are trying to discover content...
	if errTls != nil {
		logger.Debugf("StartTLS connection failed: %s", errTls)

		// Restart the connection
		_ = conn.Close()
		conn, errConn = ldap.DialURL(
			fmt.Sprintf("ldap://%s:%d", spn, ldapPort),
			ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
		)
		if errConn != nil {
			logger.Debugf("LDAP re-connection failed: %s", errConn)
			return nil, errConn
		}
	}

	// Create GSSAPI client based on provided options
	var gssapiClient *gssapi.Client

	// Build Kerberos config
	logger.Debugf("Building Kerberos config for realm '%s'.", defaultRealm)

	// Prepare Kerberos config
	krb5Config := buildKrb5Config(logger, defaultRealm, ldapAddress)

	// Prepare Kerberos client
	krbClient := client.NewWithPassword(
		ldapUser,
		defaultRealm,
		ldapPassword,
		krb5Config,
		client.DisablePAFXFAST(true),
	)

	// Prepare GSSAPI client
	gssapiClient = &gssapi.Client{
		Client: krbClient,
	}

	// Bind using GSSAPI with mutual authentication
	errBind := conn.GSSAPIBindRequestWithAPOptions(gssapiClient, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: fmt.Sprintf("ldap/%s", spn),
		AuthZID:              "",
	}, []int{flags.APOptionMutualRequired})
	if errBind != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("GSSAPI bind error: %w", errBind)
	}

	// Return authenticated connection
	return conn, nil
}

// buildKrb5Config builds a Kerberos configuration programmatically
func buildKrb5Config(logger utils.Logger, defaultDomain string, targetDomain string) *config.Config {

	// Sanitize input
	defaultRealm := strings.ToUpper(defaultDomain) // Always use uppercase for realm
	targetRealm := strings.ToUpper(targetDomain)   // Always use uppercase for realm

	// Prepare default config
	krb5Conf := config.New()

	// LibDefaults section
	krb5Conf.LibDefaults.AllowWeakCrypto = true
	krb5Conf.LibDefaults.DefaultRealm = defaultRealm
	krb5Conf.LibDefaults.DNSLookupRealm = false
	krb5Conf.LibDefaults.DNSLookupKDC = false
	krb5Conf.LibDefaults.TicketLifetime = time.Duration(24) * time.Hour
	krb5Conf.LibDefaults.RenewLifetime = time.Duration(24*7) * time.Hour
	krb5Conf.LibDefaults.Forwardable = true
	krb5Conf.LibDefaults.Proxiable = true
	krb5Conf.LibDefaults.RDNS = false
	krb5Conf.LibDefaults.UDPPreferenceLimit = 1

	// Encryption types
	krb5Conf.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac-md5"}
	krb5Conf.LibDefaults.PermittedEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	krb5Conf.LibDefaults.PreferredPreauthTypes = []int{18, 17, 23}

	// Add default realm
	realmDomain := strings.ToLower(defaultRealm)

	// Lookup kdcs for the default realm
	kdcs, _ := cache.GetKdc(logger, defaultRealm)

	// Set config realms
	krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
		Realm:         defaultRealm,
		KDC:           kdcs,
		DefaultDomain: realmDomain,
	})

	// Set domain realm
	krb5Conf.DomainRealm["."+strings.ToLower(defaultRealm)] = strings.ToUpper(defaultRealm)

	// Add a second realm configuration if target domain differs from default realm
	if targetRealm != "" && targetRealm != defaultRealm {

		// Lookup key distribution centers for the target realm
		targetKDCs, _ := cache.GetKdc(logger, targetRealm)

		// Update config realm
		krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
			Realm:         targetRealm,
			KDC:           targetKDCs,
			DefaultDomain: strings.ToLower(targetRealm),
		})

		// Update domain realm
		krb5Conf.DomainRealm["."+strings.ToLower(targetRealm)] = strings.ToUpper(targetRealm)
	}

	// Return kerberos config
	return krb5Conf
}
