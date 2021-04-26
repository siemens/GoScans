/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package active_directory

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"go-scans/utils"
	"net"
	"strconv"
	"strings"
	"time"
)

// LdapQuery queries the given Active Directory service with explicit authentication and returns a pointer to
// a populated Ad struct.
// ATTENTION: Make sure searchCn / ldapAddress are sanitized if taken from user input, to avoid SQL injection attacks!
func LdapQuery(
	logger utils.Logger,
	searchCn string,
	ldapAddress string,
	ldapPort int,
	ldapUser string,
	ldapPassword string,
	dialTimeout time.Duration,
) *Ad {

	logger.Debugf("Searching LDAP with explicit authentication for '%s'.", searchCn)

	// Connect to Active Directory
	conn, errConn := ldapConnect(logger, ldapAddress, ldapPort, ldapUser, ldapPassword, dialTimeout)
	if errConn != nil {
		logger.Debugf("LDAP connection to '%s:%d' failed: %s", ldapAddress, ldapPort, errConn)
		return &Ad{}
	} else {
		logger.Debugf("LDAP connection to '%s:%d' succeeded.", ldapAddress, ldapPort)
	}

	// Make sure connection is closed on exit
	defer conn.Close()

	// Convert domain name into distinguished name
	baseDn := fqdnToDn(ldapAddress)

	// Prepare search
	logger.Debugf("LDAP searching for computer '%s' in '%s'.", searchCn, ldapAddress)
	computerSearch := ldap.NewSearchRequest(
		baseDn, // The base dn to search
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=computer)(cn=%s))", searchCn), // The filter to apply
		[]string{
			"name", "distinguishedName", "dNSHostName", "description", "whenCreated", "managedBy", "lastLogon",
			"pwdLastSet", "location", "operatingSystem", "operatingSystemServicePack", "operatingSystemVersion",
			"servicePrincipalName", "isCriticalSystemObject",
		},
		nil,
	)

	// Execute search
	computerResult, errComputerSearch := conn.Search(computerSearch)
	if errComputerSearch != nil {
		logger.Debugf("LDAP search for computer '%s' in '%s' failed: %s", searchCn, ldapAddress, errComputerSearch)
		return &Ad{}
	}

	// Check for result
	if len(computerResult.Entries) == 0 {
		logger.Debugf("LDAP search for computer '%s' in '%s' did not return result.", searchCn, ldapAddress)
		return &Ad{}
	} else if len(computerResult.Entries) > 1 {
		logger.Warningf("LDAP search for computer '%s' in '%s' returned ambiguous results.", searchCn, ldapAddress)
		return &Ad{}
	}

	// Prepare result variables
	var created time.Time
	var lastLogon time.Time
	var lastPassword time.Time
	var criticalObject bool

	// Take first result
	entry := computerResult.Entries[0]

	// Parse special values
	var err error
	val := entry.GetAttributeValue("lastLogon")
	if len(val) > 0 {

		// Parse int64 from string and convert to time.time
		lastLogonInt8, errLastLogon := strconv.ParseInt(val, 10, 64)
		if errLastLogon != nil {
			logger.Errorf("Could not parse Integer8 '%s': %s", val, errLastLogon)
		} else {
			lastLogon = Integer8ToTime(lastLogonInt8)
		}
	}
	val = entry.GetAttributeValue("pwdLastSet")
	if len(val) > 0 {

		// Parse int64 from string and convert to time.time
		pwdLastSetInt8, errPwdLastSet := strconv.ParseInt(val, 10, 64)
		if errPwdLastSet != nil {
			logger.Errorf("Could not parse Integer8 '%s': %s", val, errPwdLastSet)
		} else {
			lastPassword = Integer8ToTime(pwdLastSetInt8)
		}
	}
	val = entry.GetAttributeValue("whenCreated")
	if len(val) > 0 {
		created, err = GeneralizedTimeToTime(val)
		if err != nil {
			logger.Errorf(
				"Could not parse GeneralizedTime '%s': %s", val, err)
		}
	}
	val = entry.GetAttributeValue("isCriticalSystemObject")
	if len(val) > 0 {
		criticalObject, err = strconv.ParseBool(val)
		if err != nil {
			logger.Errorf(
				"Could not parse boolean '%s': %s", val, err)
		}
	}

	// Read managedBy attribute, which will be used later to query user object
	managedBy := entry.GetAttributeValue("managedBy")

	// Prepare first result struct
	result := Ad{
		Name:                 entry.GetAttributeValue("name"),
		DistinguishedName:    entry.GetAttributeValue("distinguishedName"),
		DnsName:              entry.GetAttributeValue("dNSHostName"),
		Created:              created,
		LastLogon:            lastLogon,
		LastPassword:         lastPassword,
		Description:          entry.GetAttributeValues("description"),
		Location:             entry.GetAttributeValue("location"),
		ManagedBy:            managedBy,
		Os:                   entry.GetAttributeValue("operatingSystem"),
		OsServicePack:        entry.GetAttributeValue("operatingSystemServicePack"),
		OsVersion:            entry.GetAttributeValue("operatingSystemVersion"),
		ServicePrincipalName: entry.GetAttributeValues("servicePrincipalName"),
		CriticalObject:       criticalObject,
	}

	// Execute user query, if managedBy is set
	if len(managedBy) > 6 { // > 6 because there must be 'CN=' and 'DC=' at least
		ldapExpand(logger, conn, ldapAddress, ldapPort, ldapUser, ldapPassword, dialTimeout, &result)
	}

	// Return filled AD struct
	return &result
}

// ldapExpand enriches the AD result struct with user data retrieved via a second LDAP query
func ldapExpand(
	logger utils.Logger,
	conn *ldap.Conn,
	ldapAddress string,
	ldapPort int,
	ldapUser string,
	ldapPassword string,
	dialTimeout time.Duration,
	result *Ad,
) {
	// Prepare temporary vars
	var errConn error

	// Translate managedBy DN into new ldap address, search CN and base DN
	newLdapAddress, newSearchCn, newBaseDn := parseDn(result.ManagedBy)

	// Connect to new domain controller, if necessary
	if newLdapAddress != ldapAddress {

		// Close old LDAP connection
		conn.Close()

		// Connect to Active Directory
		conn, errConn = ldapConnect(logger, newLdapAddress, ldapPort, ldapUser, ldapPassword, dialTimeout)
		if errConn != nil {
			logger.Debugf("LDAP connection to '%s:%d' failed: %s", newLdapAddress, ldapPort, errConn)
			return
		} else {
			logger.Debugf("LDAP connection to '%s:%d' succeeded.", newLdapAddress, ldapPort)
		}

		// Make sure connection is closed on exit
		defer conn.Close()
	}

	// Prepare search
	logger.Debugf("LDAP searching for user '%s' in '%s'.", newSearchCn, newLdapAddress)
	userSearch := ldap.NewSearchRequest(
		newBaseDn, // The base dn to search
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=user)(cn=%s))", newSearchCn), // The filter to apply
		[]string{
			"cn", "department", "siemens-gid",
		},
		nil,
	)

	// Execute search
	userResult, errUserSearch := conn.Search(userSearch)
	if errUserSearch != nil {
		logger.Warningf(
			"LDAP search for user '%s' in '%s' failed: %s", newSearchCn, newLdapAddress, errUserSearch)
		return

	}

	// Check for result
	if len(userResult.Entries) == 0 {
		logger.Debugf("LDAP search for user '%s' in '%s' did not return results.", newSearchCn, newLdapAddress)
		return
	} else if len(userResult.Entries) > 1 {
		logger.Warningf(
			"LDAP search for user '%s' in '%s' returned ambiguous results.", newSearchCn, newLdapAddress)
		return
	}

	// Read standard values and add them to result struct
	result.ManagedByCn = userResult.Entries[0].GetAttributeValue("cn")
	result.ManagedByGid = userResult.Entries[0].GetAttributeValue("siemens-gid")
	result.ManagedByDepartment = userResult.Entries[0].GetAttributeValue("department")
}

// ldapConnect establishes an LDAP connection to an Active Directory service
func ldapConnect(
	logger utils.Logger,
	ldapAddress string,
	ldapPort int,
	ldapUser string,
	ldapPassword string,
	dialTimeout time.Duration,
) (*ldap.Conn, error) {

	// Prepare the ldap url by trimming any protocol specifications.
	baseUrl := strings.TrimPrefix(ldapAddress, "ldap://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldaps://")
	baseUrl = strings.TrimPrefix(baseUrl, "ldapi://")

	// Prepare the ldap options - namely the timeout.
	opts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}), // DialWithDialer updates net.Dialer in DialContext.
	}

	// First of try to establish an ldaps connection right away.
	conn, errDialS := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", baseUrl, ldapPort), opts...)
	if errDialS != nil {
		logger.Debugf("LDAPS connection to '%s:%d' failed: %s", ldapAddress, ldapPort, errDialS)

		// Try to establish a normal ldap connection
		var errDial error
		conn, errDial = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", baseUrl, ldapPort), opts...)
		if errDial != nil {
			logger.Debugf("LDAP connection to '%s:%d' failed: %s", ldapAddress, ldapPort, errDial)
			return nil, fmt.Errorf("neither LDAP nor LDAPS connection accepted")
		}

		// Try to upgrade to TLS
		errTls := conn.StartTLS(utils.InsecureTlsConfigFactory()) // Insecure, because this is not a user interface, we are trying to discover content...
		if errTls != nil {
			logger.Debugf("StartTLS connection to '%s:%d' failed: %s", ldapAddress, ldapPort, errTls)
		}
	}

	// Bind LDAP connection, with authentication if available, without otherwise
	if len(ldapUser) > 0 && len(ldapPassword) > 0 {
		errBind := conn.Bind(ldapUser, ldapPassword)
		if errBind != nil {
			conn.Close()
			return nil, fmt.Errorf("authenticated bind error: %s", errBind)
		}
	} else {
		errAuth := conn.UnauthenticatedBind("anonymous")
		if errAuth != nil {
			conn.Close()
			return nil, fmt.Errorf("bind error: %s", errAuth)
		}
	}

	// Return connection
	return conn, nil
}
