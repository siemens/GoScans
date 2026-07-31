/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package ad provides Active Directory and LDAP query capabilities for host discovery.
package ad

import (
	"strings"
	"time"
)

// Ad holds Active Directory attributes retrieved for a computer object.
type Ad struct {
	Name                 string    `ldap:"name"`
	DistinguishedName    string    `ldap:"distinguishedName"`
	DnsName              string    `ldap:"dNSHostName"`
	Created              time.Time `ldap:"whenCreated"`
	LastLogon            time.Time `ldap:"lastLogon"`
	LastPassword         time.Time `ldap:"pwdLastSet"`
	Description          []string  `ldap:"description"`
	Location             string    `ldap:"location"`
	ManagedBy            string    `ldap:"managedBy"`   // This is returned by the computer object and used to query the related user
	ManagedByCn          string    `ldap:"cn"`          // This is obtained by a second query for the managedBy user
	ManagedByGid         string    `ldap:"siemens-gid"` // This is obtained by a second query for the managedBy user
	ManagedByDepartment  string    `ldap:"department"`  // This is obtained by a second query for the managedBy user
	Os                   string    `ldap:"operatingSystem"`
	OsVersion            string    `ldap:"operatingSystemVersion"`
	ServicePrincipalName []string  `ldap:"servicePrincipalName"`
	CriticalObject       bool      `ldap:"isCriticalSystemObject"`
}

// fqdnToDn converts a fully qualified domain name into an LDAP distinguished name.
// For example, "sub.domain.tld" becomes "dc=sub,dc=domain,dc=tld".
func fqdnToDn(fqdn string) string {
	splits := strings.Split(fqdn, ".")
	baseDn := "dc=" + strings.Join(splits, ",dc=")
	return baseDn
}

// parseDn parses a distinguished name into its domain address, common name, and base DN components.
func parseDn(dn string) (string, string, string) {

	// Split distinguished name into its segments
	dnSplits := dnSplit(dn) // cn=name,ou=department,dc=sub,dc=domain,dc=tld => ["cn=name", "ou=department", "dc=sub", "dc=domain", "dc=tld"]

	// Extract domain segments with stripped "dc=" prefixes
	var domainSegments []string
	for _, element := range dnSplits {
		element = strings.ToLower(element)
		element = strings.Trim(element, "\n")
		if strings.HasPrefix(element, "dc=") {
			element = strings.Replace(element, "dc=", "", -1) // Strip dc= prefixes
			domainSegments = append(domainSegments, element)
		}
	}

	// Prepare target domain and target DN
	newLdapAddress := strings.Join(domainSegments, ".")
	newSearchCn := dnSplits[0][3:len(dnSplits[0])]
	newBaseDn := "dc=" + strings.Join(domainSegments, ",dc=")

	// Return values
	return newLdapAddress, newSearchCn, newBaseDn
}

// dnSplit splits a distinguished name (e.g. cn=host,dc=sub,dc=domain,dc=tld) into its elements (e.g.
// ["cn=host", "dc=sub", "dc=domain", "dc=tld"]
func dnSplit(dn string) []string {

	// Define control characters
	delimiter := ","
	escapeChar := "\\"

	// Prepare result
	var splitPositions []int

	// Find positions to split distinguished name at
	prevChar := ""
	for i, char := range dn {
		if string(char) == delimiter && prevChar != escapeChar {
			splitPositions = append(splitPositions, i)
		}
		prevChar = string(char)
	}

	// Split distinguished name at found positions
	var elements []string
	currentPos := -1
	for _, marker := range splitPositions {
		element := dn[currentPos+1 : marker]
		element = strings.Replace(element, "\\,", ",", -1)
		elements = append(elements, element)
		currentPos = marker
	}

	// Append remaining string
	element := dn[currentPos+1:]
	element = strings.Replace(element, "\\,", ",", -1)
	elements = append(elements, element)

	// Return elements
	return elements
}

// Integer8ToTime converts a Windows FILETIME integer (100-nanosecond intervals since 1601-01-01) to a time.Time.
func Integer8ToTime(val int64) time.Time {

	// Translate to seconds
	s := int(val / 10000000)

	// Add seconds to int8 start date
	timestamp := time.Date(1601, 1, 1, 0, 0, s, 0, time.UTC)

	// Return timestamp
	return timestamp
}

// GeneralizedTimeToTime parses an LDAP GeneralizedTime string into a time.Time value.
func GeneralizedTimeToTime(val string) (time.Time, error) {

	// Parse timestamp
	timestamp, errTimestamp := time.Parse("20060102150405Z0700", val)
	if errTimestamp != nil {
		return time.Time{}, errTimestamp
	}

	// Return timestamp
	return timestamp, nil
}
