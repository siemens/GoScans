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
	"database/sql"
	"github.com/go-ole/go-ole"
	_ "github.com/mattn/go-adodb"
	"github.com/siemens/GoScans/utils"
	"math"
	"reflect"
	"time"
)

// AdodbQuery queries the given Active Directory service with implicit Windows authentication and returns a
// pointer to a populated Ad struct.
// ATTENTION: Make sure searchCn / ldapAddress are sanitized if taken from user input, to avoid SQL injection attacks!
func AdodbQuery(logger utils.Logger, searchCn string, searchDomain string) *Ad {

	logger.Debugf("Searching ADODB with implicit authentication for '%s'.", searchCn)

	// Prepare ADODB connection
	adDb, errOpen := sql.Open("adodb", `Provider=ADSDSOObject`)
	if errOpen != nil {
		logger.Debugf("ADODB connection failed: %s", errOpen)
		return &Ad{}
	}

	// Make ADODB connection is closed on exit
	defer func() { _ = adDb.Close() }()

	// Convert domain name into distinguished name
	baseDn := fqdnToDn(searchDomain)

	// Execute search
	logger.Debugf("ADODB searching for computer '%s' in '%s'.", searchCn, searchDomain)
	computerResult, errComputerResult := adDb.Query(`SELECT name, distinguishedName, dNSHostName, description, 
		whenCreated, managedBy, lastLogon, pwdLastSet, location, operatingSystem, operatingSystemServicePack, 
		operatingSystemVersion, servicePrincipalName, isCriticalSystemObject 
		FROM 'LDAP://` + searchDomain + `/` + baseDn + `' 
		WHERE objectCategory = 'Computer' AND cn = '` + searchCn + `'`)
	if errComputerResult != nil {
		logger.Debugf("ADODB search for computer '%s' in '%s' failed: %s", searchCn, searchDomain, errComputerResult)
		return &Ad{}
	}

	// Make sure query gets closed on exit
	defer func() { _ = computerResult.Close() }()

	// Prepare result
	result := Ad{}

	// Fill up structure from the result
	for computerResult.Next() {

		// Populate search result into AD struct
		errPopulateComputer := adodbPopulate(&result, computerResult)
		if errPopulateComputer != nil {
			logger.Errorf(
				"ADODB search result for computer '%s:%s' could not be parsed: %s",
				searchCn,
				searchDomain,
				errPopulateComputer,
			)
			return &result
		}

		// Break as there is only a single result expected
		break
	}

	// Execute user query, if managedBy is set
	if len(result.ManagedBy) > 6 { // > 6 because there must be 'CN=' and 'DC=' at least
		adodbExpand(logger, adDb, &result)
	}

	// Prepare return data
	return &result
}

// adodbExpand enriches the AD result struct with user data retrieved via a second ADODB query
func adodbExpand(logger utils.Logger, adDb *sql.DB, result *Ad) {

	// Translate ManagedBy (distinguished name) into new ldap address, search CN and base DN
	newLdapAddress, newSearchCn, newBaseDn := parseDn(result.ManagedBy)

	// Execute search
	logger.Debugf("ADODB searching for user '%s' in '%s'.", newSearchCn, newLdapAddress)
	userResult, errUserSearch := adDb.Query(`SELECT cn, department, siemens-gid
		FROM 'LDAP://` + newLdapAddress + `/` + newBaseDn + `' 
		WHERE objectCategory = 'User' AND cn = '` + newSearchCn + `'`)
	if errUserSearch != nil {
		logger.Warningf("ADODB search for user '%s' in '%s' failed: %s", newSearchCn, newLdapAddress, errUserSearch)
		return
	}

	// Make sure query gets closed on exit
	defer func() { _ = userResult.Close() }()

	// Fill up structure from the result
	for userResult.Next() {

		// Populate search result into AD struct
		errPopulateUser := adodbPopulate(result, userResult)
		if errPopulateUser != nil {
			logger.Errorf(
				"ADODB search result for user '%s\\%s' could not be parsed: %s",
				newLdapAddress,
				newSearchCn,
				errPopulateUser,
			)
			return
		}

		// Break as there is only a single result expected
		break
	}
}

func isNil(v interface{}) bool {
	return v == nil || (reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil())
}

// adodbPopulate fills a referenced result object with results from the ADODB search
func adodbPopulate(result *Ad, sqlResult *sql.Rows) error {

	// Read column types
	columns, errC := sqlResult.ColumnTypes()
	if errC != nil {
		return errC
	}

	// Prepare temporary (type independent) slice where query results will be written to
	values := make([]interface{}, len(columns))

	// Prepare map of name<->index in values array. For some reason, results will be returned in reverse order.
	names := map[string]int{}

	// Init the arrays
	for i, column := range columns {
		values[i] = new(interface{}) // Init value slot
		names[column.Name()] = i     // Remember position of column
	}

	// Read query results and write them into values slice
	errS := sqlResult.Scan(values...)
	if errS != nil {
		return errS
	}

	// Enumerate the result structure attributes in order to fill each one with the appropriate value from the
	// temporary type independent values slice.
	t := reflect.TypeOf(*result)
	for i := 0; i < t.NumField(); i++ {

		// Get the attribute, returns https://golang.org/pkg/reflect/#StructField
		attr := t.Field(i)

		// Get the attribute's tag value
		tag := attr.Tag.Get("ldap")

		// No tag defined
		if len(tag) == 0 {
			continue
		}

		// Check if the tag exists in the columns map
		index, exists := names[tag]
		if !exists {
			continue
		}

		// Get the value from search results array which is an array of interfaces to other *interfaces
		val := values[index]

		//  Cast back *interface
		v := val.(*interface{})

		// Check for null values ... for null no data is copied
		if isNil(*v) {
			continue
		}

		// Get the underlying value from *interface
		s := reflect.ValueOf(*v)

		// Save to Ad structure for known types
		switch s.Interface().(type) {
		case bool:
			reflect.ValueOf(result).Elem().Field(i).SetBool(s.Interface().(bool))

		case string:
			reflect.ValueOf(result).Elem().Field(i).SetString(s.Interface().(string))

		case time.Time:
			reflect.ValueOf(result).Elem().Field(i).Set(reflect.ValueOf(s.Interface().(time.Time)))

		case *ole.VARIANT:

			// Cast from interface to *variant type
			vt := (*v).(*ole.VARIANT)

			// Check if variant its an array of strings
			if vt.VT == ole.VT_ARRAY|ole.VT_R4|ole.VT_BSTR {

				// Convert from variant array to safe array
				vtsArray := vt.ToArray()

				//Check for null (empty arrays)
				if vtsArray == nil {
					continue
				}

				// Convert from safe array to go array
				valArray := vtsArray.ToValueArray()

				// Copy to the structure
				for _, el := range valArray {
					// Convert elements of the array
					switch reflect.ValueOf(el).Interface().(type) {
					case string:
						reflect.ValueOf(result).Elem().Field(i).Set(
							reflect.Append(reflect.ValueOf(result).Elem().Field(i), reflect.ValueOf(el.(string))))
					default: // Other types
					}
				}
			}

			// Check if variant its of VT_DISPATCH
			if vt.VT == ole.VT_DISPATCH {

				// Get pointer to IDispatch interface
				dispatchIf := vt.ToIDispatch()

				// HighPart and LowPart are properties of Interger8 type
				// Invoke to get property for highpart ...
				vth, errH := dispatchIf.GetProperty("HighPart")
				// On error continue... probably is not integer8 and methods dont exists
				if errH != nil {
					continue
				}

				// Invoke to get property for lowpart
				vtl, errL := dispatchIf.GetProperty("LowPart")
				// On error continue
				if errL != nil {
					continue
				}

				// No values
				if vth.Val == 0 || vtl.Val == 0 {
					continue
				}

				// Transform to int duration .. as per http://www.rlmueller.net/Integer8Attributes.htm
				if vtl.Val < 0 {
					vth.Val = vth.Val + 1
				}
				dur := vth.Val*int64(math.Pow(2, 32)) + vtl.Val

				// Transform to go time.Time
				dt := Integer8ToTime(dur)

				// Save to structure
				reflect.ValueOf(result).Elem().Field(i).Set(reflect.ValueOf(dt))
			}
		default:
		}
	}

	// Return nil as everything went fine
	return nil
}
