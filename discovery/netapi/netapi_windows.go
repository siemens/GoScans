/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package netapi

import (
	"fmt"
	"github.com/siemens/GoScans/utils"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const maxPreferredLength uint32 = 0xFFFFFFFF // This will let the netapi function allocate the needed memory

var (
	modNetapi32             = windows.NewLazySystemDLL("Netapi32.dll")
	netLocalGroupGetMembers = modNetapi32.NewProc("NetLocalGroupGetMembers")
	netApiBufferFree        = modNetapi32.NewProc("NetApiBufferFree")
)

// Small helper struct in order to parse the returned data
type members2Raw struct {
	sid           *syscall.SID
	sidUsage      uint32
	domainAndName *uint16
}

// Create an instance of the helper and get the size of that instance
var (
	structInstance members2Raw
	structSize     = unsafe.Sizeof(structInstance)
)

// Some of these values are actually not valid values to be returned in "LOCALGROUP_MEMBERS_INFO_2", but we've
// encountered these types as well.
// See also https://docs.microsoft.com/de-de/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_2
var usageToString = map[uint32]string{
	1:  "User",             // SidTypeUser
	2:  "Group",            // SidTypeGroup
	3:  "Domain",           // SidTypeDomain 	- Should not be a valid value
	4:  "Alias",            // SidTypeAlias 	- Should not be a valid value
	5:  "Well Known Group", // SidTypeWellKnownGroup
	6:  "Deleted Account",  // SidTypeDeletedAccount
	7:  "Invalid",          // SidTypeInvalid 	- Should not be a valid value
	8:  "Unknown",          // SidTypeUnknown
	9:  "Computer",         // SidTypeComputer 	- Should not be a valid value
	10: "Label",            // SidTypeLabel 	- Should not be a valid value
}

func GetGroupInfo(logger utils.Logger, target, sidString string) ([]string, error) {

	var (
		level        uint32 = 2 // LOCALGROUP_MEMBERS_INFO_2
		buffer       *byte
		resumeHandle *byte
		entriesRead  uint32
		entriesTotal uint32

		users = make([]string, 0, 0)
	)

	// Encode the server name in UTF-16 and get a pointer to it
	targetPtr, errUtf := syscall.UTF16PtrFromString(target)
	if errUtf != nil {
		return users, fmt.Errorf("can not convert the target string '%s' to an UTF-16 pointer: %s", target, errUtf)
	}

	// Get the Administrator SID
	sid, errSid := syscall.StringToSid(sidString)
	if errSid != nil {
		return users, fmt.Errorf("can not convert sid string '%s' to an SID: %s", sidString, errSid)
	}

	// Make a lookup for the group name
	groupName, _, _, errLookup := sid.LookupAccount(target)
	if errLookup != nil {

		// Return without error if the endpoint wasn't available
		if strings.Contains(errLookup.Error(), "unavailable") {
			return users, nil
		}

		// Return unexpected error
		return users, fmt.Errorf("can not lookup group name for target '%s': %s", target, errLookup)
	}

	// Encode the group name in UTF-16 and get a pointer to it
	groupNamePtr, errGroup := syscall.UTF16PtrFromString(groupName)
	if errGroup != nil {
		return users, fmt.Errorf("can not convert the group name '%s' to an UTF-16 pointer: %s", target, errGroup)
	}

	// Create a function that frees the buffer and log errors that might occur
	freeFunc := func() {
		ret, _, _ := netApiBufferFree.Call(uintptr(unsafe.Pointer(buffer)))
		if ret != 0 {
			errNet := syscall.Errno(ret)
			logger.Errorf("Could not free buffer of group info call: %s", errNet)
		}
	}

	defer freeFunc()

	for {

		// Loop condition break condition
		moreData := false

		ret, _, _ := netLocalGroupGetMembers.Call(
			uintptr(unsafe.Pointer(targetPtr)),     // servername
			uintptr(unsafe.Pointer(groupNamePtr)),  // group name
			uintptr(level),                         // level, LOCALGROUP_MEMBERS_INFO_2
			uintptr(unsafe.Pointer(&buffer)),       // bufptr
			uintptr(maxPreferredLength),            // prefmaxlen
			uintptr(unsafe.Pointer(&entriesRead)),  // entriesread
			uintptr(unsafe.Pointer(&entriesTotal)), // totalentries
			uintptr(unsafe.Pointer(&resumeHandle)), // resumehandle
		)

		if ret == 234 { // ERROR_MORE_DATA
			// There's more data that needs to be transmitted. Although this is highly unlikely because let the function
			// allocate the needed memory itself ('maxPreferredLength'), we'll try to retrieve the remaining data in
			// the next iteration.
			logger.Debugf("Trying to retrieve %d remaining results from NetLocalGroupGetMembers.",
				entriesTotal-entriesRead,
			)
			moreData = true

		} else if ret == 5 {

			// Return with empty list of users due to missing rights
			return users, nil

		} else if ret != 0 { // NET_API_STATUS_NERR_Success

			// Return with unknown error
			errNet := syscall.Errno(ret)
			return users, fmt.Errorf("NetLocalGroupGetMembers exited with error: '%s' [%d]", errNet, ret)
		} else if buffer == nil || *buffer == byte(0) {

			// Check if there are supposed to be any users.
			if entriesTotal != 0 || entriesRead != 0 {
				return users, fmt.Errorf("%d users found, but the buffer is empty", entriesTotal)
			}

			return users, nil
		}

		// Change the capacity of our result slice in order to avoid unnecessary memory allocations.
		// Don't reallocate if there are already results saved or the capacity already matches.
		if len(users) == 0 && cap(users) != int(entriesTotal) {
			users = make([]string, 0, entriesTotal)
		}

		// Convert the buffer into the return struct and extract the user names from it
		var iter = buffer
		for i := uint32(0); i < entriesRead; i++ {

			// Convert to the return structure
			var data = (*members2Raw)(unsafe.Pointer(iter))

			// Convert the usage as well as the domain- and username to a string, format and save them
			usage, ok := usageToString[data.sidUsage]
			if !ok {
				logger.Warningf("Invalid usage '%d'.", data.sidUsage)
				usage = usageToString[8] // Unknown
			}

			domainAndUsername := utf16PtrToString(data.domainAndName)
			users = append(users, fmt.Sprintf("%s (SID Type: %s)", domainAndUsername, usage))

			// Set the pointer to the next value
			iter = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + structSize))
		}

		// Check if there is more data expected
		if !moreData {
			break
		}

		// We need to free the buffer if there's more data expected
		freeFunc()

	}

	return users, nil
}

// utf16PtrToString converts a  pointer to a null-terminated, UTF-16 encoded string into a (golang) string. The length
// of the string can be arbitrary. Be cautious with this function if the memory address in invalid the program might
// crash.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}

	// Allocate space for the resulting string.
	s := make([]uint16, 0, 512)

	for {
		// Null termination check.
		if p == nil || *p == 0 {
			return string(utf16.Decode(s))
		}

		// Append the current character.
		s = append(s, *p)

		// Get the next address
		p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2)) // 2 = size of a uint16
	}
}
