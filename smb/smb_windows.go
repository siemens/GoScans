/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smb

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
	"github.com/siemens/GoScans/utils/windows_systemcalls"
	"golang.org/x/sys/windows"
)

// Constants for windows

const StypeDisktree = 0x00            // Disk-tree share type
const StypeDevice = 0x02              // Device share type
const ResourcetypeDisk = 1            // Disk resource type
const MaxPreferredLength = 0xFFFFFFFF // Maximum Windows API response length

// enum for file object determination
const (
	physicalFile    = iota // Physical file
	accessibleDir          // Accessible directory
	inaccessibleDir        // Inaccessible directory
	excludedDir            // Excluded directory
	nilObj                 // Missing object
)

// shareInfo holds the name, target, UNC path, and DFS flag for a discovered SMB share.
type shareInfo struct {
	Name   string
	Target string
	Path   string
	IsDfs  bool
}

// dfsIdentifier holds the resolved hostnames and IP addresses of a DFS endpoint for link comparison.
type dfsIdentifier struct {
	hostnames []string
	ips       []string
}

// crawl enumerates shares and crawls each of them one by one
func (s *Scanner) crawl() *filecrawler.Result {

	// Initialize result data
	result := &filecrawler.Result{
		Status: utils.StatusCompleted,
	}

	// Initialize filecrawler to crawl the shares
	crawler := filecrawler.NewCrawler(
		s.logger,
		s.crawlDepth,
		s.excludedFolders,
		s.excludedExtensions,
		s.excludedLastModifiedBelow,
		int64(s.excludedFileSizeBelow),
		s.onlyAccessibleFiles,
		s.threads,
		s.contextInner,
	)

	// Enumerate all Shares from the target and abort if any errors occur
	shares, errShares := s.getShares()
	if errors.Is(errShares, windows.ERROR_BAD_NETPATH) {
		result.Status = utils.StatusNotReachable
		s.logger.Debugf("Target '%s' is not reachable: %s", s.target, errShares)
		return result
	}
	if errShares != nil {
		result.Status = utils.StatusFailed
		s.logger.Debugf("Could not get shares of '%s': %s", s.target, errShares)
		return result
	}

	// Log state
	s.logger.Debugf("Enumerated %d share(s) on '%s'.", len(shares), s.target)

	// Make map of shares to keep track of known shares and to allow fast lookups
	knownShares := make(map[string]struct{})
	for _, share := range shares {
		knownShares[strings.ToLower(share.Name)] = struct{}{}
	}

	// Append forced shares
	cnt := 0
	if len(s.forcedShares) > 0 {
		for _, share := range s.forcedShares {
			share = strings.ToLower(share)
			_, ok := knownShares[share]
			if !ok {
				shares = append(shares, shareInfo{
					Name:   share,
					Target: s.target,
					Path:   fmt.Sprintf("\\\\%s\\%s", s.target, share),
					IsDfs:  false,
				})
				knownShares[share] = struct{}{}
				cnt++
			}
		}
		s.logger.Debugf("Added %d forced share(s).", cnt)
	}

	// Run as long as there are shares left to crawl
	// ATTENTION: New shares might get detected during the process
	for len(shares) > 0 {

		// Shares we found after the initial enumeration, e.g. shares with "noBrowseable" flag in samba
		var share shareInfo

		// Pop the first share in the list
		share, shares = shares[0], shares[1:]

		// Check if share should be excluded from crawl
		if _, excluded := s.excludedShares[strings.ToLower(share.Name)]; excluded {
			s.logger.Debugf("Skipping excluded share '%s'.", share.Name)
			continue
		}

		// Crawl share
		shareResult, discoveredShares, errCrawlShare := s.crawlShare(crawler, share, knownShares)
		if errCrawlShare != nil {
			s.logger.Debugf(utils.TitleFirstLetter(errCrawlShare.Error()))
			continue
		}

		// Update crawl result
		result.FoldersReadable += shareResult.FoldersReadable
		result.FilesWritable += shareResult.FilesWritable
		result.FilesReadable += shareResult.FilesReadable
		result.Data = append(result.Data, shareResult.Data...)

		// Abort if scan deadline was reached
		if utils.ContextExpired(s.contextInner) {
			return result
		}

		// Check if new shares were found (shares which were not enumerated but are on the server)
		if len(discoveredShares) > 0 {

			// Log discovery amount
			s.logger.Infof("Discovered %d new share(s).", len(discoveredShares))

			// Inject discovered shares into processing
			for _, discoveredShare := range discoveredShares {

				// Add discovered shares to known shares for next round
				knownShares[strings.ToLower(discoveredShare.Name)] = struct{}{}

				// Add discovered shares to processing
				shares = append(shares, discoveredShare)
			}
		}
	}

	// Return result
	return result
}

// crawlShare crawls a single share
func (s *Scanner) crawlShare(
	crawler *filecrawler.Crawler,
	share shareInfo,
	knownShares map[string]struct{},
) (*filecrawler.Result, []shareInfo, error) {

	// Initialize result data
	shareResult := &filecrawler.Result{}

	// Prepare struct identifying a DFS endpoint
	var dfsIdent dfsIdentifier

	// Connect to share
	errMount := s.mountShare(share)
	if errMount != nil {
		return nil, nil, fmt.Errorf("could not mount share '%s': %w", share.Name, errMount)
	}

	// Clean up mounted shares
	defer func() {
		errUnmount := s.unmountShare(share)
		if errUnmount != nil {
			s.logger.Debugf("Could not unmount share '%s': %s", share.Path, errUnmount)
			return
		}
	}()

	// Determine ip and host names for finding DFS shares via DFS links
	if share.IsDfs {
		dfsIdent = s.extractDfsIdentifier()
	}

	// Check if we have a normal smb share or a DFS. In case of a normal share we chose the share itself as entry point
	// for crawling. In case of a DFS we only crawl the physical content inside the DFS.
	entryPoints, sharesDiscovered, foldersCrawled, errCheck := s.checkShare(share, knownShares, dfsIdent)
	if errCheck != nil {
		return nil, nil, errCheck
	}

	// Increase folders readable counter
	shareResult.FoldersReadable += foldersCrawled

	// Iterate shares to crawl
	for _, entryPoint := range entryPoints {

		// Crawl with the filesystem crawler
		result := crawler.Crawl(entryPoint)

		// Subtract 1 from readable folders if the root folder was a share, since we do not count them as folders
		if entryPoint.IsShare && result.FoldersReadable > 0 {
			result.FoldersReadable -= 1
		}

		// If we chose a file from DFS as root for crawling its depth will be 0, so we need to set its depth here
		if rootDepth := strings.Count(entryPoint.Path, string(os.PathSeparator)) - 3; rootDepth > 0 && len(result.Data) > 0 {
			result.Data[0].Depth = rootDepth
		}

		// Update counters
		shareResult.FoldersReadable += result.FoldersReadable
		shareResult.FilesWritable += result.FilesWritable
		shareResult.FilesReadable += result.FilesReadable
		shareResult.Data = append(shareResult.Data, result.Data...)

		// Abort if scan deadline was reached
		if utils.ContextExpired(s.contextInner) {
			break
		}
	}

	// Return result and additionally found shares
	return shareResult, sharesDiscovered, nil
}

// getShares enumerates all shares of the specified target
func (s *Scanner) getShares() ([]shareInfo, error) {

	// Prepare memory
	var buf *byte
	var entriesRead, totalEntries uint32
	var shares []shareInfo
	targetPtr, errTargetPtr := syscall.UTF16PtrFromString(s.target)
	if errTargetPtr != nil {
		return nil, fmt.Errorf("could not convert string to utf16Ptr: %w", errTargetPtr)
	}

	// Get all shares via WinApi call
	errEnum := windows_systemcalls.NetShareEnum(targetPtr, 1, &buf, MaxPreferredLength,
		&entriesRead, &totalEntries, nil)

	defer func() {
		// We have to free the buffer only on success or fail with ERROR_MORE_DATA (If this error happens we cannot
		// extend the memory, since we already used MaxPreferredLength)
		if errEnum == nil || errors.Is(errEnum, syscall.ERROR_MORE_DATA) {
			errFree := syscall.NetApiBufferFree(buf)
			if errFree != nil {
				s.logger.Warningf("Could not free allocated net buffer: %s", errFree)
			}
		}
	}()

	// Return when an error occurs
	if errEnum != nil {
		return nil, errEnum
	}

	// Max length of array is the max value of the default int of the system, so we go for 32 Bit to be able to run on
	// 32-Bit architecture windows
	if entriesRead > math.MaxInt32 {
		return nil, fmt.Errorf("too many shares on target, found: %d, max: %d", entriesRead, math.MaxInt32)
	}

	// Do not proceed if we did not find any entries ("buf" will be nil and there will be a panic if we try to
	// convert it)
	if entriesRead <= 0 {
		return nil, nil
	}

	// As seen in the listGroupsForUsernameAndDomain function in os\user\lookup_windows.go. We convert the returned
	// pointer to an unsafe.Pointer and cast it to an array of SHARE_INFO_1. Then we cut the slice of the right length
	entries := (*[math.MaxInt32]windows_systemcalls.SHARE_INFO_1)(unsafe.Pointer(buf))[:entriesRead:entriesRead]
	for _, entry := range entries {

		// Prepare memory
		shareName := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(entry.Netname))[:])

		// Log if a communication device was found
		shareType := entry.Type & 0xFFFF
		if shareType == StypeDevice {
			s.logger.Warningf("Found share with type 'StypeDevice': '%s'", shareName)
		}

		// We are only interested in disk drives
		if shareType != StypeDisktree {
			continue
		}

		// Check if share is a DFS
		isDfsShare, errIsDfsShare := s.isDfs(s.target, shareName)
		if errIsDfsShare != nil {
			s.logger.Debugf(
				"Skipping share '%s' because it cannot be determine whether it is a dfs share: %s",
				shareName,
				errIsDfsShare,
			)
			continue
		}

		// Create UNC path, the filepath.join method does not work here properly
		sharePath := fmt.Sprintf("\\\\%s\\%s", s.target, shareName)

		// Append share to list of shares to be crawled
		shares = append(shares, shareInfo{
			Name:   shareName,
			Target: s.target,
			Path:   sharePath,
			IsDfs:  isDfsShare,
		})
	}

	// Return shares
	return shares, nil
}

// mountShare mounts a given share
func (s *Scanner) mountShare(share shareInfo) error {

	// Encode the share path as a UTF-16 pointer
	sharePathPtr, errSharePathPtr := syscall.UTF16PtrFromString(share.Path)
	if errSharePathPtr != nil {
		return errSharePathPtr
	}

	// Prepare user and password pointers (remain nil when no credentials are supplied)
	var userPtr *uint16
	var passwordPtr *uint16

	// If a user is provided, encode credentials as UTF-16 pointers
	if s.smbUser != "" {
		userPtrLocal, errUserPtrLocal := syscall.UTF16PtrFromString(fmt.Sprintf("%s\\%s", s.smbDomain, s.smbUser))
		if errUserPtrLocal != nil {
			return errUserPtrLocal
		}
		userPtr = userPtrLocal

		passwordPtrLocal, errPasswordPtrLocal := syscall.UTF16PtrFromString(s.smbPassword)
		if errPasswordPtrLocal != nil {
			return errPasswordPtrLocal
		}
		passwordPtr = passwordPtrLocal
	}

	// Create "Netresource" with share information
	var netResource windows_systemcalls.Netresource
	netResource.Type = ResourcetypeDisk
	netResource.RemoteName = sharePathPtr

	// Connect share
	errConnect := windows_systemcalls.WNetAddConnection2(&netResource, passwordPtr, userPtr, 0)
	if errConnect != nil {
		return errConnect
	}

	// Return nil as everything went fine
	return nil
}

// unmountShare unmounts a given share
func (s *Scanner) unmountShare(share shareInfo) error {

	// Encode the share path as a UTF-16 pointer
	sharePathPtr, errSharePathPtr := syscall.UTF16PtrFromString(share.Path)
	if errSharePathPtr != nil {
		return errSharePathPtr
	}

	// Disconnect the share
	if errCancel := windows_systemcalls.WNetCancelConnection2(sharePathPtr, 0, true); errCancel != nil {
		return errCancel
	}

	// Return nil as everything went fine
	return nil
}

// checkShare checks whether a share is a normal share or a DFS share. In case of a normal share, a file struct
// is crated and returned. In case of a DFS share, the share is checked for physical content, additional shares and
// is then returned with the number of folders checked.
func (s *Scanner) checkShare(
	share shareInfo,
	knownShares map[string]struct{},
	dfsIdent dfsIdentifier,
) ([]*filecrawler.EntryPoint, []shareInfo, int, error) {

	// If it is a normal share than we add the share itself as folder to be crawled
	if !share.IsDfs {

		// Return crawl information
		return []*filecrawler.EntryPoint{
			{
				Path:      share.Path,
				InsideDfs: share.IsDfs,
				Share:     share.Name,
				IsShare:   true,
			},
		}, nil, 0, nil
	}

	// If share is a DFS than check for all physical content in it. Check also if the location of its target links
	// (where the data is physically stored) is a share on this target. If we did not have enumerated these shares
	// earlier, (eg. on samba servers, when it has the "noBrowseable" attribute) we add it to additional shares.
	entryPoints, sharesDiscovered, foldersCrawled, errCrawlDfs := s.crawlDfs(&share, knownShares, dfsIdent)
	if errCrawlDfs != nil {
		var pErr *os.PathError
		if errors.As(errCrawlDfs, &pErr) && !errors.Is(pErr.Err, syscall.ERROR_ACCESS_DENIED) {
			s.logger.Debugf("Could not fully walk DFS share '%s': %s", pErr.Path, pErr.Err)
		}
	}

	// Return crawl information
	return entryPoints, sharesDiscovered, foldersCrawled, nil
}

// crawlDfs walks (only) physical DFS share folders and retrieves all physical files. It also checks if the
// referral links of the DFS links are pointing to a share we did not enumerated yet (e.g. nobrowseble flag on Samba)
// and if so returns them.
func (s *Scanner) crawlDfs(
	share *shareInfo,
	knownShares map[string]struct{},
	dfsIdent dfsIdentifier,
) ([]*filecrawler.EntryPoint, []shareInfo, int, error) {

	// Prepare memory
	var physicalFiles []*filecrawler.EntryPoint
	var sharesDiscovered []shareInfo
	foldersCrawled := 0

	// Log action
	s.logger.Debugf("Crawling DFS share '%s'.", share.Path)

	// Check for every fsObj if it is physically on that location or if it is a DFS link
	// If it is a DFS link, check on which share it really exists and if we enumerated this share already
	errWalkResult := filepath.Walk(share.Path, func(path string, info os.FileInfo, errWalk error) error {

		// Abort if deadline is reached
		if utils.ContextExpired(s.contextInner) {
			return fmt.Errorf("deadline reached")
		}

		// Check depth
		path = strings.TrimSuffix(path, "\\")
		depth := strings.Count(path, "\\") - 3
		if depth > s.crawlDepth && s.crawlDepth > -1 {
			return filepath.SkipDir
		}

		// Skip the first walk with the share folder, since it would end the walk
		if depth == 0 {
			return nil
		}

		// Prepare variables
		var dfsShareInfoPtr *byte
		var nilPtr1, nilPtr2 *uint16
		dfsEntryPathPtr, errDfsEntryPathPtr := syscall.UTF16PtrFromString(path)
		if errDfsEntryPathPtr != nil {
			s.logger.Warningf("Skipping DFS path '%s' because of unknown error: %s", path, errDfsEntryPathPtr)
			return nil
		}

		// Win Api call returns only no error if the investigated object is a DFS link
		errDfsInfo := windows_systemcalls.NetDfsGetInfo(dfsEntryPathPtr, nilPtr1, nilPtr2, 3, &dfsShareInfoPtr)

		// Object is a DFS link, so we check if it does point to shares on the target which we did not have enumerated
		if errDfsInfo == nil {
			defer func() {
				errFree := syscall.NetApiBufferFree(dfsShareInfoPtr)
				if errFree != nil {
					s.logger.Warningf("Could not free buffer: %s", errFree)
				}
			}()

			// Search for additional shares
			discovered := s.discoverSharesViaDfs(dfsShareInfoPtr, knownShares, dfsIdent)

			// Remember additional shares
			sharesDiscovered = append(sharesDiscovered, discovered...)

			// If we got the info object of the link and it is a file then return nil to continue walking current folder
			if info != nil && !(reflect.ValueOf(info).Kind() == reflect.Ptr && reflect.ValueOf(info).IsNil()) {
				if !info.IsDir() {
					return nil
				}
			}

			// If it is a folder or we got no info object, we skip walking the object
			return filepath.SkipDir
		}

		// The Object is physical if we get the error "E_NOT_SET"
		// If this is not the case then skip the object and log the unexpected error.
		if !errors.Is(errDfsInfo, windows.E_NOT_SET) {
			s.logger.Debugf("Skipping DFS path '%s' because it might not be physical: %s", path, errDfsInfo)
			return nil
		}

		// Handle physical object
		objType := s.checkFileObj(info, path, errWalk)
		switch objType {

		// If object is a physical file, save it
		case physicalFile:
			phyFi := &filecrawler.EntryPoint{Path: path, Share: share.Name, InsideDfs: true}
			physicalFiles = append(physicalFiles, phyFi)

		// Increase foldersCrawled, if the folder is in depth range, since it will be crawled by the walk function later
		case accessibleDir:
			if depth+1 <= s.crawlDepth || s.crawlDepth <= -1 {
				foldersCrawled += 1
			}

		// Don't walk exclude directories
		case excludedDir:
			return filepath.SkipDir
		}

		// Proceed walking normally
		return nil
	})

	// If an error happens, still return the results we gathered so far
	if errWalkResult != nil {
		return physicalFiles, sharesDiscovered, foldersCrawled, errWalkResult
	}

	// Return DFS results
	return physicalFiles, sharesDiscovered, foldersCrawled, nil
}

// discoverSharesViaDfs checks if the given DFS link has referrals to shares which we did not have enumerated yet.
// This can be the case when a share is crawled on a samba server with the "noBrowseable" flag set for its shares.
func (s *Scanner) discoverSharesViaDfs(
	dfsShareInfoPtr *byte,
	knownShares map[string]struct{},
	dfsIdent dfsIdentifier,
) []shareInfo {

	// Prepare memory
	var sharesDiscovered []shareInfo
	var info = (*windows_systemcalls.DFS_INFO_3)(unsafe.Pointer(dfsShareInfoPtr))
	var numberLinks = int(info.NumberOfStorages)
	var pStorage *windows_systemcalls.DFS_STORAGE_INFO

	// Iterate links
	for i := 0; i < numberLinks; i++ {

		// flag for showing that DFS link points to the crawled target
		sameHost := false

		// Use pointer arithmetic to iterate to the right memory position and get the Storage struct
		pStorage = (*windows_systemcalls.DFS_STORAGE_INFO)(unsafe.Pointer(
			uintptr(unsafe.Pointer(info.DfsStorageInfo)) + uintptr(i)*unsafe.Sizeof(*info.DfsStorageInfo)))

		// Convert servername to golang string
		serverName := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(pStorage.ServerName))[:])

		// Check if the DFS link refers to share on the target
		if utils.StrContained(strings.ToLower(serverName), dfsIdent.ips, dfsIdent.hostnames) {
			sameHost = true
		}

		// If link is pointing to different host, skip it
		if !sameHost {
			continue
		}

		// Get the share the DFS link is pointing to: split after "\", e.g. FS_CA_GOLD1$\EBCS -> FS_CA_GOLD1$
		sharePath := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(pStorage.ShareName))[:])
		shareName := strings.Split(sharePath, "\\")[0]

		// Check if we already found this share, if yes then skip
		if _, known := knownShares[strings.ToLower(shareName)]; known {
			continue
		}

		// Check if share is a DFS share
		isDfs, errIsDfs := s.isDfs(serverName, shareName)
		if errIsDfs != nil {
			s.logger.Debugf("Could not determine if '%s' is a DFS share: %s", shareName, errIsDfs)
			continue
		}

		// Append share to
		sharesDiscovered = append(sharesDiscovered, shareInfo{
			Name:   shareName,
			Target: s.target,
			Path:   fmt.Sprintf("\\\\%s\\%s", s.target, shareName),
			IsDfs:  isDfs,
		})

		// Add new found share to the known shares
		knownShares[strings.ToLower(shareName)] = struct{}{}
	}

	// Return additional shares
	return sharesDiscovered
}

// checkFileObj determines what type of object the FileInfo refers to and returns it, excluding inaccessible or
// excluded folders as well as nil objects.
func (s *Scanner) checkFileObj(info os.FileInfo, path string, errWalk error) int {

	// Check for a nil info or a non-nil info whose underlying value is a nil value and return accordingly
	if info == nil || (reflect.ValueOf(info).Kind() == reflect.Ptr && reflect.ValueOf(info).IsNil()) {
		var pErr *os.PathError
		if errors.As(errWalk, &pErr) && !errors.Is(pErr.Err, syscall.ERROR_ACCESS_DENIED) {
			s.logger.Debugf("Could not get file info of '%s': %s", pErr.Path, pErr.Err)
		} else if !errors.As(errWalk, &pErr) {
			s.logger.Debugf("Could not get file info of '%s': %s", path, errWalk)
		}
		return nilObj
	}

	// Check if file and return
	if !info.IsDir() {
		return physicalFile
	}

	// Otherwise it is a folder
	// Skip excluded folder
	if _, excluded := s.excludedFolders[strings.ToLower(info.Name())]; excluded {
		return excludedDir
	}

	// Check if it is accessible and return result
	var pErr *os.PathError
	if errWalk == nil {
		return accessibleDir
	} else if errors.As(errWalk, &pErr) && !errors.Is(pErr.Err, syscall.ERROR_ACCESS_DENIED) {
		return accessibleDir
	} else {
		return inaccessibleDir
	}
}

// isDfs checks if a share is a DFS root
func (s *Scanner) isDfs(target string, shareName string) (bool, error) {

	// Prepare memory
	targetPtr, errTargetPtr := syscall.UTF16PtrFromString(target)
	if errTargetPtr != nil {
		return false, errTargetPtr
	}
	shareNamePtr, errShareNamePtr := syscall.UTF16PtrFromString(shareName)
	if errShareNamePtr != nil {
		return false, errShareNamePtr
	}

	// Use Win Api function to get info about the share
	var shareInfoPtr *byte
	errInfo := windows_systemcalls.NetShareGetInfo(targetPtr, shareNamePtr, 1005, &shareInfoPtr)
	if errInfo != nil {
		return false, errInfo
	}
	defer func() { _ = syscall.NetApiBufferFree(shareInfoPtr) }()
	info := (*windows_systemcalls.SHARE_INFO_1005)(unsafe.Pointer(shareInfoPtr))

	// Check flags to determine if it is a DFS share
	isDFS := info.Flags&0x0003 != 0

	// Return whether target share is DFS share
	return isDFS, nil
}

// extractDfsIdentifier determines the identifying attributes of a DFS endpoint
func (s *Scanner) extractDfsIdentifier() dfsIdentifier {

	// Try to parse target as IP
	ip := net.ParseIP(s.target)

	// If it is an IP then reverse lookup hostnames
	if ip != nil {

		// Lookup hostname
		hostnames, errHostnames := net.LookupAddr(s.target)
		hostnames = utils.TrimToLower(hostnames)
		if errHostnames != nil {
			s.logger.Debugf(
				"Could not lookup address of '%s' hindering finding hidden shares: %s",
				s.target,
				errHostnames,
			)
		}

		// Return DFS identifier struct
		return dfsIdentifier{
			hostnames: hostnames,
			ips:       []string{s.target},
		}
	}

	// If it is a hostname, then lookup corresponding IPs
	resolvedIps, errResolvedIps := net.LookupIP(s.target)
	if errResolvedIps != nil {
		s.logger.Debugf("Could not lookup IP of '%s' hindering finding hidden shares: %s", s.target, errResolvedIps)
	}

	// Translate resolved IPs into strings
	var resolvedIpStr []string
	for _, resolvedIp := range resolvedIps {
		resolvedIpStr = append(resolvedIpStr, resolvedIp.String())
	}

	// Return DFS identifier struct
	return dfsIdentifier{
		hostnames: []string{s.target},
		ips:       resolvedIpStr,
	}
}
