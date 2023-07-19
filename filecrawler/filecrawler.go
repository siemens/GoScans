/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2023.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package filecrawler

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/gabriel-vasile/mimetype"
	"github.com/siemens/GoScans/utils"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// The start information of every crawl
type EntryPoint struct {
	Path      string
	Share     string // The share in which the object is located
	IsShare   bool   // Marks if the crawled object itself is the share
	InsideDfs bool
}

type File struct {
	Share           string
	Path            string
	Name            string
	Extension       string // Without "."
	Mime            string
	Readable        bool
	Writable        bool
	Flags           string // Unix Permission bits and special file flags, such as setuid/setgid, sticky bit...
	SizeKb          int64
	LastModified    time.Time
	Depth           int
	IsSymlink       bool
	Properties      []string
	IsDfs           bool     // Windows exclusive
	NfsRestrictions []string // Linux exclusive
}

type Result struct {
	FoldersReadable int
	FilesReadable   int
	FilesWritable   int
	Data            []*File
	Status          string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception       bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the Status attribute.
}

// Intermediate result containing the processed files to be returned and new tasks (unprocessed folder and files)
type processResult struct {
	isReadableDir bool  // Is needed for calculating how many folders where crawled (we don't count unaccessible ones)
	data          *File // The actual result data for this file
	newTasks      []*task
}

// For every file or folder a task is created with attributes describing the object to be processed
type task struct {
	path          string
	isFolder      bool // Identifies for what process this task is meant
	isShareFolder bool // Identifies the object as shared folder
	isInsideDfs   bool // Shows if object was found in a dfs structure
	depth         int  // depth of the resource
	share         string
}

// OOXMLCustomPropertiesFile is the relative path to the metadata file of every Office file where the custom properties
// (also the sensitivity-labels of the MS Information Protection) are stored
const OOXMLCustomPropertiesFile = "docProps/custom.xml"

// OOXMLProperties mirrors the xml structure of custom property metadata of Open Office Files
type OOXMLProperties struct {
	XMLName    xml.Name        `xml:"Properties"` // Important when adding attributes, always use uppercase for it, otherwise unmarshalling might not work
	Properties []OOXMLProperty `xml:"property"`
}

type OOXMLProperty struct {
	Fmtid    string  `xml:"fmtid,attr"`
	Pid      string  `xml:"pid,attr"`
	Name     string  `xml:"name,attr"`
	ValStr   *string `xml:"lpwstr"`
	ValInt   *string `xml:"i4"`
	ValDate  *string `xml:"filetime"`
	ValBool  *string `xml:"bool"`
	ValFloat *string `xml:"r8"`
}

// The main crawler struct
type Crawler struct {
	logger                    utils.Logger
	crawlDepth                int
	excludedFolders           map[string]struct{} // lowercase list of folder names to exclude from crawling
	excludedExtensions        map[string]struct{} // lowercase list of file extensions without '.' to exclude from crawling
	excludedLastModifiedBelow time.Time
	excludedFileSizeBelow     int64
	onlyAccessibleFiles       bool      // Whether to only return files in results that are at least read or writable. Otherwise, also found files that were not accessible are listed.
	threads                   int       // Amount of threads sending requests in parallel
	deadline                  time.Time // Time at which the crawler has to abort
}

func NewCrawler(
	logger utils.Logger,
	maxDepth int,
	excludedFolders map[string]struct{}, // values must be converted to lowercase first!
	excludedExtensions map[string]struct{}, // values must be converted to lowercase first!
	excludedLastModifiedBelow time.Time,
	excludedFileSizeBelow int64,
	onlyAccessibleFiles bool,
	threads int,
	deadline time.Time,
) *Crawler {

	// Make sure at least one crawler thread is set
	if threads <= 0 {
		threads = 1
	}
	return &Crawler{
		logger:                    logger,
		crawlDepth:                maxDepth,
		excludedFolders:           excludedFolders,
		excludedExtensions:        excludedExtensions,
		excludedLastModifiedBelow: excludedLastModifiedBelow,
		excludedFileSizeBelow:     excludedFileSizeBelow,
		onlyAccessibleFiles:       onlyAccessibleFiles,
		threads:                   threads,
		deadline:                  deadline,
	}
}

// Crawl crawls the filesystem begging by the given entry point. For every element it discovers, a new porcessing task
// is generated, back-feeding the crawler.
func (c *Crawler) Crawl(entryPoint *EntryPoint) *Result {

	// Initialize result data
	result := &Result{
		Status: utils.StatusCompleted,
	}

	// Check that root is not nil
	if entryPoint == nil || (reflect.ValueOf(entryPoint).Kind() == reflect.Ptr && reflect.ValueOf(entryPoint).IsNil()) {
		c.logger.Debugf("Invalid crawl entry point.")
		return result
	}

	// Check that root it not empty
	if *entryPoint == (EntryPoint{}) {
		c.logger.Debugf("Invalid crawl entry point.")
		return result
	}

	// Check whether access is possible
	rootInfo, err := os.Lstat(entryPoint.Path)
	if err != nil {
		if pErr, ok := err.(*os.PathError); ok {
			c.logger.Debugf("Could not get root info of '%s': %s", pErr.Path, pErr.Err)
		}
		return result
	}

	// Log start of crawling
	c.logger.Debugf("Crawling entry point '%s'.", entryPoint.Share)

	// Create first task to be processed
	rootTask := &task{
		path:          entryPoint.Path,
		isFolder:      rootInfo.IsDir(),
		isShareFolder: entryPoint.IsShare,
		isInsideDfs:   entryPoint.InsideDfs,
		depth:         0,
		share:         entryPoint.Share,
	}

	// Start crawling-loop at the root and get the result struct to be filled
	c.run(rootTask, result)

	// Check whether the scan was ended due to the scan timeout
	if utils.DeadlineReached(c.deadline) {
		c.logger.Debugf("Filecrawler finished with timeout.")
		result.Status = utils.StatusDeadline
		result.Exception = false
		return result
	}

	// Return result
	c.logger.Debugf("Filecrawler finished.")
	return result
}

// run orchestrates the crawling by looping and starting new processes and receiving process results
func (c *Crawler) run(rootTask *task, result *Result) {

	// Initialize crawler process slots, counter and return channel
	var processCount = 0                             // Counting processed pages
	var processActive = 0                            // Counter required to decide if all goroutines have terminated
	var chThrottle = make(chan struct{}, c.threads)  // A channel instead of an integer will allow to wait via select
	var chProcessResults = make(chan *processResult) // Channel containing results returned by a crawler process
	var queue []*task

	// Create and append first task, which is the root object
	queue = append(queue, rootTask)

	// Define closure to launch a new goroutine if possible. Not blocking. Returns true if something could be launched.
	launchFunc := func() bool {
		if len(queue) > 0 {
			select {
			case chThrottle <- struct{}{}: // Launch goroutine for next queue item
				processActive++
				if queue[0].isFolder {
					go c.processFolder(queue[0], processCount, chProcessResults)
				} else {
					go c.processFile(queue[0], processCount, chProcessResults)
				}
				queue = queue[1:]
				processCount += 1
				return true
			default:
				return false
			}
		}
		return false
	}

	// Define closure to receive (blocking)
	receiveFunc := func() {
		procRes := <-chProcessResults
		// Release slot and decrease goroutine counter
		<-chThrottle
		processActive--

		if procRes.isReadableDir {
			result.FoldersReadable++
		}
		if procRes.newTasks != nil {
			queue = append(queue, procRes.newTasks...)
		}
		if procRes.data != nil {
			// Add page to crawl results
			result.Data = append(result.Data, procRes.data)
			if procRes.data.Readable {
				result.FilesReadable++
			}
			if procRes.data.Writable {
				result.FilesWritable++
			}
		}
	}

	// Manage crawling. Launch new tasks, listen for results and queue new URLs until done or scan timout
	for {

		// Do not continue feeding the crawler if scan time is reached
		if utils.DeadlineReached(c.deadline) {
			break
		}

		// Terminate queue if empty and no more crawling goroutines active
		if len(queue) == 0 && processActive == 0 {
			break
		}

		// Launch goroutine for next element if possible
		if len(queue) > 0 && launchFunc() {
			continue // Try launching further element as long as possible
		}

		// Wait for data to be processed (blocking)
		receiveFunc()
	}

	// Wait for remaining goroutines to finish (relevant in case of scan timeout)
	for processActive > 0 {
		c.logger.Debugf("Waiting for remaining %d goroutines.", processActive)
		receiveFunc()
	}
}

// processFolder processes a folder, retrieving its contents. The folder is skipped, if the max depth is reached.
func (c *Crawler) processFolder(folderTask *task, processId int, chProcessResults chan<- *processResult) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			c.logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Wrap logger again with local tag to connect log messages of this goroutine
	processLogger := utils.NewTaggedLogger(c.logger, fmt.Sprintf("t%03d", processId))

	// Crawl depth corresponds to the fs level, 1 means content of starting folder, -1 all content.
	// It is ">=" instead of ">", because with ">" the content would have a greater depth than the crawl depth.
	if folderTask.depth >= c.crawlDepth && c.crawlDepth > -1 {
		chProcessResults <- &processResult{}
		return
	}

	// Get more info about folder, if not possible then abort
	info, errStat := os.Lstat(folderTask.path)
	if errStat != nil {
		pErr, ok := errStat.(*os.PathError)
		if ok && !(errors.Is(pErr, os.ErrPermission) || pErr.Err.Error() == os.ErrPermission.Error()) {
			c.logger.Debugf("Could not get folder info of '%s': %s", pErr.Path, pErr.Err)
		}
		chProcessResults <- &processResult{}
		return
	}

	// If it is no share, check if it excluded
	_, contained := c.excludedFolders[strings.ToLower(info.Name())]
	if contained && !folderTask.isShareFolder {
		chProcessResults <- &processResult{}
		return
	}

	// Skip symlinks to folders to avoid cycles
	if info.Mode()&os.ModeSymlink != 0 {
		chProcessResults <- &processResult{}
		return
	}

	// Get all folders and files
	content, errDir := ioutil.ReadDir(folderTask.path)
	if errDir != nil { // Log if an unexpected error occurred
		pErr, ok := errDir.(*os.PathError)
		if ok && !(errors.Is(pErr, os.ErrPermission) || pErr.Err.Error() == os.ErrPermission.Error()) {
			processLogger.Debugf("Could not get folder content of '%s': %s", pErr.Path, pErr.Err)
		}
		chProcessResults <- &processResult{}
		return
	}

	// Create new task to be returned
	var newTasks []*task
	for _, entry := range content {
		newTasks = append(newTasks, &task{
			isFolder:      entry.IsDir(),
			path:          fmt.Sprintf("%s%s%s", folderTask.path, string(os.PathSeparator), entry.Name()),
			isInsideDfs:   folderTask.isInsideDfs,
			isShareFolder: false,
			depth:         folderTask.depth + 1,
			share:         folderTask.share,
		})
	}

	// Return results
	chProcessResults <- &processResult{
		isReadableDir: true,
		data:          nil,
		newTasks:      newTasks,
	}
}

// processFile checks if file is not excluded by some criteria and determines its attributes
func (c *Crawler) processFile(fileTask *task, processId int, chProcessResults chan<- *processResult) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			c.logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Get more info about file, if not possible then abort
	info, errStat := os.Lstat(fileTask.path)
	if errStat != nil {
		pErr, ok := errStat.(*os.PathError)
		if ok && !(errors.Is(pErr, os.ErrPermission) || pErr.Err.Error() == os.ErrPermission.Error()) {
			c.logger.Debugf("Could not get file info of '%s': %s", pErr.Path, pErr.Err)
		}
		chProcessResults <- &processResult{}
		return
	}

	// Create File struct with basic information
	file := &File{
		Share:        fileTask.share,
		Path:         fileTask.path,
		Name:         info.Name(),
		Flags:        getUnixFlags(info.Mode()),
		SizeKb:       info.Size() / 1000,
		LastModified: info.ModTime(),
		Depth:        fileTask.depth,
		IsSymlink:    info.Mode()&os.ModeSymlink != 0,
		IsDfs:        fileTask.isInsideDfs,
	}

	// Check if file is excluded by size
	if file.SizeKb < c.excludedFileSizeBelow {
		chProcessResults <- &processResult{} // Empty data set will not cause any change in the data
		return
	}

	// Check if file is excluded by modification date
	if !file.LastModified.IsZero() && file.LastModified.Before(c.excludedLastModifiedBelow) {
		chProcessResults <- &processResult{}
		return
	}

	// Extract extension from file. Unify to lower case because, case does not carry information
	file.Extension = strings.ToLower(strings.ReplaceAll(filepath.Ext(file.Name), ".", ""))

	// Check if file is excluded by file extension
	_, contained := c.excludedExtensions[file.Extension]
	if contained {
		chProcessResults <- &processResult{}
		return
	}

	// Wrap logger again with local tag to connect log messages of this goroutine
	processLogger := utils.NewTaggedLogger(c.logger, fmt.Sprintf("t%03d", processId))

	// Use a special routine for symlink files, since the usual routine would mostly follow the link
	if file.IsSymlink {
		determineSymlinkPermissions(file, processLogger)

		// If c.onlyAccessibleFiles = true, then only files which are readable or writable are desired
		if c.onlyAccessibleFiles && !file.Readable && !file.Writable {
			chProcessResults <- &processResult{}
			return
		}

		// Return symlink info
		chProcessResults <- &processResult{
			data:     file,
			newTasks: nil,
		}
		return
	}

	// Check read rights
	readable, errRead := accessFile(file.Path, os.O_RDONLY)
	if errRead != nil {
		c.logger.Debugf("Could not fully detect file permissions: %s", errRead)
	}
	file.Readable = readable

	// Check write rights
	writable, errWrite := accessFile(file.Path, os.O_WRONLY)
	if errWrite != nil {
		c.logger.Debugf("Could not fully detect file permissions: %s", errWrite)
	}
	file.Writable = writable

	// If c.onlyAccessibleFiles = true, then only files which are readable or writable are desired
	if c.onlyAccessibleFiles && !file.Readable && !file.Writable {
		chProcessResults <- &processResult{}
		return
	}

	// Get mime type
	mime, errMime := mimetype.DetectFile(file.Path)
	if errMime != nil {
		pErr, ok := errMime.(*os.PathError)
		if ok && !(errors.Is(pErr, os.ErrPermission) || pErr.Err.Error() == os.ErrPermission.Error()) {
			processLogger.Debugf("Could not detect the mime-type of '%s': %s", pErr.Path, pErr.Err)
		}
	}

	// According to the documentation this function will always return a valid mime struct, but let's be sure anyway.
	if mime != nil {
		file.Mime = mime.String()
	}

	// Get the custom properties
	customProps, errCustomProps := getCustomProperties(file.Path, c.logger)
	if errCustomProps != nil {
		c.logger.Debugf("custom property determination failed: %s [%s]", errCustomProps, file.Path)
		file.Properties = []string{}
	} else {
		file.Properties = customProps
	}

	// Send task and return
	chProcessResults <- &processResult{
		data:     file,
		newTasks: nil,
	}
}

// accessFile detects and returns if a file could be opened with a given flag (eg. readable/writable). If an error
// (other than a permission error) occurred it, is returned.
func accessFile(path string, flag int) (opened bool, err error) {

	// Try to open the file
	file, errOpen := os.OpenFile(path, flag, 0660) // the perm attribute does not matter, since no file is created
	if errOpen != nil {

		// Try to cast to path error
		errPath, isPathError := errOpen.(*os.PathError)

		// Check if it is a permission denied error, if yes return that file could not be opened
		if isPathError && (errors.Is(errPath, os.ErrPermission) || errPath.Err.Error() == os.ErrPermission.Error()) {
			return false, nil

			// If it is another error, additionally return the error
		} else {
			return false, errOpen
		}
	}

	// If opening was successful, close the handle and return true
	_ = file.Close()

	// Return that file could be opened
	return true, nil
}

// getCustomProperties retrieves the custom properties of OOXML files, by extracting their docProps/custom.xml file and
// returns a slice of strings in the form of "property: value"
func getCustomProperties(filepath string, logger utils.Logger) ([]string, error) {

	//Get OOXMLProperties struct with the names and values of the custom properties
	customFileProps, errOOXMLProps := getOOXMLProperties(filepath, logger)
	if errOOXMLProps != nil {
		return nil, fmt.Errorf("error while getting custom property names: %s [%s]", errOOXMLProps, filepath)
	}

	// If no custom properties were determined, the function returns with an empty result
	if customFileProps.Properties == nil {
		return []string{}, nil
	}

	// Create a string slice with all properties mapped to their values
	var customPropsResult []string
	for _, prop := range customFileProps.Properties {
		customPropsResult = append(customPropsResult, fmt.Sprintf("%s: %s", prop.Name, prop.GetVal()))
	}

	// Return found properties
	return customPropsResult, nil
}

// This function gets the properties specified in the Metadata (docProps/custom.xml) file of an OOXML-file
// (Office Open XML). It checks the OOXML-properties by opening them as a zip file and reading the docProps/custom.xml
func getOOXMLProperties(filepath string, logger utils.Logger) (*OOXMLProperties, error) {

	//Open file as zip
	readerZip, errOpen := zip.OpenReader(filepath)
	if errOpen != nil {
		if errOpen.Error() == "zip: not a valid zip file" { // this is not an error
			return &OOXMLProperties{}, nil
		}
		return nil, errOpen
	}
	defer func() {
		errClose := readerZip.Close()
		if errClose != nil {
			logger.Debugf("Could not close zip reader of '%s': %s", filepath, errClose)
		}
	}()

	// Get the docProps/custom.xml file
	var customPropsXML *zip.File
	for i := range readerZip.File {
		if readerZip.File[i].Name == OOXMLCustomPropertiesFile {
			customPropsXML = readerZip.File[i]
			break
		}
	}

	// Return if file with custom properties was not found, this is not an error, not all files have custom properties
	if customPropsXML == nil {
		return &OOXMLProperties{}, nil
	}

	// Get reader for docProps/custom.xml
	customPropsReader, errOpenProps := customPropsXML.Open()
	if errOpenProps != nil {
		return nil, fmt.Errorf("could not open '%s': %s", OOXMLCustomPropertiesFile, errOpenProps)
	}
	defer func() {
		errPropReaderClose := customPropsReader.Close()
		if errPropReaderClose != nil {
			logger.Debugf("Could not close file reader for '%s' of '%s': %s",
				OOXMLCustomPropertiesFile, filepath, errPropReaderClose)
		}
	}()

	// Get all content of the docProps/custom.xml file
	buf := &bytes.Buffer{}
	_, errCopy := io.Copy(buf, customPropsReader)
	if errCopy != nil {
		return nil, fmt.Errorf("could not get content of '%s': %s", customPropsXML.Name, errCopy)
	}

	// Unmarshal XML content of the docProps/custom.xml file
	var customProps OOXMLProperties
	errUnmarshal := xml.Unmarshal(buf.Bytes(), &customProps)
	if errUnmarshal != nil {
		return nil, fmt.Errorf("could not Unmarshal %s: %s", OOXMLCustomPropertiesFile, errUnmarshal)
	}

	// Return struct with extracted properties
	return &customProps, nil
}

// GetVal checks which tag was used for the property and returns its value as string
func (p *OOXMLProperty) GetVal() string {
	if p.ValStr != nil {
		return *p.ValStr
	}
	if p.ValInt != nil {
		return *p.ValInt
	}
	if p.ValDate != nil {
		return *p.ValDate
	}
	if p.ValBool != nil {
		return *p.ValBool
	}
	if p.ValFloat != nil {
		return *p.ValFloat
	}
	return ""
}
