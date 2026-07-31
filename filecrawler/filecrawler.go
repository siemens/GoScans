/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package filecrawler implements a scan module for crawling and extracting content from file systems and archives.
package filecrawler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/siemens/GoScans/utils"
)

// EntryPoint holds the start information for a crawl.
type EntryPoint struct {
	Path      string
	Share     string // The share in which the object is located
	IsShare   bool   // Marks if the crawled object itself is the share
	InsideDfs bool
}

// File holds all metadata and access information discovered for a single file system entry.
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

// Result aggregates the crawl statistics and all discovered file entries for a single crawl run.
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

// processResult holds the output of a single goroutine processing step: the optional file data and any new tasks spawned.
type processResult struct {
	isReadableDir bool  // Is needed for calculating how many folders where crawled (we don't count unaccessible ones)
	data          *File // The actual result data for this file
	newTasks      []*task
}

// task holds the path and metadata of a file system entry queued for processing by the crawler.
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

// maxCustomPropsBytes caps how many bytes are read from docProps/custom.xml into memory. A zip entry can advertise any
// uncompressed size, so without this cap a crafted archive (zip bomb) could exhaust heap when the entry is read. 10 MiB
// is many times larger than any legitimate Office custom-properties block.
const maxCustomPropsBytes = 10 * 1024 * 1024

// OOXMLProperties mirrors the xml structure of custom property metadata of OpenOffice Files
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

// Crawler is the main file system crawling scanner.
type Crawler struct {
	logger                    utils.Logger
	crawlDepth                int
	excludedFolders           map[string]struct{} // lowercase list of folder names to exclude from crawling
	excludedExtensions        map[string]struct{} // lowercase list of file extensions without '.' to exclude from crawling
	excludedLastModifiedBelow time.Time
	excludedFileSizeBelow     int64
	onlyAccessibleFiles       bool            // Whether to only return files in results that are at least read or writable. Otherwise, also found files that were not accessible are listed.
	threads                   int             // Amount of threads sending requests in parallel
	context                   context.Context // Context for the crawling, controllable from outside
}

// NewCrawler initialises a Crawler with the given configuration and returns it ready to call Crawl.
func NewCrawler(
	logger utils.Logger,
	maxDepth int,
	excludedFolders map[string]struct{}, // values must be converted to lowercase first!
	excludedExtensions map[string]struct{}, // values must be converted to lowercase first!
	excludedLastModifiedBelow time.Time,
	excludedFileSizeBelow int64,
	onlyAccessibleFiles bool,
	threads int,
	context context.Context,
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
		context:                   context,
	}
}

// Crawl crawls the filesystem beginning at the given entry point. For every element it discovers, a new processing task
// is generated, back-feeding the crawler.
func (c *Crawler) Crawl(entryPoint *EntryPoint) *Result {

	// Initialize result data
	result := &Result{
		Status: utils.StatusCompleted,
	}

	// Check that root is not nil
	if entryPoint == nil {
		c.logger.Debugf("Invalid crawl entry point.")
		return result
	}

	// Check that root it not empty
	if *entryPoint == (EntryPoint{}) {
		c.logger.Debugf("Invalid crawl entry point.")
		return result
	}

	// Check whether access is possible
	rootInfo, errRootInfo := os.Lstat(entryPoint.Path)
	if errRootInfo != nil {
		var pErr *os.PathError
		if errors.As(errRootInfo, &pErr) {
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
	if utils.ContextExpired(c.context) {
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

	// Manage crawling. Launch new tasks, listen for results and queue new URLs until done or scan timeout
	for {

		// Do not continue feeding the crawler if scan time is reached
		if utils.ContextExpired(c.context) {
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
			c.logger.Errorf("Panic: %s%s", r, utils.StacktraceIndented("\t"))
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
	info, errInfo := os.Lstat(folderTask.path)
	if errInfo != nil {
		var pErr *os.PathError
		ok := errors.As(errInfo, &pErr)
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
	content, errContent := os.ReadDir(folderTask.path)
	if errContent != nil { // Log if an unexpected error occurred
		var pErr *os.PathError
		ok := errors.As(errContent, &pErr)
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
			c.logger.Errorf("Panic: %s%s", r, utils.StacktraceIndented("\t"))
			panic(r)
		}
	}()

	// Get more info about file, if not possible then abort
	info, errInfo := os.Lstat(fileTask.path)
	if errInfo != nil {
		var pErr *os.PathError
		ok := errors.As(errInfo, &pErr)
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
	readable, errReadable := utils.AccessFile(file.Path, os.O_RDONLY)
	if errReadable != nil {
		c.logger.Debugf("Could not fully detect file permissions: %s", errReadable)
	}
	file.Readable = readable

	// Check write rights
	writable, errWritable := utils.AccessFile(file.Path, os.O_WRONLY)
	if errWritable != nil {
		c.logger.Debugf("Could not fully detect file permissions: %s", errWritable)
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
		var pErr *os.PathError
		ok := errors.As(errMime, &pErr)
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
		c.logger.Debugf("Could not determine custom properties of '%s': %s", file.Path, errCustomProps)
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

// getCustomProperties retrieves the custom properties of OOXML files, by extracting their docProps/custom.xml file and
// returns a slice of strings in the form of "property: value"
func getCustomProperties(filePath string, logger utils.Logger) ([]string, error) {

	// Get OOXMLProperties struct with the names and values of the custom properties
	customFileProps, errCustomFileProps := getOOXMLProperties(filePath, logger)
	if errCustomFileProps != nil {
		return nil, fmt.Errorf("could not get custom property names: %w", errCustomFileProps)
	}

	// If no custom properties were determined, the function returns with an empty result
	if len(customFileProps.Properties) == 0 {
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

// getOOXMLProperties parses the custom metadata from the docProps/custom.xml entry of an OOXML file
// (Office Open XML) by opening the file as a zip archive.
func getOOXMLProperties(filePath string, logger utils.Logger) (*OOXMLProperties, error) {

	// Open file as zip
	readerZip, errReaderZip := zip.OpenReader(filePath)
	if errReaderZip != nil {
		if errReaderZip.Error() == "zip: not a valid zip file" { // this is not an error
			return &OOXMLProperties{}, nil
		}
		return nil, errReaderZip
	}
	defer func() {
		errClose := readerZip.Close()
		if errClose != nil {
			logger.Debugf("Could not close zip reader of '%s': %s", filePath, errClose)
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
	customPropsReader, errCustomPropsReader := customPropsXML.Open()
	if errCustomPropsReader != nil {
		return nil, fmt.Errorf("could not open '%s': %w", OOXMLCustomPropertiesFile, errCustomPropsReader)
	}
	defer func() {
		errPropReaderClose := customPropsReader.Close()
		if errPropReaderClose != nil {
			logger.Debugf("Could not close file reader for '%s' of '%s': %s",
				OOXMLCustomPropertiesFile, filePath, errPropReaderClose)
		}
	}()

	// Get all content of the docProps/custom.xml file, bounded by maxCustomPropsBytes to prevent a zip-bomb DoS.
	// Reading maxCustomPropsBytes+1 lets us distinguish "exactly at the cap" from "over the cap" after the copy.
	buf := &bytes.Buffer{}
	_, errCopy := io.Copy(buf, io.LimitReader(customPropsReader, maxCustomPropsBytes+1))
	if errCopy != nil {
		return nil, fmt.Errorf("could not get content of '%s': %w", customPropsXML.Name, errCopy)
	}
	if buf.Len() > maxCustomPropsBytes {
		return nil, fmt.Errorf("'%s' in '%s' exceeds %d-byte limit", customPropsXML.Name, filePath, maxCustomPropsBytes)
	}

	// Unmarshal XML content of the docProps/custom.xml file
	var customProps OOXMLProperties
	errUnmarshal := xml.Unmarshal(buf.Bytes(), &customProps)
	if errUnmarshal != nil {
		return nil, fmt.Errorf("could not unmarshal %s: %w", OOXMLCustomPropertiesFile, errUnmarshal)
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
