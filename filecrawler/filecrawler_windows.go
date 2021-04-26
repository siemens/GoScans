package filecrawler

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/go-ole/go-ole"
	"go-scans/utils"
	"go-scans/utils/windows_systemcalls"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const OOXMLCustomPropertiesFile = "docProps/custom.xml"

type OOXMLProperties struct {
	XMLName    xml.Name        `xml:"Properties"` // Important when adding attributes, always use uppercase for it, otherwise unmarshalling might not work
	Properties []OOXMLProperty `xml:"property"`
}

type OOXMLProperty struct {
	Fmtid  string `xml:"fmtid,attr"`
	Pid    string `xml:"pid,attr"`
	Name   string `xml:"name,attr"`
	ValStr string `xlm:"lpwstr"`
}

var IPropertyStoreGuid = ole.NewGUID("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99")

// prepareCrawling prepares the OS to crawl files
func prepareCrawling(logger utils.Logger) error {

	// Initialize the COM library, which is needed for getting file properties with the property store
	errComIni := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)

	// No error means success. In COM, error code 1 means success but with a problem, in this case that the COM library
	// was already initialized. https://docs.microsoft.com/en-us/windows/win32/learnwin32/error-handling-in-com
	if errComIni != nil {
		oleErr, ok := errComIni.(*ole.OleError) // Convert to OleError for better handling
		if !ok {
			return errComIni
		}
		if oleErr.Code() == 1 {
			logger.Debugf("The COM library is already initialized on this thread.")
			return nil
		}
		return oleErr
	}

	// Return nil as everything went fine
	return nil
}

// cleanupCrawling restores preparations of the OS that were required to crawl files
func cleanupCrawling() {

	// Un-initialize the COM library
	ole.CoUninitialize()
}

// getCustomProperties retrieves the custom properties of OOXML files, by extracting their docProps/custom.xml file
func getCustomProperties(filepath string, logger utils.Logger) ([]string, error) {

	//Get OOXMLProperties struct with the names and property keys of the custom properties
	customFileProps, errOOXMLProps := getOOXMLProperties(filepath, logger)
	if errOOXMLProps != nil {
		return nil, fmt.Errorf("error while getting custom property name: %s [%s]", errOOXMLProps, filepath)
	}

	// If no custom property names were determined to look up their values, the function returns with an empty result
	if customFileProps.Properties == nil {
		return []string{}, nil
	}

	// Determine the values of the property names and add them to the OOXMLProperties struct
	errMapProps := customFileProps.determinePropertyValues(filepath, logger)
	if errMapProps != nil {
		return nil, errMapProps
	}

	// Create string slice with all properties mapped to their values, e.g. "property: value"
	var customPropsResult []string
	for _, prop := range customFileProps.Properties {
		customPropsResult = append(customPropsResult, fmt.Sprintf("%s: %s", prop.Name, prop.ValStr))
	}

	// Return found properties
	return customPropsResult, nil
}

// This function gets the properties specified in the Metadata (docProps/custom.xml) file of an OOXML-file
// (Office Open XML)
func getOOXMLProperties(filepath string, logger utils.Logger) (*OOXMLProperties, error) {

	//Open file as zip
	readerZip, errOpen := zip.OpenReader(filepath)
	if errOpen != nil {
		return &OOXMLProperties{}, nil // Is not an error
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

// This function maps the properties from OOXMLProperties to their values and writes them to the corresponding
// OOXMLProperty.ValStr
func (p *OOXMLProperties) determinePropertyValues(filePath string, logger utils.Logger) error {

	// Get property store of the file for querying the property values
	propertyStore, errGetPS := getPropertyStore(filePath)
	if errGetPS != nil {
		if errGetPS.Error() == "not an error" { // Some errors are to be expected and do not need to be logged or handled
			return nil
		}
		return errGetPS
	}
	if propertyStore == nil {
		return fmt.Errorf("returend propertystore pointer was a nil pointer")
	}
	defer propertyStore.Release()

	// Iterate through all property names, querying their corresponding values
	for i, property := range p.Properties {

		// Convert the pid to uint32
		pidUInt32, errParseInt := strconv.ParseUint(property.Pid, 10, 32)
		if errParseInt != nil {
			logger.Debugf("Could not convert PID to int of '%s' from '%s'", property.Name, filePath)
			continue
		}

		//Create a property key structure from given property
		propKey := windows_systemcalls.PROPERTYKEY{
			GUID: *ole.NewGUID(property.Fmtid),
			PID:  uint32(pidUInt32),
		}

		// Get the untyped property value
		val, errPropVal := pSGetPropertyValue(propertyStore, propKey)
		if errPropVal != nil {
			logger.Debugf("Could not get value of '%s': %s [%s]", property.Name, errPropVal, filePath)
			continue
		}

		// Convert the value to string and assign it to OOXMLProperty.ValStr
		p.Properties[i].ValStr = fmt.Sprint(val)
	}

	// Return nil as everything went fine
	return nil
}

// Returns true if a property with that name or propertykey and pid is contained
func (p *OOXMLProperties) containsSimilar(propToTest OOXMLProperty) bool {
	for _, prop := range p.Properties {
		if prop.Name == propToTest.Name || (prop.Fmtid == propToTest.Fmtid && prop.Pid == propToTest.Pid) {
			return true
		}
	}
	return false
}

// Get a property store for the given file
func getPropertyStore(filepath string) (*windows_systemcalls.IPropertyStore, error) {

	// Convert path string to a UTF16 pointer for the syscall
	filepathUTF16, errStrUTF16 := syscall.UTF16PtrFromString(filepath)
	if errStrUTF16 != nil {
		return nil, fmt.Errorf("could not convert string to utf16-pointer: %s", errStrUTF16)
	}

	// Get the property store object of the file
	var propStorePtr *windows_systemcalls.IPropertyStore
	errGetPS := windows_systemcalls.SHGetPropertyStoreFromParsingName(
		filepathUTF16, nil, windows_systemcalls.GPS_DEFAULT, IPropertyStoreGuid, &propStorePtr)

	// Check for known unproblematic errors else return error
	if errGetPS != nil {
		if strings.Contains(errGetPS.Error(), "The specified resource type cannot be found in the image file") ||
			strings.Contains(errGetPS.Error(), "The specified image file did not contain a resource section") ||
			strings.Contains(errGetPS.Error(), "%1 already exists") {
			return nil, fmt.Errorf("not an error")
		}
		return nil, fmt.Errorf("could not get property store: %s", errGetPS)
	}

	// Return propertystore
	return propStorePtr, nil
}

// Get the value of the property specified by the property key from the given property store
func pSGetPropertyValue(
	propStore *windows_systemcalls.IPropertyStore, propertyKey windows_systemcalls.PROPERTYKEY) (interface{}, error) {

	// Get the value of the property
	var pv windows_systemcalls.PROPVARIANT
	errGV := propStore.GetValue(&propertyKey, &pv)
	if errGV != nil {
		return "", fmt.Errorf("could not get value from propertystore %s", errGV)
	}

	// Convert value to a Go typed value
	convValue, errValEx := pv.ValueExt()
	if errValEx != nil {
		return nil, fmt.Errorf("erro while converting property value: %s", errValEx)
	}

	// Return untyped value
	return convValue, nil
}

// getFileProperty gets the property referenced by the given property key. Property keys for windows defined
// properties can be found at: https://docs.microsoft.com/en-us/windows/win32/properties/props. Returned value needs
// to be converted further to corresponding type.
func getFileProperty(
	filepath string,
	propertyKey windows_systemcalls.PROPERTYKEY,
) (interface{}, error) {

	// Convert path string to a UTF16 pointer for the syscall
	filepathUTF16, errStrUTF16 := syscall.UTF16PtrFromString(filepath)
	if errStrUTF16 != nil {
		return "", fmt.Errorf("could not convert string to utf16-pointer: %s", errStrUTF16)
	}

	// Get the property store object of the file
	var propStorePtr *windows_systemcalls.IPropertyStore
	errGetPS := windows_systemcalls.SHGetPropertyStoreFromParsingName(
		filepathUTF16, nil, windows_systemcalls.GPS_DEFAULT, IPropertyStoreGuid, &propStorePtr)

	// Check for known unproblematic errors else return error
	if errGetPS != nil {
		if strings.Contains(errGetPS.Error(), "The specified resource type cannot be found in the image file") ||
			strings.Contains(errGetPS.Error(), "The specified image file did not contain a resource section") ||
			strings.Contains(errGetPS.Error(), "%1 already exists") {
			return "", nil
		}
		return "", fmt.Errorf("could not get property store: %s", errGetPS)
	}

	// Release the property store object
	defer propStorePtr.Release()

	// Get the value of the property
	var pv windows_systemcalls.PROPVARIANT
	errGV := propStorePtr.GetValue(&propertyKey, &pv)
	if errGV != nil {
		return "", fmt.Errorf("could not get value from propertystore %s", errGV)
	}

	// Convert value to a Go typed value
	convValue, errValEx := pv.ValueExt()
	if errValEx != nil {
		return nil, fmt.Errorf("erro while converting property value: %s", errValEx)
	}

	// Return untyped value
	return convValue, nil
}

func determineSymlinkPermissions(symlinkInfo *File, logger utils.Logger) {

	// Determine Read permission
	readable, errRead := accessSymlink(symlinkInfo.Path, syscall.GENERIC_READ)
	if errRead != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errRead)
	}
	symlinkInfo.Readable = readable

	// Determine Write permission
	writable, errWrite := accessSymlink(symlinkInfo.Path, syscall.GENERIC_WRITE)
	if errWrite != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errWrite)
	}
	symlinkInfo.Writable = writable
}

// accessSymlink detects and returns if a symlink could be opened with a given access flag, (eg. syscall.GENERIC_READ).
// We need to use the syscall CreateFile instead of Golang's OpenFile() since we need to specify to not follow symlinks.
func accessSymlink(path string, accessFlag uint32) (access bool, err error) {

	// Convert path to a UTF16 string
	pathUTF16, errUTF16 := syscall.UTF16PtrFromString(path)
	if errUTF16 != nil {
		return false, errUTF16
	}

	// Specify that file can be used by other processes while we open it
	sharemode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE)

	// Use FILE_FLAG_BACKUP_SEMANTICS to be able to open symlinks to folders.
	// Use FILE_FLAG_OPEN_REPARSE_POINT, otherwise CreateFile will follow symlink.
	attrs := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS | syscall.FILE_FLAG_OPEN_REPARSE_POINT)

	// Try to open file with the specified access flag
	fileHandle, errOpen := syscall.CreateFile(
		pathUTF16, accessFlag, sharemode, nil, syscall.OPEN_EXISTING, attrs, 0)
	if errOpen != nil {
		if errOpen == syscall.ERROR_ACCESS_DENIED {
			return false, nil
		} else {
			return false, errOpen
		}
	}

	// If opening was successful, close the handle and return true
	errClose := syscall.CloseHandle(fileHandle)
	if errClose != nil {
		return true, err // return additionally the error of the failed file handle closing
	}

	// Return flag that file could be accessed
	return true, nil
}

// getUnixFlags extracts unix file permissions of the fileMode, which are not existing on Windows
func getUnixFlags(fm os.FileMode) string {
	return ""
}
