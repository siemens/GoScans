# GoScans
GoScans is a collection of network scan modules for infrastructure discovery and information gathering. You can also visit [Large-Scale Discovery](https://github.com/siemens/large-scale-discovery) to see it applied.

# Available scan modules
| Module                             | Linux | Windows | Windows (Domain) |
| -----------------------------------|:------| :-------| :----------------|
| **Discovery Module**               | ✔️    | ✔️     | ✔️          |
|   Device Discovery                 | ✔️    | ✔️     | ✔️          |
|   Port Enumeration                 | ✔️    | ✔️     | ✔️          |
|   Service Detection                | ✔️    | ✔️     | ✔️          |
|   Hostname Discovery               | ✔️    | ✔️     | ✔️          |
|   Enumeration of Admin/RDP Users   | ❌️    | ❌️     | ✔️*         |
|   Active Directory Enrichment      | ✔️**  | ✔️**   | ✔️          |
| **Banner Grabbing**                | ✔️    | ✔️     | ✔️          |
| **SMB Crawling**                   | ❌️    | ✔️     | ✔️          |
|   MIME Type Detection              |       | ✔️     | ✔️          |
|   Microsoft Information Protection |       | ✔️     | ✔️          |
| **NFS Crawling**                   | ✔️    | ✔️     | ✔️          |
|   NFSv3                            | ✔️    | ✔️     | ✔️          |
|   NFSv4                            | ✔️    | ❌️     | ❌️          |
|   Unix ACL Flags                   | ✔️    | ✔️     | ✔️          |
|   MIME Type Detection              | ✔️    | ✔️     | ✔️          |
|   Microsoft Information Protection | ✔️    | ✔️     | ✔️          |
| **Web Crawling**                   | ✔️    | ✔️     | ✔️          |
| **Web Enumeration**                | ✔️    | ✔️     | ✔️          |
| **SSL Enumeration**                | ✔️    | ✔️     | ✔️          |
| **SSH Enumeration**                | ✔️    | ✔️     | ✔️          |

&ast;&nbsp; Success generally depending on the domain configuration <br/>
&ast;&ast;  The configuration of AD credentials is required. In contrast, on Windows domain member machines, AD requests can be handled transparently with implicit authentication.

# Requirements
- The **discovery module** requires **Nmap** to be installed on the system
- The **SSL module** requires **SSLyze** to be installed on the system

# Module Usage
All modules work similarly and return a self-explaining result struct with all gathered information. 
Here is an example initializing a banner scan:

```go
// Prepare system configuration for scan module. For unity 
// and potential future use, all scan modules are equiped with 
// a setup function, allthough, not all of them need them.
errSetup := banner.Setup()
if errSetup != nil {
    fmt.Println("Setup failed: %s", errSetup)
    return
}

// Check system configuration for scan module. For unity 
// and potential future use, all scan modules are equiped with 
// a check function, allthough, not all of them need them.
errCheck := banner.CheckSetup()
if errCheck != nil {
    fmt.Println("Setup failed: %s", errCheck)
    return
}

// Initialize scan
t := 5 * time.Second
scanner, err := NewScanner(wrpLogger, "www.google.com", 443, t, t)
if err != nil {
    fmt.Println("Initialization failed: %s", err)
    return
}

// Run scan. This will be a blocking action, but you can do your 
// gouroutine and channels kung-fu.
result := scanner.Run()
```


# Logging
All scan modules require a logger to be passed during initialization. 
You can use any logger satisfying the defined logger interface.

If your logger does not implement all expected functions, you may wrap it like this:
```go
// Define wrapped logger
type LoggerWrapped struct {
	logger *log.Logger // interface definition
}

func (l *LoggerWrapped) Debugf(format string, v ...interface{}) { // Required function according to the interface
	l.logger.Printf(format+"\n", v...)
}
func (l *LoggerWrapped) Infof(format string, v ...interface{}) { // Required function according to the interface
	l.logger.Printf(format+"\n", v...)
}
func (l *LoggerWrapped) Warningf(format string, v ...interface{}) { // Required function according to the interface
	l.logger.Printf(format+"\n", v...)
}
func (l *LoggerWrapped) Criticalf(format string, v ...interface{}) { // Required function according to the interface
	l.logger.Printf(format+"\n", v...)
}
func (l *LoggerWrapped) Errorf(format string, v ...interface{}) { // Required function according to the interface
	l.logger.Printf(format+"\n", v...)
}

// Initialize original logger
stdLogger := log.New(os.Stdout, "", log.LstdFlags)

// Wrapp logger to satisfy interface
wrpLogger := &LoggerWrapped{stdLogger}

// Apply compatible wrapped logger
banner.NewScanner(wrpLogger ...)
```

Similarly, if you do not want log from the modules, you can create a void logger doing nothing with log messages.

# Result Data
Please have a look at the respective module's _**Result**_ struct. `result.Data` (and possibly its child structs) contains all the attributes gathered by the scan module:

- [Discovery](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/discovery/discovery.go#L124)
- [Banner](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/banner/banner.go#L55)
- [NFS](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/nfs/nfs.go#L52)
- [SMB](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/smb/smb.go#L35)
- [SSH](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/ssh/ssh.go#L62)
- [SSL](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/ssl/ssl.go#L210)
- [Webcrawler](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/webcrawler/webcrawler.go#L41)
- [Webenum](https://github.com/siemens/GoScans/blob/7b82dda3a0f1631ee7df672887242e93ce0b972a/webenum/webenum.go#L65)
