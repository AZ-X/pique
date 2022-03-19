package dlog

import (
	"flag"
	"fmt"
	"os"
	"time"
)

/*
To dboy:

There is no cross process read/write calling.

Thread Interactions with Regular File Operations
All of the following functions shall be atomic with respect to each other in the effects specified in POSIX.1-2017 when they operate on regular files or symbolic links:
chmod()
chown()
close()
creat()
dup2()
fchmod()
fchmodat()
fchown()

fchownat()
fcntl()
fstat()
fstatat()
ftruncate()
lchown()
link()
linkat()

lseek()
lstat()
open()
openat()
pread()
read()
readlink()
readlinkat()

readv()
pwrite()
rename()
renameat()
stat()
symlink()
symlinkat()
truncate()

unlink()
unlinkat()
utime()
utimensat()
utimes()
write()
writev()

*/

type Severity int32

type globals struct {
	logLevel       Severity
	useSyslog      *bool
	appName        string
	syslogFacility string
	systemLogger   *systemLogger
	fileName       *string
	outFd          *os.File
}

var (
	_globals = globals{
		appName:        "-",
	}
)

const (
	SeverityDebug Severity = iota
	SeverityInfo
	SeverityNotice
	SeverityWarning
	SeverityError
)

const (
	floodDelay      = 5 * time.Second
	floodMinRepeats = 3
)

var SeverityName = []string{
	SeverityDebug:    "DEBUG",
	SeverityInfo:     "INFO",
	SeverityNotice:   "NOTICE",
	SeverityWarning:  "WARNING",
	SeverityError:    "ERROR",
}

func Debugf(format string, args ...interface{}) {
	logf(SeverityDebug, format, args...)
}

func Infof(format string, args ...interface{}) {
	logf(SeverityInfo, format, args...)
}

func Noticef(format string, args ...interface{}) {
	logf(SeverityNotice, format, args...)
}

func Warnf(format string, args ...interface{}) {
	logf(SeverityWarning, format, args...)
}

type errorString string
func (e errorString) Error() string {
	return string(e)
}

func Errorf(format string, args ...interface{}) error {
	msg := errorString(*logf(SeverityError, format, args...))
	return msg
}

func Debug(message interface{}) {
	log(SeverityDebug, message)
}

func Info(message interface{}) {
	log(SeverityInfo, message)
}

func Notice(message interface{}) {
	log(SeverityNotice, message)
}

func Warn(message interface{}) {
	log(SeverityWarning, message)
}

func Error(message interface{}) {
	log(SeverityError, message)
}


func Init(appName string, logLevel Severity, syslogFacility string) error {
	_globals.logLevel = logLevel

	if len(syslogFacility) == 0 {
		syslogFacility = "DAEMON"
	}
	_globals.appName = appName
	_globals.syslogFacility = syslogFacility
	_globals.useSyslog = flag.Bool("syslog", false, "Send logs to the local system logger (Eventlog on Windows, syslog on Unix)")
	_globals.fileName = flag.String("logfile", "", "Write logs to file")
	return nil
}

func LogLevel() Severity {
	return _globals.logLevel
}

func SetLogLevel(logLevel Severity) {
	_globals.logLevel = logLevel
}

func UseSyslog(value bool) {
	_globals.useSyslog = &value
}

func UseLogFile(fileName string) {
	_globals.fileName = &fileName
}

func GetFileDescriptor() (*os.File) {
	createFileDescriptor()
	return _globals.outFd
}

func SetFileDescriptor(fd *os.File) {
	_globals.outFd = fd
}

func createFileDescriptor() {
	if _globals.fileName != nil && len(*_globals.fileName) > 0 && _globals.outFd == nil {
		outFd, err := os.OpenFile(*_globals.fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err == nil {
			_globals.outFd = outFd
		}
	}
}

func logf(severity Severity, format string, args ...interface{}) *string {
	if severity < _globals.logLevel {
		return nil
	}
	now := time.Now().Local()
	_, month, day := now.Date()
	hour, minute, second := now.Clock()
	message := fmt.Sprintf(format, args...)
	if *_globals.useSyslog && _globals.systemLogger == nil {
		systemLogger, err := newSystemLogger(_globals.appName, _globals.syslogFacility)
		if err == nil {
			_globals.systemLogger = systemLogger
		}
	}
	if _globals.systemLogger != nil {
		(*_globals.systemLogger).writeString(severity, message)
	} else {
		line := fmt.Sprintf("%02d-%02d %02d:%02d:%02d %5s| %s\n", month, day, hour, minute, second, SeverityName[severity], message)
		if _globals.outFd != nil {
			_globals.outFd.WriteString(line)
			_globals.outFd.Sync()
		} else {
			os.Stderr.WriteString(line)
		}
	}
	return &message
}

func log(severity Severity, args interface{}) {
	logf(severity, "%v", args)
}
