// +build !windows

package dlog

import (
	"log/syslog"
	"sync"
	_ "unsafe"
)

var severityToSyslogPriority = []syslog.Priority{
	SeverityDebug:    syslog.LOG_DEBUG,
	SeverityInfo:     syslog.LOG_INFO,
	SeverityNotice:   syslog.LOG_NOTICE,
	SeverityWarning:  syslog.LOG_WARNING,
	SeverityError:    syslog.LOG_ERR,
}

type serverConn interface {
	writeString(p syslog.Priority, hostname, tag, s, nl string) error
	close() error
}

type Writer struct {
	priority syslog.Priority
	tag      string
	hostname string
	network  string
	raddr    string

	mu   sync.Mutex // guards conn
	conn serverConn
}

type systemLogger struct {
	inner *Writer
}

func newSystemLogger(appName string, _ string) (*systemLogger, error) {
	eventLogger, err := New(syslog.LOG_INFO|syslog.LOG_DAEMON, appName)
	if err != nil {
		return nil, err
	}
	return &systemLogger{inner: eventLogger}, nil
}

func (systemLogger *systemLogger) writeString(severity Severity, message string) {
	(*systemLogger.inner).writeAndRetry(severityToSyslogPriority[severity], message)
}

//go:linkname New log/syslog.New
func New(priority syslog.Priority, tag string) (*Writer, error)

//go:linkname (*Writer).writeAndRetry log/syslog.(*Writer).writeAndRetry
func (w *Writer) writeAndRetry(p syslog.Priority, s string)