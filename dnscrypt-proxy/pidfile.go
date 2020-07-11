//MIT License
//
//Copyright (c) 2019 明城
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
//@ref https://raw.githubusercontent.com/mingcheng/pidfile/master/pidfile.go

// Package pidfile provides structure and helper functions to create and remove
// PID file. A PID file is usually a file used to store the process ID of a
// running process.
//
// @ref https://github.com/moby/moby/tree/master/pkg/pidfile
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Common error for pidfile package
var (
	ErrProcessRunning = errors.New("process is running")
	ErrFileStale      = errors.New("pidfile exists but process is not running")
	ErrFileInvalid    = errors.New("pidfile has invalid contents")
	pidfile           = flag.String("pidfile", "pidfile", "If specified, write pid to file.")

)

// PIDFile is a file used to store the process ID of a running process.
type PIDFile struct {
	path string
	pid  int
}

// New creates a PIDfile using the specified path.
func NewPidFile() (*PIDFile, error) {
	var file = PIDFile{
		path: *pidfile,
		pid:  os.Getpid(),
	}

	if pid, err := file.Content(); err == nil || processExists(pid) {
		return nil, ErrProcessRunning
	}

	if err := file.Write(); err != nil {
		return nil, err
	}

	return &file, nil
}

// Remove the PIDFile.
func (file PIDFile) Remove() error {
	return os.Remove(file.path)
}

// Read the PIDFile content.
func (file PIDFile) Content() (int, error) {
	if contents, err := ioutil.ReadFile(file.path); err != nil {
		return 0, err
	} else {
		pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
		if err != nil || file.pid != pid {
			return 0, ErrFileInvalid
		}

		return pid, nil
	}
}

// Write writes a pidfile, returning an error
// if the process is already running or pidfile is orphaned
func (file PIDFile) Write() error {
	return file.WriteControl(os.Getpid(), false)
}

func (file PIDFile) WriteControl(pid int, overwrite bool) error {
	// Check for existing pid
	if oldPid, err := file.Content(); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		// We have a pid
		if processExists(oldPid) {
			return ErrProcessRunning
		}
		if !overwrite {
			return ErrFileStale
		}
	}

	// Note MkdirAll returns nil if a directory already exists
	if err := os.MkdirAll(filepath.Dir(file.path), os.FileMode(0700)); err != nil {
		return err
	}

	// You're clear to (over)write the file
	f, err := ioutil.TempFile(filepath.Dir(file.path), filepath.Base(file.path))
	if err != nil {
		return err
	}
	if err = os.Chmod(f.Name(), 0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	defer f.Close()
	if err = ioutil.WriteFile(f.Name(), []byte(fmt.Sprintf("%d\n", pid)), 0600); err != nil {
		return err
	}
	f.Close()
	if err := os.Rename(f.Name(), file.path); err != nil {
		return err
	}
	return err
}

// Detect whether is process is running.
func (file PIDFile) Running() bool {
	return processExists(file.pid)
}