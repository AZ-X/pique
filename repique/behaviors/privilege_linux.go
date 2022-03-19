package behaviors

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	unix "syscall"

	"github.com/jedisct1/dlog"
)

// fcntl64Syscall is usually SYS_FCNTL, but is overridden on 32-bit Linux
// systems by fcntl_linux_32bit.go to be SYS_FCNTL64.
var fcntl64Syscall uintptr = syscall.SYS_FCNTL

func fcntl(fd int, cmd, arg int) (int, error) {
	valptr, _, errno := syscall.Syscall(fcntl64Syscall, uintptr(fd), uintptr(cmd), uintptr(arg))
	var err error
	if errno != 0 {
		err = errno
	}
	return int(valptr), err
}

// FcntlInt performs a fcntl syscall on fd with the provided command and argument.
func FcntlInt(fd uintptr, cmd, arg int) (int, error) {
	return fcntl(int(fd), cmd, arg)
}

func DropPrivilege(userStr string, fds []*os.File) {
	currentUser, err := user.Current()
	if err != nil && currentUser.Uid != "0" {
		panic("root privileges are required in order to switch to a different user. Maybe try again with 'sudo'")
	}
	userInfo, err := user.Lookup(userStr)
	args := os.Args

	if err != nil {
		uid, err2 := strconv.Atoi(userStr)
		if err2 != nil || uid <= 0 {
			panic(err)
		}
		dlog.Warnf("faild to retrieve any information about user [%s]: [%s] - Switching to user id [%v] with the same group id, as [%v] looks like a user id. But you should remove or fix the user_name directive in the configuration file if possible", userStr, err, uid, uid)
		userInfo = &user.User{Uid: userStr, Gid: userStr}
	}
	uid, err := strconv.Atoi(userInfo.Uid)
	if err != nil {
		panic(err)
	}
	gid, err := strconv.Atoi(userInfo.Gid)
	if err != nil {
		panic(err)
	}
	execPath, err := exec.LookPath(args[0])
	if err != nil {
		panic("faild to get the path to the repique executable file: " + err.Error())
	}
	path, err := filepath.Abs(execPath)
	if err != nil {
		panic(err)
	}

	args = append(args, "-child")

	dlog.Notice("dropping privileges")

	runtime.LockOSThread()
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(0), uintptr(0), 0); rcode != 0 {
		panic("faild to drop additional groups: " + rcode.Error())
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); rcode != 0 {
		panic("faild to drop group privileges: " + rcode.Error())
	}
	if _, _, rcode := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); rcode != 0 {
		panic("faild to drop user privileges: " + rcode.Error())
	}
	maxfd := uintptr(0)
	for _, fd := range fds {
		if fd.Fd() > maxfd {
			maxfd = fd.Fd()
		}
	}
	fdbase := maxfd + 1
	for i, fd := range fds {
		if err := unix.Dup2(int(fd.Fd()), int(fdbase+uintptr(i))); err != nil {
			panic("faild to clone file descriptor: " + err.Error())
		}
		if _, err := FcntlInt(fd.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			panic("faild to set the close on exec flag: " + err.Error())
		}
	}
	for i := range fds {
		if err := unix.Dup2(int(fdbase+uintptr(i)), int(i)+3); err != nil {
			panic("faild to reassign descriptor: " + err.Error())
		}
	}
	err = unix.Exec(path, args, os.Environ())
	os.Exit(1)
}
