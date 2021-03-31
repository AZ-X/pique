package behaviors

import (
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Alternative thing of 
/*
https://github.com/howeyc/fsnotify
https://github.com/fsnotify/fsnotify
*/// in the world by AZ-X. You are lucky to see these messages since https://github.com/golang/go/issues/44593 was public


type watcher struct {
	folder                             string
	files                              []fs
	win_handle                         syscall.Handle
}

type fs struct {
	filepath                           string
	lastinfo                           *atomic.Value //os.FileInfo
	callback                           func()
}

var (
	once                               sync.Once
	reset                              syscall.Handle
	register                           chan *struct{filename string; callback func()}
	fswatcher                          []watcher
	modkernel32                        = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstChangeNotificationW   = modkernel32.NewProc("FindFirstChangeNotificationW")
	procFindNextChangeNotification     = modkernel32.NewProc("FindNextChangeNotification")
	procFindCloseChangeNotification    = modkernel32.NewProc("FindCloseChangeNotification")
	procWaitForMultipleObjects         = modkernel32.NewProc("WaitForMultipleObjects")
	procCreateEventW                   = modkernel32.NewProc("CreateEventW")
	procResetEvent                     = modkernel32.NewProc("ResetEvent")
	procSetEvent                       = modkernel32.NewProc("SetEvent")
)

//go:linkname fixLongPath os.fixLongPath
func fixLongPath(path string) string

func findFirstChangeNotification(lpPathName *uint16, bWatchSubtree bool, mask uint32) (handle syscall.Handle, err error) {
	var watchSubtree uint32
	if bWatchSubtree {
		watchSubtree = 1
	}
	r, _, e := syscall.Syscall(procFindFirstChangeNotificationW.Addr(), 3, uintptr(unsafe.Pointer(lpPathName)), uintptr(watchSubtree), uintptr(mask))
	handle = syscall.Handle(r)
	switch e {
	case 0: err = nil
	default: err = e
	}
	return
}

func findNextChangeNotification(hChangeHandle syscall.Handle) bool {
	r, _, e := syscall.Syscall(procFindNextChangeNotification.Addr(), 1, uintptr(hChangeHandle), 0, 0)
	return e == 0 && r == 1
}

func findCloseChangeNotification(hChangeHandle syscall.Handle) bool {
	r, _, e := syscall.Syscall(procFindCloseChangeNotification.Addr(), 1, uintptr(hChangeHandle), 0, 0)
	return e == 0 && r == 1
}

func waitForMultipleObjects(lpHandles []syscall.Handle, bWaitAll bool, dwMilliseconds uint32) (dwWaitStatus uint32, err error) {
	var handlePtr = &lpHandles[0]
	var waitAll uint32
	if bWaitAll {
		waitAll = 1
	}
	r, _, e := syscall.Syscall6(procWaitForMultipleObjects.Addr(), 4, uintptr(len(lpHandles)), uintptr(unsafe.Pointer(handlePtr)), uintptr(waitAll), uintptr(dwMilliseconds), 0, 0)
	dwWaitStatus = uint32(r)
	switch e {
	case 0: err = nil
	default: err = e
	}
	return
}

func createEvent(eventAttrs *syscall.SecurityAttributes, manualReset uint32, initialState uint32, name *uint16) (handle syscall.Handle, err error) {
	r, _, e := syscall.Syscall6(procCreateEventW.Addr(), 4, uintptr(unsafe.Pointer(eventAttrs)), uintptr(manualReset), uintptr(initialState), uintptr(unsafe.Pointer(name)), 0, 0)
	handle = syscall.Handle(r)
	switch e {
	case 0: err = nil
	default: err = e
	}
	return
}

func resetEvent(hEvent syscall.Handle) bool {
	r, _, e := syscall.Syscall(procResetEvent.Addr(), 1, uintptr(hEvent), 0, 0)
	return e == 0 && r == 1
}

func setEvent(hEvent syscall.Handle) bool {
	r, _, e := syscall.Syscall(procSetEvent.Addr(), 1, uintptr(hEvent), 0, 0)
	return e == 0 && r == 1
}

func satisfyCallback(idx int) {
	for _, fs := range fswatcher[idx].files {
		lastinfo := fs.lastinfo.Load().(os.FileInfo)
		if info, err := os.Stat(fs.filepath); err != nil {
			panic("fswatcher_init failed:" + err.Error())
		} else if info.Size() != lastinfo.Size() || info.ModTime() != lastinfo.ModTime() {
			fs.lastinfo.Store(info)
			fs.callback()
		}
	}
}

func fswatcher_loop () {
	for {
		var lpHandles []syscall.Handle
		lpHandles = append(lpHandles, reset)
		for _, w := range fswatcher {
			lpHandles = append(lpHandles, w.win_handle)
		}
		if dwWaitStatus, err := waitForMultipleObjects(lpHandles, false, syscall.INFINITE); err != nil {
			panic(err)
		} else {
			switch dwWaitStatus {
				case syscall.WAIT_OBJECT_0: if !resetEvent(reset) {panic("fswatcher_loop: failed to call ResetEvent")}
				case syscall.WAIT_TIMEOUT: panic("fswatcher_loop: timeout on infinite parameter")
				case syscall.WAIT_FAILED: break
				default:idx := int(dwWaitStatus) - syscall.WAIT_OBJECT_0 - 1
						if idx < 0 || idx > len(fswatcher) -1 {panic("fswatcher_loop: status invaild") }
						if !findNextChangeNotification(fswatcher[idx].win_handle) {
							panic("fswatcher_loop: failed to call FindNextChangeNotification")
						}
						time.Sleep(500 * time.Millisecond)
						go satisfyCallback(idx)
			}
		}
	}
}

func fswatcher_init () {
	register = make(chan *struct{filename string; callback func()})
	go func(){
		var err error
		if reset, err = createEvent(nil, 0, 0, nil); err != nil {
			panic(err)
		}
		go fswatcher_loop()
		for {
			select {
			case reg := <- register:
				if path0, err := filepath.Abs(reg.filename); err != nil {
					panic("fswatcher_init failed:" + err.Error())
				} else {
					dir := fixLongPath(path.Dir(path0))
					var fs0 fs
					if info, err := os.Stat(path0); err != nil {
						panic("fswatcher_init failed:" + err.Error())
					} else {
						fs0 = fs{filepath:path0, lastinfo:&atomic.Value{},callback:reg.callback}
						fs0.lastinfo.Store(info)
					}
					var found bool
					for _, w := range fswatcher {
						if w.folder == dir {
							found = true
							w.files = append(w.files, fs0)
							break
						}
					}
					if !found {
						path_ptr, _ := syscall.UTF16PtrFromString(dir)
						if handle, err := findFirstChangeNotification(path_ptr, false, syscall.FILE_NOTIFY_CHANGE_LAST_WRITE); err != nil {
							panic("fswatcher_init failed:" + err.Error())
						} else {
							w := watcher{folder:dir, files:[]fs{fs0}, win_handle:handle}
							fswatcher = append(fswatcher, w)
							if !setEvent(reset) {
								panic("fswatcher_init failed to call SetEvent")
							}
						}
					}
				}
			}
		}
	}()
}

func RegisterFswatcher(filename string, callback func()) {
	once.Do(fswatcher_init)
	register <- &struct{filename string; callback func()}{filename:filename, callback:callback}
}