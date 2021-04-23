// Copyright 2011 The Go Authors. All rights reserved.
// Copyright 2021 The AZ-X Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package conceptions

import (
	"sync/atomic"
	_ "unsafe"
)

var (
	ErrSemaBoundary = &errSemaBoundary{}
	ErrSemaExcEntry = &errSemaExcEntry{}
)

type (
	errSemaBoundary struct{}
	errSemaExcEntry struct{}
)

func (e *errSemaBoundary) Error() string {
	return "reach permits"
}

func (e *errSemaExcEntry) Error() string {
	return "reach exclusive point"
}

//go:linkname sync_runtime_Semacquire sync.runtime_Semacquire
func sync_runtime_Semacquire(addr *uint32) 

//go:linkname sync_runtime_Semrelease sync.runtime_Semrelease
func sync_runtime_Semrelease(addr *uint32, handoff bool, skipframes int)

//go:linkname cansemacquire runtime.cansemacquire
func cansemacquire(addr *uint32) bool

type SemaGroup struct {
	permits, entry, semap uint32
}

func NewSemaGroup(threshold uint32) *SemaGroup {
	return &SemaGroup{permits:threshold, semap:threshold,}
}

func (sg *SemaGroup) Acquire(wait bool) error {
	if !atomic.CompareAndSwapUint32(&sg.entry, 0, 0) {
		return ErrSemaExcEntry
	}
	if !wait && !cansemacquire(&sg.semap) {
		return ErrSemaBoundary
	}
	sync_runtime_Semacquire(&sg.semap)
	return nil
}

func (sg *SemaGroup) Release() {
	sync_runtime_Semrelease(&sg.semap, false, 0)
}

func (sg *SemaGroup) BeginExclusive() bool {
	if !atomic.CompareAndSwapUint32(&sg.entry, 0, 1) {
		return false
	}
	for count := sg.permits; count != 0; count-- {
		sync_runtime_Semacquire(&sg.semap) // take out all
	}
	return true
}

func (sg *SemaGroup) EndExclusive() {
	for count := sg.permits; count != 0; count-- {
		sync_runtime_Semrelease(&sg.semap, false, 0) // give back all
	}
	if !atomic.CompareAndSwapUint32(&sg.entry, 1, 0) {
		panic("SemaGroup: sequential fault")
	}
}

func (sg *SemaGroup) Payload() uint32 {
	return sg.permits - atomic.LoadUint32(&sg.semap)
}