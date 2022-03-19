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

//go:linkname semacquire runtime.semacquire
func semacquire(addr *uint32)

//go:linkname semrelease runtime.semrelease
func semrelease(addr *uint32)

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
	if !wait && atomic.CompareAndSwapUint32(&sg.semap, 0, 0) {
		return ErrSemaBoundary
	}
	semacquire(&sg.semap)
	return nil
}

func (sg *SemaGroup) Release() {
	semrelease(&sg.semap)
}

func (sg *SemaGroup) BeginExclusive() bool {
	if !atomic.CompareAndSwapUint32(&sg.entry, 0, 1) {
		return false
	}
	for count := sg.permits; count != 0; count-- {
		semacquire(&sg.semap) // take out all
	}
	return true
}

func (sg *SemaGroup) EndExclusive() {
	for count := sg.permits; count != 0; count-- {
		semrelease(&sg.semap) // give back all
	}
	if !atomic.CompareAndSwapUint32(&sg.entry, 1, 0) {
		panic("SemaGroup: sequential fault")
	}
}

func (sg *SemaGroup) Payload() uint32 {
	return sg.permits - atomic.LoadUint32(&sg.semap)
}
