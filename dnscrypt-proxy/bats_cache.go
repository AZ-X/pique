// Copyright 2020 The Go & AZ-X Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the go LICENSE file.

package main

import (
	"sync"
	"unsafe"
)

type Cache struct {
	*sync.RWMutex
	entries map[interface{}]*entry
	push chan interface{}
	push2 chan interface{}
	delete chan interface{}
	set chan *struct{K interface{}; V *entry}
	full chan bool
	keys *poolDequeue
}

type CloakCache struct {
	entries map[interface{}]*entry
}

type entry struct {
	p unsafe.Pointer
}

func newEntry(i interface{}) *entry {
	return &entry{p: unsafe.Pointer(&i)}
}

type poolDequeue struct {
	headTail uint64
	vals []eface
}
const dequeueBits = 32

type eface struct {
	typ, val unsafe.Pointer
}

const bufsize = 8
func NewCache(size int) *Cache {
	cache := &Cache{keys:&poolDequeue{vals: make([]eface, size),},RWMutex:&sync.RWMutex{},}
	cache.entries = make(map[interface{}]*entry, size)
	cache.keys.headTail = cache.keys.pack(1<<dequeueBits-1, 1<<dequeueBits-1)
	cache.push = make(chan interface{}, Min(size, bufsize))
	cache.push2 = make(chan interface{}, Min(size, bufsize))
	cache.delete = make(chan interface{}, Min(size, bufsize))
	cache.set = make(chan *struct{K interface{}; V *entry}, Min(size, bufsize))
	cache.full = make(chan bool, Min(size, bufsize))

	go func() {
		for {
			select {
			case key := <-cache.push:
			full := !cache.keys.pushHead(key)
			cache.full <- full
			case key := <-cache.push2:
			cache.keys.pushHead(key)
			case key := <-cache.delete:
			cache.Lock()
			delete(cache.entries, key)
			cache.Unlock()
			case kv := <-cache.set:
			cache.Lock()
			cache.entries[kv.K] = kv.V
			cache.Unlock()
			}
		}
	}()
	return cache
}

func NewCloakCache() *CloakCache {
	cache := &CloakCache{entries : make(map[interface{}]*entry),}
	return cache
}

func (m *CloakCache) Get(key interface{}) (value interface{}, ok bool) {
	e, ok := m.entries[key]
	if !ok {
		return nil, false
	}
	return e.load()
}

func (m *CloakCache) Add(key, value interface{}) {
	m.entries[key] = newEntry(value)
}

func (m *Cache) Size() int {
	return len(m.entries)
}

func (m *Cache) Get(key interface{}) (value interface{}, ok bool) {
	m.RLock()
	e, ok := m.entries[key]
	m.RUnlock()
	if !ok {
		return nil, false
	}
	return e.load()
}

func (m *Cache) Add(key, value interface{}) {
	m.RLock()
	if e, ok := m.entries[key]; ok && e.tryStore(&value) {
		m.RUnlock()
		return
	}
	m.RUnlock()
	m.push <- key
	if full := <- m.full; full {
		if evictee_key, ok := m.keys.popTail(); ok {
			m.push2 <- key
			m.RLock()
			if evictee, ok := m.entries[evictee_key]; ok {
				m.RUnlock()
				m.delete <- evictee_key
				evictee.delete()
			} else {
				m.RUnlock()
			}
		}
	}
	m.set <- &struct{K interface{}; V *entry}{K:key,V:newEntry(value)}
}

//go:linkname (*entry).load sync.(*entry).load
func (e *entry) load() (value interface{}, ok bool)

//go:linkname (*entry).tryStore sync.(*entry).tryStore
func (e *entry) tryStore(i *interface{}) bool

//go:linkname (*entry).delete sync.(*entry).delete
func (e *entry) delete() (value interface{}, ok bool)

//go:linkname (*poolDequeue).pushHead sync.(*poolDequeue).pushHead
func (d *poolDequeue) pushHead(val interface{}) bool

//go:linkname (*poolDequeue).popTail sync.(*poolDequeue).popTail
func (d *poolDequeue) popTail() (interface{}, bool)

//go:linkname (*poolDequeue).pack sync.(*poolDequeue).pack
func (d *poolDequeue) pack(head, tail uint32) uint64
