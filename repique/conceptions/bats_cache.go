// Copyright 2022 The Go & AZ-X Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the go LICENSE file.

package conceptions

import (
	"sync/atomic"
	"unsafe"
	
	"github.com/AZ-X/pique/repique/common"
)

type Cache struct {
	snapshot *atomic.Value //map[interface{}]*entry
	set chan *struct{K interface{}; V *entry}
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

const bufsize = 8
func NewCache(size int) *Cache {
	cache := &Cache{snapshot: &atomic.Value{},}
	cache.set = make(chan *struct{K interface{}; V *entry}, common.Min(size, bufsize))
	cache.snapshot.Store(map[interface{}]*entry{})

	go func(window int) {
		type (
			revolver struct {
				entries []*entry
				pos int
				reload func(interface{}) interface{}
			}
		)
		var fresh map[interface{}]*entry
		var r *revolver
		r = &revolver{make([]*entry, window), 0,
			func (val interface{}) (evictee interface{}) {
				defer func () {r.pos = (r.pos + 1) % window}()
				if e := r.entries[r.pos]; e != nil {
					if v, ok := e.load(); ok {
						defer func() { evictee = v }()
					}
					if e.tryStore(&val) {
						return nil
					}
				}
				r.entries[r.pos] = newEntry(val)
				return nil
			},
		}
		for {
			select {
			case kv := <-cache.set:
			func() {
				value, _ := kv.V.load()
				if fresh == nil {
					snapshot := cache.snapshot.Load().(map[interface{}]*entry)
					if e, ok := snapshot[kv.K]; ok && e.tryStore(&value) {
						return
					}
					if len(snapshot) == len(r.entries) {
						fresh = make(map[interface{}]*entry, len(r.entries))
					} else {
						fresh = make(map[interface{}]*entry)
					}
					for k, v := range snapshot {
						fresh[k] = v
					}
				}
				defer func() {
					if(len(cache.set) == 0) {
						cache.snapshot.Store(fresh)
						fresh = nil
					}
				}()
				found := false
				if e, found := fresh[kv.K]; found && e.tryStore(&value) {
					return
				}
				if k := r.reload(kv.K); k != nil {
					if e, ok := fresh[k]; ok {
						e.delete()
						delete(fresh, k)
					}
				}
				if !found && len(fresh) == len(r.entries) {
					panic("key not found in cache")
				}
				fresh[kv.K] = kv.V
			}()
			}
		}
	}(size)
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

func (m *Cache) Get(key interface{}) (value interface{}, ok bool) {
	snapshot := m.snapshot.Load().(map[interface{}]*entry)
	if snapshot != nil {
		e, ok := snapshot[key]
		if ok { return e.load() }
	}
	return nil, false
}

func (m *Cache) Add(key, value interface{}) {
	snapshot := m.snapshot.Load().(map[interface{}]*entry)
	if snapshot != nil {
		if e, ok := snapshot[key]; ok && e.tryStore(&value) {
			return
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

////go:linkname (*poolDequeue).pushHead sync.(*poolDequeue).pushHead
//func (d *poolDequeue) pushHead(val interface{}) bool
//
////go:linkname (*poolDequeue).popTail sync.(*poolDequeue).popTail
//func (d *poolDequeue) popTail() (interface{}, bool)
//
////go:linkname (*poolDequeue).pack sync.(*poolDequeue).pack
//func (d *poolDequeue) pack(head, tail uint32) uint64
