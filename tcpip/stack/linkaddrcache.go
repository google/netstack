// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"sync"
	"time"

	"github.com/google/netstack/tcpip"
)

const linkAddrCacheSize = 512 // max cache entries

// linkAddrCache is a fixed-sized cache mapping IP addresses to link addresses.
//
// The entries are stored in a ring buffer, oldest entry replaced first.
type linkAddrCache struct {
	ageLimit time.Duration

	mu      sync.RWMutex
	cache   map[tcpip.FullAddress]*linkAddrEntry
	next    int // array index of next available entry
	entries [linkAddrCacheSize]linkAddrEntry
}

// A linkAddrEntry is an entry in the linkAddrCache.
type linkAddrEntry struct {
	addr       tcpip.FullAddress
	linkAddr   tcpip.LinkAddress
	expiration time.Time
}

func (c *linkAddrCache) valid(e *linkAddrEntry) bool {
	return time.Now().Before(e.expiration)
}

// add adds a k -> v mapping to the cache.
func (c *linkAddrCache) add(k tcpip.FullAddress, v tcpip.LinkAddress) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.cache[k]
	if entry != nil && entry.linkAddr == v && c.valid(entry) {
		return // Keep existing entry.
	}
	// Take next entry.
	entry = &c.entries[c.next]
	if c.cache[entry.addr] == entry {
		delete(c.cache, entry.addr)
	}
	*entry = linkAddrEntry{
		addr:       k,
		linkAddr:   v,
		expiration: time.Now().Add(c.ageLimit),
	}
	c.cache[k] = entry
	c.next++
	if c.next == len(c.entries) {
		c.next = 0
	}
}

// get reports any known link address for k.
func (c *linkAddrCache) get(k tcpip.FullAddress) (linkAddr tcpip.LinkAddress) {
	c.mu.RLock()
	if entry, found := c.cache[k]; found && c.valid(entry) {
		linkAddr = entry.linkAddr
	}
	c.mu.RUnlock()
	return linkAddr
}

func newLinkAddrCache(ageLimit time.Duration) *linkAddrCache {
	c := &linkAddrCache{
		ageLimit: ageLimit,
		cache:    make(map[tcpip.FullAddress]*linkAddrEntry, linkAddrCacheSize),
	}
	return c
}
