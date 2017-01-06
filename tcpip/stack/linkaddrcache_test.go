// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/netstack/tcpip"
)

type testaddr struct {
	addr     tcpip.FullAddress
	linkAddr tcpip.LinkAddress
}

var testaddrs []testaddr

func init() {
	for i := 0; i < 4*linkAddrCacheSize; i++ {
		addr := fmt.Sprintf("Addr%06d", i)
		testaddrs = append(testaddrs, testaddr{
			addr:     tcpip.FullAddress{NIC: 1, Addr: tcpip.Address(addr)},
			linkAddr: tcpip.LinkAddress("Link" + addr),
		})
	}
}

func TestCacheOverflow(t *testing.T) {
	c := newLinkAddrCache(1<<63 - 1)
	for i := len(testaddrs) - 1; i >= 0; i-- {
		e := testaddrs[i]
		c.add(e.addr, e.linkAddr)
		if got, want := c.get(e.addr), e.linkAddr; got != want {
			t.Errorf("insert %d, c.get(%q)=%q, want %q", i, string(e.addr.Addr), got, want)
		}
	}
	// Expect to find at least half of the most recent entries.
	for i := 0; i < linkAddrCacheSize/2; i++ {
		e := testaddrs[i]
		if got, want := c.get(e.addr), e.linkAddr; got != want {
			t.Errorf("check %d, c.get(%q)=%q, want %q", i, string(e.addr.Addr), got, want)
		}
	}
	// The earliest entries should no longer be in the cache.
	for i := len(testaddrs) - 1; i >= len(testaddrs)-linkAddrCacheSize; i-- {
		e := testaddrs[i]
		if got := c.get(e.addr); got != "" {
			t.Errorf("check %d, c.get(%q)=%q, want no entry", i, string(e.addr.Addr), got)
		}
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newLinkAddrCache(1<<63 - 1)

	var wg sync.WaitGroup
	for r := 0; r < 16; r++ {
		wg.Add(1)
		go func() {
			for _, e := range testaddrs {
				c.add(e.addr, e.linkAddr)
				c.get(e.addr) // make work for gotsan
			}
			wg.Done()
		}()
	}
	wg.Wait()

	// All goroutines add in the same order and add more values than
	// can fit in the cache, so our eviction strategy requires that
	// the last entry be present and the first be missing.
	e := testaddrs[len(testaddrs)-1]
	if got, want := c.get(e.addr), e.linkAddr; got != want {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, want)
	}
	e = testaddrs[0]
	if got := c.get(e.addr); got != "" {
		t.Errorf("c.get(%q)=%q, want no entry", string(e.addr.Addr), got)
	}
}

func TestCacheAgeLimit(t *testing.T) {
	c := newLinkAddrCache(1 * time.Millisecond)
	e := testaddrs[0]
	c.add(e.addr, e.linkAddr)
	time.Sleep(50 * time.Millisecond)
	if got := c.get(e.addr); got != "" {
		t.Errorf("c.get(%q)=%q, want no stale entry", string(e.addr.Addr), got)
	}
}

func TestCacheReplace(t *testing.T) {
	c := newLinkAddrCache(1 * time.Millisecond)
	e := testaddrs[0]
	l2 := e.linkAddr + "2"
	c.add(e.addr, e.linkAddr)
	if got := c.get(e.addr); got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}
	c.add(e.addr, l2)
	if got := c.get(e.addr); got != l2 {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, l2)
	}

}
