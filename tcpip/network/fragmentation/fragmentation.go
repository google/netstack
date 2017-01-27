// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791 and RFC 815.
package fragmentation

import (
	"log"
	"sync"
	"time"

	"github.com/google/netstack/tcpip/buffer"
)

// DefaultReassembleTimeout is based on the reassembling timeout suggest in RFC 791 (4.25 minutes).
const DefaultReassembleTimeout = 5 * time.Minute

// MemoryLimit is a suggested value for the limit on the memory used to reassemble packets.
const MemoryLimit = 8 * 1024 * 1024 // 8MB

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu           sync.Mutex
	limit        int
	reassemblers map[uint32]*reassembler
	rList        reassemblerList
	size         int
	timeout      time.Duration
}

// NewFragmentation creates a new Fragmentation.
//
// memoryLimit specifies the limit on the memory consumed
// by the fragments stored by Fragmentation (overhead of internal data-structures
// is not accounted). Fragments are dropped when the limit is reached.
//
// reassemblingTimeout specifes the maximum time allowed to reassemble a packet.
// Fragments are lazily evicted only when a new a packet with an
// already existing fragmentation-id arrives after the timeout.
func NewFragmentation(memoryLimit int, reassemblingTimeout time.Duration) Fragmentation {
	return Fragmentation{
		reassemblers: make(map[uint32]*reassembler),
		limit:        memoryLimit,
		timeout:      reassemblingTimeout,
	}
}

// Process processes an incoming fragment beloning to an ID
// and returns a complete packet when all the packets belonging to that ID have been received.
func (f *Fragmentation) Process(id uint32, first, last uint16, more bool, vv *buffer.VectorisedView) (buffer.VectorisedView, bool) {
	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) {
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		f.release(r)
		ok = false
	}
	if !ok {
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()

	res, done, consumed := r.process(first, last, more, vv)

	f.mu.Lock()
	f.size += consumed
	if done {
		f.release(r)
	}
	// Evict reassemblers if we are consuming more memory than the limit.
	for f.size > f.limit {
		f.release(f.rList.Back())
	}
	f.mu.Unlock()
	return res, done
}

func (f *Fragmentation) release(r *reassembler) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.size -= r.size
	if f.size < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.size)
		f.size = 0
	}
}
