// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791 and RFC 815.
package fragmentation

import (
	"sync"

	"github.com/google/netstack/tcpip/buffer"
)

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu           sync.Mutex
	reassemblers map[uint32]*reassembler
}

// NewFragmentation creates a new Fragmentation.
func NewFragmentation() Fragmentation {
	return Fragmentation{
		reassemblers: make(map[uint32]*reassembler),
	}
}

// Process processes an incoming fragment beloning to an ID
// and returns a complete packet when all the packets belonging to that ID have been received.
func (f *Fragmentation) Process(id uint32, first, last uint16, more bool, vv *buffer.VectorisedView) (buffer.VectorisedView, bool) {
	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if !ok {
		r = newReassembler()
		f.reassemblers[id] = r
	}
	f.mu.Unlock()

	res, done := r.process(first, last, more, vv)
	if done {
		f.mu.Lock()
		delete(f.reassemblers, id)
		f.mu.Unlock()
	}
	return res, done
}
