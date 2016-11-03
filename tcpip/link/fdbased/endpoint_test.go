// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fdbased

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
)

func TestBufConfigMaxLength(t *testing.T) {
	got := 0
	for _, i := range BufConfig {
		got += i
	}
	want := header.MaxIPPacketSize // maximum TCP packet size
	if got < want {
		t.Errorf("total buffer size is invalid: got %d, want >= %d", got, want)
	}
}

func TestBufConfigFirst(t *testing.T) {
	// The stack assumes that the TCP/IP header is enterily contained in the first view.
	// Therefore, the first view needs to be large enough to contain the maximum TCP/IP
	// header, which is 120 bytes (60 bytes for IP + 60 bytes for TCP).
	want := 120
	got := BufConfig[0]
	if got < want {
		t.Errorf("first view has an invalid size: got %d, want >= %d", got, want)
	}
}

func build(bufConfig []int) *endpoint {
	e := &endpoint{
		views:  make([]buffer.View, len(bufConfig)),
		iovecs: make([]syscall.Iovec, len(bufConfig)),
	}
	e.allocateViews(bufConfig)
	return e
}

var capLengthTestCases = []struct {
	comment     string
	config      []int
	n           int
	wantUsed    int
	wantLengths []int
}{
	{
		comment:     "Single slice",
		config:      []int{2},
		n:           1,
		wantUsed:    1,
		wantLengths: []int{1},
	},
	{
		comment:     "Multiple slices",
		config:      []int{1, 2},
		n:           2,
		wantUsed:    2,
		wantLengths: []int{1, 1},
	},
	{
		comment:     "Entire buffer",
		config:      []int{1, 2},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2},
	},
	{
		comment:     "Entire buffer but not on the last slice",
		config:      []int{1, 2, 3},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2, 3},
	},
}

func TestCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		e := build(c.config)
		used := e.capViews(c.n, c.config)
		if used != c.wantUsed {
			t.Errorf("Test \"%s\" failed when calling capViews(%d, %v). Got %d. Want %d", c.comment, c.n, c.config, used, c.wantUsed)
		}
		lengths := make([]int, len(e.views))
		for i, v := range e.views {
			lengths[i] = len(v)
		}
		if !reflect.DeepEqual(lengths, c.wantLengths) {
			t.Errorf("Test \"%s\" failed when calling capViews(%d, %v). Got %v. Want %v", c.comment, c.n, c.config, lengths, c.wantLengths)
		}

	}
}
