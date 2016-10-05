// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buffer_test contains tests for the VView type.
package buffer

import (
	"reflect"
	"testing"
)

// vv is an helper to build VectorisedView from different strings.
func vv(size int, pieces ...string) *VectorisedView {
	views := make([]View, len(pieces))
	for i, p := range pieces {
		views[i] = []byte(p)
	}

	return NewVectorisedView(size, views)
}

var capLengthTestCases = []struct {
	comment string
	in      *VectorisedView
	length  int
	want    *VectorisedView
}{
	{
		comment: "Simple case",
		in:      vv(2, "12"),
		length:  1,
		want:    vv(1, "1"),
	},
	{
		comment: "Case spanning across two Views",
		in:      vv(4, "123", "4"),
		length:  2,
		want:    vv(2, "12"),
	},
	{
		comment: "Corner case with negative length",
		in:      vv(1, "1"),
		length:  -1,
		want:    vv(0),
	},
	{
		comment: "Corner case with length = 0",
		in:      vv(3, "12", "3"),
		length:  0,
		want:    vv(0),
	},
	{
		comment: "Corner case with length = size",
		in:      vv(1, "1"),
		length:  1,
		want:    vv(1, "1"),
	},
	{
		comment: "Corner case with length > size",
		in:      vv(1, "1"),
		length:  2,
		want:    vv(1, "1"),
	},
}

func TestCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		orig := c.in.copy()
		c.in.CapLength(c.length)
		if !reflect.DeepEqual(c.in, c.want) {
			t.Errorf("Test \"%s\" failed when calling CapLength(%d) on %v. Got %v. Want %v",
				c.comment, c.length, orig, c.in, c.want)
		}
	}
}

var trimFrontTestCases = []struct {
	comment string
	in      *VectorisedView
	count   int
	want    *VectorisedView
}{
	{
		comment: "Simple case",
		in:      vv(2, "12"),
		count:   1,
		want:    vv(1, "2"),
	},
	{
		comment: "Case where we trim an entire View",
		in:      vv(2, "1", "2"),
		count:   1,
		want:    vv(1, "2"),
	},
	{
		comment: "Case spanning across two Views",
		in:      vv(3, "1", "23"),
		count:   2,
		want:    vv(1, "3"),
	},
	{
		comment: "Corner case with negative count",
		in:      vv(1, "1"),
		count:   -1,
		want:    vv(1, "1"),
	},
	{
		comment: " Corner case with count = 0",
		in:      vv(1, "1"),
		count:   0,
		want:    vv(1, "1"),
	},
	{
		comment: "Corner case with count = size",
		in:      vv(1, "1"),
		count:   1,
		want:    vv(0),
	},
	{
		comment: "Corner case with count > size",
		in:      vv(1, "1"),
		count:   2,
		want:    vv(0),
	},
}

func TestTrimFront(t *testing.T) {
	for _, c := range trimFrontTestCases {
		orig := c.in.copy()
		c.in.TrimFront(c.count)
		if !reflect.DeepEqual(c.in, c.want) {
			t.Errorf("Test \"%s\" failed when calling TrimFront(%d) on %v. Got %v. Want %v",
				c.comment, c.count, orig, c.in, c.want)
		}
	}
}
