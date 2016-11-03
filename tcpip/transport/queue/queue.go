// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package queue provides the implementation of buffer queue
// and interface of queue entry with Length method.
package queue

import (
	"sync"

	"github.com/google/netstack/ilist"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/waiter"
)

// Entry implements Linker interface and has both Length and Release methods.
type Entry interface {
	ilist.Linker
	Length() int64
	Release()
}

// Queue is a buffer queue.
type Queue struct {
	ReaderQueue *waiter.Queue
	WriterQueue *waiter.Queue

	mu       sync.Mutex
	closed   bool
	used     int64
	limit    int64
	dataList ilist.List
}

// New allocates and initializes a new queue.
func New(ReaderQueue *waiter.Queue, WriterQueue *waiter.Queue, limit int64) *Queue {
	return &Queue{ReaderQueue: ReaderQueue, WriterQueue: WriterQueue, limit: limit}
}

// Close closes q for reading and writing. It is immediately not writable and
// will become unreadble will no more data is pending.
func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()

	q.ReaderQueue.Notify(waiter.EventIn)
	q.WriterQueue.Notify(waiter.EventOut)
}

// Reset empties the queue and Releases all of the Entries.
func (q *Queue) Reset() {
	q.mu.Lock()
	for cur := q.dataList.Front(); cur != nil; cur = cur.Next() {
		cur.(Entry).Release()
	}
	q.dataList.Reset()
	q.used = 0
	q.mu.Unlock()

	q.ReaderQueue.Notify(waiter.EventIn)
	q.WriterQueue.Notify(waiter.EventOut)
}

// IsReadable determines if q is currently readable.
func (q *Queue) IsReadable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.dataList.Front() != nil
}

// IsWritable determines if q is currently writable.
func (q *Queue) IsWritable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.closed || q.used < q.limit
}

// Enqueue adds an entry to the data queue if room is available, and wakes up
// readers if needed.
func (q *Queue) Enqueue(e Entry) error {
	q.mu.Lock()

	if q.closed {
		q.mu.Unlock()
		return tcpip.ErrClosedForSend
	}

	if q.used >= q.limit {
		q.mu.Unlock()
		return tcpip.ErrWouldBlock
	}

	notify := q.dataList.Front() == nil
	q.used += e.Length()
	q.dataList.PushBack(e)

	q.mu.Unlock()

	if notify {
		q.ReaderQueue.Notify(waiter.EventIn)
	}

	return nil
}

// Dequeue removes the first entry in the data queue, if one exists.
func (q *Queue) Dequeue() (Entry, error) {
	q.mu.Lock()

	if q.dataList.Front() == nil {
		err := tcpip.ErrWouldBlock
		if q.closed {
			err = tcpip.ErrClosedForReceive
		}
		q.mu.Unlock()

		return nil, err
	}

	notify := q.used >= q.limit

	e := q.dataList.Front().(Entry)
	q.dataList.Remove(e)
	q.used -= e.Length()

	notify = notify && q.used < q.limit

	q.mu.Unlock()

	if notify {
		q.WriterQueue.Notify(waiter.EventOut)
	}

	return e, nil
}

// QueuedSize returns the number of bytes currently in the queue, that is, the
// number of readable bytes.
func (q *Queue) QueuedSize() int64 {
	return q.used
}
