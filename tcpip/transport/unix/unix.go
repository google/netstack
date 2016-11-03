// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unix contains the implementation of Unix endpoints.
package unix

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/google/netstack/ilist"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/transport/queue"
)

// initialLimit is the starting limit for the socket buffers.
const initialLimit = 16 * 1024

// queueEntry represents a buffer in the queue.
type queueEntry struct {
	ilist.Entry
	view    buffer.View
	control tcpip.ControlMessages
	addr    tcpip.FullAddress
}

// Length returns number of bytes stored in a view.
func (e *queueEntry) Length() int64 {
	return int64(len(e.view))
}

// Release releases any resources held by the queueEntry.
func (e *queueEntry) Release() {
	if e.control != nil {
		e.control.Release()
	}
}

// uniqueID is used to generate endpoint ids.
var uniqueID = func() func() uint64 {
	var id uint64
	return func() uint64 {
		return atomic.AddUint64(&id, 1)
	}
}()

type connectedEndpoint interface {
	GetLocalAddress() (tcpip.FullAddress, error)
	Passcred() bool
}

// baseEndpoint is a embedable unix endpoint base.
//
// Not to be used on its own.
type baseEndpoint struct {
	// id is the unique endpoint identifier. This is used exclusively for
	// lock ordering within connect.
	id uint64

	// passcred specifies whether SCM_CREDENTIALS socket control messages are
	// enabled on this endpoint. Must be accessed atomically.
	passcred int32

	// mu protects the below fields.
	mu sync.Mutex

	readQueue   *queue.Queue
	writeQueue  *queue.Queue
	connectedEP connectedEndpoint

	// path is not empty if the endpoint has been bound,
	// or may be used if the endpoint is connected.
	path string

	// isBound returns true iff the endpoint is bound.
	isBound func() bool `state:"manual"`
}

// Passcred implements socket.Credentialer.Passcred.
func (e *baseEndpoint) Passcred() bool {
	return atomic.LoadInt32(&e.passcred) != 0
}

// ConnectedPasscred implements socket.Credentialer.ConnectedPasscred.
func (e *baseEndpoint) ConnectedPasscred() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connectedEP != nil && e.connectedEP.Passcred()
}

func (e *baseEndpoint) setPasscred(pc bool) {
	if pc {
		atomic.StoreInt32(&e.passcred, 1)
	} else {
		atomic.StoreInt32(&e.passcred, 0)
	}
}

// isConnected returns true iff the endpoint is connected.
func (e *baseEndpoint) isConnected() bool {
	return e.readQueue != nil && e.writeQueue != nil && e.connectedEP != nil
}

// Read reads data from the endpoint.
func (e *baseEndpoint) Read(addr *tcpip.FullAddress) (buffer.View, error) {
	v, c, err := e.RecvMsg(addr)
	if c != nil {
		c.Release()
	}
	return v, err
}

// Write writes data to the endpoint's peer. This method does not block if the
// data cannot be written.
func (e *baseEndpoint) Write(v buffer.View, to *tcpip.FullAddress) (uintptr, error) {
	return e.SendMsg(v, nil, to)
}

// RecvMsg reads data and a control message from the endpoint.
func (e *baseEndpoint) RecvMsg(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry, err := e.readQueue.Dequeue()
	if err != nil {
		return buffer.View{}, nil, err
	}

	qe := entry.(*queueEntry)
	if addr != nil {
		*addr = qe.addr
	}
	return qe.view, qe.control, nil
}

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *baseEndpoint) SendMsg(v buffer.View, c tcpip.ControlMessages, to *tcpip.FullAddress) (uintptr, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.isConnected() {
		return 0, tcpip.ErrNotConnected
	}
	if to != nil {
		return 0, tcpip.ErrAlreadyConnected
	}

	entry := queueEntry{view: v, control: c}
	if e.isBound() {
		entry.addr = tcpip.FullAddress{Addr: tcpip.Address(e.path)}
	}
	if err := e.writeQueue.Enqueue(&entry); err != nil {
		return 0, err
	}

	return uintptr(len(v)), nil
}

// Peek never spans messages for Unix sockets.
func (e *baseEndpoint) Peek(io.Writer) (uintptr, error) {
	return 0, nil
}

// SetSockOpt sets a socket option. Currently not supported.
func (e *baseEndpoint) SetSockOpt(opt interface{}) error {
	switch v := opt.(type) {
	case tcpip.PasscredOption:
		e.setPasscred(v != 0)
		return nil
	}
	return tcpip.ErrInvalidEndpointState
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *baseEndpoint) GetSockOpt(opt interface{}) error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil
	case *tcpip.ReceiveQueueSizeOption:
		e.mu.Lock()
		if !e.isConnected() {
			e.mu.Unlock()
			return tcpip.ErrNotConnected
		}
		*o = tcpip.ReceiveQueueSizeOption(e.readQueue.QueuedSize())
		e.mu.Unlock()
		return nil
	case *tcpip.PasscredOption:
		if e.Passcred() {
			*o = tcpip.PasscredOption(1)
		} else {
			*o = tcpip.PasscredOption(0)
		}
		return nil
	}
	return tcpip.ErrInvalidEndpointState
}

// Connect via address is not supported.
func (*baseEndpoint) Connect(addr tcpip.FullAddress) error {
	return tcpip.ErrConnectionRefused
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *baseEndpoint) Shutdown(flags tcpip.ShutdownFlags) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.isConnected() {
		return tcpip.ErrNotConnected
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.readQueue.Close()
		e.readQueue.Reset()
	}

	if flags&tcpip.ShutdownWrite != 0 {
		e.writeQueue.Close()
	}

	return nil
}

// GetLocalAddress returns the bound path.
func (e *baseEndpoint) GetLocalAddress() (tcpip.FullAddress, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return tcpip.FullAddress{Addr: tcpip.Address(e.path)}, nil
}

// GetRemoteAddress returns the local address of the connected endpoint (if
// available).
func (e *baseEndpoint) GetRemoteAddress() (tcpip.FullAddress, error) {
	e.mu.Lock()
	ce := e.connectedEP
	e.mu.Unlock()
	if ce != nil {
		return ce.GetLocalAddress()
	}
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}
