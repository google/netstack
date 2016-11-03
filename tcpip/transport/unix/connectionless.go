// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/transport/queue"
	"github.com/google/netstack/waiter"
)

// A ConnectionlessEndpoint is a tcpip.Endpoint that allows sending messages
// to other endpoints without being connected.
type ConnectionlessEndpoint interface {
	tcpip.Endpoint

	// SendMsgTo writes data and a control message to the specified endpoint.
	SendMsgTo(v buffer.View, c tcpip.ControlMessages, to tcpip.Endpoint) (uintptr, error)
}

// connectionlessEndpoint is a unix endpoint for unix sockets that support operating in
// a conectionless fashon.
//
// Specifically, this means datagram unix sockets not created with
// socketpair(2).
type connectionlessEndpoint struct {
	baseEndpoint
}

// NewConnectionless creates a new unbound dgram endpoint.
func NewConnectionless(wq *waiter.Queue) tcpip.Endpoint {
	ep := &connectionlessEndpoint{baseEndpoint{
		id:        uniqueID(),
		readQueue: queue.New(&waiter.Queue{}, wq, initialLimit),
	}}
	ep.baseEndpoint.isBound = ep.isBound
	return ep
}

// isBound returns true iff the endpoint is bound.
func (e *connectionlessEndpoint) isBound() bool {
	return e.path != ""
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionlessEndpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isConnected() {
		e.readQueue.Close()
		e.readQueue.Reset()
		e.readQueue = nil
		e.writeQueue = nil
		e.connectedEP = nil
	}
	if e.isBound() {
		e.path = ""
	}
}

// SendMsgTo writes data and a control message to the specified endpoint.
// This method does not block if the data cannot be written.
func (e *connectionlessEndpoint) SendMsgTo(v buffer.View, c tcpip.ControlMessages, to tcpip.Endpoint) (uintptr, error) {
	var toDgram *connectionlessEndpoint
	if toDgram, _ = to.(*connectionlessEndpoint); toDgram == nil {
		// Either to was nil or not a *connectionlessEndpoint.
		return 0, tcpip.ErrInvalidEndpointState
	}

	toDgram.mu.Lock()
	writeQueue := toDgram.readQueue
	toDgram.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	entry := queueEntry{view: v, control: c}
	if e.isBound() {
		entry.addr = tcpip.FullAddress{Addr: tcpip.Address(e.path)}
	}
	if err := writeQueue.Enqueue(&entry); err != nil {
		return 0, err
	}

	return uintptr(len(v)), nil
}

// ConnectEndpoint attempts to connect directly to other.
func (e *connectionlessEndpoint) ConnectEndpoint(server tcpip.Endpoint) error {
	bound, ok := server.(*connectionlessEndpoint)
	if !ok {
		return tcpip.ErrConnectionRefused
	}

	bound.mu.Lock()
	boundReadQueue := bound.readQueue
	bound.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	e.writeQueue = boundReadQueue
	e.connectedEP = bound
	return nil
}

// Listen starts listening on the connection.
func (e *connectionlessEndpoint) Listen(int) error {
	return tcpip.ErrNotSupported
}

// Accept accepts a new connection.
func (e *connectionlessEndpoint) Accept() (tcpip.Endpoint, *waiter.Queue, error) {
	return nil, nil, tcpip.ErrNotSupported
}

// Bind binds the connection.
//
// For Unix endpoints, this _only sets the address associated with the socket_.
// Work associated with sockets in the filesystem or finding those sockets must
// be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionlessEndpoint) Bind(addr tcpip.FullAddress, commit func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isBound() {
		return tcpip.ErrAlreadyBound
	}
	if addr.Addr == "" {
		// The empty string is not permitted.
		return tcpip.ErrBadLocalAddress
	}
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}

	// Save the bound address.
	e.path = string(addr.Addr)
	return nil
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *connectionlessEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	e.mu.Lock()
	defer e.mu.Unlock()

	ready := waiter.EventMask(0)
	if mask&waiter.EventIn != 0 && e.readQueue.IsReadable() {
		ready |= waiter.EventIn
	}

	if e.isConnected() {
		if mask&waiter.EventOut != 0 && e.writeQueue.IsWritable() {
			ready |= waiter.EventOut
		}
	}

	return ready
}
