// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/transport/queue"
	"github.com/google/netstack/waiter"
)

// connectionedEndpoint is a unix-domain connected or connectable endpoint.
//
// connectionedEndpoints must be in connected state in order to transfer data.
//
// This implementation includes stream and seqpacket unix sockets created with
// socket(2), accept(2) or socketpair(2) and dgram unix sockets created with
// socketpair(2). See unix_connectionless.go for the implementation of dgram
// unix sockets created with socket(2).
//
// The state is much simpler than a TCP endpoint, so it is not encoded
// explicitly. Instead we enforce the following invariants:
//
// readQueue != nil, writeQueue != nil => connected.
// path != "" && acceptedChan == nil => bound, not listening.
// path != "" && acceptedChan != nil => bound and listening.
//
// Only one of these will be true at any moment. See the isX functions.
type connectionedEndpoint struct {
	baseEndpoint

	// waiterQueue is protected by baseEndpoint.mu.
	waiterQueue *waiter.Queue

	// acceptedChan is per the TCP endpoint implementation. Note that the
	// sockets in this channel are _already in the connected state_, and
	// have another associated connectionedEndpoint.
	//
	// If nil, then no listen call has been made.
	acceptedChan chan *connectionedEndpoint `state:"manual"`
}

// NewConnectioned creates a new unbound connectionedEndpoint.
func NewConnectioned(wq *waiter.Queue) tcpip.Endpoint {
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{id: uniqueID()},
		waiterQueue:  wq,
	}
	ep.baseEndpoint.isBound = ep.isBound
	return ep
}

// NewPair allocates a new pair of connected unix-domain connectionedEndpoints.
func NewPair(wq1 *waiter.Queue, wq2 *waiter.Queue) (tcpip.Endpoint, tcpip.Endpoint) {
	q1 := queue.New(wq1, wq2, initialLimit)
	q2 := queue.New(wq2, wq1, initialLimit)

	a := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			id:         uniqueID(),
			readQueue:  q1,
			writeQueue: q2,
		},
		waiterQueue: wq1,
	}
	b := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			id:         uniqueID(),
			readQueue:  q2,
			writeQueue: q1,
		},
		waiterQueue: wq2,
	}
	a.baseEndpoint.isBound = a.isBound
	b.baseEndpoint.isBound = b.isBound
	a.connectedEP = b
	b.connectedEP = a

	return a, b
}

// isBound returns true iff the connectionedEndpoint is bound.
func (e *connectionedEndpoint) isBound() bool {
	return e.path != "" && e.acceptedChan == nil
}

// isListening returns true iff the connectionedEndpoint is listening.
func (e *connectionedEndpoint) isListening() bool {
	return e.acceptedChan != nil
}

// Close puts the connectionedEndpoint in a closed state and frees all
// resources associated with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionedEndpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.isConnected():
		e.writeQueue.Close()
		e.readQueue.Close()
		e.readQueue.Reset()
		e.writeQueue = nil
		e.readQueue = nil
		e.connectedEP = nil
	case e.isBound():
		e.path = ""
	case e.isListening():
		close(e.acceptedChan)
		for n := range e.acceptedChan {
			n.Close()
		}
		e.acceptedChan = nil
		e.path = ""
	}
}

// ConnectEndpoint attempts to connect directly to other.
func (e *connectionedEndpoint) ConnectEndpoint(server tcpip.Endpoint) error {
	bound, ok := server.(*connectionedEndpoint)
	if !ok {
		return tcpip.ErrConnectionRefused
	}

	// Do a dance to safely acquire locks on both connectionedEndpoints.
	if e.id < bound.id {
		e.mu.Lock()
		bound.mu.Lock()
	} else {
		bound.mu.Lock()
		e.mu.Lock()
	}
	defer e.mu.Unlock()
	defer bound.mu.Unlock()

	// Check connecting state.
	if e.isConnected() {
		return tcpip.ErrAlreadyConnected
	}
	if e.isListening() {
		return tcpip.ErrInvalidEndpointState
	}

	// Check bound state.
	if !bound.isListening() {
		return tcpip.ErrConnectionRefused
	}

	// Create a newly bound connectionedEndpoint.
	wq := &waiter.Queue{}
	readQueue := queue.New(e.waiterQueue, wq, initialLimit)
	writeQueue := queue.New(wq, e.waiterQueue, initialLimit)
	ne := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			id:          uniqueID(),
			readQueue:   writeQueue,
			writeQueue:  readQueue,
			connectedEP: e,
			path:        bound.path,
		},
		waiterQueue: wq,
	}
	ne.baseEndpoint.isBound = ne.isBound

	select {
	case bound.acceptedChan <- ne:
		// Commit state.
		e.readQueue = readQueue
		e.writeQueue = writeQueue
		e.connectedEP = ne

		// Notify on the other end.
		bound.waiterQueue.Notify(waiter.EventIn)
		e.waiterQueue.Notify(waiter.EventOut)
		return nil
	default:
		// Busy; return ECONNREFUSED per spec.
		ne.Close()
		return tcpip.ErrConnectionRefused
	}
}

// Listen starts listening on the connection.
func (e *connectionedEndpoint) Listen(backlog int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isListening() {
		// Adjust the size of the channel iff we can fix existing
		// pending connections into the new one.
		if len(e.acceptedChan) > backlog {
			return tcpip.ErrInvalidEndpointState
		}
		origChan := e.acceptedChan
		e.acceptedChan = make(chan *connectionedEndpoint, backlog)
		close(origChan)
		for ep := range origChan {
			e.acceptedChan <- ep
		}
		return nil
	}
	if !e.isBound() {
		return tcpip.ErrInvalidEndpointState
	}

	// Normal case.
	e.acceptedChan = make(chan *connectionedEndpoint, backlog)
	return nil
}

// Accept accepts a new connection.
func (e *connectionedEndpoint) Accept() (tcpip.Endpoint, *waiter.Queue, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isListening() {
		return nil, nil, tcpip.ErrInvalidEndpointState
	}

	select {
	case ne := <-e.acceptedChan:
		return ne, ne.waiterQueue, nil

	default:
		// Nothing left.
		return nil, nil, tcpip.ErrWouldBlock
	}
}

// Bind binds the connection.
//
// For Unix connectionedEndpoints, this _only sets the address associated with
// the socket_. Work associated with sockets in the filesystem or finding those
// sockets must be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionedEndpoint) Bind(addr tcpip.FullAddress, commit func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isConnected() {
		return tcpip.ErrAlreadyConnected
	}
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

// Readiness returns the current readiness of the connectionedEndpoint. For
// example, if waiter.EventIn is set, the connectionedEndpoint is immediately
// readable.
func (e *connectionedEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	e.mu.Lock()
	defer e.mu.Unlock()

	ready := waiter.EventMask(0)
	switch {
	case e.isConnected():
		if mask&waiter.EventIn != 0 && e.readQueue.IsReadable() {
			ready |= waiter.EventIn
		}
		if mask&waiter.EventOut != 0 && e.writeQueue.IsWritable() {
			ready |= waiter.EventOut
		}
	case e.isListening():
		if mask&waiter.EventIn != 0 && len(e.acceptedChan) > 0 {
			ready |= waiter.EventIn
		}
	}

	return ready
}
