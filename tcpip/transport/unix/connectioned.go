// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import (
	"sync"
	"sync/atomic"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/transport/queue"
	"github.com/google/netstack/waiter"
)

// UniqueID is used to generate endpoint ids.
var UniqueID = func() func() uint64 {
	var id uint64
	return func() uint64 {
		return atomic.AddUint64(&id, 1)
	}
}()

// A ConnectingEndpoint is a connectioned unix endpoint that is attempting to
// connect to a ConnectionedEndpoint.
type ConnectingEndpoint interface {
	// ID returns the endpoint's globally unique identifier. This identifier
	// must be used to determine locking order if more than one endpoint is
	// to be locked in the same codepath. The endpoint with the smaller
	// identifier must be locked before endpoints with larger identifiers.
	ID() uint64

	// Passcred implements socket.Credentialer.Passcred.
	Passcred() bool

	// GetLocalAddress returns the bound path.
	GetLocalAddress() (tcpip.FullAddress, error)

	// Locker protects the following methods. While locked, only the holder of
	// the lock can change the return value of the protected methods.
	sync.Locker

	// Connected returns true iff the ConnectingEndpoint is in the connected
	// state. ConnectingEndpoints can only be connected to a single endpoint,
	// so the connection attempt must be aborted if this returns true.
	Connected() bool

	// Listening returns true iff the ConnectingEndpoint is in the listening
	// state. ConnectingEndpoints cannot make connections while listening, so
	// the connection attempt must be aborted if this returns true.
	Listening() bool

	// WaiterQueue returns a pointer to the endpoint's waiter queue.
	WaiterQueue() *waiter.Queue
}

// A ConnectableEndpoint is a unix endpoint that can be connected to.
type ConnectableEndpoint interface {
	// BidirectionalConnect establishes a bi-directional connection between two
	// unix endpoints in an all-or-nothing manner. If an error occurs during
	// connecting, the state of neither endpoint should be modified.
	//
	// In order for an endpoint to establish such a bidirectional connection
	// with a ConnectableEndpoint, the endpoint calls the BidirectionalConnect
	// method on the ConnectableEndpoint and sends a representation of itself
	// (the ConnectingEndpoint) and a callback (returnConnect) to receive the
	// connection information (Receiver and ConnectedEndpoint) upon a
	// sucessful connect. The callback should only be called on a sucessful
	// connect.
	//
	// For a connection attempt to be sucessful, the ConnectingEndpoint must
	// be unconnected and not listening and the ConnectableEndpoint whose
	// BidirectionalConnect method is being called must be listening.
	//
	// For example, both STREAM and SEQPACKET sockets implement
	// ConnectableEndpoint, but DGRAM sockets do not (see
	// ConnectionlessEndpoint).
	BidirectionalConnect(ep ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) error
}

// connectionedEndpoint is a Unix-domain connected or connectable endpoint and implements
// ConnectingEndpoint, ConnectableEndpoint and tcpip.Endpoint.
//
// connectionedEndpoints must be in connected state in order to transfer data.
//
// This implementation includes STREAM and SEQPACKET Unix sockets created with
// socket(2), accept(2) or socketpair(2) and dgram unix sockets created with
// socketpair(2). See unix_connectionless.go for the implementation of DGRAM
// Unix sockets created with socket(2).
//
// The state is much simpler than a TCP endpoint, so it is not encoded
// explicitly. Instead we enforce the following invariants:
//
// receiver != nil, connected != nil => connected.
// path != "" && acceptedChan == nil => bound, not listening.
// path != "" && acceptedChan != nil => bound and listening.
//
// Only one of these will be true at any moment.
type connectionedEndpoint struct {
	baseEndpoint

	// id is the unique endpoint identifier. This is used exclusively for
	// lock ordering within connect.
	id uint64

	// waiterQueue is protected by baseEndpoint.Mutex.
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
		id:          UniqueID(),
		waiterQueue: wq,
	}
	ep.baseEndpoint.isBound = ep.isBound
	return ep
}

// NewPair allocates a new pair of connected unix-domain connectionedEndpoints.
func NewPair(wq1 *waiter.Queue, wq2 *waiter.Queue) (tcpip.Endpoint, tcpip.Endpoint) {
	q1 := queue.New(wq1, wq2, initialLimit)
	q2 := queue.New(wq2, wq1, initialLimit)

	a := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{receiver: &queueReceiver{q1}},
		id:           UniqueID(),
		waiterQueue:  wq1,
	}
	b := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{receiver: &queueReceiver{q2}},
		id:           UniqueID(),
		waiterQueue:  wq2,
	}

	a.connected = &connectedEndpoint{
		endpoint:   b,
		writeQueue: q2,
	}
	b.connected = &connectedEndpoint{
		endpoint:   a,
		writeQueue: q1,
	}

	a.baseEndpoint.isBound = a.isBound
	b.baseEndpoint.isBound = b.isBound

	return a, b
}

// ID implements ConnectingEndpoint.ID.
func (e *connectionedEndpoint) ID() uint64 {
	return e.id
}

// WaiterQueue implements ConnectingEndpoint.WaiterQueue.
func (e *connectionedEndpoint) WaiterQueue() *waiter.Queue {
	return e.waiterQueue
}

// isBound returns true iff the connectionedEndpoint is bound.
func (e *connectionedEndpoint) isBound() bool {
	return e.path != "" && e.acceptedChan == nil
}

// Listening implements ConnectingEndpoint.Listening.
func (e *connectionedEndpoint) Listening() bool {
	return e.acceptedChan != nil
}

// Close puts the connectionedEndpoint in a closed state and frees all
// resources associated with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionedEndpoint) Close() {
	e.Lock()
	defer e.Unlock()
	switch {
	case e.Connected():
		e.connected.CloseSend()
		e.receiver.CloseRecv()
		e.connected = nil
		e.receiver = nil
	case e.isBound():
		e.path = ""
	case e.Listening():
		close(e.acceptedChan)
		for n := range e.acceptedChan {
			n.Close()
		}
		e.acceptedChan = nil
		e.path = ""
	}
}

// BidirectionalConnect implements ConnectableEndpoint.BidirectionalConnect.
func (e *connectionedEndpoint) BidirectionalConnect(ce ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) error {
	// Do a dance to safely acquire locks on both endpoints.
	if e.id < ce.ID() {
		e.Lock()
		ce.Lock()
	} else {
		ce.Lock()
		e.Lock()
	}
	defer e.Unlock()
	defer ce.Unlock()

	// Check connecting state.
	if ce.Connected() {
		return tcpip.ErrAlreadyConnected
	}
	if ce.Listening() {
		return tcpip.ErrInvalidEndpointState
	}

	// Check bound state.
	if !e.Listening() {
		return tcpip.ErrConnectionRefused
	}

	// Create a newly bound connectionedEndpoint.
	wq := &waiter.Queue{}
	readQueue := queue.New(ce.WaiterQueue(), wq, initialLimit)
	writeQueue := queue.New(wq, ce.WaiterQueue(), initialLimit)
	ne := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			connected: &connectedEndpoint{
				endpoint:   ce,
				writeQueue: readQueue,
			},
			receiver: &queueReceiver{readQueue: writeQueue},
			path:     e.path,
		},
		id:          UniqueID(),
		waiterQueue: wq,
	}
	ne.baseEndpoint.isBound = ne.isBound

	select {
	case e.acceptedChan <- ne:
		// Commit state.
		connected := &connectedEndpoint{
			endpoint:   ne,
			writeQueue: writeQueue,
		}
		receiver := &queueReceiver{readQueue: readQueue}
		returnConnect(receiver, connected)

		// Notify on the other end.
		e.waiterQueue.Notify(waiter.EventIn)

		return nil
	default:
		// Busy; return ECONNREFUSED per spec.
		ne.Close()
		return tcpip.ErrConnectionRefused
	}
}

// ConnectEndpoint attempts to directly connect to another tcpip.Endpoint.
// Implements tcpip.Endpoint.ConnectEndpoint.
//
// FIXME: Currently SREAM and SEQPACKET sockets can connect to
// each other.
func (e *connectionedEndpoint) ConnectEndpoint(server tcpip.Endpoint) error {
	bound, ok := server.(ConnectableEndpoint)
	if !ok {
		return tcpip.ErrConnectionRefused
	}

	returnConnect := func(r Receiver, ce ConnectedEndpoint) {
		e.receiver = r
		e.connected = ce
		e.waiterQueue.Notify(waiter.EventOut)
	}

	return bound.BidirectionalConnect(e, returnConnect)
}

// Listen starts listening on the connection.
func (e *connectionedEndpoint) Listen(backlog int) error {
	e.Lock()
	defer e.Unlock()
	if e.Listening() {
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
	e.Lock()
	defer e.Unlock()

	if !e.Listening() {
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
	e.Lock()
	defer e.Unlock()
	if e.Connected() {
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
	e.Lock()
	defer e.Unlock()

	ready := waiter.EventMask(0)
	switch {
	case e.Connected():
		if mask&waiter.EventIn != 0 && e.receiver.Readable() {
			ready |= waiter.EventIn
		}
		if mask&waiter.EventOut != 0 && e.connected.Writable() {
			ready |= waiter.EventOut
		}
	case e.Listening():
		if mask&waiter.EventIn != 0 && len(e.acceptedChan) > 0 {
			ready |= waiter.EventIn
		}
	}

	return ready
}
