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

	// Type returns the socket type, typically either SockStream or
	// SockSeqpacket. The connection attempt must be aborted if this
	// value doesn't match the ConnectableEndpoint's type.
	Type() SockType

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

	// stype is used by connecting sockets to ensure that they are the
	// same type. The value is typically either tcpip.SockSeqpacket or
	// tcpip.SockStream.
	stype SockType

	// acceptedChan is per the TCP endpoint implementation. Note that the
	// sockets in this channel are _already in the connected state_, and
	// have another associated connectionedEndpoint.
	//
	// If nil, then no listen call has been made.
	acceptedChan chan *connectionedEndpoint `state:"manual"`
}

// NewConnectioned creates a new unbound connectionedEndpoint.
func NewConnectioned(stype SockType) Endpoint {
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           UniqueID(),
		stype:        stype,
	}
	ep.baseEndpoint.isBound = ep.isBound
	return ep
}

// NewPair allocates a new pair of connected unix-domain connectionedEndpoints.
func NewPair(stype SockType) (Endpoint, Endpoint) {
	a := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           UniqueID(),
		stype:        stype,
	}
	b := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           UniqueID(),
		stype:        stype,
	}

	q1 := queue.New(a.Queue, b.Queue, initialLimit)
	q2 := queue.New(b.Queue, a.Queue, initialLimit)

	if stype == SockStream {
		a.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q1}}
		b.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q2}}
	} else {
		a.receiver = &queueReceiver{q1}
		b.receiver = &queueReceiver{q2}
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

// Type implements ConnectingEndpoint.Type and Endpoint.Type.
func (e *connectionedEndpoint) Type() SockType {
	return e.stype
}

// WaiterQueue implements ConnectingEndpoint.WaiterQueue.
func (e *connectionedEndpoint) WaiterQueue() *waiter.Queue {
	return e.Queue
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
	if ce.Type() != e.stype {
		return tcpip.ErrConnectionRefused
	}

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
	ne := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			path:  e.path,
			Queue: &waiter.Queue{},
		},
		id:    UniqueID(),
		stype: e.stype,
	}
	readQueue := queue.New(ce.WaiterQueue(), ne.Queue, initialLimit)
	writeQueue := queue.New(ne.Queue, ce.WaiterQueue(), initialLimit)
	ne.connected = &connectedEndpoint{
		endpoint:   ce,
		writeQueue: readQueue,
	}
	if e.stype == SockStream {
		ne.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{readQueue: writeQueue}}
	} else {
		ne.receiver = &queueReceiver{readQueue: writeQueue}
	}
	ne.baseEndpoint.isBound = ne.isBound

	select {
	case e.acceptedChan <- ne:
		// Commit state.
		connected := &connectedEndpoint{
			endpoint:   ne,
			writeQueue: writeQueue,
		}
		if e.stype == SockStream {
			returnConnect(&streamQueueReceiver{queueReceiver: queueReceiver{readQueue: readQueue}}, connected)
		} else {
			returnConnect(&queueReceiver{readQueue: readQueue}, connected)
		}

		// Notify on the other end.
		e.Notify(waiter.EventIn)

		return nil
	default:
		// Busy; return ECONNREFUSED per spec.
		ne.Close()
		return tcpip.ErrConnectionRefused
	}
}

// Connect attempts to directly connect to another Endpoint.
// Implements Endpoint.Connect.
//
// FIXME: Currently SREAM and SEQPACKET sockets can connect to
// each other.
func (e *connectionedEndpoint) Connect(server Endpoint) error {
	bound, ok := server.(ConnectableEndpoint)
	if !ok {
		return tcpip.ErrConnectionRefused
	}

	returnConnect := func(r Receiver, ce ConnectedEndpoint) {
		e.receiver = r
		e.connected = ce
		e.Notify(waiter.EventOut)
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
func (e *connectionedEndpoint) Accept() (Endpoint, error) {
	e.Lock()
	defer e.Unlock()

	if !e.Listening() {
		return nil, tcpip.ErrInvalidEndpointState
	}

	select {
	case ne := <-e.acceptedChan:
		return ne, nil

	default:
		// Nothing left.
		return nil, tcpip.ErrWouldBlock
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
