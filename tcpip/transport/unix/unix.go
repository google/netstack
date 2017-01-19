// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unix contains the implementation of Unix endpoints.
package unix

import (
	"sync"
	"sync/atomic"

	"github.com/google/netstack/ilist"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/transport/queue"
	"github.com/google/netstack/waiter"
)

// initialLimit is the starting limit for the socket buffers.
const initialLimit = 16 * 1024

// A SockType is a type (as opposed to family) of sockets. These are enumerated
// in the syscall package as syscall.SOCK_* constants.
type SockType int

const (
	// SockStream corresponds to syscall.SOCK_STREAM.
	SockStream SockType = 1
	// SockDgram corresponds to syscall.SOCK_DGRAM.
	SockDgram SockType = 2
	// SockSeqpacket corresponds to syscall.SOCK_SEQPACKET.
	SockSeqpacket SockType = 5
)

// A ControlMessages represents a collection of socket control messages.
type ControlMessages interface {
	// Release releases any resources owned by the control message.
	Release()

	// CloneCreds returns a copy of any credentials (if any) contained in the
	// ControlMessages.
	CloneCreds() ControlMessages

	// Clone returns a copy of the ControlMessages.
	Clone() ControlMessages
}

// Endpoint is the interface implemented by Unix transport protocol
// implementations that expose functionality like sendmsg, recvmsg, connect,
// etc. to Unix socket implementations.
type Endpoint interface {
	Credentialer
	waiter.Waitable

	// Close puts the endpoint in a closed state and frees all resources
	// associated with it.
	Close()

	// RecvMsg reads data and a control message from the endpoint. This method
	// does not block if there is no data pending.
	//
	// numRights is the number of SCM_RIGHTS FDs requested by the caller. This
	// is useful if one must allocate a buffer to receive a SCM_RIGHTS message.
	// numRights is a hint and can be safely ignored if the number of available
	// SCM_RIGHTS FDs is known. It is fine for the returned number of
	// SCM_RIGHTS FDs to be either higher or lower than the requested number.
	//
	// If peek is true, no data should be consumed from the Endpoint. Any and
	// all data returned from a peek should be available in the next call to
	// RecvMsg.
	RecvMsg(data [][]byte, numRights uintptr, peek bool, addr *tcpip.FullAddress) (uintptr, ControlMessages, error)

	// SendMsg writes data and a control message to the endpoint's peer.
	// This method does not block if the data cannot be written.
	//
	// SendMsg does not take ownership of any of its arguments on error.
	SendMsg([][]byte, ControlMessages, Endpoint) (uintptr, error)

	// Connect connects this endpoint directly to another.
	//
	// This should be called on the client endpoint, and the (bound)
	// endpoint passed in as a parameter.
	//
	// The error codes are the same as Connect.
	Connect(server Endpoint) error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags tcpip.ShutdownFlags) error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(backlog int) error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	Accept() (Endpoint, error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	//
	// An optional commit function will be executed atomically with respect
	// to binding the endpoint. If this returns an error, the bind will not
	// occur and the error will be propagated back to the caller.
	Bind(address tcpip.FullAddress, commit func() error) error

	// Type return the socket type, typically either SockStream, SockDgram
	// or SockSeqpacket.
	Type() SockType

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (tcpip.FullAddress, error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (tcpip.FullAddress, error)

	// SetSockOpt sets a socket option. opt should be one of the tcpip.*Option
	// types.
	SetSockOpt(opt interface{}) error

	// GetSockOpt gets a socket option. opt should be a pointer to one of the
	// tcpip.*Option types.
	GetSockOpt(opt interface{}) error
}

// A Credentialer is a socket or endpoint that supports the SO_PASSCRED socket
// option.
type Credentialer interface {
	// Passcred returns whether or not the SO_PASSCRED socket option is
	// enabled on this end.
	Passcred() bool

	// ConnectedPasscred returns whether or not the SO_PASSCRED socket option
	// is enabled on the connected end.
	ConnectedPasscred() bool
}

// message represents a message passed over a Unix domain socket.
type message struct {
	ilist.Entry

	// Data is the Message payload.
	Data buffer.View

	// Control is auxiliary control message data that goes along with the
	// data.
	Control ControlMessages

	// Address is the bound address of the endpoint that sent the message.
	//
	// If the endpoint that sent the message is not bound, the Address is
	// the empty string.
	Address tcpip.FullAddress
}

// Length returns number of bytes stored in the Message.
func (m *message) Length() int64 {
	return int64(len(m.Data))
}

// Release releases any resources held by the Message.
func (m *message) Release() {
	if m.Control != nil {
		m.Control.Release()
	}
}

func (m *message) Peek() queue.Entry {
	var c ControlMessages
	if m.Control != nil {
		c = m.Control.Clone()
	}
	return &message{Data: m.Data, Control: c, Address: m.Address}
}

// A Receiver can be used to receive Messages.
type Receiver interface {
	// Recv receives a single message. This method does not block.
	Recv(data [][]byte, numRights uintptr, peek bool) (uintptr, ControlMessages, tcpip.FullAddress, error)

	// CloseRecv prevents the receiving of additional Messages.
	CloseRecv()

	// Readable returns if messages should be attempted to be received.
	Readable() bool

	// QueuedSize returns the total amount of data currently receivable.
	QueuedSize() int64
}

// queueReceiver implements Receiver for datagram sockets.
type queueReceiver struct {
	readQueue *queue.Queue
}

// Recv implements Receiver.Recv.
func (q *queueReceiver) Recv(data [][]byte, numRights uintptr, peek bool) (uintptr, ControlMessages, tcpip.FullAddress, error) {
	var m queue.Entry
	var err error
	if peek {
		m, err = q.readQueue.Peek()
	} else {
		m, err = q.readQueue.Dequeue()
	}
	if err != nil {
		return 0, nil, tcpip.FullAddress{}, err
	}
	msg := m.(*message)
	src := []byte(msg.Data)
	var copied uintptr
	for i := 0; i < len(data) && len(src) > 0; i++ {
		n := copy(data[i], src)
		copied += uintptr(n)
		src = src[n:]
	}
	return copied, msg.Control, msg.Address, nil
}

// CloseRecv implements Receiver.CloseRecv.
func (q *queueReceiver) CloseRecv() {
	q.readQueue.Close()
}

// Readable implements Receiver.Readable.
func (q *queueReceiver) Readable() bool {
	return q.readQueue.IsReadable()
}

// QueuedSize implements Receiver.QueuedSize.
func (q *queueReceiver) QueuedSize() int64 {
	return q.readQueue.QueuedSize()
}

// streamQueueReceiver implements Receiver for stream sockets.
type streamQueueReceiver struct {
	queueReceiver

	mu      sync.Mutex
	buffer  []byte
	control ControlMessages
	addr    tcpip.FullAddress
}

// Recv implements Receiver.Recv.
func (q *streamQueueReceiver) Recv(data [][]byte, numRights uintptr, peek bool) (uintptr, ControlMessages, tcpip.FullAddress, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.buffer) == 0 {
		// Load the next message into a buffer, even if we are peeking. Peeking
		// won't consume the message, so it will be still available to be read
		// the next time Recv() is called.
		m, err := q.readQueue.Dequeue()
		if err != nil {
			return 0, nil, tcpip.FullAddress{}, err
		}
		msg := m.(*message)
		q.buffer = []byte(msg.Data)
		q.control = msg.Control
		q.addr = msg.Address
	}
	buf := q.buffer
	var copied uintptr
	for _, d := range data {
		if len(buf) == 0 {
			break
		}
		n := copy(d, buf)
		copied += uintptr(n)
		buf = buf[n:]
	}
	c := q.control
	if !peek {
		// Consume data and control message if we are not peeking.
		if c != nil {
			q.control = c.CloneCreds()
		}
		q.buffer = buf
	} else if q.control != nil {
		// Don't consume control message if we are peeking.
		c = c.Clone()
	}
	return copied, c, q.addr, nil
}

// A ConnectedEndpoint is an Endpoint that can be used to send Messages.
type ConnectedEndpoint interface {
	// Passcred implements Endpoint.Passcred.
	Passcred() bool

	// GetLocalAddress implements Endpoint.GetLocalAddress.
	GetLocalAddress() (tcpip.FullAddress, error)

	// Send sends a single message. This method does not block.
	Send(data [][]byte, controlMessages ControlMessages, from tcpip.FullAddress) (uintptr, error)

	// CloseSend prevents the sending of additional Messages.
	CloseSend()

	// Writable returns if messages should be attempted to be sent.
	Writable() bool
}

type connectedEndpoint struct {
	// endpoint represents the subset of the Endpoint functionality needed by
	// the connectedEndpoint. It is implemented by both connectionedEndpoint
	// and connectionlessEndpoint and allows the use of types which don't
	// fully implement Endpoint.
	endpoint interface {
		// Passcred implements Endpoint.Passcred.
		Passcred() bool

		// GetLocalAddress implements Endpoint.GetLocalAddress.
		GetLocalAddress() (tcpip.FullAddress, error)

		// Type implements Endpoint.Type.
		Type() SockType
	}

	writeQueue *queue.Queue
}

// Passcred implements ConnectedEndpoint.Passcred.
func (e *connectedEndpoint) Passcred() bool {
	return e.endpoint.Passcred()
}

// GetLocalAddress implements ConnectedEndpoint.GetLocalAddress.
func (e *connectedEndpoint) GetLocalAddress() (tcpip.FullAddress, error) {
	return e.endpoint.GetLocalAddress()
}

// Send implements Receiver.Send.
func (e *connectedEndpoint) Send(data [][]byte, controlMessages ControlMessages, from tcpip.FullAddress) (uintptr, error) {
	var l int
	for _, d := range data {
		l += len(d)
	}
	// Discard empty stream packets. Since stream sockets don't preserve
	// message boundaries, sending zero bytes is a no-op. In Linux, the
	// receiver actually uses a zero-length receive as an indication that the
	// stream was closed.
	if l == 0 && e.endpoint.Type() == SockStream {
		controlMessages.Release()
		return 0, nil
	}
	v := make([]byte, 0, l)
	for _, d := range data {
		v = append(v, d...)
	}
	return uintptr(l), e.writeQueue.Enqueue(&message{Data: buffer.View(v), Control: controlMessages, Address: from})
}

// CloseSend implements Receiver.CloseSend.
func (e *connectedEndpoint) CloseSend() {
	e.writeQueue.Close()
}

// Writable implements Receiver.Writable.
func (e *connectedEndpoint) Writable() bool {
	return e.writeQueue.IsWritable()
}

// baseEndpoint is an embeddable unix endpoint base used in both the connected and connectionless
// unix domain socket Endpoint implementations.
//
// Not to be used on its own.
type baseEndpoint struct {
	*waiter.Queue

	// passcred specifies whether SCM_CREDENTIALS socket control messages are
	// enabled on this endpoint. Must be accessed atomically.
	passcred int32

	// Mutex protects the below fields.
	sync.Mutex

	// receiver allows Messages to be received.
	receiver Receiver

	// connected allows messages to be sent and state information about the
	// connected endpoint to be read.
	connected ConnectedEndpoint

	// path is not empty if the endpoint has been bound,
	// or may be used if the endpoint is connected.
	path string

	// isBound returns true iff the endpoint is bound.
	isBound func() bool `state:"manual"`
}

// Passcred implements Credentialer.Passcred.
func (e *baseEndpoint) Passcred() bool {
	return atomic.LoadInt32(&e.passcred) != 0
}

// ConnectedPasscred implements Credentialer.ConnectedPasscred.
func (e *baseEndpoint) ConnectedPasscred() bool {
	e.Lock()
	defer e.Unlock()
	return e.connected != nil && e.connected.Passcred()
}

func (e *baseEndpoint) setPasscred(pc bool) {
	if pc {
		atomic.StoreInt32(&e.passcred, 1)
	} else {
		atomic.StoreInt32(&e.passcred, 0)
	}
}

// Connected implements ConnectingEndpoint.Connected.
func (e *baseEndpoint) Connected() bool {
	return e.receiver != nil && e.connected != nil
}

// RecvMsg reads data and a control message from the endpoint.
func (e *baseEndpoint) RecvMsg(data [][]byte, numRights uintptr, peek bool, addr *tcpip.FullAddress) (uintptr, ControlMessages, error) {
	e.Lock()
	defer e.Unlock()

	if e.receiver == nil {
		return 0, nil, tcpip.ErrNotConnected
	}

	n, cms, a, err := e.receiver.Recv(data, numRights, peek)
	if err != nil {
		return 0, nil, err
	}

	if addr != nil {
		*addr = a
	}
	return n, cms, nil
}

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *baseEndpoint) SendMsg(data [][]byte, c ControlMessages, to Endpoint) (uintptr, error) {
	e.Lock()
	defer e.Unlock()
	if !e.Connected() {
		return 0, tcpip.ErrNotConnected
	}
	if to != nil {
		return 0, tcpip.ErrAlreadyConnected
	}

	n, err := e.connected.Send(data, c, tcpip.FullAddress{Addr: tcpip.Address(e.path)})
	if err != nil {
		return 0, err
	}

	return n, nil
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
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return tcpip.ErrNotConnected
		}
		*o = tcpip.ReceiveQueueSizeOption(e.receiver.QueuedSize())
		e.Unlock()
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

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *baseEndpoint) Shutdown(flags tcpip.ShutdownFlags) error {
	e.Lock()
	defer e.Unlock()
	if !e.Connected() {
		return tcpip.ErrNotConnected
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.receiver.CloseRecv()
	}

	if flags&tcpip.ShutdownWrite != 0 {
		e.connected.CloseSend()
	}

	return nil
}

// GetLocalAddress returns the bound path.
func (e *baseEndpoint) GetLocalAddress() (tcpip.FullAddress, error) {
	e.Lock()
	defer e.Unlock()
	return tcpip.FullAddress{Addr: tcpip.Address(e.path)}, nil
}

// GetRemoteAddress returns the local address of the connected endpoint (if
// available).
func (e *baseEndpoint) GetRemoteAddress() (tcpip.FullAddress, error) {
	e.Lock()
	c := e.connected
	e.Unlock()
	if c != nil {
		return c.GetLocalAddress()
	}
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}
