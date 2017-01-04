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

// Message represents a message passed over a Unix domain socket.
type Message struct {
	ilist.Entry

	// Data is the Message payload.
	Data buffer.View

	// Control is auxiliary control message data that goes along with the
	// data.
	Control tcpip.ControlMessages

	// Address is the bound address of the endpoint that sent the message.
	//
	// If the endpoint that sent the message is not bound, the Address is
	// the empty string.
	Address tcpip.FullAddress
}

// Length returns number of bytes stored in the Message.
func (m *Message) Length() int64 {
	return int64(len(m.Data))
}

// Release releases any resources held by the Message.
func (m *Message) Release() {
	if m.Control != nil {
		m.Control.Release()
	}
}

// A Receiver can be used to receive Messages.
type Receiver interface {
	// Recv receives a single message. This method does not block.
	Recv() (*Message, error)

	// CloseRecv prevents the receiving of additional Messages.
	CloseRecv()

	// Readable returns if messages should be attempted to be received.
	Readable() bool

	// QueuedSize returns the total amount of data currently receivable.
	QueuedSize() int64
}

// queueReceiver implements Receiver.
type queueReceiver struct {
	readQueue *queue.Queue
}

// Recv implements Receiver.Recv.
func (q *queueReceiver) Recv() (*Message, error) {
	m, err := q.readQueue.Dequeue()
	if err != nil {
		return nil, err
	}
	return m.(*Message), nil
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

// An endpoint is a unix domain socket node.
type endpoint interface {
	// Passcred implements Credentialer.Passcred.
	Passcred() bool

	// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
	GetLocalAddress() (tcpip.FullAddress, error)
}

// A ConnectedEndpoint is an Endpoint that can be used to send Messages.
type ConnectedEndpoint interface {
	endpoint

	// Send sends a single message. This method does not block.
	Send(*Message) error

	// CloseSend prevents the sending of additional Messages.
	CloseSend()

	// Writable returns if messages should be attempted to be sent.
	Writable() bool
}

type connectedEndpoint struct {
	endpoint

	writeQueue *queue.Queue
}

// Send implements Receiver.Send.
func (e *connectedEndpoint) Send(m *Message) error {
	return e.writeQueue.Enqueue(m)
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
// unix domain socket tcpip.Endpoint implementations.
//
// Not to be used on its own.
type baseEndpoint struct {
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
	e.Lock()
	defer e.Unlock()

	msg, err := e.receiver.Recv()
	if err != nil {
		return buffer.View{}, nil, err
	}

	if addr != nil {
		*addr = msg.Address
	}
	return msg.Data, msg.Control, nil
}

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *baseEndpoint) SendMsg(v buffer.View, c tcpip.ControlMessages, to *tcpip.FullAddress) (uintptr, error) {
	e.Lock()
	defer e.Unlock()
	if !e.Connected() {
		return 0, tcpip.ErrNotConnected
	}
	if to != nil {
		return 0, tcpip.ErrAlreadyConnected
	}

	msg := Message{Data: v, Control: c}
	if e.isBound() {
		msg.Address = tcpip.FullAddress{Addr: tcpip.Address(e.path)}
	}
	if err := e.connected.Send(&msg); err != nil {
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

// Connect via address is not supported.
func (*baseEndpoint) Connect(addr tcpip.FullAddress) error {
	return tcpip.ErrConnectionRefused
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
