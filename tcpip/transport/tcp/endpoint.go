// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"crypto/rand"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/netstack/sleep"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tmutex"
	"github.com/google/netstack/waiter"
)

type endpointState int

const (
	stateInitial endpointState = iota
	stateBound
	stateListen
	stateConnecting
	stateConnected
	stateClosed
	stateError
)

// Reasons for notifying the protocol goroutine.
const (
	notifyNonZeroReceiveWindow = 1 << iota
	notifyReceiveWindowChanged
	notifyClose
)

// DefaultBufferSize is the default size of the receive and send buffers.
const DefaultBufferSize = 208 * 1024

// endpoint represents a TCP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized. The protocol implementation, however, runs in a single
// goroutine.
type endpoint struct {
	// workMu is used to arbitrate which goroutine may perform protocol
	// work. Only the main protocol goroutine is expected to call Lock() on
	// it, but other goroutines (e.g., send) may call TryLock() to eagerly
	// perform work without having to wait for the main one to wake up.
	workMu tmutex.Mutex

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue

	// lastError represents the last error that the endpoint reported;
	// access to it is protected by the following mutex.
	lastErrorMu sync.Mutex
	lastError   *tcpip.Error

	// The following fields are used to manage the receive queue. The
	// protocol goroutine adds ready-for-delivery segments to rcvList,
	// which are returned by Read() calls to users.
	//
	// Once the peer has closed the its send side, rcvClosed is set to true
	// to indicate to users that no more data is coming.
	rcvListMu  sync.Mutex
	rcvList    segmentList
	rcvClosed  bool
	rcvBufSize int
	rcvBufUsed int

	// The following fields are protected by the mutex.
	mu             sync.RWMutex
	id             stack.TransportEndpointID
	state          endpointState
	isPortReserved bool
	isRegistered   bool
	boundNICID     tcpip.NICID
	route          stack.Route
	v6only         bool

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// hardError is meaningful only when state is stateError, it stores the
	// error to be returned when read/write syscalls are called and the
	// endpoint is in this state.
	hardError *tcpip.Error

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// workerCleanup specifies if the worker goroutine must perform cleanup
	// before exitting. This can only be set to true when workerRunning is
	// also true, and they're both protected by the mutex.
	workerCleanup bool

	// sendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1
	sendTSOk bool

	// recentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	recentTS uint32

	// tsOffset is a randomized offset added to the value of the
	// TSVal field in the timestamp option.
	tsOffset uint32

	// The options below aren't implemented, but we remember the user
	// settings because applications expect to be able to set/query these
	// options.
	noDelay   bool
	reuseAddr bool

	// segmentQueue is used to hand received segments to the protocol
	// goroutine. Segments are queued as long as the queue is not full,
	// and dropped when it is.
	segmentQueue segmentQueue

	// The following fields are used to manage the send buffer. When
	// segments are ready to be sent, they are added to sndQueue and the
	// protocol goroutine is signaled via sndWaker.
	//
	// When the send side is closed, the protocol goroutine is notified via
	// sndCloseWaker, and sndBufSize is set to -1.
	sndBufMu      sync.Mutex
	sndBufSize    int
	sndBufUsed    int
	sndBufInQueue seqnum.Size
	sndQueue      segmentList
	sndWaker      sleep.Waker
	sndCloseWaker sleep.Waker

	// newSegmentWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and handle new segments queued to it.
	newSegmentWaker sleep.Waker

	// notificationWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and check for notifications.
	notificationWaker sleep.Waker

	// notifyFlags is a bitmask of flags used to indicate to the protocol
	// goroutine what it was notified; this is only accessed atomically.
	notifyFlags uint32

	// acceptedChan is used by a listening endpoint protocol goroutine to
	// send newly accepted connections to the endpoint so that they can be
	// read by Accept() calls.
	acceptedChan chan *endpoint

	// The following are only used from the protocol goroutine, and
	// therefore don't need locks to protect them.
	rcv *receiver
	snd *sender
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
		rcvBufSize:  DefaultBufferSize,
		sndBufSize:  DefaultBufferSize,
		noDelay:     true,
		reuseAddr:   true,
	}
	e.segmentQueue.setLimit(2 * e.rcvBufSize)
	e.workMu.Init()
	e.workMu.Lock()
	e.tsOffset = timeStampOffset()
	return e
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.EventMask(0)

	e.mu.RLock()
	defer e.mu.RUnlock()

	switch e.state {
	case stateInitial, stateBound, stateConnecting:
		// Ready for nothing.

	case stateClosed, stateError:
		// Ready for anything.
		result = mask

	case stateListen:
		// Check if there's anything in the accepted channel.
		if (mask & waiter.EventIn) != 0 {
			if len(e.acceptedChan) > 0 {
				result |= waiter.EventIn
			}
		}

	case stateConnected:
		// Determine if the endpoint is writable if requested.
		if (mask & waiter.EventOut) != 0 {
			e.sndBufMu.Lock()
			if e.sndBufSize < 0 || e.sndBufUsed <= e.sndBufSize {
				result |= waiter.EventOut
			}
			e.sndBufMu.Unlock()
		}

		// Determine if the endpoint is readable if requested.
		if (mask & waiter.EventIn) != 0 {
			e.rcvListMu.Lock()
			if e.rcvBufUsed > 0 || e.rcvClosed {
				result |= waiter.EventIn
			}
			e.rcvListMu.Unlock()
		}
	}

	return result
}

func (e *endpoint) fetchNotifications() uint32 {
	return atomic.SwapUint32(&e.notifyFlags, 0)
}

func (e *endpoint) notifyProtocolGoroutine(n uint32) {
	for {
		v := atomic.LoadUint32(&e.notifyFlags)
		if v&n == n {
			// The flags are already set.
			return
		}

		if atomic.CompareAndSwapUint32(&e.notifyFlags, v, v|n) {
			if v == 0 {
				// We are causing a transition from no flags to
				// at least one flag set, so we must cause the
				// protocol goroutine to wake up.
				e.notificationWaker.Assert()
			}
			return
		}
	}
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it. It must be called only once and with no other concurrent calls to
// the endpoint.
func (e *endpoint) Close() {
	// Issue a shutdown so that the peer knows we won't send any more data
	// if we're connected, or stop accepting if we're listening.
	e.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)

	// While we hold the lock, determine if the cleanup should happen
	// inline or if we should tell the worker (if any) to do the cleanup.
	e.mu.Lock()
	worker := e.workerRunning
	if worker {
		e.workerCleanup = true
	}

	// We always release ports inline so that they are immediately available
	// for reuse after Close() is called. If also registered, it means this
	// is a listening socket, so we must unregister as well otherwise the
	// next user would fail in Listen() when trying to register.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
		e.isPortReserved = false

		if e.isRegistered {
			e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
			e.isRegistered = false
		}
	}

	e.mu.Unlock()

	// Now that we don't hold the lock anymore, either perform the local
	// cleanup or kick the worker to make sure it knows it needs to cleanup.
	if !worker {
		e.cleanup()
	} else {
		e.notifyProtocolGoroutine(notifyClose)
	}
}

// cleanup frees all resources associated with the endpoint. It is called after
// Close() is called and the worker goroutine (if any) is done with its work.
func (e *endpoint) cleanup() {
	// Close all endpoints that might have been accepted by TCP but not by
	// the client.
	if e.acceptedChan != nil {
		close(e.acceptedChan)
		for n := range e.acceptedChan {
			n.resetConnection(tcpip.ErrConnectionAborted)
			n.Close()
		}
	}

	if e.isRegistered {
		e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
	}

	e.route.Release()
}

// Read reads data from the endpoint.
func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, *tcpip.Error) {
	e.mu.RLock()

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data.
	if s := e.state; s != stateConnected && s != stateClosed {
		e.mu.RUnlock()
		if s == stateError {
			return buffer.View{}, e.hardError
		}
		return buffer.View{}, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	v, err := e.readLocked()
	e.rcvListMu.Unlock()

	e.mu.RUnlock()

	return v, err
}

func (e *endpoint) readLocked() (buffer.View, *tcpip.Error) {
	if e.rcvBufUsed == 0 {
		if e.rcvClosed || e.state != stateConnected {
			return buffer.View{}, tcpip.ErrClosedForReceive
		}
		return buffer.View{}, tcpip.ErrWouldBlock
	}

	s := e.rcvList.Front()
	views := s.data.Views()
	v := views[s.viewToDeliver]
	s.viewToDeliver++

	if s.viewToDeliver >= len(views) {
		e.rcvList.Remove(s)
		s.decRef()
	}

	scale := e.rcv.rcvWndScale
	wasZero := e.zeroReceiveWindow(scale)
	e.rcvBufUsed -= len(v)
	if wasZero && !e.zeroReceiveWindow(scale) {
		e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
	}

	return v, nil
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(v buffer.View, to *tcpip.FullAddress) (uintptr, *tcpip.Error) {
	// Linux completely ignores any address passed to sendto(2) for TCP sockets
	// (without the MSG_FASTOPEN flag).

	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be written to if it's not connected.
	if e.state != stateConnected {
		switch e.state {
		case stateError:
			return 0, e.hardError
		default:
			return 0, tcpip.ErrClosedForSend
		}
	}

	// Nothing to do if the buffer is empty.
	if len(v) == 0 {
		return 0, nil
	}

	e.sndBufMu.Lock()

	// Check if the connection has already been closed for sends.
	if e.sndBufSize < 0 {
		e.sndBufMu.Unlock()
		return 0, tcpip.ErrClosedForSend
	}

	// Check if we're already over the limit.
	avail := e.sndBufSize - e.sndBufUsed
	if avail <= 0 {
		e.sndBufMu.Unlock()
		return 0, tcpip.ErrWouldBlock
	}

	// If writing would put us over the size limit, create a smaller view
	// with the maximum available size and copy into it. We also return
	// ErrWouldBlock in this case.
	sizedView := v
	var err *tcpip.Error
	if len(sizedView) > avail {
		sizedView = buffer.NewViewFromBytes(v[:avail])
		err = tcpip.ErrWouldBlock
	}
	l := len(sizedView)
	s := newSegmentFromView(&e.route, e.id, sizedView)

	// Add data to the send queue.
	e.sndBufUsed += l
	e.sndBufInQueue += seqnum.Size(l)
	e.sndQueue.PushBack(s)

	e.sndBufMu.Unlock()

	if e.workMu.TryLock() {
		// Do the work inline.
		e.handleWrite()
		e.workMu.Unlock()
	} else {
		// Let the protocol goroutine do the work.
		e.sndWaker.Assert()
	}
	return uintptr(l), err
}

// Peek reads data without consuming it from the endpoint.
//
// This method does not block if there is no data pending.
func (e *endpoint) Peek(vec [][]byte) (uintptr, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data.
	if s := e.state; s != stateConnected && s != stateClosed {
		if s == stateError {
			return 0, e.hardError
		}
		return 0, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed || e.state != stateConnected {
			return 0, tcpip.ErrClosedForReceive
		}
		return 0, tcpip.ErrWouldBlock
	}

	// Make a copy of vec so we can modify the slide headers.
	vec = append([][]byte(nil), vec...)

	var num uintptr

	for s := e.rcvList.Front(); s != nil; s = s.Next() {
		views := s.data.Views()

		for i := s.viewToDeliver; i < len(views); i++ {
			v := views[i]

			for len(v) > 0 {
				if len(vec) == 0 {
					return num, nil
				}
				if len(vec[0]) == 0 {
					vec = vec[1:]
					continue
				}

				n := copy(vec[0], v)
				v = v[n:]
				vec[0] = vec[0][n:]
				num += uintptr(n)
			}
		}
	}

	return num, nil
}

// zeroReceiveWindow checks if the receive window to be announced now would be
// zero, based on the amount of available buffer and the receive window scaling.
//
// It must be called with rcvListMu held.
func (e *endpoint) zeroReceiveWindow(scale uint8) bool {
	if e.rcvBufUsed >= e.rcvBufSize {
		return true
	}

	return ((e.rcvBufSize - e.rcvBufUsed) >> scale) == 0
}

// SetSockOpt sets a socket option.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.NoDelayOption:
		e.mu.Lock()
		e.noDelay = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.ReuseAddressOption:
		e.mu.Lock()
		e.reuseAddr = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.ReceiveBufferSizeOption:
		mask := uint32(notifyReceiveWindowChanged)

		e.rcvListMu.Lock()

		// Make sure the receive buffer size allows us to send a
		// non-zero window size.
		scale := uint8(0)
		if e.rcv != nil {
			scale = e.rcv.rcvWndScale
		}
		if v>>scale == 0 {
			v = 1 << scale
		}

		// Make sure 2*v doesn't overflow.
		if int(v) > math.MaxInt32/2 {
			v = math.MaxInt32 / 2
		}

		wasZero := e.zeroReceiveWindow(scale)
		e.rcvBufSize = int(v)
		if wasZero && !e.zeroReceiveWindow(scale) {
			mask |= notifyNonZeroReceiveWindow
		}
		e.rcvListMu.Unlock()

		e.segmentQueue.setLimit(2 * int(v))

		e.notifyProtocolGoroutine(mask)
		return nil

	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != stateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0
	}

	return nil
}

// readyReceiveSize returns the number of bytes ready to be received.
func (e *endpoint) readyReceiveSize() (int, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be in listen state.
	if e.state == stateListen {
		return 0, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	return e.rcvBufUsed, nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		e.lastErrorMu.Lock()
		err := e.lastError
		e.lastError = nil
		e.lastErrorMu.Unlock()
		return err

	case *tcpip.SendBufferSizeOption:
		e.sndBufMu.Lock()
		*o = tcpip.SendBufferSizeOption(e.sndBufSize)
		e.sndBufMu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.rcvListMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSize * 2)
		e.rcvListMu.Unlock()
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		v, err := e.readyReceiveSize()
		if err != nil {
			return err
		}

		*o = tcpip.ReceiveQueueSizeOption(v)
		return nil

	case *tcpip.NoDelayOption:
		e.mu.RLock()
		v := e.noDelay
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.ReuseAddressOption:
		e.mu.RLock()
		v := e.reuseAddr
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil
	}

	return tcpip.ErrUnknownProtocolOption
}

func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto := e.netProto
	if header.IsV4MappedAddress(addr.Addr) {
		// Fail if using a v4 mapped address on a v6only endpoint.
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		netProto = header.IPv4ProtocolNumber
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		if addr.Addr == "\x00\x00\x00\x00" {
			addr.Addr = ""
		}
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	if l := len(e.id.LocalAddress); l != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Connect connects the endpoint to its peer.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}

	nicid := addr.NIC
	switch e.state {
	case stateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicid != 0 && nicid != e.boundNICID {
			return tcpip.ErrNoRoute
		}

		nicid = e.boundNICID

	case stateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID
		// (if any) when we find a route.

	case stateConnecting:
		// A connection request has already been issued but hasn't
		// completed yet.
		return tcpip.ErrAlreadyConnecting

	case stateConnected:
		// The endpoint is already connected.
		return tcpip.ErrAlreadyConnected

	default:
		return tcpip.ErrInvalidEndpointState
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	origID := e.id

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	e.id.LocalAddress = r.LocalAddress
	e.id.RemoteAddress = addr.Addr
	e.id.RemotePort = addr.Port

	if e.id.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, e.id, e)
		if err != nil {
			return err
		}
	} else {
		// The endpoint doesn't have a local port yet, so try to get
		// one.
		_, err := e.stack.PickEphemeralPort(func(p uint16) (bool, *tcpip.Error) {
			e.id.LocalPort = p
			err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, e.id, e)
			switch err {
			case nil:
				return true, nil
			case tcpip.ErrPortInUse:
				return false, nil
			default:
				return false, err
			}
		})
		if err != nil {
			return err
		}
	}

	// Remove the port reservation. This can happen when Bind is called
	// before Connect: in such a case we don't want to hold on to
	// reservations anymore.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, origID.LocalAddress, origID.LocalPort)
		e.isPortReserved = false
	}

	e.isRegistered = true
	e.state = stateConnecting
	e.route = r.Clone()
	e.boundNICID = nicid
	e.effectiveNetProtos = netProtos
	e.workerRunning = true

	go e.protocolMainLoop(false)

	return tcpip.ErrConnectStarted
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case stateConnected:
		// Close for write.
		if (flags & tcpip.ShutdownWrite) != 0 {
			e.sndBufMu.Lock()

			if e.sndBufSize < 0 {
				// Already closed.
				e.sndBufMu.Unlock()
				break
			}

			// Queue fin segment.
			s := newSegmentFromView(&e.route, e.id, nil)
			e.sndQueue.PushBack(s)
			e.sndBufInQueue++

			// Mark endpoint as closed.
			e.sndBufSize = -1

			e.sndBufMu.Unlock()

			// Tell protocol goroutine to close.
			e.sndCloseWaker.Assert()
		}

	case stateListen:
		// Tell protocolListenLoop to stop.
		if flags&tcpip.ShutdownRead != 0 {
			e.notifyProtocolGoroutine(notifyClose)
		}

	default:
		return tcpip.ErrInvalidEndpointState
	}

	return nil
}

// Listen puts the endpoint in "listen" mode, which allows it to accept
// new connections.
func (e *endpoint) Listen(backlog int) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Allow the backlog to be adjusted if the endpoint is not shutting down.
	// When the endpoint shuts down, it sets workerCleanup to true, and from
	// that point onward, acceptedChan is the responsibility of the cleanup()
	// method (and should not be touched anywhere else, including here).
	if e.state == stateListen && !e.workerCleanup {
		// Adjust the size of the channel iff we can fix existing
		// pending connections into the new one.
		if len(e.acceptedChan) > backlog {
			return tcpip.ErrInvalidEndpointState
		}
		origChan := e.acceptedChan
		e.acceptedChan = make(chan *endpoint, backlog)
		close(origChan)
		for ep := range origChan {
			e.acceptedChan <- ep
		}
		return nil
	}

	// Endpoint must be bound before it can transition to listen mode.
	if e.state != stateBound {
		return tcpip.ErrInvalidEndpointState
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e); err != nil {
		return err
	}

	e.isRegistered = true
	e.state = stateListen
	e.acceptedChan = make(chan *endpoint, backlog)
	e.workerRunning = true

	go e.protocolListenLoop(seqnum.Size(e.receiveBufferAvailable()))

	return nil
}

// startAcceptedLoop sets up required state and starts a goroutine with the
// main loop for accepted connections.
func (e *endpoint) startAcceptedLoop(waiterQueue *waiter.Queue) {
	e.waiterQueue = waiterQueue
	e.workerRunning = true
	go e.protocolMainLoop(true)
}

// Accept returns a new endpoint if a peer has established a connection
// to an endpoint previously set to listen mode.
func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Endpoint must be in listen state before it can accept connections.
	if e.state != stateListen {
		return nil, nil, tcpip.ErrInvalidEndpointState
	}

	// Get the new accepted endpoint.
	var n *endpoint
	select {
	case n = <-e.acceptedChan:
	default:
		return nil, nil, tcpip.ErrWouldBlock
	}

	// Start the protocol goroutine.
	wq := &waiter.Queue{}
	n.startAcceptedLoop(wq)

	return n, wq, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) (retErr *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.state != stateInitial {
		return tcpip.ErrAlreadyBound
	}

	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}

	// Expand netProtos to include v4 and v6 if the caller is binding to a
	// wildcard (empty) address, and this is an IPv6 endpoint with v6only
	// set to false.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}

	// Reserve the port.
	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port)
	if err != nil {
		return err
	}

	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.id.LocalPort = port

	// Any failures beyond this point must remove the port registration.
	defer func() {
		if retErr != nil {
			e.stack.ReleasePort(netProtos, ProtocolNumber, addr.Addr, port)
			e.isPortReserved = false
			e.effectiveNetProtos = nil
			e.id.LocalPort = 0
			e.id.LocalAddress = ""
			e.boundNICID = 0
		}
	}()

	// If an address is specified, we must ensure that it's one of our
	// local addresses.
	if len(addr.Addr) != 0 {
		nic := e.stack.CheckLocalAddress(addr.NIC, addr.Addr)
		if nic == 0 {
			return tcpip.ErrBadLocalAddress
		}

		e.boundNICID = nic
		e.id.LocalAddress = addr.Addr
	}

	// Check the commit function.
	if commit != nil {
		if err := commit(); err != nil {
			// The defer takes care of unwind.
			return err
		}
	}

	// Mark endpoint as bound.
	e.state = stateBound

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrInvalidEndpointState
	}

	return tcpip.FullAddress{
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
		NIC:  e.boundNICID,
	}, nil
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv *buffer.VectorisedView) {
	s := newSegment(r, id, vv)
	if !s.parse() {
		atomic.AddUint64(&e.stack.MutableStats().MalformedRcvdPackets, 1)
		s.decRef()
		return
	}

	// Send packet to worker goroutine.
	if e.segmentQueue.enqueue(s) {
		e.newSegmentWaker.Assert()
	} else {
		// The queue is full, so we drop the segment.
		atomic.AddUint64(&e.stack.MutableStats().DroppedPackets, 1)
		s.decRef()
	}
}

// updateSndBufferUsage is called by the protocol goroutine when room opens up
// in the send buffer. The number of newly available bytes is v.
func (e *endpoint) updateSndBufferUsage(v int) {
	e.sndBufMu.Lock()
	notify := e.sndBufUsed >= e.sndBufSize
	e.sndBufUsed -= v
	notify = notify && e.sndBufUsed < e.sndBufSize
	e.sndBufMu.Unlock()

	if notify {
		e.waiterQueue.Notify(waiter.EventOut)
	}
}

// readyToRead is called by the protocol goroutine when a new segment is ready
// to be read, or when the connection is closed for receiving (in which case
// s will be nil).
func (e *endpoint) readyToRead(s *segment) {
	e.rcvListMu.Lock()
	if s != nil {
		s.incRef()
		e.rcvBufUsed += s.data.Size()
		e.rcvList.PushBack(s)
	} else {
		e.rcvClosed = true
	}
	e.rcvListMu.Unlock()

	e.waiterQueue.Notify(waiter.EventIn)
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer.
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	used := e.rcvBufUsed
	e.rcvListMu.Unlock()

	// We may use more bytes than the buffer size when the receive buffer
	// shrinks.
	if used >= size {
		return 0
	}

	return size - used
}

func (e *endpoint) receiveBufferSize() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	e.rcvListMu.Unlock()

	return size
}

// updateRecentTimestamp updates the recent timestamp using the algorithm
// described in https://tools.ietf.org/html/rfc7323#section-4.3
func (e *endpoint) updateRecentTimestamp(tsVal uint32, maxSentAck seqnum.Value, segSeq seqnum.Value) {
	if e.sendTSOk && seqnum.Value(e.recentTS).LessThan(seqnum.Value(tsVal)) && segSeq.LessThanEq(maxSentAck) {
		e.recentTS = tsVal
	}
}

// maybeEnableTimestamp marks the timestamp option enabled for this endpoint if
// the SYN options indicate that timestamp option was negotiated. It also
// initializes the recentTS with the value provided in synOpts.TSval.
func (e *endpoint) maybeEnableTimestamp(synOpts *header.TCPSynOptions) {
	if synOpts.TS {
		e.sendTSOk = true
		e.recentTS = synOpts.TSVal
	}
}

// timestamp returns the timestamp value to be used in the TSVal field of the
// timestamp option for outgoing TCP segments for a given endpoint.
func (e *endpoint) timestamp() uint32 {
	return tcpTimeStamp(e.tsOffset)
}

// tcpTimeStamp returns a timestamp offset by the provided offset. This is
// not inlined above as it's used when SYN cookies are in use and endpoint
// is not created at the time when the SYN cookie is sent.
func tcpTimeStamp(offset uint32) uint32 {
	now := time.Now()
	return uint32(now.Unix()*1000+int64(now.Nanosecond()/1e6)) + offset
}

// timeStampOffset returns a randomized timestamp offset to be used when sending
// timestamp values in a timestamp option for a TCP segment.
func timeStampOffset() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// Initialize a random tsOffset that will be added to the recentTS
	// everytime the timestamp is sent when the Timestamp option is enabled.
	//
	// See https://tools.ietf.org/html/rfc7323#section-5.4 for details on
	// why this is required.
	//
	// NOTE: This is not completely to spec as normally this should be
	// initialized in a manner analogous to how sequence numbers are
	// randomized per connection basis. But for now this is sufficient.
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
