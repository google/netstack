package tcp

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
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

// endpoint represents a TCP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized. The protocol implementation, however, runs in a single
// goroutine.
type endpoint struct {
	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue

	// lastError represents the last error that the endpoint reported;
	// access to it is protected by the following mutex.
	lastErrorMu sync.Mutex
	lastError   error

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

	// hardError is meaningful only when state is stateError, it stores the
	// error to be returned when read/write syscalls are called and the
	// endpoint is in this state.
	hardError error

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// workerCleanup specifies if the worker goroutine must perform cleanup
	// before exitting. This can only be set to true when workerRunning is
	// also true, and they're both protected by the mutex.
	workerCleanup bool

	// The options below aren't implemented, but we remember the user
	// settings because applications expect to be able to set/query these
	// options.
	noDelay   bool
	reuseAddr bool

	// segmentChan is used to hand received segments to the protocol
	// goroutine. Segments are queued in the channel as long as it is not
	// full, and dropped when it is.
	segmentChan chan *segment

	// The following fields are used to manage the send buffer. When
	// segments are ready to be sent, they are added to sndQueue and the
	// protocol goroutine is signaled by a write to sndChan.
	//
	// When the send side is closed, the channel is closed (so that the
	// protocol goroutine is aware), and sndBufSize is set to -1.
	sndBufMu      sync.Mutex
	sndBufSize    int
	sndBufUsed    int
	sndBufInQueue seqnum.Size
	sndQueue      segmentList
	sndChan       chan struct{}

	// notifyChan is used to indicate to the protocol goroutine that it
	// needs to wake up and check for notifications.
	notifyChan chan struct{}

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
	return &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
		segmentChan: make(chan *segment, 10),
		rcvBufSize:  208 * 1024,
		sndBufSize:  208 * 1024,
		sndChan:     make(chan struct{}, 1),
		notifyChan:  make(chan struct{}, 1),
		noDelay:     true,
		reuseAddr:   true,
	}
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
				select {
				case e.notifyChan <- struct{}{}:
				default:
				}
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

	if e.isPortReserved {
		e.stack.ReleasePort(e.netProto, ProtocolNumber, e.id.LocalPort)
	}

	if e.isRegistered {
		e.stack.UnregisterTransportEndpoint(e.boundNICID, ProtocolNumber, e.id)
	}

	e.route.Release()
}

// Read reads data from the endpoint.
func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be read from if it's not connected.
	if e.state != stateConnected {
		switch e.state {
		case stateClosed:
			return buffer.View{}, tcpip.ErrClosedForReceive
		case stateError:
			return buffer.View{}, e.hardError
		default:
			return buffer.View{}, tcpip.ErrInvalidEndpointState
		}
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed {
			return buffer.View{}, tcpip.ErrClosedForReceive
		}
		return buffer.View{}, tcpip.ErrWouldBlock
	}

	s := e.rcvList.Front()
	v := s.data

	e.rcvList.Remove(s)
	wasZero := e.rcvBufUsed >= e.rcvBufSize
	e.rcvBufUsed -= len(s.data)
	if wasZero && e.rcvBufUsed < e.rcvBufSize {
		e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
	}
	s.decRef()

	return v, nil
}

// RecvMsg implements tcpip.RecvMsg.
func (e *endpoint) RecvMsg(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, error) {
	v, err := e.Read(addr)
	return v, nil, err
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(v buffer.View, to *tcpip.FullAddress) (uintptr, error) {
	if to != nil {
		return 0, tcpip.ErrAlreadyConnected
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be written to if it's not connected.
	if e.state != stateConnected {
		switch e.state {
		case stateError:
			return 0, e.hardError
		default:
			return 0, tcpip.ErrInvalidEndpointState
		}
	}

	s := newSegment(&e.route, e.id, v)

	e.sndBufMu.Lock()

	// Check if the connection has already been closed for sends.
	if e.sndBufSize < 0 {
		e.sndBufMu.Unlock()
		s.decRef()
		return 0, tcpip.ErrClosedForSend
	}

	// Check if we're already over the limit.
	if e.sndBufUsed > e.sndBufSize {
		e.sndBufMu.Unlock()
		s.decRef()
		return 0, tcpip.ErrWouldBlock
	}

	// Add data to the send queue.
	e.sndBufUsed += len(v)
	e.sndBufInQueue += seqnum.Size(len(v))
	e.sndQueue.PushBack(s)

	e.sndBufMu.Unlock()

	// Wake up the protocol goroutine.
	select {
	case e.sndChan <- struct{}{}:
	default:
	}

	return uintptr(len(v)), nil
}

// SendMsg implements tcpip.SendMsg.
func (e *endpoint) SendMsg(v buffer.View, c tcpip.ControlMessages, to *tcpip.FullAddress) (uintptr, error) {
	// Reject control messages.
	if c != nil {
		// tcpip.ErrInvalidEndpointState turns into syscall.EINVAL.
		return 0, tcpip.ErrInvalidEndpointState
	}
	return e.Write(v, to)
}

// Peek reads data without consuming it from the endpoint.
//
// This method does not block if there is no data pending.
func (e *endpoint) Peek(w io.Writer) (uintptr, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be read from if it's not connected.
	if e.state != stateConnected {
		switch e.state {
		case stateClosed:
			return 0, tcpip.ErrClosedForReceive
		case stateError:
			return 0, e.hardError
		default:
			return 0, tcpip.ErrInvalidEndpointState
		}
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed {
			return 0, tcpip.ErrClosedForReceive
		}
		return 0, tcpip.ErrWouldBlock
	}

	var num uintptr

	for s := e.rcvList.Front(); s != nil; s = s.Next() {
		n, err := w.Write(s.data)
		num += uintptr(n)
		if err != nil {
			return num, err
		}
	}

	return num, nil
}

// SetSockOpt sets a socket option. Currently not supported.
func (e *endpoint) SetSockOpt(opt interface{}) error {
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
		wasZero := e.rcvBufUsed >= e.rcvBufSize
		e.rcvBufSize = int(v)
		if wasZero && e.rcvBufUsed < e.rcvBufSize {
			mask |= notifyNonZeroReceiveWindow
		}
		e.rcvListMu.Unlock()

		e.notifyProtocolGoroutine(mask)
		return nil
	}

	return nil
}

// readyReceiveSize returns the number of bytes ready to be received.
func (e *endpoint) readyReceiveSize() (int, error) {
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
func (e *endpoint) GetSockOpt(opt interface{}) error {
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
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSize)
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
	}

	return tcpip.ErrInvalidEndpointState
}

// Connect connects the endpoint to its peer.
func (e *endpoint) Connect(addr tcpip.FullAddress) error {
	e.mu.Lock()
	defer e.mu.Unlock()

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
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, e.netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	e.id.LocalAddress = r.LocalAddress
	e.id.RemoteAddress = addr.Addr
	e.id.RemotePort = addr.Port

	if e.id.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(nicid, ProtocolNumber, e.id, e)
		if err != nil {
			return err
		}
	} else {
		// The endpoint doesn't have a local port yet, so try to get
		// one.
		_, err := e.stack.PickEphemeralPort(func(p uint16) (bool, error) {
			e.id.LocalPort = p
			err := e.stack.RegisterTransportEndpoint(nicid, ProtocolNumber, e.id, e)
			switch err {
			case nil:
				return true, nil
			case tcpip.ErrDuplicateAddress:
				return false, nil
			default:
				return false, err
			}
		})
		if err != nil {
			return err
		}
	}

	e.isRegistered = true
	e.state = stateConnecting
	e.route = r.Clone()
	e.boundNICID = nicid
	e.workerRunning = true

	go e.protocolMainLoop(false)

	return tcpip.ErrConnectStarted
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) error {
	return tcpip.ErrInvalidEndpointState
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case stateConnected:
		// Close for write.
		if (flags & tcpip.ShutdownWrite) != 0 {
			e.sndBufMu.Lock()
			defer e.sndBufMu.Unlock()

			if e.sndBufSize >= 0 {
				e.sndBufSize = -1
				close(e.sndChan)
			}
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
func (e *endpoint) Listen(backlog int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Endpoint must be bound before it can transition to listen mode.
	if e.state != stateBound {
		return tcpip.ErrInvalidEndpointState
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID, ProtocolNumber, e.id, e); err != nil {
		return err
	}

	e.isRegistered = true
	e.state = stateListen
	e.acceptedChan = make(chan *endpoint, backlog)
	e.workerRunning = true

	go e.protocolListenLoop(seqnum.Size(e.rcvBufSize))

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
func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, error) {
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
func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() error) (retErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.state != stateInitial {
		return tcpip.ErrAlreadyBound
	}

	// Reserve the port.
	port, err := e.stack.ReservePort(e.netProto, ProtocolNumber, addr.Port)
	if err != nil {
		return err
	}

	e.isPortReserved = true
	e.id.LocalPort = port

	// Any failures beyond this point must remove the port registration.
	defer func() {
		if retErr != nil {
			e.stack.ReleasePort(e.netProto, ProtocolNumber, port)
			e.isPortReserved = false
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
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, error) {
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
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, v buffer.View) {
	s := newSegment(r, id, v)
	if !s.parse() {
		// TODO: Inform the stack that the packet is malformed.
		s.decRef()
		return
	}

	// Send packet to worker goroutine.
	select {
	case e.segmentChan <- s:
	default:
		// The channel is full, so we drop the segment.
		// TODO: Add some stat on this.
		s.decRef()
	}
}

// updateSndBufferUsage is called by the protocol goroutine when room opens up
// in the send buffer. The number of newly available bytes is v.
func (e *endpoint) updateSndBufferUsage(v int) {
	e.sndBufMu.Lock()
	notify := e.sndBufUsed > e.sndBufSize
	e.sndBufUsed -= v
	notify = notify && e.sndBufUsed <= e.sndBufSize
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
		e.rcvBufUsed += len(s.data)
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
