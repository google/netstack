package tcp

import (
	"crypto/rand"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

type handshakeState int

// The following are the possible states of the TCP connection during a 3-way
// handshake. A depiction of the states and transitions can be found in RFC 793,
// page 23.
const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

// handshake holds the state used during a TCP 3-way handshake.
type handshake struct {
	ep     *endpoint
	state  handshakeState
	active bool
	flags  uint8
	ackNum seqnum.Value

	// iss is the initial send sequence number, as defined in RFC 793.
	iss seqnum.Value

	// rcvWnd is the receive window, as defined in RFC 793.
	rcvWnd seqnum.Size

	// sndWnd is the send window, as defined in RFC 793.
	sndWnd seqnum.Size
}

func newHandshake(ep *endpoint, rcvWnd seqnum.Size) (handshake, error) {
	h := handshake{ep: ep, active: true, rcvWnd: rcvWnd}
	if err := h.resetState(); err != nil {
		return handshake{}, err
	}

	return h, nil
}

// resetState resets the state of the handshake object such that it becomes
// ready for a new 3-way handshake.
func (h *handshake) resetState() error {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return err
	}

	h.state = handshakeSynSent
	h.flags = flagSyn
	h.ackNum = 0
	h.iss = seqnum.Value(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)

	return nil
}

// resetToSynRcvd resets the state of the handshake object to the SYN-RCVD
// state.
func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value) {
	h.active = false
	h.state = handshakeSynRcvd
	h.flags = flagSyn | flagAck
	h.iss = iss
	h.ackNum = irs + 1
}

// checkAck checks if the ACK number, if present, of a segment received during
// a TCP 3-way handshake is valid. If it's not, a RST segment is sent back in
// response.
func (h *handshake) checkAck(s *segment) bool {
	if s.flagIsSet(flagAck) && s.ackNumber != h.iss+1 {
		// RFC 793, page 36, states that a reset must be generated when
		// the connection is in any non-synchronized state and an
		// incoming segment acknowledges something not yet sent. The
		// connection remains in the same state.
		ack := s.sequenceNumber.Add(s.logicalLen())
		h.ep.sendRaw(nil, flagRst|flagAck, s.ackNumber, ack, 0)
		return false
	}

	return true
}

// synSentState handles a segment received when the TCP 3-way handshake is in
// the SYN-SENT state.
func (h *handshake) synSentState(s *segment) error {
	// RFC 793, page 37, states that in the SYN-SENT state, a reset is
	// acceptable if the ack field acknowledges the SYN.
	if s.flagIsSet(flagRst) {
		if s.flagIsSet(flagAck) && s.ackNumber == h.iss+1 {
			return tcpip.ErrConnectionRefused
		}
		return nil
	}

	if !h.checkAck(s) {
		return nil
	}

	// We are in the SYN-SENT state. We only care about segments that have
	// the SYN flag.
	if !s.flagIsSet(flagSyn) {
		return nil
	}

	// Remember the sequence we'll ack from now on.
	h.ackNum = s.sequenceNumber + 1
	h.flags |= flagAck

	// If this is a SYN ACK response, we only need to acknowledge the SYN
	// and the handshake is completed.
	if s.flagIsSet(flagAck) {
		h.state = handshakeCompleted
		h.ep.sendRaw(nil, flagAck, h.iss+1, h.ackNum, h.rcvWnd)
		return nil
	}

	// A SYN segment was received, but no ACK in it. We acknowledge the SYN
	// but resend our own SYN and wait for it to be acknowledged in the
	// SYN-RCVD state.
	h.state = handshakeSynRcvd
	h.ep.sendRaw(nil, h.flags, h.iss, h.ackNum, h.rcvWnd)

	return nil
}

// synRcvdState handles a segment received when the TCP 3-way handshake is in
// the SYN-RCVD state.
func (h *handshake) synRcvdState(s *segment) error {
	if s.flagIsSet(flagRst) {
		// RFC 793, page 37, states that in the SYN-RCVD state, a reset
		// is acceptable if the sequence number is in the window.
		if s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
			return tcpip.ErrConnectionRefused
		}
		return nil
	}

	if !h.checkAck(s) {
		return nil
	}

	if s.flagIsSet(flagSyn) && s.sequenceNumber != h.ackNum-1 {
		// We received two SYN segments with different sequence
		// numbers, so we reset this and restart the whole
		// process, except that we don't reset the timer.
		ack := s.sequenceNumber.Add(s.logicalLen())
		seq := seqnum.Value(0)
		if s.flagIsSet(flagAck) {
			seq = s.ackNumber
		}
		h.ep.sendRaw(nil, flagRst|flagAck, seq, ack, 0)

		if !h.active {
			return tcpip.ErrInvalidEndpointState
		}

		if err := h.resetState(); err != nil {
			return err
		}

		h.ep.sendRaw(nil, h.flags, h.iss, h.ackNum, h.rcvWnd)
		return nil
	}

	// We have previously received (and acknowledged) the peer's SYN. If the
	// peer acknowledges our SYN, the handshake is completed.
	if s.flagIsSet(flagAck) {
		h.state = handshakeCompleted
		return nil
	}

	return nil
}

// execute executes the TCP 3-way handshake.
func (h *handshake) execute() error {
	// Initialize the resend timer.
	timeOut := time.Duration(time.Second)
	rt := time.NewTimer(timeOut)
	defer rt.Stop()

	// Send the initial SYN segment and loop until the handshake is
	// completed.
	h.ep.sendRaw(nil, h.flags, h.iss, h.ackNum, h.rcvWnd)
	for h.state != handshakeCompleted {
		select {
		case <-rt.C:
			timeOut *= 2
			if timeOut > 60*time.Second {
				return tcpip.ErrTimeout
			}
			rt.Reset(timeOut)
			h.ep.sendRaw(nil, h.flags, h.iss, h.ackNum, h.rcvWnd)

		case s := <-h.ep.segmentChan:
			h.sndWnd = s.window
			var err error
			switch h.state {
			case handshakeSynRcvd:
				err = h.synRcvdState(s)
			case handshakeSynSent:
				err = h.synSentState(s)
			}
			s.decRef()
			if err != nil {
				return err
			}

		case <-h.ep.notifyChan:
			n := h.ep.fetchNotifications()
			if n&notifyClose != 0 {
				return tcpip.ErrAborted
			}
		}
	}

	return nil
}

// sendTCP sends a TCP segment via the provided network endpoint and under the
// provided identity.
func sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.View, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size) error {
	// Allocate a buffer for the TCP header.
	hdr := buffer.NewPrependable(header.TCPMinimumSize + int(r.MaxHeaderLength()))

	if rcvWnd > 0xffff {
		rcvWnd = 0xffff
	}

	// Initialize the header.
	tcp := header.TCP(hdr.Prepend(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{
		SrcPort:    id.LocalPort,
		DstPort:    id.RemotePort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: uint16(rcvWnd),
	})

	length := uint16(hdr.UsedLength())
	xsum := r.PseudoHeaderChecksum(ProtocolNumber)
	if data != nil {
		length += uint16(len(data))
		xsum = header.Checksum(data, xsum)
	}

	tcp.SetChecksum(^tcp.CalculateChecksum(xsum, length))

	return r.WritePacket(&hdr, data, ProtocolNumber)
}

// sendRaw sends a TCP segment to the endpoint's peer.
func (e *endpoint) sendRaw(data buffer.View, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size) error {
	return sendTCP(&e.route, e.id, data, flags, seq, ack, rcvWnd)
}

func (e *endpoint) handleWrite(ok bool) {
	// Move packets from send queue to send list. The queue is accessible
	// from other goroutines and protected by the send mutex, while the send
	// list is only accessible from the handler goroutine, so it needs no
	// mutexes.
	e.sndBufMu.Lock()

	first := e.sndQueue.Front()
	if first != nil {
		e.snd.writeList.PushBackList(&e.sndQueue)
		e.snd.sndNxtList.UpdateForward(e.sndBufInQueue)
		e.sndBufInQueue = 0
	}

	e.sndBufMu.Unlock()

	// If the channel has been closed, queue the FIN packet and mark send
	// side as closed.
	if !ok {
		e.snd.closed = true
		e.sndChan = nil
		e.snd.sndNxtList++
	}

	// Initialize the next segment to write if it's currently nil.
	if e.snd.writeNext == nil {
		e.snd.writeNext = first
	}

	// Push out any new packets.
	e.snd.sendData()
}

// resetConnection sends a RST segment and puts the endpoint in an error state
// with the given error code.
// This method must only be called from the protocol goroutine.
func (e *endpoint) resetConnection(err error) {
	e.sendRaw(nil, flagAck|flagRst, e.snd.sndUna, e.rcv.rcvNxt, e.rcv.rcvNxt.Size(e.rcv.rcvAcc))

	e.mu.Lock()
	e.state = stateError
	e.hardError = err
	e.mu.Unlock()
}

// completeWorker is called by the worker goroutine when it's about to exit. It
// marks the worker as completed and performs cleanup work if requested by
// Close().
func (e *endpoint) completeWorker() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.workerRunning = false
	if e.workerCleanup {
		e.cleanup()
	}
}

// protocolMainLoop is the main loop of the TCP protocol. It runs in its own
// goroutine and is responsible for sending segments and handling received
// segments.
func (e *endpoint) protocolMainLoop(passive bool) error {
	defer func() {
		e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut)
		e.completeWorker()
	}()

	if !passive {
		// This is an active connection, so we must initiate the 3-way
		// handshake, and then inform potential waiters about its
		// completion.
		h, err := newHandshake(e, seqnum.Size(e.rcvBufSize))
		if err == nil {
			err = h.execute()
		}
		if err != nil {
			e.lastErrorMu.Lock()
			e.lastError = err
			e.lastErrorMu.Unlock()

			e.mu.Lock()
			e.state = stateError
			e.hardError = err
			e.mu.Unlock()

			return err
		}

		// Transfer handshake state to TCP connection.
		e.snd = newSender(e, h.iss, h.sndWnd)
		e.rcv = newReceiver(e, h.ackNum-1, h.rcvWnd)
	}

	// Tell waiters that the endpoint is connected and writable.
	e.mu.Lock()
	e.state = stateConnected
	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventOut)

	// Main loop. Handle segments until both send and receive ends of the
	// connection have completed.
	var closeTimer <-chan time.Time

	for !e.rcv.closed || !e.snd.closed || e.snd.sndUna != e.snd.sndNxtList {
		select {
		case s := <-e.segmentChan:
			if s.flagIsSet(flagRst) {
				if e.rcv.acceptable(s.sequenceNumber, 0) {
					// RFC 793, page 37 states that "in all
					// states except SYN-SENT, all reset
					// (RST) segments are validated by
					// checking their SEQ-fields." So we
					// only process it if it's acceptable.
					s.decRef()
					e.mu.Lock()
					e.state = stateError
					e.hardError = tcpip.ErrConnectionReset
					e.mu.Unlock()
					return nil
				}
			} else if s.flagIsSet(flagAck) {
				// RFC 793, page 41 states that "once in the ESTABLISHED
				// state all segments must carry current acknowledgment
				// information."
				e.rcv.handleRcvdSegment(s)
				e.snd.handleRcvdSegment(s)
			}
			s.decRef()

		case _, ok := <-e.sndChan:
			e.handleWrite(ok)

		case <-e.notifyChan:
			n := e.fetchNotifications()
			if n&notifyNonZeroReceiveWindow != 0 {
				e.rcv.nonZeroWindow()
			}

			if n&notifyReceiveWindowChanged != 0 {
				e.rcv.pendingBufSize = seqnum.Size(e.receiveBufferSize())
			}

			if n&notifyClose != 0 && closeTimer == nil {
				// Reset the connection 3 seconds after the
				// endpoint has been closed.
				closeTimer = time.After(3 * time.Second)
			}

		case <-closeTimer:
			e.resetConnection(tcpip.ErrConnectionAborted)
			return nil

		case <-e.snd.resendTimer.C:
			if !e.snd.retransmitTimerExpired() {
				e.resetConnection(tcpip.ErrTimeout)
				return nil
			}
		}
	}

	// Mark endpoint as closed.
	e.mu.Lock()
	e.state = stateClosed
	e.mu.Unlock()

	return nil
}
