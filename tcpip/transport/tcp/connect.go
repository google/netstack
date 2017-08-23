// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"crypto/rand"
	"sync/atomic"
	"time"

	"github.com/google/netstack/sleep"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

// maxSegmentsPerWake is the maximum number of segments to process in the main
// protocol goroutine per wake-up. Yielding [after this number of segments are
// processed] allows other events to be processed as well (e.g., timeouts,
// resets, etc.).
const maxSegmentsPerWake = 100

type handshakeState int

// The following are the possible states of the TCP connection during a 3-way
// handshake. A depiction of the states and transitions can be found in RFC 793,
// page 23.
const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

// The following are used to set up sleepers.
const (
	wakerForNotification = iota
	wakerForNewSegment
	wakerForResend
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

	// mss is the maximum segment size received from the peer.
	mss uint16

	// sndWndScale is the send window scale, as defined in RFC 1323. A
	// negative value means no scaling is supported by the peer.
	sndWndScale int

	// rcvWndScale is the receive window scale, as defined in RFC 1323.
	rcvWndScale int
}

func newHandshake(ep *endpoint, rcvWnd seqnum.Size) (handshake, *tcpip.Error) {
	h := handshake{
		ep:          ep,
		active:      true,
		rcvWnd:      rcvWnd,
		rcvWndScale: FindWndScale(rcvWnd),
	}
	if err := h.resetState(); err != nil {
		return handshake{}, err
	}

	return h, nil
}

// FindWndScale determines the window scale to use for the given maximum window
// size.
func FindWndScale(wnd seqnum.Size) int {
	if wnd < 0x10000 {
		return 0
	}

	max := seqnum.Size(0xffff)
	s := 0
	for wnd > max && s < header.MaxWndScale {
		s++
		max <<= 1
	}

	return s
}

// resetState resets the state of the handshake object such that it becomes
// ready for a new 3-way handshake.
func (h *handshake) resetState() *tcpip.Error {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	h.state = handshakeSynSent
	h.flags = flagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = seqnum.Value(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)

	return nil
}

// effectiveRcvWndScale returns the effective receive window scale to be used.
// If the peer doesn't support window scaling, the effective rcv wnd scale is
// zero; otherwise it's the value calculated based on the initial rcv wnd.
func (h *handshake) effectiveRcvWndScale() uint8 {
	if h.sndWndScale < 0 {
		return 0
	}
	return uint8(h.rcvWndScale)
}

// resetToSynRcvd resets the state of the handshake object to the SYN-RCVD
// state.
func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value, opts *header.TCPSynOptions) {
	h.active = false
	h.state = handshakeSynRcvd
	h.flags = flagSyn | flagAck
	h.iss = iss
	h.ackNum = irs + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
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
func (h *handshake) synSentState(s *segment) *tcpip.Error {
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

	// Parse the SYN options.
	rcvSynOpts := parseSynSegmentOptions(s)

	// Remember if the Timetstamp option was negotiated.
	h.ep.maybeEnableTimestamp(&rcvSynOpts)

	// Remember the sequence we'll ack from now on.
	h.ackNum = s.sequenceNumber + 1
	h.flags |= flagAck
	h.mss = rcvSynOpts.MSS
	h.sndWndScale = rcvSynOpts.WS

	// If this is a SYN ACK response, we only need to acknowledge the SYN
	// and the handshake is completed.
	if s.flagIsSet(flagAck) {
		h.state = handshakeCompleted
		h.ep.sendRaw(nil, flagAck, h.iss+1, h.ackNum, h.rcvWnd>>h.effectiveRcvWndScale())
		return nil
	}

	// A SYN segment was received, but no ACK in it. We acknowledge the SYN
	// but resend our own SYN and wait for it to be acknowledged in the
	// SYN-RCVD state.
	h.state = handshakeSynRcvd
	synOpts := header.TCPSynOptions{
		WS:    h.rcvWndScale,
		TS:    rcvSynOpts.TS,
		TSVal: h.ep.timestamp(),
		TSEcr: h.ep.recentTS,
	}
	sendSynTCP(&s.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

	return nil
}

// synRcvdState handles a segment received when the TCP 3-way handshake is in
// the SYN-RCVD state.
func (h *handshake) synRcvdState(s *segment) *tcpip.Error {
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
		synOpts := header.TCPSynOptions{
			WS:    h.rcvWndScale,
			TS:    h.ep.sendTSOk,
			TSVal: h.ep.timestamp(),
			TSEcr: h.ep.recentTS,
		}
		sendSynTCP(&s.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
		return nil
	}

	// We have previously received (and acknowledged) the peer's SYN. If the
	// peer acknowledges our SYN, the handshake is completed.
	if s.flagIsSet(flagAck) {

		// If the timestamp option is negotiated and the segment does
		// not carry a timestamp option then the segment must be dropped
		// as per https://tools.ietf.org/html/rfc7323#section-3.2.
		if h.ep.sendTSOk && !s.parsedOptions.TS {
			atomic.AddUint64(&h.ep.stack.MutableStats().DroppedPackets, 1)
			return nil
		}

		// Update timestamp if required. See RFC7323, section-4.3.
		h.ep.updateRecentTimestamp(s.parsedOptions.TSVal, h.ackNum, s.sequenceNumber)

		h.state = handshakeCompleted
		return nil
	}

	return nil
}

// processSegments goes through the segment queue and processes up to
// maxSegmentsPerWake (if they're available).
func (h *handshake) processSegments() *tcpip.Error {
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := h.ep.segmentQueue.dequeue()
		if s == nil {
			return nil
		}

		h.sndWnd = s.window
		if !s.flagIsSet(flagSyn) && h.sndWndScale > 0 {
			h.sndWnd <<= uint8(h.sndWndScale)
		}

		var err *tcpip.Error
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

		// We stop processing packets once the handshake is completed,
		// otherwise we may process packets meant to be processed by
		// the main protocol goroutine.
		if h.state == handshakeCompleted {
			break
		}
	}

	// If the queue is not empty, make sure we'll wake up in the next
	// iteration.
	if !h.ep.segmentQueue.empty() {
		h.ep.newSegmentWaker.Assert()
	}

	return nil
}

// execute executes the TCP 3-way handshake.
func (h *handshake) execute() *tcpip.Error {
	// Initialize the resend timer.
	resendWaker := sleep.Waker{}
	timeOut := time.Duration(time.Second)
	rt := time.AfterFunc(timeOut, func() {
		resendWaker.Assert()
	})
	defer rt.Stop()

	// Set up the wakers.
	s := sleep.Sleeper{}
	s.AddWaker(&resendWaker, wakerForResend)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	s.AddWaker(&h.ep.newSegmentWaker, wakerForNewSegment)
	defer s.Done()

	// Send the initial SYN segment and loop until the handshake is
	// completed.
	synOpts := header.TCPSynOptions{
		WS:    h.rcvWndScale,
		TS:    true,
		TSVal: h.ep.timestamp(),
		TSEcr: h.ep.recentTS,
	}

	// Execute is also called in a listen context so we want to make sure we
	// only send the TS option when we received the TS in the initial SYN.
	if h.state == handshakeSynRcvd {
		synOpts.TS = h.ep.sendTSOk
	}
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
	for h.state != handshakeCompleted {
		switch index, _ := s.Fetch(true); index {
		case wakerForResend:
			timeOut *= 2
			if timeOut > 60*time.Second {
				return tcpip.ErrTimeout
			}
			rt.Reset(timeOut)
			sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

		case wakerForNotification:
			n := h.ep.fetchNotifications()
			if n&notifyClose != 0 {
				return tcpip.ErrAborted
			}

		case wakerForNewSegment:
			if err := h.processSegments(); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseSynSegmentOptions(s *segment) header.TCPSynOptions {
	synOpts := header.ParseSynOptions(s.options, s.flagIsSet(flagAck))
	if synOpts.TS {
		s.parsedOptions.TSVal = synOpts.TSVal
		s.parsedOptions.TSEcr = synOpts.TSEcr
	}
	return synOpts
}

func sendSynTCP(r *stack.Route, id stack.TransportEndpointID, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts header.TCPSynOptions) *tcpip.Error {
	// The MSS in opts is ignored as this function is called from many
	// places and we don't want every call point being embedded with the MSS
	// calculation. So we just do it here and ignore the MSS value passed in
	// the opts.
	mss := r.MTU() - header.TCPMinimumSize
	options := []byte{
		// Initialize the MSS option.
		header.TCPOptionMSS, 4, byte(mss >> 8), byte(mss),
	}

	if opts.TS {
		tsOpt := header.EncodeTSOption(opts.TSVal, opts.TSEcr)
		options = append(options, tsOpt[:]...)
	}

	// NOTE: a WS of zero is a valid value and it indicates a scale of 1.
	if opts.WS >= 0 {
		// Initialize the WS option.
		options = append(options,
			header.TCPOptionWS, 3, uint8(opts.WS), header.TCPOptionNOP)
	}

	return sendTCPWithOptions(r, id, nil, flags, seq, ack, rcvWnd, options)
}

// sendTCPWithOptions sends a TCP segment with the provided options via the
// provided network endpoint and under the provided identity.
func sendTCPWithOptions(r *stack.Route, id stack.TransportEndpointID, data buffer.View, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte) *tcpip.Error {
	optLen := len(opts)
	// Allocate a buffer for the TCP header.
	hdr := buffer.NewPrependable(header.TCPMinimumSize + int(r.MaxHeaderLength()) + optLen)

	if rcvWnd > 0xffff {
		rcvWnd = 0xffff
	}

	// Initialize the header.
	tcp := header.TCP(hdr.Prepend(header.TCPMinimumSize + optLen))
	tcp.Encode(&header.TCPFields{
		SrcPort:    id.LocalPort,
		DstPort:    id.RemotePort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      flags,
		WindowSize: uint16(rcvWnd),
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	length := uint16(hdr.UsedLength())
	xsum := r.PseudoHeaderChecksum(ProtocolNumber)
	if data != nil {
		length += uint16(len(data))
		xsum = header.Checksum(data, xsum)
	}

	tcp.SetChecksum(^tcp.CalculateChecksum(xsum, length))

	return r.WritePacket(&hdr, data, ProtocolNumber)
}

// sendTCP sends a TCP segment via the provided network endpoint and under the
// provided identity.
func sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.View, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size) *tcpip.Error {
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
func (e *endpoint) sendRaw(data buffer.View, flags byte, seq, ack seqnum.Value, rcvWnd seqnum.Size) *tcpip.Error {
	if e.sendTSOk {
		// Embed the timestamp if timestamp has been enabled.
		//
		// We only use the lower 32 bits of the unix time in
		// milliseconds. This is similar to what Linux does where it
		// uses the lower 32 bits of the jiffies value in the tsVal
		// field of the timestamp option.
		//
		// Further, RFC7323 section-5.4 recommends millisecond
		// resolution as the lowest recommended resolution for the
		// timestamp clock.
		//
		// Ref: https://tools.ietf.org/html/rfc7323#section-5.4.
		options := header.EncodeTSOption(e.timestamp(), uint32(e.recentTS))
		return sendTCPWithOptions(&e.route, e.id, data, flags, seq, ack, rcvWnd, options[:])
	}
	return sendTCP(&e.route, e.id, data, flags, seq, ack, rcvWnd)
}

func (e *endpoint) handleWrite() bool {
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

	// Initialize the next segment to write if it's currently nil.
	if e.snd.writeNext == nil {
		e.snd.writeNext = first
	}

	// Push out any new packets.
	e.snd.sendData()

	return true
}

func (e *endpoint) handleClose() bool {
	// Drain the send queue.
	e.handleWrite()

	// Mark send side as closed.
	e.snd.closed = true

	return true
}

// resetConnection sends a RST segment and puts the endpoint in an error state
// with the given error code.
// This method must only be called from the protocol goroutine.
func (e *endpoint) resetConnection(err *tcpip.Error) {
	e.sendRaw(nil, flagAck|flagRst, e.snd.sndUna, e.rcv.rcvNxt, 0)

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

// handleSegments pulls segments from the queue and processes them. It returns
// true if the protocol loop should continue, false otherwise.
func (e *endpoint) handleSegments() bool {
	checkRequeue := true
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := e.segmentQueue.dequeue()
		if s == nil {
			checkRequeue = false
			break
		}

		if s.flagIsSet(flagRst) {
			if e.rcv.acceptable(s.sequenceNumber, 0) {
				// RFC 793, page 37 states that "in all states
				// except SYN-SENT, all reset (RST) segments are
				// validated by checking their SEQ-fields." So
				// we only process it if it's acceptable.
				s.decRef()
				e.mu.Lock()
				e.state = stateError
				e.hardError = tcpip.ErrConnectionReset
				e.mu.Unlock()
				return false
			}
		} else if s.flagIsSet(flagAck) {
			// Patch the window size in the segment according to the
			// send window scale.
			s.window <<= e.snd.sndWndScale

			// If the timestamp option is negotiated and the segment
			// does not carry a timestamp option then the segment
			// must be dropped as per
			// https://tools.ietf.org/html/rfc7323#section-3.2.
			if e.sendTSOk && !s.parsedOptions.TS {
				atomic.AddUint64(&e.stack.MutableStats().DroppedPackets, 1)
				s.decRef()
				continue
			}

			// RFC 793, page 41 states that "once in the ESTABLISHED
			// state all segments must carry current acknowledgment
			// information."
			e.rcv.handleRcvdSegment(s)
			e.snd.handleRcvdSegment(s)
		}
		s.decRef()
	}

	// If the queue is not empty, make sure we'll wake up in the next
	// iteration.
	if checkRequeue && !e.segmentQueue.empty() {
		e.newSegmentWaker.Assert()
	}

	// Send an ACK for all processed packets if needed.
	if e.rcv.rcvNxt != e.snd.maxSentAck {
		e.snd.sendAck()
	}

	return true
}

// protocolMainLoop is the main loop of the TCP protocol. It runs in its own
// goroutine and is responsible for sending segments and handling received
// segments.
func (e *endpoint) protocolMainLoop(passive bool) *tcpip.Error {
	var closeTimer *time.Timer
	var closeWaker sleep.Waker

	defer func() {
		e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut)
		e.completeWorker()

		if e.snd != nil {
			e.snd.resendTimer.cleanup()
		}

		if closeTimer != nil {
			closeTimer.Stop()
		}
	}()

	if !passive {
		// This is an active connection, so we must initiate the 3-way
		// handshake, and then inform potential waiters about its
		// completion.
		h, err := newHandshake(e, seqnum.Size(e.receiveBufferAvailable()))
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

		// Transfer handshake state to TCP connection. We disable
		// receive window scaling if the peer doesn't support it
		// (indicated by a negative send window scale).
		e.snd = newSender(e, h.iss, h.ackNum-1, h.sndWnd, h.mss, h.sndWndScale)

		e.rcvListMu.Lock()
		e.rcv = newReceiver(e, h.ackNum-1, h.rcvWnd, h.effectiveRcvWndScale())
		e.rcvListMu.Unlock()
	}

	// Tell waiters that the endpoint is connected and writable.
	e.mu.Lock()
	e.state = stateConnected
	e.mu.Unlock()

	e.waiterQueue.Notify(waiter.EventOut)

	// Set up the functions that will be called when the main protocol loop
	// wakes up.
	funcs := []struct {
		w *sleep.Waker
		f func() bool
	}{
		{
			w: &e.sndWaker,
			f: e.handleWrite,
		},
		{
			w: &e.sndCloseWaker,
			f: e.handleClose,
		},
		{
			w: &e.newSegmentWaker,
			f: e.handleSegments,
		},
		{
			w: &closeWaker,
			f: func() bool {
				e.resetConnection(tcpip.ErrConnectionAborted)
				return false
			},
		},
		{
			w: &e.snd.resendWaker,
			f: func() bool {
				if !e.snd.retransmitTimerExpired() {
					e.resetConnection(tcpip.ErrTimeout)
					return false
				}
				return true
			},
		},
		{
			w: &e.notificationWaker,
			f: func() bool {
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
					closeTimer = time.AfterFunc(3*time.Second, func() {
						closeWaker.Assert()
					})
				}
				return true
			},
		},
	}

	// Initialize the sleeper based on the wakers in funcs.
	s := sleep.Sleeper{}
	for i := range funcs {
		s.AddWaker(funcs[i].w, i)
	}

	// Main loop. Handle segments until both send and receive ends of the
	// connection have completed.
	for !e.rcv.closed || !e.snd.closed || e.snd.sndUna != e.snd.sndNxtList {
		e.workMu.Unlock()
		v, _ := s.Fetch(true)
		e.workMu.Lock()
		if !funcs[v].f() {
			return nil
		}
	}

	// Mark endpoint as closed.
	e.mu.Lock()
	e.state = stateClosed
	e.mu.Unlock()

	return nil
}
