// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gonet provides a Go net package compatible wrapper for a tcpip stack.
package gonet

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"
)

var errCanceled = errors.New("operation canceled")

// timeoutError is how the net package reports timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// A Listener is a wrapper around a tcpip endpoint that implements
// net.Listener.
type Listener struct {
	stack  tcpip.Stack
	tcpEP  tcpip.Endpoint
	wq     *waiter.Queue
	cancel chan struct{}
}

// NewListener creates a new Listener.
func NewListener(s tcpip.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*Listener, error) {
	// Create TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	tcpEP, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, err
	}

	if err := tcpEP.Bind(addr, nil); err != nil {
		tcpEP.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  err,
		}
	}

	if err := tcpEP.Listen(10); err != nil {
		tcpEP.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  err,
		}
	}

	return &Listener{
		stack:  s,
		tcpEP:  tcpEP,
		wq:     &wq,
		cancel: make(chan struct{}),
	}, nil
}

// Close implements net.Listener.Close.
func (l *Listener) Close() error {
	l.tcpEP.Close()
	return nil
}

// Shutdown stops the HTTP server.
func (l *Listener) Shutdown() {
	l.tcpEP.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	close(l.cancel) // broadcast cancellation
}

// Addr implements net.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	a, err := l.tcpEP.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// A Conn is a wrapper around a tcpip.Endpoint that implements the net.Conn
// interface.
type Conn struct {
	wq *waiter.Queue
	ep tcpip.Endpoint

	// deadlineMu protects readTimer, readCancel, writeTimer and writeCancel.
	deadlineMu sync.Mutex

	readTimer   *time.Timer
	readCancel  chan struct{}
	writeTimer  *time.Timer
	writeCancel chan struct{}

	// readMu serializes reads and implicitly protects read.
	//
	// Lock ordering:
	// If both readMu and deadlineMu are to be used in a single request, readMu
	// must be aquired before deadlineMu.
	readMu sync.Mutex

	// read contains bytes that have been read from the endpoint,
	// but haven't yet been returned.
	read buffer.View
}

// NewConn creates a new Conn.
func NewConn(wq *waiter.Queue, ep tcpip.Endpoint) *Conn {
	return &Conn{
		wq:          wq,
		ep:          ep,
		readCancel:  make(chan struct{}),
		writeCancel: make(chan struct{}),
	}
}

// Accept implements net.Conn.Accept.
func (l *Listener) Accept() (net.Conn, error) {
	n, wq, err := l.tcpEP.Accept()

	if err == tcpip.ErrWouldBlock {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		l.wq.EventRegister(&waitEntry, waiter.EventIn)
		defer l.wq.EventUnregister(&waitEntry)

		for {
			n, wq, err = l.tcpEP.Accept()

			if err != tcpip.ErrWouldBlock {
				break
			}

			select {
			case <-l.cancel:
				return nil, errCanceled
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  err,
		}
	}

	return NewConn(wq, n), nil
}

// Read implements net.Conn.Read.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.deadlineMu.Lock()
	dl := c.readCancel
	c.deadlineMu.Unlock()

	// Check if deadline has already expired.
	select {
	case <-dl:
		return 0, c.newOpError("read", &timeoutError{})
	default:
	}

	if len(c.read) == 0 {
		var err error
		c.read, err = c.ep.Read(nil)

		if err == tcpip.ErrWouldBlock {
			// Create wait queue entry that notifies a channel.
			waitEntry, notifyCh := waiter.NewChannelEntry(nil)
			c.wq.EventRegister(&waitEntry, waiter.EventIn)
			defer c.wq.EventUnregister(&waitEntry)
			for {
				c.read, err = c.ep.Read(nil)
				if err != tcpip.ErrWouldBlock {
					break
				}
				select {
				case <-dl:
					return 0, c.newOpError("read", &timeoutError{})
				case <-notifyCh:
				}
			}
		}

		if err == tcpip.ErrClosedForReceive {
			return 0, io.EOF
		}

		if err != nil {
			return 0, c.newOpError("read", err)
		}
	}

	n := copy(b, c.read)
	c.read.TrimFront(n)
	if len(c.read) == 0 {
		c.read = nil
	}
	return n, nil
}

// Write implements net.Conn.Write.
func (c *Conn) Write(b []byte) (int, error) {
	c.deadlineMu.Lock()
	dl := c.writeCancel
	c.deadlineMu.Unlock()

	// Check if deadline has already expired.
	select {
	case <-dl:
		return 0, c.newOpError("write", &timeoutError{})
	default:
	}

	v := buffer.NewView(len(b))
	copy(v, b)

	// We must handle two soft failure conditions simultaneously:
	//  1. Write may write nothing and return tcpip.ErrWouldBlock.
	//     If this happens, we need to register for notifications if we have
	//     not already and wait to try again.
	//  2. Write may write fewer than the full number of bytes and return
	//     without error. In this case we need to try writing the remaining
	//     bytes again. I do not need to register for notifications.
	//
	// What is more, these two soft failure conditions can be interspersed.
	// There is no guarantee that all of the condition #1s will occur before
	// all of the condition #2s or visa-versa.
	var (
		err      error
		nbytes   int
		reg      bool
		notifyCh chan struct{}
	)
	for nbytes < len(b) && (err == tcpip.ErrWouldBlock || err == nil) {
		if err == tcpip.ErrWouldBlock {
			if !reg {
				// Only register once.
				reg = true

				// Create wait queue entry that notifies a channel.
				var waitEntry waiter.Entry
				waitEntry, notifyCh = waiter.NewChannelEntry(nil)
				c.wq.EventRegister(&waitEntry, waiter.EventOut)
				defer c.wq.EventUnregister(&waitEntry)
			} else {
				// Don't wait immediately after registration in case more data
				// became available between when we last checked and when we setup
				// the notification.
				select {
				case <-dl:
					return 0, c.newOpError("write", &timeoutError{})
				case <-notifyCh:
				}
			}
		}

		var n uintptr
		n, err = c.ep.Write(v, nil)
		nbytes += int(n)
		v.TrimFront(int(n))
	}

	if err == nil {
		return nbytes, nil
	}

	return 0, c.newOpError("write", err)
}

// Close implements net.Conn.Close.
func (c *Conn) Close() error {
	c.ep.Close()
	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// setReadDeadline must only be called while holding c.deadlineMu.
func (c *Conn) setReadDeadline(t time.Time) {
	if c.readTimer != nil && !c.readTimer.Stop() {
		c.readCancel = make(chan struct{})
	}

	// "A zero value for t means I/O operations will not time out."
	if !t.IsZero() {
		// Timer.Stop returns whether or not the AfterFunc has started, but
		// does not indicate whether or not it has completed. Make a copy of
		// the cancel channel to prevent this code from racing with the next
		// call of setReadDeadline replacing c.readCancel.
		ch := c.readCancel
		c.readTimer = time.AfterFunc(t.Sub(time.Now()), func() {
			close(ch)
		})
	}
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.setReadDeadline(t)
	c.deadlineMu.Unlock()
	return nil
}

// setWriteDeadline must only be called while holding c.deadlineMu.
func (c *Conn) setWriteDeadline(t time.Time) {
	if c.writeTimer != nil && !c.writeTimer.Stop() {
		c.writeCancel = make(chan struct{})
	}

	// "A zero value for t means I/O operations will not time out."
	if !t.IsZero() {
		// Timer.Stop returns whether or not the AfterFunc has started, but
		// does not indicate whether or not it has completed. Make a copy of
		// the cancel channel to prevent this code from racing with the next
		// call of setWriteDeadline replacing c.writeCancel.
		ch := c.writeCancel
		c.writeTimer = time.AfterFunc(t.Sub(time.Now()), func() {
			close(ch)
		})
	}
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.setWriteDeadline(t)
	c.deadlineMu.Unlock()
	return nil
}

// SetDeadline implements net.Conn.SetDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.setWriteDeadline(t)
	c.setReadDeadline(t)
	c.deadlineMu.Unlock()
	return nil
}

func (c *Conn) newOpError(op string, err error) error {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Addr:   c.LocalAddr(),
		Source: c.RemoteAddr(),
		Err:    err,
	}
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}
