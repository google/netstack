// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fdbased provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// FD based endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package fdbased

import (
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/rawfile"
	"github.com/google/netstack/tcpip/stack"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type endpoint struct {
	// fd is the file descriptor used to send and receive packets.
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	// pendingReaders is the number of readers that haven't stopped yet.
	pendingReaders int32

	// readerCh is a channel used as a semaphore to allow only one reader
	// goroutine to run at a time.
	readerCh chan struct{}
}

// New creates a new fd-based endpoint.
func New(fd int, mtu uint32, checksumOffload bool, closed func(*tcpip.Error)) tcpip.LinkEndpointID {
	syscall.SetNonblock(fd, true)

	caps := stack.LinkEndpointCapabilities(0)
	if checksumOffload {
		caps |= stack.CapabilityChecksumOffload
	}

	e := &endpoint{
		fd:       fd,
		mtu:      mtu,
		caps:     caps,
		closed:   closed,
		readerCh: make(chan struct{}, 1),
	}
	return stack.RegisterLinkEndpoint(e)
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	// Allow one reader to go through.
	e.readerCh <- struct{}{}

	// Start all readers.
	n := int32(runtime.GOMAXPROCS(0))
	atomic.StoreInt32(&e.pendingReaders, n)
	for i := n; i > 0; i-- {
		go e.dispatchLoop(dispatcher)
	}
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the header. Given that it
// doesn't have a header, it just returns 0.
func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (*endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if payload == nil {
		return rawfile.NonBlockingWrite(e.fd, hdr.UsedBytes())

	}

	return rawfile.NonBlockingWrite2(e.fd, hdr.UsedBytes(), payload)
}

func capViews(n int, buffers []int, views []buffer.View) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func allocateViews(bufConfig []int, views []buffer.View, iovecs []syscall.Iovec) {
	for i, v := range views {
		if v != nil {
			break
		}
		b := buffer.NewView(bufConfig[i])
		views[i] = b
		iovecs[i] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) dispatch(d stack.NetworkDispatcher, vv *buffer.VectorisedView, views []buffer.View, iovecs []syscall.Iovec) (bool, *tcpip.Error) {
	allocateViews(BufConfig, views, iovecs)

	// Read the next packet. After we've read it, allow another reader to
	// concurrently read from the fd.
	n, err := rawfile.BlockingReadv(e.fd, iovecs)
	e.readerCh <- struct{}{}
	if err != nil {
		return false, err
	}

	if n <= 0 {
		return false, nil
	}

	// We don't get any indication of what the packet is, so try to guess
	// if it's an IPv4 or IPv6 packet.
	var p tcpip.NetworkProtocolNumber
	switch header.IPVersion(views[0]) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	used := capViews(n, BufConfig, views)
	vv.SetViews(views[:used])
	vv.SetSize(n)

	d.DeliverNetworkPacket(e, "", p, vv)

	// Prepare e.views for another packet: release used views.
	for i := 0; i < used; i++ {
		views[i] = nil
	}

	return true, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) *tcpip.Error {
	views := make([]buffer.View, len(BufConfig))
	iovecs := make([]syscall.Iovec, len(BufConfig))
	vv := buffer.NewVectorisedView(0, views)
	for {
		// Wait for this reader's turn to read from the fd.
		<-e.readerCh

		// Attempt to read and dispatch the next packet.
		cont, err := e.dispatch(d, &vv, views, iovecs)
		if err != nil || !cont {
			if e.closed != nil && atomic.AddInt32(&e.pendingReaders, -1) == 0 {
				// We call this once, when the last reader
				// completes.
				e.closed(err)
			}
			return err
		}
	}
}

// InjectableEndpoint is an injectable fd-based endpoint. The endpoint writes
// to the FD, but does not read from it. All reads come from injected packets.
type InjectableEndpoint struct {
	endpoint

	dispatcher stack.NetworkDispatcher
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// Inject injects an inbound packet.
func (e *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	e.dispatcher.DeliverNetworkPacket(e, "", protocol, vv)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32) (tcpip.LinkEndpointID, *InjectableEndpoint) {
	syscall.SetNonblock(fd, true)

	e := &InjectableEndpoint{endpoint: endpoint{
		fd:   fd,
		mtu:  mtu,
		caps: stack.CapabilityChecksumOffload,
	}}

	return stack.RegisterLinkEndpoint(e), e
}
