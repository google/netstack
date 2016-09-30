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
	"syscall"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/rawfile"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip"
)

type endpoint struct {
	// fd is the file descriptor used to send and receive packets.
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu int

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(error)
}

// New creates a new fd-based endpoint.
func New(fd int, mtu int, closed func(error)) tcpip.LinkEndpointID {
	syscall.SetNonblock(fd, true)

	return stack.RegisterLinkEndpoint(&endpoint{
		fd:     fd,
		mtu:    mtu,
		closed: closed,
	})
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	go e.dispatchLoop(dispatcher)
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return uint32(e.mtu)
}

// MaxHeaderLength returns the maximum size of the header. Given that it
// doesn't have a header, it just returns 0.
func (*endpoint) MaxHeaderLength() uint16 {
	return 0
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) error {
	if payload == nil {
		return rawfile.NonBlockingWrite(e.fd, hdr.UsedBytes())

	}

	return rawfile.NonBlockingWrite2(e.fd, hdr.UsedBytes(), payload)
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) dispatch(d stack.NetworkDispatcher, largeV buffer.View) (bool, error) {
	n, err := rawfile.BlockingRead(e.fd, largeV)
	if err != nil {
		return false, err
	}

	if n <= 0 {
		return false, nil
	}

	v := buffer.NewView(n)
	copy(v, largeV)

	// We don't get any indication of what the packet is, so try to guess
	// if it's an IPv4 or IPv6 packet.
	var p tcpip.NetworkProtocolNumber
	switch header.IPVersion(v) {
	case header.IPv4Version:
		p = header.IPv4ProtocolNumber
	case header.IPv6Version:
		p = header.IPv6ProtocolNumber
	default:
		return true, nil
	}

	d.DeliverNetworkPacket(e, p, v)

	return true, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) error {
	v := buffer.NewView(header.MaxIPPacketSize)
	for {
		cont, err := e.dispatch(d, v)
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}
