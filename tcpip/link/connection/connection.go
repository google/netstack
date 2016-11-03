// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package connection provides the implementation of data-link layer endpoints
// that write outbound packets to a net.Conn. Such endpoints allow injection of
// inbound packets, but do not read them from the net.Conn.
package connection

import (
	"net"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/stack"
)

// Endpoint is link layer endpoint that writes outbound packets to a net.Conn
// and allows injection of inbound packets.
type Endpoint struct {
	dispatcher stack.NetworkDispatcher
	mtu        uint32

	// conn is the connection used to send packets.
	conn net.Conn
}

// New creates a new net.Conn writer endpoint.
func New(conn net.Conn, mtu uint32) (tcpip.LinkEndpointID, *Endpoint) {
	e := &Endpoint{
		conn: conn,
	}

	return stack.RegisterLinkEndpoint(e), e
}

// Inject injects an inbound packet.
func (e *Endpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	uu := vv.Clone(nil)
	e.dispatcher.DeliverNetworkPacket(e, protocol, &uu)
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// WritePacket writes outbound packets to the net.Conn.
func (e *Endpoint) WritePacket(_ *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) error {
	buf := make([]byte, len(payload)+hdr.UsedLength())
	copy(buf, hdr.UsedBytes())
	copy(buf[hdr.UsedLength():], payload)

	if _, err := e.conn.Write(buf); err != nil {
		return err
	}

	return nil
}
