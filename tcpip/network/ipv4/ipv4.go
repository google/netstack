// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ipv4 contains the implementation of the ipv4 network protocol. To use
// it in the networking stack, this package must be added to the project, and
// activated on the stack by passing ipv4.ProtocolName (or "ipv4") as one of the
// network protocols when calling stack.New(). Then endpoints can be created
// by passing ipv4.ProtocolNumber as the network protocol number when calling
// Stack.NewEndpoint().
package ipv4

import (
	"crypto/rand"
	"sync/atomic"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip"
)

const (
	// ProtocolName is the string representation of the ipv4 protocol name.
	ProtocolName = "ipv4"

	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// maxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	maxTotalSize = 0xffff

	// buckets is the number of identifier buckets.
	buckets = 2048
)

type address [header.IPv4AddressSize]byte

type endpoint struct {
	nicid      tcpip.NICID
	id         stack.NetworkEndpointID
	address    address
	linkEP     stack.LinkEndpoint
	dispatcher stack.TransportDispatcher
}

func newEndpoint(nicid tcpip.NICID, addr tcpip.Address, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) *endpoint {
	e := &endpoint{
		nicid:      nicid,
		linkEP:     linkEP,
		dispatcher: dispatcher,
	}
	copy(e.address[:], addr)
	e.id = stack.NetworkEndpointID{tcpip.Address(e.address[:])}

	return e
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
func (e *endpoint) MTU() uint32 {
	lmtu := e.linkEP.MTU()
	if lmtu > maxTotalSize {
		lmtu = maxTotalSize
	}
	return lmtu - uint32(e.MaxHeaderLength())
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicid
}

// ID returns the ipv4 endpoint ID.
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv4MinimumSize
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.TransportProtocolNumber) error {
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	length := uint16(hdr.UsedLength() + len(payload))
	id := uint32(0)
	if length > header.IPv4MaximumHeaderSize+8 {
		// Packets of 68 bytes or less are required by RFC 791 to not be
		// fragmented, so we only assign ids to larger packets.
		id = atomic.AddUint32(&ids[hash(r, protocol)%buckets], 1)
	}
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: length,
		ID:          uint16(id),
		TTL:         65,
		Protocol:    uint8(protocol),
		SrcAddr:     tcpip.Address(e.address[:]),
		DstAddr:     r.RemoteAddress,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	return e.linkEP.WritePacket(r, hdr, payload, ProtocolNumber)
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, v buffer.View) {
	h := header.IPv4(v)
	if !h.IsValid() {
		return
	}

	// For now we don't support fragmentation, so reject fragmented packets.
	if h.FragmentOffset() != 0 || (h.Flags()&header.IPv4FlagMoreFragments) != 0 {
		return
	}

	hlen := int(h.HeaderLength())
	tlen := int(h.TotalLength())
	v.TrimFront(hlen)
	v.CapLength(tlen - hlen)
	e.dispatcher.DeliverTransportPacket(r, tcpip.TransportProtocolNumber(h.Protocol()), v)
}

type protocol struct{}

// NewProtocol creates a new protocol ipv4 protocol descriptor. This is exported
// only for tests that short-circuit the stack. Regular use of the protocol is
// done via the stack, which gets a protocol descriptor from the init() function
// below.
func NewProtocol() stack.NetworkProtocol {
	return &protocol{}
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint creates a new ipv4 endpoint.
func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, error) {
	return newEndpoint(nicid, addr, dispatcher, linkEP), nil
}

// hash3Words calculates the Jenkins hash of 3 32-bit words. This is adapted
// from linux.
func hash3Words(a, b, c, initval uint32) uint32 {
	const iv = 0xdeadbeef + (3 << 2)
	initval += iv

	a += initval
	b += initval
	c += initval

	c ^= b
	c -= rol32(b, 14)
	a ^= c
	a -= rol32(c, 11)
	b ^= a
	b -= rol32(a, 25)
	c ^= b
	c -= rol32(b, 16)
	a ^= c
	a -= rol32(c, 4)
	b ^= a
	b -= rol32(a, 14)
	c ^= b
	c -= rol32(b, 24)

	return c
}

// hash calculates a hash value for the given route. It uses the source &
// destination address, the transport protocol number, and a random initial
// value (generated once on initialization) to generate the hash.
func hash(r *stack.Route, protocol tcpip.TransportProtocolNumber) uint32 {
	t := r.LocalAddress
	a := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = r.RemoteAddress
	b := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return hash3Words(a, b, uint32(protocol), hashIV)
}

// rand32 generates a cryptographic random 32-bit number.
func rand32() uint32 {
	r := make([]byte, 4)
	rand.Read(r)
	return uint32(r[0]) | uint32(r[1])<<8 | uint32(r[2])<<16 | uint32(r[3])<<24
}

func rol32(v, shift uint32) uint32 {
	return (v << shift) | (v >> ((-shift) & 31))
}

var (
	ids    = make([]uint32, buckets)
	hashIV = rand32()
)

func init() {
	// Randomly initialize the ids.
	for i := range ids {
		ids[i] = rand32()
	}

	stack.RegisterNetworkProtocol(ProtocolName, NewProtocol())
}
