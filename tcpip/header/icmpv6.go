// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"github.com/google/netstack/tcpip"
)

// ICMPv6 represents an ICMPv6 header stored in a byte array.
type ICMPv6 []byte

const (
	// ICMPv6MinimumSize is the minimum size of a valid ICMP packet.
	ICMPv6MinimumSize = 4

	// ICMPv6ProtocolNumber is the ICMP transport protocol number.
	ICMPv6ProtocolNumber tcpip.TransportProtocolNumber = 58

	// ICMPv6NeighborSolicitMinimumSize is the minimum size of a
	// neighbor solicitation packet.
	ICMPv6NeighborSolicitMinimumSize = ICMPv6MinimumSize + 4 + 16

	// ICMPv6NeighborSolicitMinimumSize is size of a neighbor advertisement.
	ICMPv6NeighborAdvertSize = 32

	// ICMPv6EchoMinimumSize is the minimum size of a valid ICMP echo packet.
	ICMPv6EchoMinimumSize = 8
)

// ICMPv6Type is the ICMP type field described in RFC 4443 and friends.
type ICMPv6Type byte

// Typical values of ICMPv6Type defined in RFC 792.
const (
	ICMPv6DstUnreachable ICMPv6Type = 1
	ICMPv6PacketTooBig   ICMPv6Type = 2
	ICMPv6TimeExceeded   ICMPv6Type = 3
	ICMPv6ParamProblem   ICMPv6Type = 4
	ICMPv6EchoRequest    ICMPv6Type = 128
	ICMPv6EchoReply      ICMPv6Type = 129

	// Neighbor Discovery Protocol (NDP) messages, see RFC 4861.

	ICMPv6RouterSolicit   ICMPv6Type = 133
	ICMPv6RouterAdvert    ICMPv6Type = 134
	ICMPv6NeighborSolicit ICMPv6Type = 135
	ICMPv6NeighborAdvert  ICMPv6Type = 136
	ICMPv6RedirectMsg     ICMPv6Type = 137
)

// Type is the ICMP type field.
func (b ICMPv6) Type() ICMPv6Type { return ICMPv6Type(b[0]) }

// SetType sets the ICMP type field.
func (b ICMPv6) SetType(t ICMPv6Type) { b[0] = byte(t) }

// Code is the ICMP code field. Its meaning depends on the value of Type.
func (b ICMPv6) Code() byte { return b[1] }

// SetChecksum calculates and sets the ICMP checksum field.
func (b ICMPv6) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[2:], checksum)
}
