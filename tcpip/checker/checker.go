// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package checker provides helper functions to check networking packets for
// validity.
package checker

import (
	"testing"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/header"
)

// NetworkChecker is a function to check a property of a network packet.
type NetworkChecker func(*testing.T, header.Network)

// TransportChecker is a function to check a property of a transport packet.
type TransportChecker func(*testing.T, header.Transport)

// IPv4 checks the validity and properties of the given ipv4 packet. It is
// expected to be used in conjunction with other network checkers for specific
// properties. For example, to check the source and destination address, one
// would call:
//
// checker.IPv4(t, b, checker.SrcAddr(x), checker.DstAddr(y))
func IPv4(t *testing.T, b []byte, checkers ...NetworkChecker) {
	ipv4 := header.IPv4(b)

	if !ipv4.IsValid(len(b)) {
		t.Fatalf("Not a valid IPv4 packet")
	}

	xsum := ipv4.CalculateChecksum()
	if xsum != 0 && xsum != 0xffff {
		t.Fatalf("Bad checksum: 0x%x, checksum in packet: 0x%x", xsum, ipv4.Checksum())
	}

	for _, f := range checkers {
		f(t, ipv4)
	}
}

// IPv6 checks the validity and properties of the given ipv4 packet. The usage
// is similar to IPv4.
func IPv6(t *testing.T, b []byte, checkers ...NetworkChecker) {
	ipv6 := header.IPv6(b)
	if !ipv6.IsValid(len(b)) {
		t.Fatalf("Not a valid IPv4 packet")
	}

	for _, f := range checkers {
		f(t, ipv6)
	}
}

// SrcAddr creates a checker that checks the source address.
func SrcAddr(addr tcpip.Address) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if a := h.SourceAddress(); a != addr {
			t.Fatalf("Bad source address, got %v, want %v", a, addr)
		}
	}
}

// DstAddr creates a checker that checks the destination address.
func DstAddr(addr tcpip.Address) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if a := h.DestinationAddress(); a != addr {
			t.Fatalf("Bad destination address, got %v, want %v", a, addr)
		}
	}
}

// PayloadLen creates a checker that checks the payload length.
func PayloadLen(plen int) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if l := len(h.Payload()); l != plen {
			t.Fatalf("Bad payload length, got %v, want %v", l, plen)
		}
	}
}

// FragmentOffset creates a checker that checks the FragmentOffset field.
func FragmentOffset(offset uint16) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		// We only do this of IPv4 for now.
		switch ip := h.(type) {
		case header.IPv4:
			if v := ip.FragmentOffset(); v != offset {
				t.Fatalf("Bad fragment offset, got %v, want %v", v, offset)
			}
		}
	}
}

// FragmentFlags creates a checker that checks the fragment flags field.
func FragmentFlags(flags uint8) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		// We only do this of IPv4 for now.
		switch ip := h.(type) {
		case header.IPv4:
			if v := ip.Flags(); v != flags {
				t.Fatalf("Bad fragment offset, got %v, want %v", v, flags)
			}
		}
	}
}

// TOS creates a checker that checks the TOS field.
func TOS(tos uint8, label uint32) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if v, l := h.TOS(); v != tos || l != label {
			t.Fatalf("Bad TOS, got (%v, %v), want (%v,%v)", v, l, tos, label)
		}
	}
}

// TCP creates a checker that checks that the transport protocol is TCP and
// potentially additional transport header fields.
func TCP(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if p := h.TransportProtocol(); p != header.TCPProtocolNumber {
			t.Fatalf("Bad protocol, got %v, want %v", p, header.TCPProtocolNumber)
		}

		// Verify the checksum.
		tcp := header.TCP(h.Payload())
		l := uint16(len(tcp))

		xsum := header.Checksum([]byte(h.SourceAddress()), 0)
		xsum = header.Checksum([]byte(h.DestinationAddress()), xsum)
		xsum = header.Checksum([]byte{0, byte(h.TransportProtocol())}, xsum)
		xsum = header.Checksum([]byte{byte(l >> 8), byte(l)}, xsum)
		xsum = header.Checksum(tcp, xsum)

		if xsum != 0 && xsum != 0xffff {
			t.Fatalf("Bad checksum: 0x%x, checksum in segment: 0x%x", xsum, tcp.Checksum())
		}

		// Run the transport checkers.
		for _, f := range checkers {
			f(t, tcp)
		}
	}
}

// UDP creates a checker that checks that the transport protocol is UDP and
// potentially additional transport header fields.
func UDP(checkers ...TransportChecker) NetworkChecker {
	return func(t *testing.T, h header.Network) {
		if p := h.TransportProtocol(); p != header.UDPProtocolNumber {
			t.Fatalf("Bad protocol, got %v, want %v", p, header.UDPProtocolNumber)
		}

		udp := header.UDP(h.Payload())
		for _, f := range checkers {
			f(t, udp)
		}
	}
}

// SrcPort creates a checker that checks the source port.
func SrcPort(port uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		if p := h.SourcePort(); p != port {
			t.Fatalf("Bad source port, got %v, want %v", p, port)
		}
	}
}

// DstPort creates a checker that checks the destination port.
func DstPort(port uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		if p := h.DestinationPort(); p != port {
			t.Fatalf("Bad destination port, got %v, want %v", p, port)
		}
	}
}

// SeqNum creates a checker that checks the sequence number.
func SeqNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if s := tcp.SequenceNumber(); s != seq {
			t.Fatalf("Bad sequence number, got %v, want %v", s, seq)
		}
	}
}

// AckNum creates a checker that checks the ack number.
func AckNum(seq uint32) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if s := tcp.AckNumber(); s != seq {
			t.Fatalf("Bad ack number, got %v, want %v", s, seq)
		}
	}
}

// Window creates a checker that checks the tcp window.
func Window(window uint16) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if w := tcp.WindowSize(); w != window {
			t.Fatalf("Bad window, got 0x%x, want 0x%x", w, window)
		}
	}
}

// TCPFlags creates a checker that checks the tcp flags.
func TCPFlags(flags uint8) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if f := tcp.Flags(); f != flags {
			t.Fatalf("Bad flags, got 0x%x, want 0x%x", f, flags)
		}
	}
}

// TCPFlagsMatch creates a checker that checks that the tcp flags, masked by the
// given mask, match the supplied flags.
func TCPFlagsMatch(flags, mask uint8) TransportChecker {
	return func(t *testing.T, h header.Transport) {
		tcp, ok := h.(header.TCP)
		if !ok {
			return
		}

		if f := tcp.Flags(); (f & mask) != (flags & mask) {
			t.Fatalf("Bad masked flags, got 0x%x, want 0x%x, mask 0x%x", f, flags, mask)
		}
	}
}
