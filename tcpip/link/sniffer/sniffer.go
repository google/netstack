// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sniffer provides the implementation of data-link layer endpoints that
// wrap another endpoint and logs inbound and outbound packets.
//
// Sniffer endpoints can be used in the networking stack by calling New(eID) to
// create a new endpoint, where eID is the ID of the endpoint being wrapped,
// and then passing it as an argument to Stack.CreateNIC().
package sniffer

import (
	"fmt"
	"sync/atomic"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
	"log"
)

// LogPackets is a flag used to enable or disable packet valid values
// are 0 or 1.
var LogPackets uint32 = 1

type endpoint struct {
	dispatcher stack.NetworkDispatcher
	lower      stack.LinkEndpoint
}

// New creates a new sniffer link-layer endpoint. It wraps around another
// endpoint and logs packets and they traverse the endpoint.
func New(lower tcpip.LinkEndpointID) tcpip.LinkEndpointID {
	return stack.RegisterLinkEndpoint(&endpoint{
		lower: stack.FindLinkEndpoint(lower),
	})
}

// DeliverNetworkPacket implements the stack.NetworkDispatcher interface. It is
// called by the link-layer endpoint being wrapped when a packet arrives, and
// logs the packet before forwarding to the actual dispatcher.
func (e *endpoint) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remoteLinkAddr tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	if atomic.LoadUint32(&LogPackets) == 1 {
		LogPacket("recv", protocol, vv.First(), nil)
	}
	e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, protocol, vv)
}

// Attach implements the stack.LinkEndpoint interface. It saves the dispatcher
// and registers with the lower endpoint as its dispatcher so that "e" is called
// for inbound packets.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.lower.Attach(e)
}

// MTU implements stack.LinkEndpoint.MTU. It just forwards the request to the
// lower endpoint.
func (e *endpoint) MTU() uint32 {
	return e.lower.MTU()
}

// MaxHeaderLength implements the stack.LinkEndpoint interface. It just forwards
// the request to the lower endpoint.
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}

// WritePacket implements the stack.LinkEndpoint interface. It is called by
// higher-level protocols to write packets; it just logs the packet and forwards
// the request to the lower endpoint.
func (e *endpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if atomic.LoadUint32(&LogPackets) == 1 {
		LogPacket("send", protocol, hdr.UsedBytes(), payload)
	}
	return e.lower.WritePacket(r, hdr, payload, protocol)
}

// LogPacket logs the given packet.
func LogPacket(prefix string, protocol tcpip.NetworkProtocolNumber, b, plb []byte) {
	// Figure out the network layer info.
	var transProto uint8
	src := tcpip.Address("unknown")
	dst := tcpip.Address("unknown")
	id := 0
	size := uint16(0)
	switch protocol {
	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(b)
		src = ipv4.SourceAddress()
		dst = ipv4.DestinationAddress()
		transProto = ipv4.Protocol()
		size = ipv4.TotalLength() - uint16(ipv4.HeaderLength())
		b = b[ipv4.HeaderLength():]
		id = int(ipv4.ID())

	case header.IPv6ProtocolNumber:
		ipv6 := header.IPv6(b)
		src = ipv6.SourceAddress()
		dst = ipv6.DestinationAddress()
		transProto = ipv6.NextHeader()
		size = ipv6.PayloadLength()
		b = b[header.IPv6MinimumSize:]

	case header.ARPProtocolNumber:
		arp := header.ARP(b)
		log.Printf(
			"%s arp %v (%v) -> %v (%v) valid:%v",
			prefix,
			tcpip.Address(arp.ProtocolAddressSender()), tcpip.LinkAddress(arp.HardwareAddressSender()),
			tcpip.Address(arp.ProtocolAddressTarget()), tcpip.LinkAddress(arp.HardwareAddressTarget()),
			arp.IsValid(),
		)
		return
	default:
		log.Printf("%s unknown network protocol", prefix)
		return
	}

	// Figure out the transport layer info.
	transName := "unknown"
	srcPort := uint16(0)
	dstPort := uint16(0)
	details := ""
	switch tcpip.TransportProtocolNumber(transProto) {
	case header.ICMPv4ProtocolNumber:
		transName = "icmp"
		icmp := header.ICMPv4(b)
		icmpType := "unknown"
		switch icmp.Type() {
		case header.ICMPv4EchoReply:
			icmpType = "echo reply"
		case header.ICMPv4DstUnreachable:
			icmpType = "destination unreachable"
		case header.ICMPv4SrcQuench:
			icmpType = "source quench"
		case header.ICMPv4Redirect:
			icmpType = "redirect"
		case header.ICMPv4Echo:
			icmpType = "echo"
		case header.ICMPv4TimeExceeded:
			icmpType = "time exceeded"
		case header.ICMPv4ParamProblem:
			icmpType = "param problem"
		case header.ICMPv4Timestamp:
			icmpType = "timestamp"
		case header.ICMPv4TimestampReply:
			icmpType = "timestamp reply"
		case header.ICMPv4InfoRequest:
			icmpType = "info request"
		case header.ICMPv4InfoReply:
			icmpType = "info reply"
		}
		log.Printf("%s %s %v -> %v %s len:%d id:%04x code:%d", prefix, transName, src, dst, icmpType, size, id, icmp.Code())
		return

	case header.UDPProtocolNumber:
		transName = "udp"
		udp := header.UDP(b)
		srcPort = udp.SourcePort()
		dstPort = udp.DestinationPort()
		size -= header.UDPMinimumSize

		details = fmt.Sprintf("xsum: 0x%x", udp.Checksum())

	case header.TCPProtocolNumber:
		transName = "tcp"
		tcp := header.TCP(b)
		srcPort = tcp.SourcePort()
		dstPort = tcp.DestinationPort()
		size -= uint16(tcp.DataOffset())

		// Initialize the TCP flags.
		flags := tcp.Flags()
		flagsStr := []byte("FSRPAU")
		for i := range flagsStr {
			if flags&(1<<uint(i)) == 0 {
				flagsStr[i] = ' '
			}
		}
		details = fmt.Sprintf("flags:0x%02x (%v) seqnum: %v ack: %v win: %v xsum:0x%x", flags, string(flagsStr), tcp.SequenceNumber(), tcp.AckNumber(), tcp.WindowSize(), tcp.Checksum())
		if flags&header.TCPFlagSyn != 0 {
			details += fmt.Sprintf(" options: %+v", header.ParseSynOptions(tcp.Options(), flags&header.TCPFlagAck != 0))
		} else {
			details += fmt.Sprintf(" options: %+v", tcp.ParsedOptions())
		}
	default:
		log.Printf("%s %v -> %v unknown transport protocol: %d", prefix, src, dst, transProto)
		return
	}

	log.Printf("%s %s %v:%v -> %v:%v len:%d id:%04x %s", prefix, transName, src, srcPort, dst, dstPort, size, id, details)
}
