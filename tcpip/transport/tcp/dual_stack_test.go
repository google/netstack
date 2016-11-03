// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp_test

import (
	"testing"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/checker"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"
)

const (
	stackV6Addr          = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr           = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	stackV4MappedAddr    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + stackAddr
	testV4MappedAddr     = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + testAddr
	V4MappedWildcardAddr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"
)

func newDualTestContext(t *testing.T, mtu uint32) *testContext {
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName}, []string{tcp.ProtocolName})

	id, linkEP := channel.New(256, mtu)
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	if err := s.AddAddress(1, ipv6.ProtocolNumber, stackV6Addr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: "\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
		{
			Destination: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			Gateway:     "",
			NIC:         1,
		},
	})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

func (c *testContext) createV6Endpoint(v4only bool) {
	var err error
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	var v tcpip.V6OnlyOption
	if v4only {
		v = 1
	}
	if err := c.ep.SetSockOpt(v); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}
}

func (c *testContext) getV6Packet() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv6.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv6.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv6(c.t, b, checker.SrcAddr(stackV6Addr), checker.DstAddr(testV6Addr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

func (c *testContext) sendV6Packet(payload []byte, h *headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.TCPMinimumSize + len(payload)),
		NextHeader:    uint8(tcp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       testV6Addr,
		DstAddr:       stackV6Addr,
	})

	// Initialize the TCP header.
	t := header.TCP(buf[header.IPv6MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    h.srcPort,
		DstPort:    h.dstPort,
		SeqNum:     uint32(h.seqNum),
		AckNum:     uint32(h.ackNum),
		DataOffset: header.TCPMinimumSize,
		Flags:      uint8(h.flags),
		WindowSize: uint16(h.rcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.Checksum([]byte(testV6Addr), 0)
	xsum = header.Checksum([]byte(stackV6Addr), xsum)
	xsum = header.Checksum([]byte{0, uint8(tcp.ProtocolNumber)}, xsum)

	// Calculate the TCP checksum and set it.
	length := uint16(header.TCPMinimumSize + len(payload))
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv6.ProtocolNumber, &vv)
}

func TestV4MappedConnectOnV6Only(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(true)

	// Start connection attempt, it must fail.
	err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort})
	if err != tcpip.ErrNoRoute {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}
}

func testV4Connect(c *testContext) {
	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventOut)
	defer c.wq.EventUnregister(&we)

	err := c.ep.Connect(tcpip.FullAddress{Addr: testV4MappedAddr, Port: testPort})
	if err != tcpip.ErrConnectStarted {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)

	tcp := header.TCP(header.IPv4(b).Payload())
	c.irs = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.sendPacket(nil, &headers{
		srcPort: tcp.DestinationPort(),
		dstPort: tcp.SourcePort(),
		flags:   header.TCPFlagSyn | header.TCPFlagAck,
		seqNum:  iss,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Receive ACK packet.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		err = c.ep.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}
}

func TestV4MappedConnect(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Test the connection request.
	testV4Connect(c)
}

func TestV4ConnectWhenBoundToWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(c)
}

func TestV4ConnectWhenBoundToV4MappedWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: V4MappedWildcardAddr}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(c)
}

func TestV4ConnectWhenBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to v4 mapped address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV4Connect(c)
}

func testV6Connect(c *testContext) {
	// Start connection attempt to IPv6 address.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventOut)
	defer c.wq.EventUnregister(&we)

	err := c.ep.Connect(tcpip.FullAddress{Addr: testV6Addr, Port: testPort})
	if err != tcpip.ErrConnectStarted {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.getV6Packet()
	checker.IPv6(c.t, b,
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)

	tcp := header.TCP(header.IPv6(b).Payload())
	c.irs = seqnum.Value(tcp.SequenceNumber())

	iss := seqnum.Value(789)
	c.sendV6Packet(nil, &headers{
		srcPort: tcp.DestinationPort(),
		dstPort: tcp.SourcePort(),
		flags:   header.TCPFlagSyn | header.TCPFlagAck,
		seqNum:  iss,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Receive ACK packet.
	checker.IPv6(c.t, c.getV6Packet(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(iss)+1),
		),
	)

	// Wait for connection to be established.
	select {
	case <-ch:
		err = c.ep.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}
}

func TestV6Connect(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Test the connection request.
	testV6Connect(c)
}

func TestV6ConnectV6Only(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(true)

	// Test the connection request.
	testV6Connect(c)
}

func TestV6ConnectWhenBoundToWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV6Connect(c)
}

func TestV6ConnectWhenBoundToLocalAddress(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to local address.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV6Addr}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test the connection request.
	testV6Connect(c)
}

func TestV4RefuseOnV6Only(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(true)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Start listening.
	if err := c.ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagSyn,
		seqNum:  irs,
		rcvWnd:  30000,
	})

	// Receive the RST reply.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.SrcPort(stackPort),
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.AckNum(uint32(irs)+1),
		),
	)
}

func TestV6RefuseOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind and listen.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: V4MappedWildcardAddr, Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := c.ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.sendV6Packet(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagSyn,
		seqNum:  irs,
		rcvWnd:  30000,
	})

	// Receive the RST reply.
	checker.IPv6(c.t, c.getV6Packet(),
		checker.TCP(
			checker.SrcPort(stackPort),
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
			checker.AckNum(uint32(irs)+1),
		),
	)
}

func testV4Accept(c *testContext) {
	// Start listening.
	if err := c.ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagSyn,
		seqNum:  irs,
		rcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.getPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv4(c.t, b,
		checker.TCP(
			checker.SrcPort(stackPort),
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.AckNum(uint32(irs)+1),
		),
	)

	// Send ACK.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagAck,
		seqNum:  irs + 1,
		ackNum:  iss + 1,
		rcvWnd:  30000,
	})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	nep, _, err := c.ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	// Make sure we get the same error when calling the original ep and the
	// new one. This validates that v4-mapped endpoints are still able to
	// query the V6Only flag, whereas pure v4 endpoints are not.
	var v tcpip.V6OnlyOption
	expected := c.ep.GetSockOpt(&v)
	if err := nep.GetSockOpt(&v); err != expected {
		c.t.Fatalf("GetSockOpt returned unexpected value: got %v, want %v", err, expected)
	}

	// Check the peer address.
	addr, err := nep.GetRemoteAddress()
	if err != nil {
		c.t.Fatalf("GetRemoteAddress failed failed: %v", err)
	}

	if addr.Addr != testAddr {
		c.t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, testAddr)
	}
}

func TestV4AcceptOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(c)
}

func TestV4AcceptOnBoundToV4MappedWildcard(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind to v4 mapped wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: V4MappedWildcardAddr, Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(c)
}

func TestV4AcceptOnBoundToV4Mapped(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind and listen.
	if err := c.ep.Bind(tcpip.FullAddress{Addr: stackV4MappedAddr, Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(c)
}

func TestV6AcceptOnV6(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createV6Endpoint(false)

	// Bind and listen.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := c.ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Send a SYN request.
	irs := seqnum.Value(789)
	c.sendV6Packet(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagSyn,
		seqNum:  irs,
		rcvWnd:  30000,
	})

	// Receive the SYN-ACK reply.
	b := c.getV6Packet()
	tcp := header.TCP(header.IPv6(b).Payload())
	iss := seqnum.Value(tcp.SequenceNumber())
	checker.IPv6(c.t, b,
		checker.TCP(
			checker.SrcPort(stackPort),
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
			checker.AckNum(uint32(irs)+1),
		),
	)

	// Send ACK.
	c.sendV6Packet(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagAck,
		seqNum:  irs + 1,
		ackNum:  iss + 1,
		rcvWnd:  30000,
	})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	nep, _, err := c.ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			nep, _, err = c.ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	// Make sure we can still query the v6 only status of the new endpoint,
	// that is, that it is in fact a v6 socket.
	var v tcpip.V6OnlyOption
	if err := nep.GetSockOpt(&v); err != nil {
		c.t.Fatalf("GetSockOpt failed failed: %v", err)
	}

	// Check the peer address.
	addr, err := nep.GetRemoteAddress()
	if err != nil {
		c.t.Fatalf("GetRemoteAddress failed failed: %v", err)
	}

	if addr.Addr != testV6Addr {
		c.t.Fatalf("Unexpected remote address: got %v, want %v", addr.Addr, testV6Addr)
	}
}

func TestV4AcceptOnV4(t *testing.T) {
	c := newDualTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create TCP endpoint.
	var err error
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Bind to wildcard.
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	// Test acceptance.
	testV4Accept(c)
}
