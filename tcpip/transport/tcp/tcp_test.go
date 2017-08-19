// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/checker"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/link/sniffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"
)

const (
	stackAddr = "\x0a\x00\x00\x01"
	stackPort = 1234
	testAddr  = "\x0a\x00\x00\x02"
	testPort  = 4096
)

type headers struct {
	srcPort uint16
	dstPort uint16
	seqNum  seqnum.Value
	ackNum  seqnum.Value
	flags   int
	rcvWnd  seqnum.Size
	tcpOpts []byte
}

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      tcpip.Stack

	irs  seqnum.Value
	port uint16
	ep   tcpip.Endpoint
	wq   waiter.Queue

	// timeStampEnabled is true if ep is connected with the Timestamp option
	// enabled.
	timeStampEnabled bool
}

const (
	// defaultMTU is the MTU, in bytes, used throughout the tests, except
	// where another value is explicitly used. It is chosen to match the MTU
	// of loopback interfaces on linux systems.
	defaultMTU = 65535

	// defaultIPv4MSS is the MSS sent by the network stack in syn/syn-ack for an
	// IPv4 endpoint when the MTU is set to defaultMTU in the test.
	defaultIPv4MSS = defaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize
)

// newTestContext allocates and initializes a test context containing a new
// stack and a link-layer endpoint.
func newTestContext(t *testing.T, mtu uint32) *testContext {
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName})

	id, linkEP := channel.New(256, mtu, "")
	if testing.Verbose() {
		id = sniffer.New(id)
	}
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: "\x00\x00\x00\x00",
			Mask:        "\x00\x00\x00\x00",
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

func (c *testContext) cleanup() {
	if c.ep != nil {
		c.ep.Close()
	}
}

func (c *testContext) checkNoPacketTimeout(errMsg string, wait time.Duration) {
	select {
	case <-c.linkEP.C:
		c.t.Fatalf(errMsg)

	case <-time.After(wait):
	}
}

func (c *testContext) checkNoPacket(errMsg string) {
	c.checkNoPacketTimeout(errMsg, 1*time.Second)
}

func (c *testContext) getPacket() []byte {
	select {
	case p := <-c.linkEP.C:
		if p.Proto != ipv4.ProtocolNumber {
			c.t.Fatalf("Bad network protocol: got %v, wanted %v", p.Proto, ipv4.ProtocolNumber)
		}
		b := make([]byte, len(p.Header)+len(p.Payload))
		copy(b, p.Header)
		copy(b[len(p.Header):], p.Payload)

		checker.IPv4(c.t, b, checker.SrcAddr(stackAddr), checker.DstAddr(testAddr))
		return b

	case <-time.After(2 * time.Second):
		c.t.Fatalf("Packet wasn't written out")
	}

	return nil
}

func (c *testContext) sendPacket(payload []byte, h *headers) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.TCPMinimumSize + header.IPv4MinimumSize + len(h.tcpOpts) + len(payload))
	copy(buf[len(buf)-len(payload):], payload)
	copy(buf[len(buf)-len(payload)-len(h.tcpOpts):], h.tcpOpts)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     testAddr,
		DstAddr:     stackAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the TCP header.
	t := header.TCP(buf[header.IPv4MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    h.srcPort,
		DstPort:    h.dstPort,
		SeqNum:     uint32(h.seqNum),
		AckNum:     uint32(h.ackNum),
		DataOffset: uint8(header.TCPMinimumSize + len(h.tcpOpts)),
		Flags:      uint8(h.flags),
		WindowSize: uint16(h.rcvWnd),
	})

	// Calculate the TCP pseudo-header checksum.
	xsum := header.Checksum([]byte(testAddr), 0)
	xsum = header.Checksum([]byte(stackAddr), xsum)
	xsum = header.Checksum([]byte{0, uint8(tcp.ProtocolNumber)}, xsum)

	// Calculate the TCP checksum and set it.
	length := uint16(header.TCPMinimumSize + len(h.tcpOpts) + len(payload))
	xsum = header.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum, length))

	// Inject packet.
	var views [1]buffer.View
	vv := buf.ToVectorisedView(views)
	c.linkEP.Inject(ipv4.ProtocolNumber, &vv)
}

func (c *testContext) sendAck(seq seqnum.Value, bytesReceived int) {
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1 + seqnum.Size(bytesReceived)),
		rcvWnd:  30000,
	})
}

func (c *testContext) receiveAndCheckPacket(data []byte, offset, size int) {
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(size+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1+uint32(offset)),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	pdata := data[offset:][:size]
	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; bytes.Compare(pdata, p) != 0 {
		c.t.Fatalf("Data is different: expected %v, got %v", pdata, p)
	}
}

// createConnected creates a connected TCP endpoint.
func (c *testContext) createConnected(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf *tcpip.ReceiveBufferSizeOption) {
	c.createConnectedWithOptions(iss, rcvWnd, epRcvBuf, nil)
}

func (c *testContext) createConnectedWithOptions(iss seqnum.Value, rcvWnd seqnum.Size, epRcvBuf *tcpip.ReceiveBufferSizeOption, options []byte) {
	// Create TCP endpoint.
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	if epRcvBuf != nil {
		if err := c.ep.SetSockOpt(*epRcvBuf); err != nil {
			c.t.Fatalf("SetSockOpt failed failed: %v", err)
		}
	}

	// Start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&waitEntry, waiter.EventOut)
	defer c.wq.EventUnregister(&waitEntry)

	err = c.ep.Connect(tcpip.FullAddress{Addr: testAddr, Port: testPort})
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

	c.sendPacket(nil, &headers{
		srcPort: tcp.DestinationPort(),
		dstPort: tcp.SourcePort(),
		flags:   header.TCPFlagSyn | header.TCPFlagAck,
		seqNum:  iss,
		ackNum:  c.irs.Add(1),
		rcvWnd:  rcvWnd,
		tcpOpts: options,
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
	case <-notifyCh:
		err = c.ep.GetSockOpt(tcpip.ErrorOption{})
		if err != nil {
			c.t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(1 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}

	c.port = tcp.SourcePort()
}

func TestGiveUpConnect(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	var wq waiter.Queue
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NeEndpoint failed: %v", err)
	}

	// Register for notification, then start connection attempt.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	defer wq.EventUnregister(&waitEntry)

	err = ep.Connect(tcpip.FullAddress{Addr: testAddr, Port: testPort})
	if err != tcpip.ErrConnectStarted {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Close the connection, wait for completion.
	ep.Close()

	// Wait for ep to become writable.
	<-notifyCh
	err = ep.GetSockOpt(tcpip.ErrorOption{})
}

func TestActiveHandshake(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)
}

func TestNonBlockingClose(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)
	ep := c.ep
	c.ep = nil

	// Close the endpoint and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		c.t.Fatalf("Took too long to close: %v", diff)
	}
}

func TestConnectResetAfterClose(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)
	ep := c.ep
	c.ep = nil

	// Close the endpoint, make sure we get a FIN segment, then acknowledge
	// to complete closure of sender, but don't send our own FIN.
	ep.Close()
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Wait for the ep to give up waiting for a FIN, and send a RST.
	time.Sleep(3 * time.Second)
	for {
		b := c.getPacket()
		tcp := header.TCP(header.IPv4(b).Payload())
		if tcp.Flags() == header.TCPFlagAck|header.TCPFlagFin {
			// This is a retransmit of the FIN, ignore it.
			continue
		}

		checker.IPv4(c.t, b,
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1),
				checker.AckNum(790),
				checker.TCPFlags(header.TCPFlagAck|header.TCPFlagRst),
			),
		)
		break
	}
}

func TestSimpleReceive(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	if _, err := c.ep.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	data := []byte{1, 2, 3}
	c.sendPacket(data, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Receive data.
	v, err := c.ep.Read(nil)
	if err != nil {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	if bytes.Compare(data, v) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, v)
	}

	// Check that ACK is received.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestOutOfOrderReceive(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	if _, err := c.ep.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Send second half of data first, with seqnum 3 ahead of expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	c.sendPacket(data[3:], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  793,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Check that we get an ACK specifying which seqnum is expected.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Wait 200ms and check that no data has been received.
	time.Sleep(200 * time.Millisecond)
	if _, err := c.ep.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Send the first 3 bytes now.
	c.sendPacket(data[:3], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Receive data.
	read := make([]byte, 0, 6)
	for len(read) < len(data) {
		v, err := c.ep.Read(nil)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				// Wait for receive to be notified.
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatalf("Timed out waiting for data to arrive")
				}
				continue
			}
			t.Fatalf("Unexpected error from Read: %v", err)
		}

		read = append(read, v...)
	}

	// Check that we received the data in proper order.
	if bytes.Compare(data, read) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, read)
	}

	// Check that the whole data is acknowledged.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestOutOfOrderFlood(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create a new connection with initial window size of 10.
	opt := tcpip.ReceiveBufferSizeOption(10)
	c.createConnected(789, 30000, &opt)

	if _, err := c.ep.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Send 100 packets before the actual one that is expected.
	data := []byte{1, 2, 3, 4, 5, 6}
	for i := 0; i < 100; i++ {
		c.sendPacket(data[3:], &headers{
			srcPort: testPort,
			dstPort: c.port,
			flags:   header.TCPFlagAck,
			seqNum:  796,
			ackNum:  c.irs.Add(1),
			rcvWnd:  30000,
		})

		checker.IPv4(c.t, c.getPacket(),
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1),
				checker.AckNum(790),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Send packet with seqnum 793. It must be discarded because the
	// out-of-order buffer was filled by the previous packets.
	c.sendPacket(data[3:], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  793,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Now send the expected packet, seqnum 790.
	c.sendPacket(data[:3], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Check that only packet 790 is acknowledged.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(793),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFullWindowReceive(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	opt := tcpip.ReceiveBufferSizeOption(10)
	c.createConnected(789, 30000, &opt)

	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	_, err := c.ep.Read(nil)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Fill up the window.
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.sendPacket(data, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that data is acknowledged, and window goes to zero.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(0),
		),
	)

	// Receive data and check it.
	v, err := c.ep.Read(nil)
	if err != nil {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	if bytes.Compare(data, v) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, v)
	}

	// Check that we get an ACK for the newly non-zero window.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(10),
		),
	)
}

func TestNoWindowShrinking(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Start off with a window size of 10, then shrink it to 5.
	opt := tcpip.ReceiveBufferSizeOption(10)
	c.createConnected(789, 30000, &opt)

	opt = 5
	if err := c.ep.SetSockOpt(opt); err != nil {
		t.Fatalf("SetSockOpt failed: %v", err)
	}

	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	_, err := c.ep.Read(nil)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Send 3 bytes, check that the peer acknowledges them.
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.sendPacket(data[:3], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that data is acknowledged, and that window doesn't go to zero
	// just yet because it was previously set to 10. It must go to 7 now.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(793),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(7),
		),
	)

	// Send 7 more bytes, check that the window fills up.
	c.sendPacket(data[3:], &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  793,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(0),
		),
	)

	// Receive data and check it.
	read := make([]byte, 0, 10)
	for len(read) < len(data) {
		v, err := c.ep.Read(nil)
		if err != nil {
			t.Fatalf("Unexpected error from Read: %v", err)
		}

		read = append(read, v...)
	}

	if bytes.Compare(data, read) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, read)
	}

	// Check that we get an ACK for the newly non-zero window, which is the
	// new size.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
			checker.Window(5),
		),
	)
}

func TestSimpleSend(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; bytes.Compare(data, p) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, p)
	}

	// Acknowledge the data.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1 + seqnum.Size(len(data))),
		rcvWnd:  30000,
	})
}

func TestZeroWindowSend(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 0, nil)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	_, err := c.ep.Write(view, nil)
	if err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Since the window is currently zero, check that no packet is received.
	c.checkNoPacket("Packet received when window is zero")

	// Open up the window. Data should be received now.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  30000,
	})

	// Check that data is received.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	if p := b[header.IPv4MinimumSize+header.TCPMinimumSize:]; bytes.Compare(data, p) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, p)
	}

	// Acknowledge the data.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1 + seqnum.Size(len(data))),
		rcvWnd:  30000,
	})
}

func TestScaledWindowConnect(t *testing.T) {
	// This test ensures that window scaling is used when the peer
	// does advertise it and connection is established with Connect().
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Set the window size greater than the maximum non-scaled window.
	opt := tcpip.ReceiveBufferSizeOption(65535 * 3)
	c.createConnectedWithOptions(789, 30000, &opt, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received, and that advertised window is 0xbfff,
	// that is, that it is scaled.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.Window(0xbfff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestNonScaledWindowConnect(t *testing.T) {
	// This test ensures that window scaling is not used when the peer
	// doesn't advertise it and connection is established with Connect().
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Set the window size greater than the maximum non-scaled window.
	opt := tcpip.ReceiveBufferSizeOption(65535 * 3)
	c.createConnected(789, 30000, &opt)

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.Window(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestScaledWindowAccept(t *testing.T) {
	// This test ensures that window scaling is used when the peer
	// does advertise it and connection is established with Accept().
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(65535 * 3)); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	passiveConnectWithOptions(c, 100, 2, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.ep, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.ep, _, err = ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received, and that advertised window is 0xbfff,
	// that is, that it is scaled.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.Window(0xbfff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestNonScaledWindowAccept(t *testing.T) {
	// This test ensures that window scaling is not used when the peer
	// doesn't advertise it and connection is established with Accept().
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the window size greater than the maximum non-scaled window.
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(65535 * 3)); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	passiveConnect(c, 100, 2, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.ep, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.ep, _, err = ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received, and that advertised window is 0xffff,
	// that is, that it's not scaled.
	b := c.getPacket()
	checker.IPv4(c.t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.Window(0xffff),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
}

func TestZeroScaledWindowReceive(t *testing.T) {
	// This test ensures that the endpoint sends a non-zero window size
	// advertisement when the scaled window transitions from 0 to non-zero,
	// but the actual window (not scaled) hasn't gotten to zero.
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Set the window size such that a window scale of 4 will be used.
	const wnd = 65535 * 10
	const ws = uint32(4)
	opt := tcpip.ReceiveBufferSizeOption(wnd)
	c.createConnectedWithOptions(789, 30000, &opt, []byte{
		header.TCPOptionWS, 3, 0, header.TCPOptionNOP,
	})

	// Write chunks of 50000 bytes.
	remain := wnd
	sent := 0
	data := make([]byte, 50000)
	for remain > len(data) {
		c.sendPacket(data, &headers{
			srcPort: testPort,
			dstPort: c.port,
			flags:   header.TCPFlagAck,
			seqNum:  seqnum.Value(790 + sent),
			ackNum:  c.irs.Add(1),
			rcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		checker.IPv4(c.t, c.getPacket(),
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1),
				checker.AckNum(uint32(790+sent)),
				checker.Window(uint16(remain>>ws)),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Make the window non-zero, but the scaled window zero.
	if remain >= 16 {
		data = data[:remain-15]
		c.sendPacket(data, &headers{
			srcPort: testPort,
			dstPort: c.port,
			flags:   header.TCPFlagAck,
			seqNum:  seqnum.Value(790 + sent),
			ackNum:  c.irs.Add(1),
			rcvWnd:  30000,
		})
		sent += len(data)
		remain -= len(data)
		checker.IPv4(c.t, c.getPacket(),
			checker.PayloadLen(header.TCPMinimumSize),
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1),
				checker.AckNum(uint32(790+sent)),
				checker.Window(0),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
	}

	// Read some data. An ack should be sent in response to that.
	v, err := c.ep.Read(nil)
	if err != nil {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(uint32(790+sent)),
			checker.Window(uint16(len(v)>>ws)),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func testBrokenUpWrite(c *testContext, maxPayload int) {
	payloadMultiplier := 10
	dataLen := payloadMultiplier * maxPayload
	data := make([]byte, dataLen)
	for i := range data {
		data[i] = byte(i)
	}

	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.ep.Write(view, nil); err != nil {
		c.t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received in chunks.
	bytesReceived := 0
	numPackets := 0
	for bytesReceived != dataLen {
		b := c.getPacket()
		numPackets++
		tcp := header.TCP(header.IPv4(b).Payload())
		payloadLen := len(tcp.Payload())
		c.t.Logf("bytesReceived: %d, payloadLen: %d\n", bytesReceived, payloadLen)
		checker.IPv4(c.t, b,
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1+uint32(bytesReceived)),
				checker.AckNum(790),
				checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
			),
		)

		pdata := data[bytesReceived : bytesReceived+payloadLen]
		if p := tcp.Payload(); bytes.Compare(pdata, p) != 0 {
			c.t.Fatalf("Data is different: expected %v, got %v", pdata, p)
		}
		bytesReceived += payloadLen
		var options []byte
		if c.timeStampEnabled {
			// If timestamp option is enabled then echo back the timestamp and increment
			// the TSEcr value included in the packet and send that back as the TSVal.
			parsedOpts := tcp.ParsedOptions()
			tsOpt := [12]byte{}
			header.EncodeTSOption(tsOpt[:], parsedOpts.TSEcr+1, parsedOpts.TSVal)
			options = append(options, tsOpt[:]...)
		}
		// Acknowledge the data.
		c.sendPacket(nil, &headers{
			srcPort: testPort,
			dstPort: c.port,
			flags:   header.TCPFlagAck,
			seqNum:  790,
			ackNum:  c.irs.Add(1 + seqnum.Size(bytesReceived)),
			rcvWnd:  30000,
			tcpOpts: options,
		})
	}
	if numPackets == 1 {
		c.t.Fatalf("expected write to be broken up into multiple packets, but got 1 packet")
	}
}

func TestSendGreaterThanMTU(t *testing.T) {
	const maxPayload = 100
	c := newTestContext(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.cleanup()

	c.createConnected(789, 30000, nil)
	testBrokenUpWrite(c, maxPayload)
}

func TestActiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	c := newTestContext(t, 65535)
	defer c.cleanup()

	c.createConnectedWithOptions(789, 30000, nil, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	})
	testBrokenUpWrite(c, maxPayload)
}

// passiveConnect just disables WindowScaling and delegates the call to
// passiveConnectWithOptions.
func passiveConnect(c *testContext, maxPayload, wndScale int, synOptions header.TCPSynOptions) {
	synOptions.WS = -1
	passiveConnectWithOptions(c, maxPayload, wndScale, synOptions)
}

// NOTE: MSS is not a negotiated option and it can be asymmetric in each
// direction. This function uses the maxPayload to set the MSS to be sent to the
// peer on a connect and validates that the MSS in the synACK response is equal
// to the MTU- (tcphdr len + iphdr len).
//
// wndScale is the expected window scale in the synack and sndWndScale is the
// value of the window scaling option to be sent in the syn. If sndWndScale > 0
// then we send the WindowScale option.
func passiveConnectWithOptions(c *testContext, maxPayload, wndScale int, synOptions header.TCPSynOptions) {
	opts := []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
	}

	if synOptions.WS >= 0 {
		opts = append(opts, []byte{
			header.TCPOptionWS, 3, byte(synOptions.WS), header.TCPOptionNOP,
		}...)
	}
	if synOptions.TS {
		tsOpt := [12]byte{}
		header.EncodeTSOption(tsOpt[:], synOptions.TSVal, synOptions.TSEcr)
		opts = append(opts, tsOpt[:]...)
	}

	// Send a SYN request.
	iss := seqnum.Value(789)
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagSyn,
		seqNum:  iss,
		rcvWnd:  30000,
		tcpOpts: opts,
	})

	// Receive the SYN-ACK reply. Make sure MSS is present.
	b := c.getPacket()
	tcp := header.TCP(header.IPv4(b).Payload())
	c.irs = seqnum.Value(tcp.SequenceNumber())

	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(stackPort),
		checker.DstPort(testPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.AckNum(uint32(iss) + 1),
		checker.TCPSynOptions(header.TCPSynOptions{MSS: synOptions.MSS, WS: wndScale}),
	}

	// If TS option was enabled in the original syn then add a checker to
	// validate the Timestamp option in the syn-ack.
	if synOptions.TS {
		tcpCheckers = append(tcpCheckers, checker.TCPTimestampChecker(synOptions.TS, 0, synOptions.TSVal))
	}

	checker.IPv4(c.t, b, checker.TCP(tcpCheckers...))
	rcvWnd := seqnum.Size(30000)
	ackHeaders := &headers{
		srcPort: testPort,
		dstPort: stackPort,
		flags:   header.TCPFlagAck,
		seqNum:  iss + 1,
		ackNum:  c.irs + 1,
		rcvWnd:  rcvWnd,
	}

	// If WS was expected to be in effect then scale the advertised window
	// correspondingly.
	if synOptions.WS > 0 {
		ackHeaders.rcvWnd = rcvWnd >> byte(synOptions.WS)
	}

	if synOptions.TS {
		// Echo the tsVal back to the peer in the tsEcr field of the
		// timestamp option.
		opts := tcp.ParsedOptions()
		tsOpt := [12]byte{}
		// Increment TSVal by 1 from the value sent in the syn and echo
		// the TSVal in the syn-ack in the TSEcr field.
		header.EncodeTSOption(tsOpt[:], synOptions.TSVal+1, opts.TSVal)
		ackHeaders.tcpOpts = tsOpt[:]
	}

	// Send ACK.
	c.sendPacket(nil, ackHeaders)

	c.port = stackPort
}

func TestPassiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := newTestContext(t, mtu)
	defer c.cleanup()

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	const wndScale = 2
	if err := ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(rcvBufferSize)); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	passiveConnect(c, maxPayload, wndScale, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.ep, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.ep, _, err = ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(c, maxPayload)
}

func TestSynCookiePassiveSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 536
	const mtu = 2000
	c := newTestContext(t, mtu)
	defer c.cleanup()

	// Set the SynRcvd threshold to zero to force a syn cookie based accept
	// to happen.
	saved := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = saved
	}()
	tcp.SynRcvdCountThreshold = 0

	// Create EP and start listening.
	wq := &waiter.Queue{}
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}
	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Do 3-way handshake.
	passiveConnect(c, maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Try to accept the connection.
	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	c.ep, _, err = ep.Accept()
	if err == tcpip.ErrWouldBlock {
		// Wait for connection to be established.
		select {
		case <-ch:
			c.ep, _, err = ep.Accept()
			if err != nil {
				c.t.Fatalf("Accept failed: %v", err)
			}

		case <-time.After(1 * time.Second):
			c.t.Fatalf("Timed out waiting for accept")
		}
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(c, maxPayload)
}

func TestForwarderSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := newTestContext(t, mtu)
	defer c.cleanup()

	s := c.s.(*stack.Stack)
	ch := make(chan *tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err *tcpip.Error
		c.ep, err = r.CreateEndpoint(&c.wq)
		ch <- err
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do 3-way handshake.
	passiveConnect(c, maxPayload, 1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Wait for connection to be available.
	select {
	case err := <-ch:
		if err != nil {
			c.t.Fatalf("Error creating endpoint: %v", err)
		}
	case <-time.After(2 * time.Second):
		c.t.Fatalf("Timed out waiting for connection")
	}

	// Check that data gets properly segmented.
	testBrokenUpWrite(c, maxPayload)
}

func TestSynOptionsOnActiveConnect(t *testing.T) {
	const mtu = 1400
	c := newTestContext(t, mtu)
	defer c.cleanup()

	// Create TCP endpoint.
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	// Set the buffer size to a deterministic size so that we can check the
	// window scaling option.
	const rcvBufferSize = 0x20000
	const wndScale = 2
	if err := c.ep.SetSockOpt(tcpip.ReceiveBufferSizeOption(rcvBufferSize)); err != nil {
		c.t.Fatalf("SetSockOpt failed failed: %v", err)
	}

	// Start connection attempt.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventOut)
	defer c.wq.EventUnregister(&we)

	err = c.ep.Connect(tcpip.FullAddress{Addr: testAddr, Port: testPort})
	if err != tcpip.ErrConnectStarted {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Receive SYN packet.
	b := c.getPacket()

	checker.IPv4(c.t, b,
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.TCPSynOptions(header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize, WS: wndScale}),
		),
	)

	tcp := header.TCP(header.IPv4(b).Payload())
	c.irs = seqnum.Value(tcp.SequenceNumber())

	// Wait for retransmit.
	time.Sleep(1 * time.Second)
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.TCPFlags(header.TCPFlagSyn),
			checker.SrcPort(tcp.SourcePort()),
			checker.SeqNum(tcp.SequenceNumber()),
			checker.TCPSynOptions(header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize, WS: wndScale}),
		),
	)

	// Send SYN-ACK.
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

func TestCloseListener(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create listener.
	var wq waiter.Queue
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Close the listener and measure how long it takes.
	t0 := time.Now()
	ep.Close()
	if diff := time.Now().Sub(t0); diff > 3*time.Second {
		c.t.Fatalf("Took too long to close: %v", diff)
	}
}

func TestReceiveOnResetConnection(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Send RST segment.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagRst,
		seqNum:  790,
		rcvWnd:  30000,
	})

	// Try to read.
	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

loop:
	for {
		switch _, err := c.ep.Read(nil); err {
		case nil:
			t.Fatalf("Unexpected success.")
		case tcpip.ErrWouldBlock:
			select {
			case <-ch:
			case <-time.After(1 * time.Second):
				t.Fatalf("Timed out waiting for reset to arrive")
			}
		case tcpip.ErrConnectionReset:
			break loop
		default:
			t.Fatalf("Unexpected error: want %v, got %v", tcpip.ErrConnectionReset, err)
		}
	}
}

func TestSendOnResetConnection(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Send RST segment.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagRst,
		seqNum:  790,
		rcvWnd:  30000,
	})

	// Wait for the RST to be received.
	time.Sleep(1 * time.Second)

	// Try to write.
	view := buffer.NewView(10)
	_, err := c.ep.Write(view, nil)
	if err != tcpip.ErrConnectionReset {
		t.Fatalf("Unexpected error from Write: want %v, got %v", tcpip.ErrConnectionReset, err)
	}
}

func TestFinImmediately(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Shutdown immediately, check that we get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  c.irs.Add(2),
		rcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+2),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinRetransmit(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Shutdown immediately, check that we get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Don't acknowledge yet. We should get a retransmit of the FIN.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Ack and send FIN as well.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  c.irs.Add(2),
		rcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+2),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithNoPendingData(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Write something out, and have it acknowledged.
	view := buffer.NewView(10)
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	next := uint32(c.irs) + 1
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	// Shutdown, check that we get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Ack and send FIN as well.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	// Check that the stack acks the FIN.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingDataCwndFull(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Write something out but don't ACK it yet.
	view := buffer.NewView(10)
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	next := uint32(c.irs) + 1
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that the FIN segment isn't sent
	// because the congestion window doesn't allow it. Wait until a
	// retransmit is received.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next-uint32(len(view))),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Send the ACK that will allow the FIN to be sent as well.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPendingData(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Write something out, and acknowledge it to get cwnd to 2.
	view := buffer.NewView(10)
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	next := uint32(c.irs) + 1
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	// Write new data, but don't acknowledge it.
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send a FIN that acknowledges everything. Get an ACK back.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)
}

func TestFinWithPartialAck(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Write something out, and acknowledge it to get cwnd to 2. Also send
	// FIN from the test side.
	view := buffer.NewView(10)
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	next := uint32(c.irs) + 1
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})

	// Check that we get an ACK for the fin.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Write new data, but don't acknowledge it.
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(len(view)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)
	next += uint32(len(view))

	// Shutdown the connection, check that we do get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(next),
			checker.AckNum(791),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)
	next++

	// Send an ACK for the data, but not for the FIN yet.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  791,
		ackNum:  seqnum.Value(next - 1),
		rcvWnd:  30000,
	})

	// Check that we don't get a retransmit of the FIN.
	c.checkNoPacketTimeout("FIN retransmitted when data was ack'd", 100*time.Millisecond)

	// Ack the FIN.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  791,
		ackNum:  seqnum.Value(next),
		rcvWnd:  30000,
	})
}

func TestExponentialIncreaseDuringSlowStart(t *testing.T) {
	maxPayload := 10
	c := newTestContext(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	const iterations = 7
	data := buffer.NewView(maxPayload * (1 << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, err := c.ep.Write(data, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	expected := 1
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.sendAck(790, bytesRead)

		// Double the number of expected packets for the next iteration.
		expected *= 2
	}
}

func TestCongestionAvoidance(t *testing.T) {
	maxPayload := 10
	c := newTestContext(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	const iterations = 7
	data := buffer.NewView(2 * maxPayload * (1 << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, err := c.ep.Write(data, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Do slow start for a few iterations.
	expected := 1
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = 1 << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.sendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Don't acknowledge the first packet of the last packet train. Let's
	// wait for them to time out, which will trigger a restart of slow
	// start, and initialization of ssthresh to cwnd/2.
	rtxOffset := bytesRead - maxPayload*expected
	c.receiveAndCheckPacket(data, rtxOffset, maxPayload)

	// Acknowledge all the data received so far.
	c.sendAck(790, bytesRead)

	// This part is tricky: when the timeout happened, we had "expected"
	// packets pending, cwnd reset to 1, and ssthresh set to expected/2.
	// By acknowledging "expected" packets, the slow-start part will
	// increase cwnd to expected/2 (which "consumes" expected/2-1 of the
	// acknowledgements), then the congestion avoidance part will consume
	// an extra expected/2 acks to take cwnd to expected/2 + 1. One ack
	// remains in the "ack count" (which will cause cwnd to be incremented
	// once it reaches cwnd acks).
	//
	// So we're straight into congestion avoidance with cwnd set to
	// expected/2 + 1.
	//
	// Check that packets trains of cwnd packets are sent, and that cwnd is
	// incremented by 1 after we acknowledge each packet.
	expected = expected/2 + 1
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.sendAck(790, bytesRead)

		// In cogestion avoidance, the packets trains increase by 1 in
		// each iteration.
		expected++
	}
}

func TestFastRecovery(t *testing.T) {
	maxPayload := 10
	c := newTestContext(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	const iterations = 7
	data := buffer.NewView(2 * maxPayload * (1 << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in one shot. Packets will only be written at the
	// MTU size though.
	if _, err := c.ep.Write(data, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Do slow start for a few iterations.
	expected := 1
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = 1 << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.sendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Send 10 duplicate acks. This should force an immediate retransmit of
	// the pending packet, and inflation of cwnd to expected/2+7.
	rtxOffset := bytesRead - maxPayload*expected
	for i := 0; i < 10; i++ {
		c.sendAck(790, rtxOffset)
	}

	// Receive the retransmitted packet.
	c.receiveAndCheckPacket(data, rtxOffset, maxPayload)

	// Acknowledge half of the pending data.
	rtxOffset = bytesRead - expected*maxPayload/2
	c.sendAck(790, rtxOffset)

	// Receive the retransmit due to partial ack.
	c.receiveAndCheckPacket(data, rtxOffset, maxPayload)

	// This part is tricky: when the retransmit happened, we had "expected"
	// packets pending, cwnd reset to expected/2, and ssthresh set to
	// expected/2. By acknowledging expected/2 packets, 7 new packets are
	// allowed to be sent immediately.
	for j := 0; j < 7; j++ {
		c.receiveAndCheckPacket(data, bytesRead, maxPayload)
		bytesRead += maxPayload
	}

	c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)

	// Acknowledge all pending data.
	c.sendAck(790, bytesRead)

	// Now the inflation is removed, so cwnd is expected/2. But since we've
	// received expected+7 packets since cwnd changed, it must now be set
	// expected/2 + 2, given that floor((expected+7)/(expected/2)) == 2.
	expected = expected/2 + 2
	for i := 0; i < iterations; i++ {
		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)

		// Acknowledge all the data received so far.
		c.sendAck(790, bytesRead)

		// In cogestion avoidance, the packets trains increase by 1 in
		// each iteration.
		expected++
	}
}

func TestRetransmit(t *testing.T) {
	maxPayload := 10
	c := newTestContext(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	const iterations = 7
	data := buffer.NewView(maxPayload * (1 << (iterations + 1)))
	for i := range data {
		data[i] = byte(i)
	}

	// Write all the data in two shots. Packets will only be written at the
	// MTU size though.
	if _, err := c.ep.Write(data[:len(data)/2], nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}
	if _, err := c.ep.Write(data[len(data)/2:], nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Do slow start for a few iterations.
	expected := 1
	bytesRead := 0
	for i := 0; i < iterations; i++ {
		expected = 1 << uint(i)
		if i > 0 {
			// Acknowledge all the data received so far if not on
			// first iteration.
			c.sendAck(790, bytesRead)
		}

		// Read all packets expected on this iteration. Don't
		// acknowledge any of them just yet, so that we can measure the
		// congestion window.
		for j := 0; j < expected; j++ {
			c.receiveAndCheckPacket(data, bytesRead, maxPayload)
			bytesRead += maxPayload
		}

		// Check we don't receive any more packets on this iteration.
		// The timeout can't be too high or we'll trigger a timeout.
		c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
	}

	// Wait for a timeout and retransmit.
	rtxOffset := bytesRead - maxPayload*expected
	c.receiveAndCheckPacket(data, rtxOffset, maxPayload)

	// Acknowledge half of the pending data.
	rtxOffset = bytesRead - expected*maxPayload/2
	c.sendAck(790, rtxOffset)

	// Receive the remaining data, making sure that acknowledge data is not
	// retransmitted.
	for offset := rtxOffset; offset < len(data); offset += maxPayload {
		c.receiveAndCheckPacket(data, offset, maxPayload)
		c.sendAck(790, offset+maxPayload)
	}

	c.checkNoPacketTimeout("More packets received than expected for this cwnd.", 50*time.Millisecond)
}

func TestUpdateListenBacklog(t *testing.T) {
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// Create listener.
	var wq waiter.Queue
	ep, err := c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	if err := ep.Listen(10); err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}

	// Update the backlog with another Listen() on the same endpoint.
	if err := ep.Listen(20); err != nil {
		c.t.Fatalf("Listen failed to update backlog: %v", err)
	}

	ep.Close()
}

func scaledSendWindow(t *testing.T, scale uint8) {
	// This test ensures that the endpoint is using the right scaling by
	// sending a buffer that is larger than the window size, and ensuring
	// that the endpoint doesn't send more than allowed.
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	maxPayload := defaultMTU - header.IPv4MinimumSize - header.TCPMinimumSize
	c.createConnectedWithOptions(789, 0, nil, []byte{
		header.TCPOptionMSS, 4, byte(maxPayload / 256), byte(maxPayload % 256),
		header.TCPOptionWS, 3, scale, header.TCPOptionNOP,
	})

	// Open up the window with a scaled value.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck,
		seqNum:  790,
		ackNum:  c.irs.Add(1),
		rcvWnd:  1,
	})

	// Send some data. Check that it's capped by the window size.
	view := buffer.NewView(65535)
	if _, err := c.ep.Write(view, nil); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that only data that fits in the scaled window is sent.
	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen((1<<scale)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
		),
	)

	// Reset the connection to free resources.
	c.sendPacket(nil, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagRst,
		seqNum:  790,
	})
}

func TestScaledSendWindow(t *testing.T) {
	for scale := uint8(0); scale <= 14; scale++ {
		scaledSendWindow(t, scale)
	}
}

func TestReceivedSegmentQueuing(t *testing.T) {
	// This test sends 200 segments containing a few bytes each to an
	// endpoint and checks that they're all received and acknowledged by
	// the endpoint, that is, that none of the segments are dropped by
	// internal queues.
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	// Send 200 segments.
	data := []byte{1, 2, 3}
	for i := 0; i < 200; i++ {
		c.sendPacket(data, &headers{
			srcPort: testPort,
			dstPort: c.port,
			flags:   header.TCPFlagAck,
			seqNum:  seqnum.Value(790 + i*len(data)),
			ackNum:  c.irs.Add(1),
			rcvWnd:  30000,
		})
	}

	// Receive ACKs for all segments.
	last := seqnum.Value(790 + 200*len(data))
	for {
		b := c.getPacket()
		checker.IPv4(c.t, b,
			checker.TCP(
				checker.DstPort(testPort),
				checker.SeqNum(uint32(c.irs)+1),
				checker.TCPFlags(header.TCPFlagAck),
			),
		)
		tcp := header.TCP(header.IPv4(b).Payload())
		ack := seqnum.Value(tcp.AckNumber())
		if ack == last {
			break
		}

		if last.LessThan(ack) {
			t.Fatalf("Acknowledge (%v) beyond the expected (%v)", ack, last)
		}
	}
}

func TestReadAfterClosedState(t *testing.T) {
	// This test ensures that calling Read() or Peek() after the endpoint
	// has transitioned to closedState still works if there is pending
	// data. To transition to stateClosed without calling Close(), we must
	// shutdown the send path and the peer must send its own FIN.
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	c.createConnected(789, 30000, nil)

	we, ch := waiter.NewChannelEntry(nil)
	c.wq.EventRegister(&we, waiter.EventIn)
	defer c.wq.EventUnregister(&we)

	if _, err := c.ep.Read(nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	// Shutdown immediately for write, check that we get a FIN.
	if err := c.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		t.Fatalf("Unexpected error from Shutdown: %v", err)
	}

	checker.IPv4(c.t, c.getPacket(),
		checker.PayloadLen(header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+1),
			checker.AckNum(790),
			checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin),
		),
	)

	// Send some data and acknowledge the FIN.
	data := []byte{1, 2, 3}
	c.sendPacket(data, &headers{
		srcPort: testPort,
		dstPort: c.port,
		flags:   header.TCPFlagAck | header.TCPFlagFin,
		seqNum:  790,
		ackNum:  c.irs.Add(2),
		rcvWnd:  30000,
	})

	// Check that ACK is received.
	checker.IPv4(c.t, c.getPacket(),
		checker.TCP(
			checker.DstPort(testPort),
			checker.SeqNum(uint32(c.irs)+2),
			checker.AckNum(uint32(791+len(data))),
			checker.TCPFlags(header.TCPFlagAck),
		),
	)

	// Give the stack the chance to transition to closed state.
	time.Sleep(1 * time.Second)

	// Wait for receive to be notified.
	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Check that peek works.
	peekBuf := make([]byte, 10)
	n, err := c.ep.Peek([][]byte{peekBuf})
	if err != nil {
		t.Fatalf("Unexpected error from Peek: %v", err)
	}

	peekBuf = peekBuf[:n]
	if bytes.Compare(data, peekBuf) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, peekBuf)
	}

	// Receive data.
	v, err := c.ep.Read(nil)
	if err != nil {
		t.Fatalf("Unexpected error from Read: %v", err)
	}

	if bytes.Compare(data, v) != 0 {
		t.Fatalf("Data is different: expected %v, got %v", data, v)
	}

	// Now that we drained the queue, check that functions fail with the
	// right error code.
	if _, err := c.ep.Read(nil); err != tcpip.ErrClosedForReceive {
		t.Fatalf("Unexpected return from Read: got %v, want %v", err, tcpip.ErrClosedForReceive)
	}

	if _, err := c.ep.Peek([][]byte{peekBuf}); err != tcpip.ErrClosedForReceive {
		t.Fatalf("Unexpected return from Peek: got %v, want %v", err, tcpip.ErrClosedForReceive)
	}
}

func TestReusePort(t *testing.T) {
	// This test ensures that ports are immediately available for reuse
	// after Close on the endpoints using them returns.
	c := newTestContext(t, defaultMTU)
	defer c.cleanup()

	// First case, just an endpoint that was bound.
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}

	c.ep.Close()
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	c.ep.Close()

	// Second case, an endpoint that was bound and is connecting..
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	err = c.ep.Connect(tcpip.FullAddress{Addr: testAddr, Port: testPort})
	if err != tcpip.ErrConnectStarted {
		c.t.Fatalf("Unexpected return value from Connect: %v", err)
	}
	c.ep.Close()

	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	c.ep.Close()

	// Third case, an endpoint that was bound and is listening.
	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	err = c.ep.Listen(10)
	if err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}
	c.ep.Close()

	c.ep, err = c.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		c.t.Fatalf("NewEndpoint failed; %v", err)
	}
	if err := c.ep.Bind(tcpip.FullAddress{Port: stackPort}, nil); err != nil {
		c.t.Fatalf("Bind failed: %v", err)
	}
	err = c.ep.Listen(10)
	if err != nil {
		c.t.Fatalf("Listen failed: %v", err)
	}
}
