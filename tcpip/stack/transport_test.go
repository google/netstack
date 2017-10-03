// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack_test

import (
	"testing"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/waiter"
)

const (
	fakeTransNumber    tcpip.TransportProtocolNumber = 1
	fakeTransHeaderLen                               = 3
)

// fakeTransportEndpoint is a transport-layer protocol endpoint. It counts
// received packets; the counts of all endpoints are aggregated in the protocol
// descriptor.
//
// Headers of this protocol are fakeTransHeaderLen bytes, but we currently don't
// use it.
type fakeTransportEndpoint struct {
	id       stack.TransportEndpointID
	stack    *stack.Stack
	netProto tcpip.NetworkProtocolNumber
	proto    *fakeTransportProtocol
	peerAddr tcpip.Address
	route    stack.Route
}

func newFakeTransportEndpoint(stack *stack.Stack, proto *fakeTransportProtocol, netProto tcpip.NetworkProtocolNumber) tcpip.Endpoint {
	return &fakeTransportEndpoint{stack: stack, netProto: netProto, proto: proto}
}

func (f *fakeTransportEndpoint) Close() {
	f.route.Release()
}

func (*fakeTransportEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mask
}

func (*fakeTransportEndpoint) Read(*tcpip.FullAddress) (buffer.View, *tcpip.Error) {
	return buffer.View{}, nil
}

func (f *fakeTransportEndpoint) Write(v buffer.View, _ *tcpip.FullAddress) (uintptr, *tcpip.Error) {
	if len(f.route.RemoteAddress) == 0 {
		return 0, tcpip.ErrNoRoute
	}

	hdr := buffer.NewPrependable(int(f.route.MaxHeaderLength()))
	err := f.route.WritePacket(&hdr, v, fakeTransNumber)
	if err != nil {
		return 0, err
	}

	return uintptr(len(v)), nil
}

func (f *fakeTransportEndpoint) Peek([][]byte) (uintptr, *tcpip.Error) {
	return 0, nil
}

// SetSockOpt sets a socket option. Currently not supported.
func (*fakeTransportEndpoint) SetSockOpt(interface{}) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*fakeTransportEndpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch opt.(type) {
	case tcpip.ErrorOption:
		return nil
	}
	return tcpip.ErrInvalidEndpointState
}

func (f *fakeTransportEndpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	f.peerAddr = addr.Addr

	// Find the route.
	r, err := f.stack.FindRoute(addr.NIC, "", addr.Addr, fakeNetNumber)
	if err != nil {
		return tcpip.ErrNoRoute
	}
	defer r.Release()

	// Try to register so that we can start receiving packets.
	f.id.RemoteAddress = addr.Addr
	err = f.stack.RegisterTransportEndpoint(0, []tcpip.NetworkProtocolNumber{fakeNetNumber}, fakeTransNumber, f.id, f)
	if err != nil {
		return err
	}

	f.route = r.Clone()

	return nil
}

func (f *fakeTransportEndpoint) ConnectEndpoint(e tcpip.Endpoint) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Shutdown(tcpip.ShutdownFlags) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Reset() {
}

func (*fakeTransportEndpoint) Listen(int) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, nil
}

func (*fakeTransportEndpoint) Bind(_ tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	return commit()
}

func (*fakeTransportEndpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

func (*fakeTransportEndpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

func (f *fakeTransportEndpoint) HandlePacket(*stack.Route, stack.TransportEndpointID, *buffer.VectorisedView) {
	// Increment the number of received packets.
	f.proto.packetCount++
}

type fakeTransportGoodOption bool

type fakeTransportBadOption bool

type fakeTransportInvalidValueOption int

type fakeTransportProtocolOptions struct {
	good bool
}

// fakeTransportProtocol is a transport-layer protocol descriptor. It
// aggregates the number of packets received via endpoints of this protocol.
type fakeTransportProtocol struct {
	packetCount int
	opts        fakeTransportProtocolOptions
}

func (*fakeTransportProtocol) Number() tcpip.TransportProtocolNumber {
	return fakeTransNumber
}

func (f *fakeTransportProtocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, _ *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newFakeTransportEndpoint(stack, f, netProto), nil
}

func (*fakeTransportProtocol) MinimumPacketSize() int {
	return fakeTransHeaderLen
}

func (*fakeTransportProtocol) ParsePorts(buffer.View) (src, dst uint16, err *tcpip.Error) {
	return 0, 0, nil
}

func (*fakeTransportProtocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, *buffer.VectorisedView) bool {
	return true
}

func (f *fakeTransportProtocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case fakeTransportGoodOption:
		f.opts.good = bool(v)
		return nil
	case fakeTransportInvalidValueOption:
		return tcpip.ErrInvalidOptionValue
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func TestTransportReceive(t *testing.T) {
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Create endpoint and connect to remote address.
	wq := waiter.Queue{}
	ep, err := s.NewEndpoint(fakeTransNumber, fakeNetNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Connect(tcpip.FullAddress{0, "\x02", 0}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	fakeTrans := s.TransportProtocolInstance(fakeTransNumber).(*fakeTransportProtocol)

	var views [1]buffer.View
	// Create buffer that will hold the packet.
	buf := buffer.NewView(30)

	// Make sure packet with wrong protocol is not delivered.
	buf[0] = 1
	buf[2] = 0
	vv := buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeTrans.packetCount != 0 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 0)
	}

	// Make sure packet from the wrong source is not delivered.
	buf[0] = 1
	buf[1] = 3
	buf[2] = byte(fakeTransNumber)
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeTrans.packetCount != 0 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 0)
	}

	// Make sure packet is delivered.
	buf[0] = 1
	buf[1] = 2
	buf[2] = byte(fakeTransNumber)
	vv = buf.ToVectorisedView(views)
	linkEP.Inject(fakeNetNumber, &vv)
	if fakeTrans.packetCount != 1 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 1)
	}
}

func TestTransportSend(t *testing.T) {
	id, _ := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	// Create endpoint and bind it.
	wq := waiter.Queue{}
	ep, err := s.NewEndpoint(fakeTransNumber, fakeNetNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Connect(tcpip.FullAddress{0, "\x02", 0}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Create buffer that will hold the payload.
	view := buffer.NewView(30)
	_, err = ep.Write(view, nil)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	if fakeNet.sendPacketCount[2] != 1 {
		t.Errorf("sendPacketCount = %d, want %d", fakeNet.sendPacketCount[2], 1)
	}
}

func TestTransportSetOption(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"})

	// Try an unsupported transport protocol.
	if err := s.SetTransportProtocolOption(tcpip.TransportProtocolNumber(99999), fakeTransportGoodOption(false)); err != tcpip.ErrUnknownProtocol {
		t.Fatalf("SetTransportProtocolOption(fakeTrans2, blah, false) = %v, want = tcpip.ErrUnknownProtocol", err)
	}

	testCases := []struct {
		option   interface{}
		want     *tcpip.Error
		verifier func(t *testing.T, p stack.TransportProtocol)
	}{
		{fakeTransportGoodOption(true), nil, func(t *testing.T, p stack.TransportProtocol) {
			fakeTrans := p.(*fakeTransportProtocol)
			if fakeTrans.opts.good != true {
				t.Fatalf("fakeTrans.opts.good = false, want = true")
			}
		}},
		{fakeTransportBadOption(true), tcpip.ErrUnknownProtocolOption, nil},
		{fakeTransportInvalidValueOption(1), tcpip.ErrInvalidOptionValue, nil},
	}
	for _, tc := range testCases {
		if got := s.SetTransportProtocolOption(fakeTransNumber, tc.option); tc.want != got {
			t.Errorf("s.SetOption(fakeTrans, %v) = %v, want = %v", tc.option, got, tc.want)
		}
		if tc.verifier != nil {
			tc.verifier(t, s.TransportProtocolInstance(fakeTransNumber))
		}
	}
}

func init() {
	stack.RegisterTransportProtocolFactory("fakeTrans", func() stack.TransportProtocol {
		return &fakeTransportProtocol{}
	})
}
