package stack

import (
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip"
)

// Route represents a route through the networking stack to a given destination.
type Route struct {
	// RemoteAddress is the final destination of the route.
	RemoteAddress tcpip.Address

	// LocalAddress is the local address where the route starts.
	LocalAddress tcpip.Address

	// NextHop is the next node in the path to the destination.
	NextHop tcpip.Address

	// NetProto is the network-layer protocol.
	NetProto tcpip.NetworkProtocolNumber

	// ref a reference to the network endpoint through which the route
	// starts.
	ref *referencedNetworkEndpoint
}

// makeRoute initializes a new route. It takes ownership of the provided
// reference to a network endpoint.
func makeRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, ref *referencedNetworkEndpoint) Route {
	return Route{
		NetProto:      netProto,
		LocalAddress:  localAddr,
		RemoteAddress: remoteAddr,
		ref:           ref,
	}
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.ref.ep.NICID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.ref.ep.MaxHeaderLength()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress)
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(hdr *buffer.Prependable, payload buffer.View, protocol tcpip.TransportProtocolNumber) error {
	return r.ref.ep.WritePacket(r, hdr, payload, protocol)
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.ref.ep.MTU()
}

// Release frees all resources associated with the route.
func (r *Route) Release() {
	if r.ref != nil {
		r.ref.decRef()
		r.ref = nil
	}
}

// Clone Clone a route such that the original one can be released and the new
// one will remain valid.
func (r *Route) Clone() Route {
	r.ref.incRef()
	return *r
}
