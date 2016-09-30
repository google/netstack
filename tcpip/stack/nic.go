package stack

import (
	"sync"
	"sync/atomic"

	"github.com/google/netstack/ilist"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip"
)

// NIC represents a "network interface card" to which the networking stack is
// attached.
type NIC struct {
	stack  *Stack
	id     tcpip.NICID
	linkEP LinkEndpoint

	demux *transportDemuxer

	mu          sync.RWMutex
	promiscuous bool
	primary     map[tcpip.NetworkProtocolNumber]*ilist.List
	endpoints   map[NetworkEndpointID]*referencedNetworkEndpoint
}

func newNIC(stack *Stack, id tcpip.NICID, ep LinkEndpoint) *NIC {
	return &NIC{
		stack:     stack,
		id:        id,
		linkEP:    ep,
		demux:     newTransportDemuxer(stack),
		primary:   make(map[tcpip.NetworkProtocolNumber]*ilist.List),
		endpoints: make(map[NetworkEndpointID]*referencedNetworkEndpoint),
	}
}

// attachLinkEndpoint attaches the NIC to the endpoint, which will enable it
// to start delivering packets.
func (n *NIC) attachLinkEndpoint() {
	n.linkEP.Attach(n)
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.promiscuous = enable
	n.mu.Unlock()
}

// primaryEndpoint returns the primary endpoint of n for the given network
// protocol.
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber) *referencedNetworkEndpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := n.primary[protocol]
	if list == nil {
		return nil
	}

	for e := list.Front(); e != nil; e = e.Next() {
		r := e.(*referencedNetworkEndpoint)
		if r.tryIncRef() {
			return r
		}
	}

	return nil
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *NIC) findEndpoint(address tcpip.Address) *referencedNetworkEndpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ref := n.endpoints[NetworkEndpointID{address}]
	if ref == nil || !ref.tryIncRef() {
		return nil
	}

	return ref
}

func (n *NIC) addAddressLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, replace bool) (*referencedNetworkEndpoint, error) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	// Create the new network endpoint.
	ep, err := netProto.NewEndpoint(n.id, addr, n, n.linkEP)
	if err != nil {
		return nil, err
	}

	id := *ep.ID()
	if ref, ok := n.endpoints[id]; ok {
		if !replace {
			return nil, tcpip.ErrDuplicateAddress
		}

		n.removeEndpointLocked(ref)
	}

	ref := newReferencedNetworkEndpoint(ep, protocol, n)

	n.endpoints[id] = ref

	l, ok := n.primary[protocol]
	if !ok {
		l = &ilist.List{}
		n.primary[protocol] = l
	}

	l.PushBack(ref)

	return ref, nil
}

// AddAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *NIC) AddAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) error {
	// Add the endpoint.
	n.mu.Lock()
	_, err := n.addAddressLocked(protocol, addr, false)
	n.mu.Unlock()

	return err
}

func (n *NIC) removeEndpointLocked(r *referencedNetworkEndpoint) {
	id := *r.ep.ID()

	// Nothing to do if the reference has already been replaced with a
	// different one.
	if n.endpoints[id] != r {
		return
	}

	if r.holdsInsertRef {
		panic("Reference count dropped to zero before being removed")
	}

	delete(n.endpoints, id)
	n.primary[r.protocol].Remove(r)
}

func (n *NIC) removeEndpoint(r *referencedNetworkEndpoint) {
	n.mu.Lock()
	n.removeEndpointLocked(r)
	n.mu.Unlock()
}

// RemoveAddress removes an address from n.
func (n *NIC) RemoveAddress(addr tcpip.Address) error {
	n.mu.Lock()
	r := n.endpoints[NetworkEndpointID{addr}]
	if r == nil || !r.holdsInsertRef {
		n.mu.Unlock()
		return tcpip.ErrBadLocalAddress
	}

	r.holdsInsertRef = false
	n.mu.Unlock()

	r.decRef()

	return nil
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the physical interface.
func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, protocol tcpip.NetworkProtocolNumber, v buffer.View) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		atomic.AddUint64(&n.stack.stats.UnknownProtocolRcvdPackets, 1)
		return
	}

	if len(v) < netProto.MinimumPacketSize() {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	src, dst := netProto.ParseAddresses(v)
	id := NetworkEndpointID{dst}

	n.mu.RLock()
	ref := n.endpoints[id]
	if ref != nil && !ref.tryIncRef() {
		ref = nil
	}
	promiscuous := n.promiscuous
	n.mu.RUnlock()

	if ref == nil && promiscuous {
		// Try again with the lock in exclusive mode. If we still can't
		// get the endpoint, create a new "temporary" one. It will only
		// exist while there's a route through it.
		n.mu.Lock()
		ref = n.endpoints[id]
		if ref == nil || !ref.tryIncRef() {
			ref, _ = n.addAddressLocked(protocol, dst, true)
			if ref != nil {
				ref.holdsInsertRef = false
			}
		}
		n.mu.Unlock()
	}

	if ref == nil {
		atomic.AddUint64(&n.stack.stats.UnknownNetworkEndpointRcvdPackets, 1)
		return
	}

	r := makeRoute(protocol, dst, src, ref)
	ref.ep.HandlePacket(&r, v)
	ref.decRef()
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, v buffer.View) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		atomic.AddUint64(&n.stack.stats.UnknownProtocolRcvdPackets, 1)
		return
	}

	transProto := state.proto
	if len(v) < transProto.MinimumPacketSize() {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(v)
	if err != nil {
		atomic.AddUint64(&n.stack.stats.MalformedRcvdPackets, 1)
		return
	}

	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	if n.demux.deliverPacket(r, protocol, v, id) ||
		n.stack.demux.deliverPacket(r, protocol, v, id) {
		return
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(r, id, v) {
			return
		}
	}

	// We could not find an appropriate destination for this packet, so
	// deliver it to the global handler.
	transProto.HandleUnknownDestinationPacket(r, id, v)
}

// ID returns the identifier of n.
func (n *NIC) ID() tcpip.NICID {
	return n.id
}

type referencedNetworkEndpoint struct {
	ilist.Entry

	refs     int32
	ep       NetworkEndpoint
	nic      *NIC
	protocol tcpip.NetworkProtocolNumber

	// holdsInsertRef is protected by the NIC's mutex. It indicates whether
	// the reference count is biased by 1 due to the insertion of the
	// endpoint. It is reset to false when RemoveAddress is called on the
	// NIC.
	holdsInsertRef bool
}

func newReferencedNetworkEndpoint(ep NetworkEndpoint, protocol tcpip.NetworkProtocolNumber, nic *NIC) *referencedNetworkEndpoint {
	return &referencedNetworkEndpoint{
		refs:           1,
		ep:             ep,
		nic:            nic,
		protocol:       protocol,
		holdsInsertRef: true,
	}
}

func (r *referencedNetworkEndpoint) decRef() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpoint(r)
	}
}

func (r *referencedNetworkEndpoint) incRef() {
	atomic.AddInt32(&r.refs, 1)
}

func (r *referencedNetworkEndpoint) tryIncRef() bool {
	for {
		v := atomic.LoadInt32(&r.refs)
		if v == 0 {
			return false
		}

		if atomic.CompareAndSwapInt32(&r.refs, v, v+1) {
			return true
		}
	}
}
