// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
//
// For protocol implementers, RegisterTransportProtocol() and
// RegisterNetworkProtocol() are used to register protocols with the stack,
// which will then be instantiated when consumers interact with the stack.
package stack

import (
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/ports"
	"github.com/google/netstack/waiter"
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.View) bool
}

// Stack is a networking stack, with all supported protocols, NICs, and route
// table.
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol

	demux *transportDemuxer

	stats tcpip.Stats

	mu   sync.RWMutex
	nics map[tcpip.NICID]*NIC

	// route is the route table passed in by the user via SetRouteTable(),
	// it is used by FindRoute() to build a route for a specific
	// destination.
	routeTable []tcpip.Route

	*ports.PortManager
}

// New allocates a new networking stack with only the requested networking and
// transport protocols.
func New(network []string, transport []string) tcpip.Stack {
	s := &Stack{
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		nics:               make(map[tcpip.NICID]*NIC),
		PortManager:        ports.NewPortManager(),
	}

	// Add specified network protocols.
	for _, name := range network {
		netProto, ok := networkProtocols[name]
		if !ok {
			continue
		}

		s.networkProtocols[netProto.Number()] = netProto
	}

	// Add specified transport protocols.
	for _, name := range transport {
		transProto, ok := transportProtocols[name]
		if !ok {
			continue
		}

		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	// Create the global transport demuxer.
	s.demux = newTransportDemuxer(s)

	return s
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(*Route, TransportEndpointID, buffer.View) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// Stats returns a snapshot of the current stats.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for a given destination address mask.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routeTable = table
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	return t.proto.NewEndpoint(s, network, waiterQueue)
}

// createNIC creates a NIC with the provided id and link-layer endpoint, and
// optionally enable it.
func (s *Stack) createNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID, enabled bool) error {
	ep := FindLinkEndpoint(linkEP)
	if ep == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique.
	if _, ok := s.nics[id]; ok {
		return tcpip.ErrDuplicateNICID
	}

	n := newNIC(s, id, ep)

	s.nics[id] = n
	if enabled {
		n.attachLinkEndpoint()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and link-layer endpoint.
func (s *Stack) CreateNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) error {
	return s.createNIC(id, linkEP, true)
}

// CreateDisabledNIC creates a NIC with the provided id and link-layer endpoint,
// but leave it disable. Stack.EnableNIC must be called before the link-layer
// endpoint starts delivering packets to it.
func (s *Stack) CreateDisabledNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) error {
	return s.createNIC(id, linkEP, false)
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start
// delivering packets to it.
func (s *Stack) EnableNIC(id tcpip.NICID) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	nic.attachLinkEndpoint()

	return nil
}

// AddAddress adds a new network-layer address to the specified NIC.
func (s *Stack) AddAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.AddAddress(protocol, addr)
}

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.RemoveAddress(addr)
}

// FindRoute creates a route to the given destination address, leaving through
// the given nic and local address (if provided).
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) (Route, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.routeTable {
		if id != 0 && id != s.routeTable[i].NIC || !s.routeTable[i].Match(remoteAddr) {
			continue
		}

		nic := s.nics[s.routeTable[i].NIC]
		if nic == nil {
			continue
		}

		var ref *referencedNetworkEndpoint
		if len(localAddr) != 0 {
			ref = nic.findEndpoint(localAddr)
		} else {
			ref = nic.primaryEndpoint(netProto)
		}

		if ref == nil {
			continue
		}

		return makeRoute(netProto, ref.ep.ID().LocalAddress, remoteAddr, ref), nil
	}

	return Route{}, tcpip.ErrNoRoute
}

// CheckLocalAddress determines if the given local address exists, and if it
// does, returns the id of the NIC it's bound to. Returns 0 if the address
// does not exist.
func (s *Stack) CheckLocalAddress(nicid tcpip.NICID, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, we try to find the address there only.
	if nicid != 0 {
		nic := s.nics[nicid]
		if nic == nil {
			return 0
		}

		ref := nic.findEndpoint(addr)
		if ref == nil {
			return 0
		}

		ref.decRef()

		return nic.id
	}

	// Go through all the NICs.
	for _, nic := range s.nics {
		ref := nic.findEndpoint(addr)
		if ref != nil {
			ref.decRef()
			return nic.id
		}
	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	nic.setPromiscuousMode(enable)

	return nil
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optinal, but
// nic-specific IDs have precedence over global ones.
func (s *Stack) RegisterTransportEndpoint(nicID tcpip.NICID, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) error {
	if nicID == 0 {
		return s.demux.registerEndpoint(protocol, id, ep)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.demux.registerEndpoint(protocol, id, ep)
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(nicID tcpip.NICID, protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	if nicID == 0 {
		s.demux.unregisterEndpoint(protocol, id)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic != nil {
		nic.demux.unregisterEndpoint(protocol, id)
	}
}
