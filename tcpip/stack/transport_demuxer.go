// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

import (
	"sync"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip"
)

// transportEndpoints manages all endpoints of a given protocol. It has its own
// mutex so as to reduce interference between protocols.
type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
}

// transportDemuxer demultiplexes packets targeted at a transport endpoint
// (i.e., after they've been parsed by the network layer). It does two levels
// of demultiplexing: first based on the transport protocol, then based on
// endpoints IDs.
type transportDemuxer struct {
	protocol map[tcpip.TransportProtocolNumber]*transportEndpoints
}

func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{protocol: make(map[tcpip.TransportProtocolNumber]*transportEndpoints)}

	// Add each transport to the demuxer.
	for proto := range stack.transportProtocols {
		d.protocol[proto] = &transportEndpoints{endpoints: make(map[TransportEndpointID]TransportEndpoint)}
	}

	return d
}

// registerEndpoint registers the given endpoint with the dispatcher such that
// packets that match the endpoint ID are delivered to it.
func (d *transportDemuxer) registerEndpoint(protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) error {
	eps, ok := d.protocol[protocol]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	if _, ok := eps.endpoints[id]; ok {
		return tcpip.ErrDuplicateAddress
	}

	eps.endpoints[id] = ep

	return nil
}

// unregisterEndpoint unregisters the endpoint with the given id such that it
// won't receive any more packets.
func (d *transportDemuxer) unregisterEndpoint(protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	eps, ok := d.protocol[protocol]
	if !ok {
		return
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	delete(eps.endpoints, id)
}

// deliverPacket attempts to deliver the given packet. Returns true if it found
// an endpoint, false otherwise.
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, v buffer.View, id TransportEndpointID) bool {
	eps, ok := d.protocol[protocol]
	if !ok {
		return false
	}

	eps.mu.RLock()
	defer eps.mu.RUnlock()

	// Try to find a match with the id as provided.
	if ep := eps.endpoints[id]; ep != nil {
		ep.HandlePacket(r, id, v)
		return true
	}

	// Try to find a match with the id minus the local address.
	nid := id

	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, v)
		return true
	}

	// Try to find a match with the id minus the remote part.
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, v)
		return true
	}

	// Try to find a match with only the local port.
	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		ep.HandlePacket(r, id, v)
		return true
	}

	return false
}
