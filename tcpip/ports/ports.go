// Package ports provides PortManager that manages allocating, reserving and releasing ports.
package ports

import (
	"math"
	"math/rand"
	"sync"

	"github.com/google/netstack/tcpip"
)

const (
	// firstEphemeral is the first ephemeral port.
	firstEphemeral uint16 = 16000
)

type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// PortManager manages allocating, reserving and releasing ports.
type PortManager struct {
	mu             sync.RWMutex
	allocatedPorts map[portDescriptor]struct{}
}

// NewPortManager creates new PortManager.
func NewPortManager() *PortManager {
	return &PortManager{allocatedPorts: make(map[portDescriptor]struct{})}
}

// PickEphemeralPort randomly chooses a starting point and iterates over all
// possible ephemeral ports, allowing the caller to decide whether a given port
// is suitable for its needs, and stopping when a port is found or an error
// occurs.
func (s *PortManager) PickEphemeralPort(testPort func(p uint16) (bool, error)) (port uint16, err error) {
	count := uint16(math.MaxUint16 - firstEphemeral + 1)
	offset := uint16(rand.Int31n(int32(count)))

	for i := uint16(0); i < count; i++ {
		port = firstEphemeral + (offset+i)%count
		ok, err := testPort(port)
		if err != nil {
			return 0, err
		}

		if ok {
			return port, nil
		}
	}

	return 0, tcpip.ErrNoPortAvailable
}

// ReservePort marks a port as reserved so that it cannot be reserved by another
// endpoint. If port is zero, ReservePort will search for an unreserved
// ephemeral port and reserve it, returning its value in the "port" return value.
func (s *PortManager) ReservePort(network tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, port uint16) (reservedPort uint16, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	desc := portDescriptor{network, transport, port}

	// If a port is specified, just try to reserve it.
	if port != 0 {
		if _, ok := s.allocatedPorts[desc]; ok {
			return 0, tcpip.ErrPortInUse
		}

		s.allocatedPorts[desc] = struct{}{}
		return port, nil
	}

	// A port wasn't specified, so try to find one.
	return s.PickEphemeralPort(func(p uint16) (bool, error) {
		desc.port = p
		if _, ok := s.allocatedPorts[desc]; ok {
			return false, nil
		}

		s.allocatedPorts[desc] = struct{}{}
		return true, nil
	})
}

// ReleasePort releases the reservation on a port so that it can be reserved by
// other endpoints.
func (s *PortManager) ReleasePort(network tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, port uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.allocatedPorts, portDescriptor{network, transport, port})
}
