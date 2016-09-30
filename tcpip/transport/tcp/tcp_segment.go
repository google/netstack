package tcp

import (
	"sync/atomic"

	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/seqnum"
	"github.com/google/netstack/tcpip/stack"
)

// Flags that may be set in a TCP segment.
const (
	flagFin = 1 << iota
	flagSyn
	flagRst
	flagPsh
	flagAck
	flagUrg
)

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
type segment struct {
	segmentEntry
	refCnt int32
	id     stack.TransportEndpointID
	route  stack.Route
	data   buffer.View

	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          uint8
	window         seqnum.Size
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	return &segment{
		refCnt: 1,
		data:   v,
		id:     id,
		route:  r.Clone(),
	}
}

func (s *segment) clone() *segment {
	return &segment{
		refCnt:         1,
		data:           s.data,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		route:          s.route.Clone(),
	}
}

func (s *segment) flagIsSet(flag uint8) bool {
	return (s.flags & flag) != 0
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		s.route.Release()
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

// logicalLen is the segment length in the sequence number space. It's defined
// as the data length plus one for each of the SYN and FIN bits set.
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(len(s.data))
	if s.flagIsSet(flagSyn) {
		l++
	}
	if s.flagIsSet(flagFin) {
		l++
	}
	return l
}

// parse populates the sequence & ack numbers, flags, and window fields of the
// segment from the TCP header stored in the data. It then updates the view to
// skip the data. Returns boolean indicating if the parsing was successful.
func (s *segment) parse() bool {
	h := header.TCP(s.data)

	// h is the header followed by the payload. We check that the offset to
	// the data respects the following constraints:
	// 1. That it's at least the minimum header size; if we don't do this
	//    then part of the header would be delivered to user.
	// 2. That the header fits within the buffer; if we don't do this, we
	//    would panic when we tried to access data beyond the buffer.
	//
	// N.B. The segment has already been validated as having at least the
	//      minimum TCP size before reaching here, so it's safe to read the
	//      fields.
	if offset := int(h.DataOffset()); offset < header.TCPMinimumSize || offset > len(h) {
		return false
	}

	s.data.TrimFront(int(h.DataOffset()))

	s.sequenceNumber = seqnum.Value(h.SequenceNumber())
	s.ackNumber = seqnum.Value(h.AckNumber())
	s.flags = h.Flags()
	s.window = seqnum.Size(h.WindowSize())

	return true
}
