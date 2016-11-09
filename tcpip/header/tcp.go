// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

import (
	"encoding/binary"

	"github.com/google/netstack/tcpip"
)

const (
	srcPort     = 0
	dstPort     = 2
	seqNum      = 4
	ackNum      = 8
	dataOffset  = 12
	tcpFlags    = 13
	winSize     = 14
	tcpChecksum = 16
	urgentPtr   = 18
)

// Flags that may be set in a TCP segment.
const (
	TCPFlagFin = 1 << iota
	TCPFlagSyn
	TCPFlagRst
	TCPFlagPsh
	TCPFlagAck
	TCPFlagUrg
)

// Options that may be present in a TCP segment.
const (
	TCPOptionEOL = 0
	TCPOptionNOP = 1
	TCPOptionMSS = 2
	TCPOptionWS  = 3
)

// TCPFields contains the fields of a TCP packet. It is used to describe the
// fields of a packet that needs to be encoded.
type TCPFields struct {
	// SrcPort is the "source port" field of a TCP packet.
	SrcPort uint16

	// DstPort is the "destination port" field of a TCP packet.
	DstPort uint16

	// SeqNum is the "sequence number" field of a TCP packet.
	SeqNum uint32

	// AckNum is the "acknowledgement number" field of a TCP packet.
	AckNum uint32

	// DataOffset is the "data offset" field of a TCP packet.
	DataOffset uint8

	// Flags is the "flags" field of a TCP packet.
	Flags uint8

	// WindowSize is the "window size" field of a TCP packet.
	WindowSize uint16

	// Checksum is the "checksum" field of a TCP packet.
	Checksum uint16

	// UrgentPointer is the "urgent pointer" field of a TCP packet.
	UrgentPointer uint16
}

// TCP represents a TCP header stored in a byte array.
type TCP []byte

const (
	// TCPMinimumSize is the minimum size of a valid TCP packet.
	TCPMinimumSize = 20

	// TCPProtocolNumber is TCP's transport protocol number.
	TCPProtocolNumber tcpip.TransportProtocolNumber = 6
)

// SourcePort returns the "source port" field of the tcp header.
func (b TCP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[srcPort:])
}

// DestinationPort returns the "destination port" field of the tcp header.
func (b TCP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[dstPort:])
}

// SequenceNumber returns the "sequence number" field of the tcp header.
func (b TCP) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(b[seqNum:])
}

// AckNumber returns the "ack number" field of the tcp header.
func (b TCP) AckNumber() uint32 {
	return binary.BigEndian.Uint32(b[ackNum:])
}

// DataOffset returns the "data offset" field of the tcp header.
func (b TCP) DataOffset() uint8 {
	return (b[dataOffset] >> 4) * 4
}

// Payload returns the data in the tcp packet.
func (b TCP) Payload() []byte {
	return b[b.DataOffset():]
}

// Flags returns the flags field of the tcp header.
func (b TCP) Flags() uint8 {
	return b[tcpFlags]
}

// WindowSize returns the "window size" field of the tcp header.
func (b TCP) WindowSize() uint16 {
	return binary.BigEndian.Uint16(b[winSize:])
}

// Checksum returns the "checksum" field of the tcp header.
func (b TCP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[tcpChecksum:])
}

// SetSourcePort sets the "source port" field of the tcp header.
func (b TCP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[srcPort:], port)
}

// SetDestinationPort sets the "destination port" field of the tcp header.
func (b TCP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[dstPort:], port)
}

// SetChecksum sets the checksum field of the tcp header.
func (b TCP) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[tcpChecksum:], checksum)
}

// CalculateChecksum calculates the checksum of the tcp segment given
// the totalLen and partialChecksum(descriptions below)
// totalLen is the total length of the segment
// partialChecksum is the checksum of the network-layer pseudo-header
// (excluding the total length) and the checksum of the segment data.
func (b TCP) CalculateChecksum(partialChecksum uint16, totalLen uint16) uint16 {
	// Add the length portion of the checksum to the pseudo-checksum.
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	checksum := Checksum(tmp, partialChecksum)

	// Calculate the rest of the checksum.
	return Checksum(b[:b.DataOffset()], checksum)
}

func (b TCP) encodeSubset(seq, ack uint32, flags uint8, rcvwnd uint16) {
	binary.BigEndian.PutUint32(b[seqNum:], seq)
	binary.BigEndian.PutUint32(b[ackNum:], ack)
	b[tcpFlags] = flags
	binary.BigEndian.PutUint16(b[winSize:], rcvwnd)
}

// Encode encodes all the fields of the tcp header.
func (b TCP) Encode(t *TCPFields) {
	b.encodeSubset(t.SeqNum, t.AckNum, t.Flags, t.WindowSize)
	binary.BigEndian.PutUint16(b[srcPort:], t.SrcPort)
	binary.BigEndian.PutUint16(b[dstPort:], t.DstPort)
	b[dataOffset] = (t.DataOffset / 4) << 4
	binary.BigEndian.PutUint16(b[tcpChecksum:], t.Checksum)
	binary.BigEndian.PutUint16(b[urgentPtr:], t.UrgentPointer)
}

// EncodePartial updates a subset of the fields of the tcp header. It is useful
// in cases when similar segments are produced.
func (b TCP) EncodePartial(partialChecksum, length uint16, seqnum, acknum uint32, flags byte, rcvwnd uint16) {
	// Add the total length and "flags" field contributions to the checksum.
	// We don't use the flags field directly from the header because it's a
	// one-byte field with an odd offset, so it would be accounted for
	// incorrectly by the Checksum routine.
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp, length)
	binary.BigEndian.PutUint16(tmp[2:], uint16(flags))
	checksum := Checksum(tmp, partialChecksum)

	// Encode the passed-in fields.
	b.encodeSubset(seqnum, acknum, flags, rcvwnd)

	// Add the contributions of the passed-in fields to the checksum.
	checksum = Checksum(b[seqNum:seqNum+8], checksum)
	checksum = Checksum(b[winSize:winSize+2], checksum)

	// Encode the checksum.
	b.SetChecksum(^checksum)
}
