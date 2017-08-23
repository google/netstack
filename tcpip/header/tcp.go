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

const (
	// MaxWndScale is maximum allowed window scaling, as described in
	// RFC 1323, section 2.3, page 11.
	MaxWndScale = 14
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
	TCPOptionTS  = 8
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

// TCPSynOptions is used to return the parsed TCP Options in a syn
// segment.
type TCPSynOptions struct {
	// MSS is the maximum segment size provided by the peer in the SYN.
	MSS uint16

	// WS is the window scale option provided by the peer in the SYN.
	//
	// Set to -1 if no window scale option was provided.
	WS int

	// TS is true if the timestamp option was provided in the syn/syn-ack.
	TS bool

	// TSVal is the value of the TSVal field in the timestamp option.
	TSVal uint32

	// TSEcr is the value of the TSEcr field in the timestamp option.
	TSEcr uint32
}

// TCPOptions are used to parse and cache the TCP segment options for a non
// syn/syn-ack segment.
type TCPOptions struct {
	// TS is true if the TimeStamp option is enabled.
	TS bool

	// TSVal is the value in the TSVal field of the segment.
	TSVal uint32

	// TSEcr is the value in the TSEcr field of the segment.
	TSEcr uint32
}

// TCP represents a TCP header stored in a byte array.
type TCP []byte

const (
	// TCPMinimumSize is the minimum size of a valid TCP packet.
	TCPMinimumSize = 20

	// TCPProtocolNumber is TCP's transport protocol number.
	TCPProtocolNumber tcpip.TransportProtocolNumber = 6

	// TCPTimeStampOptionSize is the size of an encoded TCP timestamp
	// option.
	//
	// NOTE: The actual option is 10 bytes but we always include 2
	// NOP options to quad align the timestamp option and hence it's
	// 12 and not 10.
	TCPTimeStampOptionSize = 12
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

// Options returns a slice that holds the unparsed TCP options in the segment.
func (b TCP) Options() []byte {
	return b[TCPMinimumSize:b.DataOffset()]
}

// ParsedOptions returns a TCPOptions structure which parses and caches the TCP
// option values in the TCP segment. NOTE: Invoking this function repeatedly is
// expensive as it reparses the options on each invocation.
func (b TCP) ParsedOptions() TCPOptions {
	return ParseTCPOptions(b.Options())
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

// ParseSynOptions parses the options received in a SYN segment and returns the
// relevant ones. opts should point to the option part of the TCP Header.
func ParseSynOptions(opts []byte, isAck bool) TCPSynOptions {
	limit := len(opts)

	synOpts := TCPSynOptions{
		// Per RFC 1122, page 85: "If an MSS option is not received at
		// connection setup, TCP MUST assume a default send MSS of 536."
		MSS: 536,
		// If no window scale option is specified, WS in options is
		// returned as -1; this is because the absence of the option
		// indicates that the we cannot use window scaling on the
		// receive end either.
		WS: -1,
	}

	for i := 0; i < limit; {
		switch opts[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionMSS:
			if i+4 > limit || opts[i+1] != 4 {
				return synOpts
			}
			mss := uint16(opts[i+2])<<8 | uint16(opts[i+3])
			if mss == 0 {
				return synOpts
			}
			synOpts.MSS = mss
			i += 4

		case TCPOptionWS:
			if i+3 > limit || opts[i+1] != 3 {
				return synOpts
			}
			ws := int(opts[i+2])
			if ws > MaxWndScale {
				ws = MaxWndScale
			}
			synOpts.WS = ws
			i += 3

		case TCPOptionTS:
			if i+10 > limit || opts[i+1] != 10 {
				return synOpts
			}
			synOpts.TSVal = binary.BigEndian.Uint32(opts[i+2:])
			if isAck {
				// If the segment is a SYN-ACK then store the Timestamp Echo Reply
				// in the segment.
				synOpts.TSEcr = binary.BigEndian.Uint32(opts[i+6:])
			}
			synOpts.TS = true
			i += 10

		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return synOpts
			}
			l := int(opts[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return synOpts
			}
			i += l
		}
	}

	return synOpts
}

// ParseTCPOptions extracts and stores all known options in the provided byte
// slice in a TCPOptions structure.
func ParseTCPOptions(b []byte) TCPOptions {
	opts := TCPOptions{}
	limit := len(b)
	for i := 0; i < limit; {
		switch b[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionTS:
			if i+10 > limit || b[i+1] != 10 {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return opts
			}
			i += l
		}
	}
	return opts
}

// EncodeTSOption builds and returns an array containing a TCP
// timestamp option with the TSVal/TSEcr fields set to the value of
// tsVal/tsEcr. This function also pads the option with two
// TCPOptionNOP to make sure it is correctly quad aligned.
func EncodeTSOption(tsVal, tsEcr uint32) (b [12]byte) {
	b[0] = TCPOptionTS
	b[1] = 10
	binary.BigEndian.PutUint32(b[2:], tsVal)
	binary.BigEndian.PutUint32(b[6:], tsEcr)
	b[10] = TCPOptionNOP
	b[11] = TCPOptionNOP
	return b
}
