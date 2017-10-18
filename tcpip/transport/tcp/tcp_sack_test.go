package tcp_test

import (
	"fmt"
	"testing"

	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/tcpip/transport/tcp/testing/context"
)

// createConnectWithSACKPermittedOption creates and connects c.ep with
// the SACKPermitted option enabled if the stack in the context has the
// SACK support enabled.
func createConnectedWithSACKPermittedOption(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled()})
}

func setStackSACKPermitted(t *testing.T, c *context.Context, enable bool) {
	t.Helper()
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true)); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(tcp.ProtocolNumber, SACKEnabled(true) = %v", err)
	}
}

// TestSackPermittedConnect establishes a connection with the SACK
// option enabled.
//
// TODO: Update this to verify receipt of SACKs for out of order
// delivery once the code to send SACKs is implemented. Also test that SACKs
// sent to the stack are correctly handled and retransmissions of SACKed
// segments is done only when an RTO expires.
func TestSackPermittedConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)
			createConnectedWithSACKPermittedOption(c)
		})
	}
}

// TestSackDisabledConnect establishes a connection with the SACK option
// disabled and verifies that no SACKs are sent for out of order segments.
func TestSackDisabledConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)

			rep := c.CreateConnectedWithOptions(header.TCPSynOptions{})

			data := []byte{1, 2, 3}

			rep.SendPacket(data, nil)
			savedSeqNum := rep.NextSeqNum
			rep.VerifyACKNoSACK()

			// Make an out of order packet and send it.
			rep.NextSeqNum += 3
			rep.SendPacket(data, nil)

			// The ACK should contain the older sequence number and
			// no SACK blocks.
			rep.NextSeqNum = savedSeqNum
			rep.VerifyACKNoSACK()

			// Send the missing segment.
			rep.SendPacket(data, nil)
			// The ACK should contain the cumulative ACK for all 9
			// bytes sent and no SACK blocks.
			rep.NextSeqNum += 3
			// Check that no SACK block is returned in the ACK.
			rep.VerifyACKNoSACK()
		})
	}
}

// TestSackPermittedAccept accepts and establishes a connection with the
// SACKPermitted option enabled if the connection request specifies the
// SACKPermitted option. In case of SYN cookies SACK should be disabled as we
// don't encode the SACK information in the cookie.
//
// TODO: Update this to verify receipt of SACKs for out of order
// delivery once the code to send SACKs is implemented. Also test that SACKs
// sent to the stack are correctly handled and retransmissions of SACKed
// segments is done only when an RTO expires.
func TestSackPermittedAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		sackPermitted bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, false, -1, 0xffff},
		{false, true, 2, 0xd000},
	}
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			if tc.cookieEnabled {
				tcp.SynRcvdCountThreshold = 0
			} else {
				tcp.SynRcvdCountThreshold = savedSynCountThreshold
			}
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, defaultMTU)
					defer c.Cleanup()
					setStackSACKPermitted(t, c, sackEnabled)

					c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS, SACKPermitted: tc.sackPermitted})
				})
			}
		})
	}
}

// TestSackDisabledAccept accepts and establishes a connection with the
// SACKPermitted option disabled and verifies that no SACKs are sent for out of
// order packets.
func TestSackDisabledAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, -1, 0xffff},
		{false, 2, 0xd000},
	}
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			if tc.cookieEnabled {
				tcp.SynRcvdCountThreshold = 0
			} else {
				tcp.SynRcvdCountThreshold = savedSynCountThreshold
			}
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test: sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, defaultMTU)
					defer c.Cleanup()
					setStackSACKPermitted(t, c, sackEnabled)

					rep := c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS})

					//  Now verify no SACK blocks are
					//  received when sack is disabled.
					data := []byte{1, 2, 3}
					rep.SendPacket(data, nil)
					rep.VerifyACKNoSACK()
					savedSeqNum := rep.NextSeqNum

					// Make an out of order packet and send
					// it.
					rep.NextSeqNum += 3
					rep.SendPacket(data, nil)

					// The ACK should contain the older
					// sequence number and no SACK blocks.
					rep.NextSeqNum = savedSeqNum
					rep.VerifyACKNoSACK()

					// Send the missing segment.
					rep.SendPacket(data, nil)
					// The ACK should contain the cumulative
					// ACK for all 9 bytes sent and no SACK
					// blocks.
					rep.NextSeqNum += 3
					// Check that no SACK block is returned
					// in the ACK.
					rep.VerifyACKNoSACK()
				})
			}
		})
	}
}
