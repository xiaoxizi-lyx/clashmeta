package sniffer

// Tests for the fork-only sniffer.force-override-domain feature. They pin the
// behavior of the two hook sites in dispatcher.go, so a rebase that applies
// cleanly but silently drops or bypasses a hook is caught before release.

import (
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

// forceOverrideSniffer sniffs a fixed host out of any data on any port.
type forceOverrideSniffer struct {
	network C.NetWork
	host    string
}

func (s forceOverrideSniffer) SupportNetwork() C.NetWork        { return s.network }
func (s forceOverrideSniffer) SniffData([]byte) (string, error) { return s.host, nil }
func (forceOverrideSniffer) Protocol() string                   { return "force-override-test" }
func (forceOverrideSniffer) SupportPort(uint16) bool            { return true }

type forceOverrideMatcher string

func (m forceOverrideMatcher) MatchDomain(domain string) bool { return domain == string(m) }

// forceOverridePacket implements the only two methods UDPSniff reads.
type forceOverridePacket struct {
	C.PacketAdapter
	metadata *C.Metadata
}

func (p forceOverridePacket) Metadata() *C.Metadata { return p.metadata }
func (forceOverridePacket) Data() []byte            { return []byte{0} }

func TestForceOverrideDomain(t *testing.T) {
	const sniffed = "forced.example.com"

	tests := []struct {
		name         string
		overrideDest bool
		skip         []C.DomainMatcher
		force        []C.DomainMatcher
		wantSniffed  bool
		wantOverride bool
	}{
		{
			name:         "overrides the destination although override-destination is off",
			force:        []C.DomainMatcher{forceOverrideMatcher(sniffed)},
			wantSniffed:  true,
			wantOverride: true,
		},
		{
			name:        "leaves unlisted domains to override-destination",
			force:       []C.DomainMatcher{forceOverrideMatcher("other.example.com")},
			wantSniffed: true,
		},
		{
			name:         "keeps override-destination working for unlisted domains",
			overrideDest: true,
			wantSniffed:  true,
			wantOverride: true,
		},
		{
			name:  "skip-domain takes precedence",
			skip:  []C.DomainMatcher{forceOverrideMatcher(sniffed)},
			force: []C.DomainMatcher{forceOverrideMatcher(sniffed)},
		},
	}

	for _, test := range tests {
		for _, network := range []C.NetWork{C.TCP, C.UDP} {
			t.Run(network.String()+" "+test.name, func(t *testing.T) {
				sd, err := NewDispatcher(&Config{
					Enable:              true,
					ParsePureIp:         true,
					SkipDomain:          test.skip,
					ForceOverrideDomain: test.force,
				})
				assert.NoError(t, err)
				sd.sniffers = []configuredSniffer{{
					Sniffer: forceOverrideSniffer{network: network, host: sniffed},
					config:  SnifferConfig{OverrideDest: test.overrideDest},
				}}
				dstIP := netip.MustParseAddr("192.0.2.1")
				metadata := &C.Metadata{NetWork: network, DstIP: dstIP, DstPort: 443}

				if network == C.TCP {
					client, server := net.Pipe()
					t.Cleanup(func() {
						_ = client.Close()
						_ = server.Close()
					})
					go func() { _, _ = client.Write([]byte{0}) }()
					assert.Equal(t, test.wantSniffed, sd.TCPSniff(N.NewBufferedConn(server), metadata))
				} else {
					sd.UDPSniff(forceOverridePacket{metadata: metadata}, nil)
				}

				if test.wantSniffed {
					assert.Equal(t, sniffed, metadata.SniffHost)
				} else {
					assert.Empty(t, metadata.SniffHost)
				}
				if test.wantOverride {
					assert.Equal(t, sniffed, metadata.Host)
					assert.False(t, metadata.DstIP.IsValid())
				} else {
					assert.Empty(t, metadata.Host)
					assert.Equal(t, dstIP, metadata.DstIP)
				}
			})
		}
	}
}
