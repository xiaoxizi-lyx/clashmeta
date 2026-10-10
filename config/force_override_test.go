package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Fork-only: sniffer.force-override-domain must survive the trip from the
// config file to the sniffer config.
func TestSnifferForceOverrideDomain(t *testing.T) {
	rawCfg, err := UnmarshalRawConfig([]byte("sniffer:\n  force-override-domain:\n    - +.example.com\n"))
	assert.NoError(t, err)
	assert.Equal(t, []string{"+.example.com"}, rawCfg.Sniffer.ForceOverrideDomain)

	snifferConfig, err := parseSniffer(rawCfg.Sniffer, nil)
	assert.NoError(t, err)
	match := func(domain string) bool {
		for _, matcher := range snifferConfig.ForceOverrideDomain {
			if matcher.MatchDomain(domain) {
				return true
			}
		}
		return false
	}
	assert.True(t, match("www.example.com"))
	assert.False(t, match("www.example.org"))

	rawCfg, err = UnmarshalRawConfig(nil)
	assert.NoError(t, err)
	snifferConfig, err = parseSniffer(rawCfg.Sniffer, nil)
	assert.NoError(t, err)
	assert.Empty(t, snifferConfig.ForceOverrideDomain)
}
