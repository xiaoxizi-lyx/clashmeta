package sniffer

import "github.com/metacubex/mihomo/log"

// Fork-only feature: sniffer.force-override-domain.
//
// The logic is kept in this file, away from dispatcher.go, so that rebasing
// onto upstream rarely conflicts. dispatcher.go only carries the two field
// declarations, their hand-over in NewDispatcher and the two replaceDomain
// call sites that consult forceOverrideDest.

// forceOverrideDest reports whether the sniffed host matches
// force-override-domain, which forces the destination to be overridden
// regardless of any override-destination setting. Callers only reach it for
// hosts that already passed skip-domain, so skip-domain keeps precedence.
func (sd *Dispatcher) forceOverrideDest(host string) bool {
	for _, matcher := range sd.forceOverrideDomain {
		if matcher.MatchDomain(host) {
			log.Debugln("[Sniffer] Force override destination for domain [%s]", host)
			return true
		}
	}
	return false
}
