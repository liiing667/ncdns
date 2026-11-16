//go:build no_namecoin_tls
// +build no_namecoin_tls

package tlshook

import (
	"github.com/namecoin/ncdns/ncdomain"
)

// LookupResult mirrors the TLS-enabled build's LookupResult so that backend
// code does not need build-tag-specific call sites.
type LookupResult struct {
	StreamIsolationID string
	ClaimVersion      string
	Value             *ncdomain.Value
	NoSuchName        bool
}

// DomainBaseValueHook is a no-op in builds without TLS support.
func DomainBaseValueHook(qname string, result LookupResult) error {
	return nil
}
