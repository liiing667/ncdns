//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"github.com/hlandau/xlog"
	"github.com/namecoin/ncdns/ncdomain"
)

var log, Log = xlog.New("ncdns.tlshook")

// LookupResult describes the outcome of a base-name lookup so that the PKI
// cache can distinguish positive results, explicit "no such name" results and
// transient failures.
type LookupResult struct {
	// StreamIsolationID is the tenant context the lookup ran in.  Cache
	// entries are never shared across distinct streams.
	StreamIsolationID string

	// ClaimVersion is the immutable identity (txid:vout) of the namecoin
	// claim returned by the lookup.  Empty for negative results or for old
	// Namecoin Core releases which omit the transaction fields.
	ClaimVersion string

	// Value is the parsed name value for a successful lookup.  Nil for a
	// negative result.
	Value *ncdomain.Value

	// NoSuchName is true when the lookup explicitly established that the
	// name does not exist (NXDOMAIN).
	NoSuchName bool
}

// DomainBaseValueHook feeds the outcome of every base-name lookup into the
// PKI cache.  Transient lookup failures are ignored: nothing is cached, so a
// later successful lookup can populate the cache and a temporary RPC outage
// can never poison the cache with a long-lived negative entry.
func DomainBaseValueHook(qname string, result LookupResult) (err error) {

	log.Debug("Intercepted a lookup result for ", qname)

	switch {
	case result.NoSuchName:
		// The name disappeared (for example because it was revoked or
		// expired), so drop every previously cached claim for it in
		// every stream, then remember the negative result briefly.
		invalidateTrustInfoAllStreams(qname)
		cacheNegativeTrustInfo(qname, result.StreamIsolationID)
	case result.Value != nil:
		// A fresh claim supersedes older state in the same stream
		// (including a negative entry).  Other tenants' entries are not
		// touched here; the read path separately refuses to mix entries
		// from different claim versions.
		invalidateTrustInfo(qname, result.StreamIsolationID)
		cacheTrustInfo(qname, result.StreamIsolationID, result.ClaimVersion, result.Value)
	default:
		// Transient failure: do not cache anything.
	}

	err = nil

	return

}
