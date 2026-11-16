//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/namecoin/ncdns/ncdomain"
	"github.com/namecoin/ncdns/util"
)

const (
	// positiveCacheTTL is how long a successfully resolved claim remains
	// usable by the TLS hook.  It is sized to outlive the Unbound cache so
	// that a TLS connection induced by a recent DNS query can always find
	// the matching trust information.
	positiveCacheTTL = time.Hour

	// negativeCacheTTL is how long an explicit "no such name" result is
	// remembered.  It is deliberately much shorter than the positive TTL so
	// that transient name creation is picked up promptly while an attacker
	// still cannot force repeated RPC traffic by inducing repeated misses.
	negativeCacheTTL = 60 * time.Second
)

// pkiCacheKey identifies a cache entry.  Including the stream isolation ID
// guarantees that a query made in one tenant context can never be served from
// data fetched in another tenant's context.  Including the claim version means
// that stale entries for an older namecoin transaction are never returned once
// the name has been updated.
type pkiCacheKey struct {
	eTLD1        string
	streamID     string
	claimVersion string
}

type cachedTrustInfo struct {
	expiration time.Time

	// ncv is the parsed value for the eTLD+1 domain.  It is nil in a
	// negative cache entry.
	ncv *ncdomain.Value

	// negative records an explicit "no such name" lookup rather than a
	// successful one.  A negative entry must never be mistaken for a
	// successful lookup.
	negative bool
}

var (
	pkiCache      map[string]cachedTrustInfo
	pkiCacheMutex sync.RWMutex
)

func init() {
	pkiCache = map[string]cachedTrustInfo{}
}

func getETLD1(qname string) string {
	_, basename, rootname, err := util.SplitDomainByFloatingAnchor(qname, "bit")
	if err != nil {
		// The only possible error is NotInZone, and that can't occur here.
		panic(err)
	}

	return basename + "." + rootname
}

func makePKICacheKey(qname, streamIsolationID, claimVersion string) pkiCacheKey {
	return pkiCacheKey{
		eTLD1:        getETLD1(qname),
		streamID:     streamIsolationID,
		claimVersion: claimVersion,
	}
}

func cacheKeyString(key pkiCacheKey) string {
	return key.eTLD1 + "\x00" + key.streamID + "\x00" + key.claimVersion
}

// unmarshal parses a key produced by cacheKeyString.  It exists so the
// read-side consensus check can inspect the claim version without keeping a
// parallel index.
func (key *pkiCacheKey) unmarshal(keyString string) error {
	parts := strings.SplitN(keyString, "\x00", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed PKI cache key: %q", keyString)
	}

	key.eTLD1 = parts[0]
	key.streamID = parts[1]
	key.claimVersion = parts[2]

	return nil
}

// lookupCachedTrustInfo returns the cached entry for the exact stream and
// claim version.  Expired entries are treated as misses and removed.  A nil
// result means nothing is cached; callers must use the returned
// cachedTrustInfo to distinguish negative entries from positive ones.
func lookupCachedTrustInfo(key pkiCacheKey) *cachedTrustInfo {
	keyString := cacheKeyString(key)

	pkiCacheMutex.RLock()
	trustInfo, ok := pkiCache[keyString]
	pkiCacheMutex.RUnlock()

	if !ok {
		return nil
	}

	if time.Now().After(trustInfo.expiration) {
		pkiCacheMutex.Lock()
		// Re-check under the write lock in case another goroutine
		// already replaced or removed the entry.
		if current, ok := pkiCache[keyString]; ok && time.Now().After(current.expiration) {
			delete(pkiCache, keyString)
		}
		pkiCacheMutex.Unlock()

		return nil
	}

	return &trustInfo
}

func storeCachedTrustInfo(key pkiCacheKey, trustInfo cachedTrustInfo) {
	pkiCacheMutex.Lock()
	defer pkiCacheMutex.Unlock()

	pkiCache[cacheKeyString(key)] = trustInfo
}

func cacheTrustInfo(qname, streamIsolationID, claimVersion string, ncv *ncdomain.Value) {
	key := makePKICacheKey(qname, streamIsolationID, claimVersion)
	trustInfo := cachedTrustInfo{
		expiration: time.Now().Add(positiveCacheTTL),
		ncv:        ncv,
	}

	storeCachedTrustInfo(key, trustInfo)
}

// cacheNegativeTrustInfo records an explicit "no such name" result so that the
// absence of a name is a deliberate, short-lived state rather than an
// unlimited cache miss.
func cacheNegativeTrustInfo(qname, streamIsolationID string) {
	key := makePKICacheKey(qname, streamIsolationID, "")
	trustInfo := cachedTrustInfo{
		expiration: time.Now().Add(negativeCacheTTL),
		negative:   true,
	}

	storeCachedTrustInfo(key, trustInfo)
}

// invalidateTrustInfo removes every cached entry for the eTLD+1 domain of
// qname within the given stream isolation context, regardless of claim
// version.  It is used when a stream observes a new claim or an explicit
// "no such name" result, so that the same tenant never keeps using a stale
// entry after the chain state changed.  Other streams are intentionally left
// untouched: evicting another tenant's entries would mix contexts through
// cache side effects.
func invalidateTrustInfo(qname, streamIsolationID string) {
	eTLD1 := getETLD1(qname)
	prefix := eTLD1 + "\x00" + streamIsolationID + "\x00"

	pkiCacheMutex.Lock()
	defer pkiCacheMutex.Unlock()

	for keyString := range pkiCache {
		if strings.HasPrefix(keyString, prefix) {
			delete(pkiCache, keyString)
		}
	}
}

// invalidateTrustInfoAllStreams removes every cached entry, in every stream
// and for every claim version, for the eTLD+1 domain of qname.  It is used
// when the chain itself establishes that a name no longer exists: continuing
// to serve a stale positive claim to any tenant after the name was revoked or
// expired would be a security failure.
func invalidateTrustInfoAllStreams(qname string) {
	eTLD1 := getETLD1(qname)
	prefix := eTLD1 + "\x00"

	pkiCacheMutex.Lock()
	defer pkiCacheMutex.Unlock()

	for keyString := range pkiCache {
		if strings.HasPrefix(keyString, prefix) {
			delete(pkiCache, keyString)
		}
	}
}

// getCachedTrustInfo returns the cached value for the exact stream and claim
// version.  A miss, an expired entry, or a negative entry yields nil.
func getCachedTrustInfo(qname, streamIsolationID, claimVersion string) *ncdomain.Value {
	trustInfo := lookupCachedTrustInfo(makePKICacheKey(qname, streamIsolationID, claimVersion))
	if trustInfo == nil || trustInfo.negative {
		return nil
	}

	return trustInfo.ncv
}

// lookupConsistentTrustInfo returns the positive trust information for an
// eTLD+1 domain without knowing the querying stream, which is the situation
// the embedded TLS hook is in.  It only succeeds when every non-expired
// positive entry cached for the domain (across all streams) describes the
// same claim version and the same value; disagreement means the name changed
// or tenant contexts diverged, in which case no result is returned rather
// than guessing which tenant's data applies.  Negative entries never produce
// a successful lookup.
func lookupConsistentTrustInfo(qname string) (*ncdomain.Value, error) {
	eTLD1 := getETLD1(qname)
	prefix := eTLD1 + "\x00"

	now := time.Now()

	pkiCacheMutex.RLock()
	defer pkiCacheMutex.RUnlock()

	var consensus *ncdomain.Value
	var consensusClaimVersion string

	for keyString, trustInfo := range pkiCache {
		if !strings.HasPrefix(keyString, prefix) {
			continue
		}

		if now.After(trustInfo.expiration) || trustInfo.negative {
			continue
		}

		var key pkiCacheKey
		if err := key.unmarshal(keyString); err != nil {
			return nil, err
		}

		if consensus == nil {
			consensus = trustInfo.ncv
			consensusClaimVersion = key.claimVersion
			continue
		}

		if key.claimVersion != consensusClaimVersion {
			return nil, fmt.Errorf("conflicting PKI cache claim versions for %s across stream isolation contexts; refusing to serve a superseded namecoin claim", eTLD1)
		}

		if !reflect.DeepEqual(consensus, trustInfo.ncv) {
			return nil, fmt.Errorf("conflicting PKI cache entries for %s across stream isolation contexts; refusing to select a tenant context", eTLD1)
		}
	}

	if consensus == nil {
		// The domain isn't positively cached, so return an error rather
		// than an empty record set.  Generally this isn't expected to
		// happen, but a malicious TLS peer can induce it.
		return nil, fmt.Errorf("eTLD+1 not in PKI cache; this is either a bug or a malicious TLS peer")
	}

	return consensus, nil
}

// Returns all TLSA records that existed for the given qname at the time of the
// most recent DNS query for that qname. No refreshing is done; no network
// traffic is generated. Resistant to FPI leaks.  Internally entries are keyed
// by stream isolation ID and claim version; this read path only succeeds when
// all cached contexts agree, so a query can never silently reuse another
// tenant's divergent data.
func GetTLSARecords(qname string) ([]*dns.TLSA, error) {
	trustInfo, err := lookupConsistentTrustInfo(qname)
	if err != nil {
		return nil, err
	}

	wildcardQname := "*." + qname

	wildcardSubname, _, _, err := util.SplitDomainByFloatingAnchor(wildcardQname, "bit")
	if err != nil {
		return nil, err
	}

	subTrustInfo, err := trustInfo.FindSubdomainByName(wildcardSubname)
	if err != nil {
		return nil, err
	}

	return subTrustInfo.TLSA, nil
}

// Returns all Revocation records that existed for the given qname at the time of the
// most recent DNS query for that qname. No refreshing is done; no network
// traffic is generated. Resistant to FPI leaks.  As with GetTLSARecords, the
// stream- and version-scoped entries must all agree before data is returned.
func GetRevocationRecords(qname string) ([]*ncdomain.Revocation, error) {
	trustInfo, err := lookupConsistentTrustInfo(qname)
	if err != nil {
		return nil, err
	}

	subname, _, _, err := util.SplitDomainByFloatingAnchor(qname, "bit")
	if err != nil {
		return nil, err
	}

	subTrustInfo, err := trustInfo.FindSubdomainByName(subname)
	if err != nil {
		return nil, err
	}

	return subTrustInfo.Revocations, nil
}

// TODO: search toward base domain too
func IsRevoked(qname string, issuerHash, serial []byte) (bool, error) {
	revocations, err := GetRevocationRecords(qname)
	if err != nil {
		return false, err
	}

	issuerHashHex := hex.EncodeToString(issuerHash)
	serialHex := hex.EncodeToString(serial)
	for _, rev := range revocations {
		if strings.HasPrefix(issuerHashHex, rev.IssuerHashPrefixHex) && strings.HasPrefix(serialHex, rev.SerialPrefixHex) {
			return true, nil
		}
	}

	return false, nil
}
