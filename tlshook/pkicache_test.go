//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package tlshook

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/namecoin/ncdns/ncdomain"
)

const testQname = "example.bit."

func resetPKICache() {
	pkiCacheMutex.Lock()
	defer pkiCacheMutex.Unlock()

	pkiCache = map[string]cachedTrustInfo{}
}

func valueWithTLSA(usage, selector, matchingType uint8, certificate []byte) *ncdomain.Value {
	tlsa := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: testQname, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 600},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Certificate:  string(certificate),
	}

	return &ncdomain.Value{
		IsTopLevel: true,
		TLSA:       []*dns.TLSA{tlsa},
		// GetTLSARecords resolves via the wildcard subname.
		Map: map[string]*ncdomain.Value{
			"*": {TLSA: []*dns.TLSA{tlsa}},
		},
	}
}

func TestPositiveCacheIsStreamAndVersionScoped(t *testing.T) {
	resetPKICache()

	ncv := valueWithTLSA(3, 1, 1, []byte{0xde, 0xad})

	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx1:0",
		Value:             ncv,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	// Exact stream and claim version match hits.
	if got := getCachedTrustInfo(testQname, "stream-a", "tx1:0"); got != ncv {
		t.Fatal("exact key lookup missed the cached value")
	}

	// A different tenant stream must not see stream-a's entry.
	if got := getCachedTrustInfo(testQname, "stream-b", "tx1:0"); got != nil {
		t.Fatal("cache entry leaked across stream isolation contexts")
	}

	// The same stream must not reuse a superseded claim version.
	if got := getCachedTrustInfo(testQname, "stream-a", "tx2:0"); got != nil {
		t.Fatal("superseded claim version was returned from the cache")
	}

	// The read-only TLS API returns the data while all cached contexts agree.
	tlsa, err := GetTLSARecords(testQname)
	if err != nil {
		t.Fatalf("GetTLSARecords failed: %v", err)
	}

	if len(tlsa) != 1 || tlsa[0].Certificate != string([]byte{0xde, 0xad}) {
		t.Fatalf("unexpected TLSA records: %+v", tlsa)
	}
}

func TestConflictingStreamsAreNotMixed(t *testing.T) {
	resetPKICache()

	ncvA := valueWithTLSA(3, 1, 1, []byte{0xaa})
	ncvB := valueWithTLSA(3, 1, 1, []byte{0xbb})

	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx1:0",
		Value:             ncvA,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-b",
		ClaimVersion:      "tx1:0",
		Value:             ncvB,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	// Direct stream-scoped lookups still return each tenant's own data.
	if got := getCachedTrustInfo(testQname, "stream-a", "tx1:0"); got != ncvA {
		t.Fatal("stream-a lost its own cache entry")
	}

	if got := getCachedTrustInfo(testQname, "stream-b", "tx1:0"); got != ncvB {
		t.Fatal("stream-b lost its own cache entry")
	}

	// The domain-agnostic TLS API must refuse to pick a tenant context when
	// the cached values disagree.
	if _, err := GetTLSARecords(testQname); err == nil {
		t.Fatal("expected a conflict error, got TLSA records from an arbitrary tenant")
	}

	if _, err := GetRevocationRecords(testQname); err == nil {
		t.Fatal("expected a conflict error from the revocation path too")
	}
}

func TestNegativeCacheDoesNotLookLikeSuccess(t *testing.T) {
	resetPKICache()

	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		NoSuchName:        true,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	if got := getCachedTrustInfo(testQname, "stream-a", ""); got != nil {
		t.Fatal("a negative cache entry must not be returned as a positive value")
	}

	if _, err := GetTLSARecords(testQname); err == nil {
		t.Fatal("negative cache entry was treated as a successful TLSA lookup")
	}

	// A subsequent successful claim in the same stream replaces the negative
	// entry; other streams were never populated by the negative result.
	ncv := valueWithTLSA(3, 1, 1, []byte{0xcc})

	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx9:3",
		Value:             ncv,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	if got := getCachedTrustInfo(testQname, "stream-a", "tx9:3"); got != ncv {
		t.Fatal("positive claim did not replace the negative entry")
	}

	if got := getCachedTrustInfo(testQname, "stream-a", ""); got != nil {
		t.Fatal("stale negative entry survived the positive update")
	}
}

func TestClaimUpdateEvictsStaleVersionsInAllStreams(t *testing.T) {
	resetPKICache()

	oldClaim := valueWithTLSA(3, 1, 1, []byte{0x01})
	newClaim := valueWithTLSA(3, 1, 1, []byte{0x02})

	_ = DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx1:0",
		Value:             oldClaim,
	})
	_ = DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-b",
		ClaimVersion:      "tx1:0",
		Value:             oldClaim,
	})

	// stream-a observes the namecoin transaction spending the name.
	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx2:0",
		Value:             newClaim,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	// The new claim is cached for the updating stream.
	if got := getCachedTrustInfo(testQname, "stream-a", "tx2:0"); got != newClaim {
		t.Fatal("new claim was not cached")
	}

	// The updating stream no longer carries its own old version.
	if got := getCachedTrustInfo(testQname, "stream-a", "tx1:0"); got != nil {
		t.Fatal("updating stream kept the superseded claim version")
	}

	// Another stream has not re-resolved yet, so its own entry is left
	// untouched (cross-tenant cache writes are forbidden).
	if got := getCachedTrustInfo(testQname, "stream-b", "tx1:0"); got != oldClaim {
		t.Fatal("the other stream's entry must not be mutated by a different tenant")
	}

	// The read API must refuse to choose between the current and superseded
	// claim versions instead of serving stale data to a TLS peer.
	if _, err := GetTLSARecords(testQname); err == nil {
		t.Fatal("expected a claim-version conflict error, got records from a potentially stale claim")
	}

	// Once stream-b re-resolves to the same claim version, the contexts
	// agree again and the read path succeeds.
	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-b",
		ClaimVersion:      "tx2:0",
		Value:             newClaim,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	tlsa, err := GetTLSARecords(testQname)
	if err != nil {
		t.Fatalf("expected the conflict to resolve after re-resolution: %v", err)
	}

	if len(tlsa) != 1 || tlsa[0].Certificate != string([]byte{0x02}) {
		t.Fatalf("unexpected records after re-resolution: %+v", tlsa)
	}
}

func TestRevocationInvalidatesAllStreamsAndVersions(t *testing.T) {
	resetPKICache()

	ncvA := valueWithTLSA(3, 1, 1, []byte{0x01})
	ncvB := valueWithTLSA(3, 1, 1, []byte{0x02})

	_ = DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx1:0",
		Value:             ncvA,
	})
	_ = DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-b",
		ClaimVersion:      "tx2:0",
		Value:             ncvB,
	})

	// The name disappears from the chain in a later query.
	if err := DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		NoSuchName:        true,
	}); err != nil {
		t.Fatalf("hook failed: %v", err)
	}

	if got := getCachedTrustInfo(testQname, "stream-a", "tx1:0"); got != nil {
		t.Fatal("revoking stream's positive entry was not invalidated")
	}

	// Security requirement: another tenant must not keep using the revoked
	// name after the chain established that it no longer exists.
	if got := getCachedTrustInfo(testQname, "stream-b", "tx2:0"); got != nil {
		t.Fatal("revoked name remained cached for another stream")
	}

	if _, err := GetTLSARecords(testQname); err == nil {
		t.Fatal("revoked name still served through the TLS read API")
	}
}

func TestExpiredEntriesAreMisses(t *testing.T) {
	resetPKICache()

	ncv := valueWithTLSA(3, 1, 1, []byte{0x0d})

	storeCachedTrustInfo(
		makePKICacheKey(testQname, "stream-a", "tx1:0"),
		cachedTrustInfo{
			expiration: time.Now().Add(-time.Second),
			ncv:        ncv,
		},
	)

	if got := getCachedTrustInfo(testQname, "stream-a", "tx1:0"); got != nil {
		t.Fatal("expired positive entry was returned as fresh")
	}

	storeCachedTrustInfo(
		makePKICacheKey(testQname, "stream-a", ""),
		cachedTrustInfo{
			expiration: time.Now().Add(-time.Second),
			negative:   true,
		},
	)

	if _, err := GetTLSARecords(testQname); err == nil {
		t.Fatal("expired negative/empty state produced a successful lookup")
	}
}

func TestIsRevokedUsesCachedRecords(t *testing.T) {
	resetPKICache()

	ncv := &ncdomain.Value{
		IsTopLevel: true,
		Revocations: []*ncdomain.Revocation{
			{
				IssuerHashPrefixHex: "abcd",
				SerialPrefixHex:     "1234",
			},
		},
	}

	_ = DomainBaseValueHook(testQname, LookupResult{
		StreamIsolationID: "stream-a",
		ClaimVersion:      "tx1:0",
		Value:             ncv,
	})

	revoked, err := IsRevoked(testQname, []byte{0xab, 0xcd, 0x99}, []byte{0x12, 0x34, 0x56})
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}

	if !revoked {
		t.Fatal("expected the cached revocation to match")
	}

	revoked, err = IsRevoked(testQname, []byte{0xff}, []byte{0xff})
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}

	if revoked {
		t.Fatal("unexpected revocation match")
	}
}
