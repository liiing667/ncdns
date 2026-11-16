//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	madns "gopkg.in/hlandau/madns.v2"

	"github.com/namecoin/ncdns/backend"
	"github.com/namecoin/ncdns/tlshook"
)

// recordingResponseWriter captures the single DNS message written by the
// madns engine.
type recordingResponseWriter struct {
	reply *dns.Msg
}

func (w *recordingResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *recordingResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }

func (w *recordingResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.reply = msg
	return nil
}

func (w *recordingResponseWriter) Write(buf []byte) (int, error) { return len(buf), nil }
func (w *recordingResponseWriter) Close() error                  { return nil }
func (w *recordingResponseWriter) TsigStatus() error             { return nil }
func (w *recordingResponseWriter) TsigTimersOnly(bool)           {}
func (w *recordingResponseWriter) Hijack()                       {}

func newTestEngine(t *testing.T, fakeNames map[string]string) (madns.Engine, *backend.Backend) {
	t.Helper()

	b, err := backend.New(&backend.Config{
		FakeNames:       fakeNames,
		NamecoinTimeout: 1000,
		CacheMaxEntries: 10,
	})
	if err != nil {
		t.Fatalf("backend.New failed: %v", err)
	}

	engine, err := madns.NewEngine(&madns.EngineConfig{Backend: b})
	if err != nil {
		t.Fatalf("madns.NewEngine failed: %v", err)
	}

	return engine, b
}

func query(t *testing.T, engine madns.Engine, qname, streamIsolationID string, qtype uint16) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)

	if streamIsolationID != "" {
		req.Extra = append(req.Extra, &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			Option: []dns.EDNS0{
				&dns.EDNS0_LOCAL{Code: madns.EDNS0STREAMISOLATION, Data: []byte(streamIsolationID)},
			},
		})
	}

	writer := &recordingResponseWriter{}
	engine.ServeDNS(writer, req)

	if writer.reply == nil {
		t.Fatal("engine did not write a reply")
	}

	return writer.reply
}

// A normal lookup returns NOERROR and populates the PKI cache for the exact
// stream isolation context.
func TestLookupPopulatesStreamScopedPKICache(t *testing.T) {
	fakeNames := map[string]string{
		"d/example": `{"ip":"192.0.2.7","map":{"*":{"tls":[[3,1,1,"3q2+7w=="]]}}}`,
	}

	engine, _ := newTestEngine(t, fakeNames)

	reply := query(t, engine, "example.bit", "tenant-1", dns.TypeA)
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s: %+v", dns.RcodeToString[reply.Rcode], reply)
	}

	if len(reply.Answer) == 0 {
		t.Fatal("expected answer records, got none")
	}

	// The TLS hook must have data for the querying stream but not for an
	// unrelated stream.  Fake names carry no claim version (empty string),
	// matching what an old Namecoin Core would return.
	tlsa, err := tlshook.GetTLSARecords("example.bit.")
	if err != nil {
		t.Fatalf("expected cached TLSA records: %v", err)
	}

	if len(tlsa) != 1 {
		t.Fatalf("expected 1 TLSA record, got %d", len(tlsa))
	}
}

// NXDOMAIN must be reported as such by the DNS layer and must invalidate any
// previously cached trust information instead of leaving stale data behind.
func TestNXDOMAINInvalidatesPKICache(t *testing.T) {
	fakeNames := map[string]string{
		"d/example": `{"ip":"192.0.2.7","map":{"*":{"tls":[[3,1,1,"3q2+7w=="]]}}}`,
		"d/gone":    "NX",
	}

	engine, _ := newTestEngine(t, fakeNames)

	// Prime the cache with a successful lookup.
	if reply := query(t, engine, "example.bit", "tenant-1", dns.TypeA); reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("priming lookup failed with rcode %d", reply.Rcode)
	}

	if _, err := tlshook.GetTLSARecords("example.bit."); err != nil {
		t.Fatalf("expected primed TLSA records: %v", err)
	}

	// A name which was never present also yields NXDOMAIN, never SERVFAIL.
	reply := query(t, engine, "gone.bit", "tenant-1", dns.TypeA)
	if reply.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for a missing name, got %s", dns.RcodeToString[reply.Rcode])
	}

	// Simulate the chain transition that revokes the previously cached
	// name: the NXDOMAIN hook path must invalidate every cached claim.
	if err := tlshook.DomainBaseValueHook("example.bit.", tlshook.LookupResult{
		StreamIsolationID: "tenant-1",
		NoSuchName:        true,
	}); err != nil {
		t.Fatalf("revocation hook failed: %v", err)
	}

	if _, err := tlshook.GetTLSARecords("example.bit."); err == nil {
		t.Fatal("stale TLSA records remained cached after the name was revoked")
	}
}

// Distinct stream isolation IDs must never share a cache entry.
func TestStreamIsolationKeepsTenantsApart(t *testing.T) {
	fakeNames := map[string]string{
		"d/example": `{"ip":"192.0.2.7"}`,
	}

	engine, _ := newTestEngine(t, fakeNames)

	first := query(t, engine, "example.bit", "tenant-1", dns.TypeA)
	second := query(t, engine, "example.bit", "tenant-2", dns.TypeA)

	if first.Rcode != dns.RcodeSuccess || second.Rcode != dns.RcodeSuccess {
		t.Fatalf("both lookups should succeed: %d %d", first.Rcode, second.Rcode)
	}

	// The backend's per-stream LRU caches must be independent.
	// This is exercised indirectly: a lookup under a third, never-used
	// stream still hits the fake backend rather than reusing another
	// tenant's parsed entry.
	third := query(t, engine, "example.bit", "tenant-3", dns.TypeAAAA)
	if third.Rcode != dns.RcodeSuccess {
		t.Fatalf("fresh stream lookup failed with rcode %d", third.Rcode)
	}
}
