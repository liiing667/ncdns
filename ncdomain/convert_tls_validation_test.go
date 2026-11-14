//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package ncdomain_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/namecoin/ncdns/ncdomain"
)

const (
	// 32 bytes (SHA-256 length), base64 encoded.
	tlsaB64SHA256 = "i4hXddaCCdb7+m1rFzonluIisL7S/G+ttz2PWdKH4m0="
	// 64 bytes (SHA-512 length), base64 encoded.
	tlsaB64SHA512 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
)

type tlsaParseResult struct {
	records []string
	errors  int
}

func parseTLSAValue(t *testing.T, jsonValue string) tlsaParseResult {
	t.Helper()

	resolve := func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	result := tlsaParseResult{}
	errFunc := func(err error, isWarning bool) {
		if !isWarning {
			result.errors++
		}
	}

	v := ncdomain.ParseValue("d/example", jsonValue, resolve, errFunc)
	if v == nil {
		return result
	}

	rrs, _ := v.RRsRecursive(nil, "example.bit.", "example.bit.")
	for _, rr := range rrs {
		result.records = append(result.records, strings.Join(strings.Fields(rr.String()), " "))
	}
	sort.Strings(result.records)

	return result
}

func TestTLSAValidValues(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		expected string
	}{
		{
			name:     "PKIX-TA cert full cert",
			json:     `{"tls":[[1,0,0,"` + tlsaB64SHA256 + `"]]}`,
			expected: "example.bit. 600 IN TLSA 1 0 0 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D",
		},
		{
			name:     "SHA-256 digest",
			json:     `{"tls":[[3,1,1,"` + tlsaB64SHA256 + `"]]}`,
			expected: "example.bit. 600 IN TLSA 3 1 1 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D",
		},
		{
			name:     "SHA-512 digest",
			json:     `{"tls":[[3,1,2,"` + tlsaB64SHA512 + `"]]}`,
			expected: "example.bit. 600 IN TLSA 3 1 2 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
		},
		{
			// In-range but unassigned code points must be preserved rather
			// than silently mapped to a different meaning.
			name:     "unknown code points preserved",
			json:     `{"tls":[[5,6,7,"` + tlsaB64SHA256 + `"]]}`,
			expected: "example.bit. 600 IN TLSA 5 6 7 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D",
		},
		{
			name:     "boundary values zero and 255",
			json:     `{"tls":[[0,0,0,"` + tlsaB64SHA256 + `"],[255,255,1,"` + tlsaB64SHA256 + `"]]}`,
			expected: "example.bit. 600 IN TLSA 0 0 0 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D\nexample.bit. 600 IN TLSA 255 255 1 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D",
		},
		{
			name:     "dane map form",
			json:     `{"tls":[{"dane":[1,2,1,"` + tlsaB64SHA256 + `"]}]}`,
			expected: "example.bit. 600 IN TLSA 1 2 1 8B885775D68209D6FBFA6D6B173A2796E222B0BED2FC6FADB73D8F59D287E26D",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseTLSAValue(t, tc.json)
			if result.errors != 0 {
				t.Fatalf("unexpected errors: %d", result.errors)
			}
			if got := strings.Join(result.records, "\n"); got != tc.expected {
				t.Fatalf("records mismatch:\ngot:  %q\nwant: %q", got, tc.expected)
			}
		})
	}
}

func TestTLSAInvalidValuesRejected(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"usage 256 truncated to 0", `{"tls":[[256,1,1,"` + tlsaB64SHA256 + `"]]}`},
		{"usage 257 truncated to 1", `{"tls":[[257,1,1,"` + tlsaB64SHA256 + `"]]}`},
		{"negative usage wraps to 255", `{"tls":[[-1,1,1,"` + tlsaB64SHA256 + `"]]}`},
		{"selector out of range", `{"tls":[[1,256,1,"` + tlsaB64SHA256 + `"]]}`},
		{"matching type out of range", `{"tls":[[1,1,256,"` + tlsaB64SHA256 + `"]]}`},
		{"negative matching type", `{"tls":[[1,1,-2,"` + tlsaB64SHA256 + `"]]}`},
		{"fractional code point", `{"tls":[[1.5,1,1,"` + tlsaB64SHA256 + `"]]}`},
		{"non-integer code point", `{"tls":[["1",1,1,"` + tlsaB64SHA256 + `"]]}`},
		{"SHA-256 digest wrong length", `{"tls":[[3,1,1,"` + tlsaB64SHA512 + `"]]}`},
		{"SHA-512 digest wrong length", `{"tls":[[3,1,2,"` + tlsaB64SHA256 + `"]]}`},
		{"SHA-256 empty digest", `{"tls":[[3,1,1,""]]}`},
		{"invalid base64", `{"tls":[[1,1,1,"not base64!"]]}`},
		{"too few items", `{"tls":[[1,1,1]]}`},
		{"item not an array", `{"tls":[{"dane":"not-an-array"}]}`},
		{"tls field not an array", `{"tls":{"dane":[1,1,1,"` + tlsaB64SHA256 + `"]}}`},
		{"unknown item format", `{"tls":["not-a-tlsa-item"]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseTLSAValue(t, tc.json)
			if result.errors == 0 {
				t.Fatalf("expected at least one error, got none; records: %v", result.records)
			}
			if len(result.records) != 0 {
				t.Fatalf("no TLSA records should be published for invalid input, got: %v", result.records)
			}
		})
	}
}

func TestTLSAFieldIsAtomic(t *testing.T) {
	// A malformed item must not leave the previously accepted item published.
	jsonValue := `{"tls":[[1,1,1,"` + tlsaB64SHA256 + `"],[256,1,1,"` + tlsaB64SHA256 + `"]]}`
	result := parseTLSAValue(t, jsonValue)

	if result.errors != 1 {
		t.Fatalf("expected exactly one error, got %d", result.errors)
	}
	if len(result.records) != 0 {
		t.Fatalf("expected no records after a malformed item, got: %v", result.records)
	}
}
