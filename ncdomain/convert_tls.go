//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package ncdomain

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// TLSA code points and digest lengths, per RFC 6698.
//
// The certificate usage, selector and matching type fields are single
// unsigned bytes on the wire.  Only the code points registered with IANA are
// interpreted here; any other value which fits in a byte is carried through
// verbatim as an unknown code point rather than being silently remapped.
const (
	tlsaMatchingTypeFullCert = 0 // full certificate, no digest length constraint
	tlsaMatchingTypeSHA256   = 1 // SHA-256, 32 byte digest
	tlsaMatchingTypeSHA512   = 2 // SHA-512, 64 byte digest

	tlsaSHA256DigestLen = 32
	tlsaSHA512DigestLen = 64
)

// tlsaDigestLen returns the required certificate association data length for
// the given matching type, or -1 when no length constraint applies (full
// certificate matching, or a matching type which is not known to us).
func tlsaDigestLen(matchingType uint8) int {
	switch matchingType {
	case tlsaMatchingTypeFullCert:
		return -1
	case tlsaMatchingTypeSHA256:
		return tlsaSHA256DigestLen
	case tlsaMatchingTypeSHA512:
		return tlsaSHA512DigestLen
	default:
		// Unknown matching type: preserve it as an unknown code point and
		// leave the association data unconstrained.
		return -1
	}
}

// parseTLSAUint8 converts a JSON number to a TLSA uint8 field.  Values outside
// the unsigned byte range are rejected rather than being truncated, so that
// e.g. 256 is not silently published as 0.
func parseTLSAUint8(field string, value interface{}) (uint8, error) {
	number, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("%s in TLSA value must be an integer", field)
	}

	// encoding/json decodes all numbers as float64; reject fractions so that
	// e.g. 1.5 is not rounded to a code point.
	if number != float64(int64(number)) {
		return 0, fmt.Errorf("%s in TLSA value must be an integer", field)
	}

	if number < 0 || number > 255 {
		return 0, fmt.Errorf("%s in TLSA value is out of range (0-255): %v", field, number)
	}

	return uint8(int64(number)), nil
}

func (v *Value) appendTLSA(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, tlsa := range v.TLSA {
		out = append(out, tlsa)
	}

	return out, nil
}

func parseTLSADANE(tlsa1dane interface{}) (*dns.TLSA, error) {
	if tlsa, ok := tlsa1dane.([]interface{}); ok {
		// Format: [1, 2, 3, "base64 certificate data"]
		if len(tlsa) < 4 {
			return nil, fmt.Errorf("TLSA item must have four items")
		}

		usage, err := parseTLSAUint8("first item (usage)", tlsa[0])
		if err != nil {
			return nil, err
		}

		selector, err := parseTLSAUint8("second item (selector)", tlsa[1])
		if err != nil {
			return nil, err
		}

		matchingType, err := parseTLSAUint8("third item (matching type)", tlsa[2])
		if err != nil {
			return nil, err
		}

		a4, ok := tlsa[3].(string)
		if !ok {
			return nil, fmt.Errorf("Fourth item in TLSA value must be a string (certificate)")
		}

		a4b, err := base64.StdEncoding.DecodeString(a4)
		if err != nil {
			return nil, fmt.Errorf("Fourth item in TLSA value must be valid base64: %v", err)
		}

		if expectedLen := tlsaDigestLen(matchingType); expectedLen >= 0 && len(a4b) != expectedLen {
			return nil, fmt.Errorf("Fourth item in TLSA value has a digest length of %d bytes, but matching type %d requires %d bytes",
				len(a4b), matchingType, expectedLen)
		}

		a4h := hex.EncodeToString(a4b)

		return &dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: defaultTTL},
			Usage:        usage,
			Selector:     selector,
			MatchingType: matchingType,
			Certificate:  strings.ToUpper(a4h),
		}, nil
	} else {
		return nil, fmt.Errorf("TLSA item must be an array")
	}
}

func parseTLSA(rv map[string]interface{}, v *Value, errFunc ErrorFunc) {
	tlsa, ok := rv["tls"]
	if !ok || tlsa == nil {
		return
	}

	v.TLSA = nil

	if tlsaa, ok := tlsa.([]interface{}); ok {
		// Parse every item into a temporary slice so that a malformed item
		// cannot leave a partially accepted, semantically truncated TLSA set
		// behind.  The value is only updated when the whole field is valid.
		tlsaRecords := make([]*dns.TLSA, 0, len(tlsaa))
		fieldValid := true

		for _, tlsa1 := range tlsaa {
			var tlsa1m map[string]interface{}

			if _, ok := tlsa1.([]interface{}); ok {
				tlsa1m = map[string]interface{}{
					"dane": tlsa1,
				}
			} else if m, ok := tlsa1.(map[string]interface{}); ok {
				tlsa1m = m
			} else {
				errFunc.add(fmt.Errorf("Unknown TLSA item format"))
				fieldValid = false
				continue
			}

			if tlsa1dane, ok := tlsa1m["dane"]; ok {
				record, err := parseTLSADANE(tlsa1dane)
				if err == nil {
					tlsaRecords = append(tlsaRecords, record)
					continue
				}
				errFunc.add(err)
				fieldValid = false
			} else {
				errFunc.add(fmt.Errorf("Unknown TLSA item format"))
				fieldValid = false
			}
		}

		if !fieldValid {
			return
		}

		v.TLSA = tlsaRecords
		return
	}

	errFunc.add(fmt.Errorf("Malformed TLSA field format"))
}
