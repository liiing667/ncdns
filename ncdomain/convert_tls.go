//go:build !no_namecoin_tls
// +build !no_namecoin_tls

package ncdomain

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/miekg/dns"
)

func (v *Value) appendTLSA(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, tlsa := range v.TLSA {
		out = append(out, tlsa)
	}

	return out, nil
}

func parseTLSADANE(tlsa1dane interface{}, v *Value, ps *parseState) error {
	if tlsa, ok := tlsa1dane.([]interface{}); ok {
		// Format: [1, 2, 3, "base64 certificate data"]
		if len(tlsa) < 4 {
			return fmt.Errorf("TLSA item must have four items")
		}

		a1, ok := validateUint(tlsa[0], 0, math.MaxUint8)
		if !ok {
			return fmt.Errorf("First item in TLSA value must be an integer between 0 and %d (usage)", math.MaxUint8)
		}

		a2, ok := validateUint(tlsa[1], 0, math.MaxUint8)
		if !ok {
			return fmt.Errorf("Second item in TLSA value must be an integer between 0 and %d (selector)", math.MaxUint8)
		}

		a3, ok := validateUint(tlsa[2], 0, math.MaxUint8)
		if !ok {
			return fmt.Errorf("Third item in TLSA value must be an integer between 0 and %d (match type)", math.MaxUint8)
		}

		a4, ok := tlsa[3].(string)
		if !ok {
			return fmt.Errorf("Fourth item in TLSA value must be a string (certificate)")
		}

		a4b, err := base64.StdEncoding.DecodeString(a4)
		if err != nil {
			return fmt.Errorf("Fourth item in TLSA value must be valid base64: %v", err)
		}

		if len(v.TLSA) >= maxRecordsPerField {
			return fmt.Errorf("tls field exceeds the maximum of %d records", maxRecordsPerField)
		}
		if !ps.recordReserved() {
			return fmt.Errorf("record count limit exceeded (maximum %d records per value)", maxRecordsTotal)
		}

		a4h := hex.EncodeToString(a4b)

		v.TLSA = append(v.TLSA, &dns.TLSA{
			Hdr: dns.RR_Header{Name: "", Rrtype: dns.TypeTLSA, Class: dns.ClassINET,
				Ttl: defaultTTL},
			Usage:        uint8(a1),
			Selector:     uint8(a2),
			MatchingType: uint8(a3),
			Certificate:  strings.ToUpper(a4h),
		})

		return nil
	} else {
		return fmt.Errorf("TLSA item must be an array")
	}
}

func parseTLSA(rv map[string]interface{}, v *Value, ps *parseState) {
	tlsa, ok := rv["tls"]
	if !ok || tlsa == nil {
		return
	}

	v.TLSA = nil

	if tlsaa, ok := tlsa.([]interface{}); ok {
		for _, tlsa1 := range tlsaa {
			var tlsa1m map[string]interface{}

			if _, ok := tlsa1.([]interface{}); ok {
				tlsa1m = map[string]interface{}{
					"dane": tlsa1,
				}
			} else {
				tlsa1m = tlsa1.(map[string]interface{})
			}

			if tlsa1dane, ok := tlsa1m["dane"]; ok {
				err := parseTLSADANE(tlsa1dane, v, ps)
				if err == nil {
					continue
				}
				ps.errFunc.add(err)
			}

			ps.errFunc.add(fmt.Errorf("Unknown TLSA item format"))
		}
		return
	}

	ps.errFunc.add(fmt.Errorf("Malformed TLSA field format"))
}
