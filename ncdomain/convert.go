package ncdomain

import "encoding/json"
import "net"
import "fmt"
import "github.com/fxamacker/cbor"
import "github.com/miekg/dns"
import "encoding/base64"
import "encoding/hex"
import "github.com/namecoin/ncdns/util"
import "strings"
import "strconv"
import "reflect"
import "math"

const depthLimit = 16
const mergeDepthLimit = 4
const defaultTTL = 600

// Bounds on how much data a single Namecoin value is allowed to produce.
// Without these, a maliciously large JSON/CBOR value (or a chain of
// import/delegate merges) can force ncdns to allocate unbounded amounts of
// memory and to emit arbitrarily large DNS response sets.
const (
	// maxRecordsPerField limits the number of records accepted for any single
	// record type (IP, NS, DS, TXT, SRV, MX, TLSA, ...) in one Value.
	maxRecordsPerField = 1024
	// maxRecordsTotal limits the total number of records produced by an entire
	// ParseValue call, including records brought in via import/delegate and
	// records nested in "map" subdomains.
	maxRecordsTotal = 16384
	// maxMapEntries limits the number of subdomain entries accepted in a single
	// "map" object.
	maxMapEntries = 1024
)

// Note: Name values in Value (e.g. those in Alias and Target, Services, MXs,
// etc.) are not necessarily fully qualified and must be fully qualified before
// being used. Non-fully-qualified names are relative to the name apex, and
// should be qualified as such based on whatever the corresponding name for the
// Value is and the zone apex you are using for .bit. These assumptions are not
// built-in for you to give flexibility in where the .bit zone is mounted,
// DNS namespace-wise. If you just call RRs() or RRsRecursive() you don't have
// to worry about any of this.
//
// Because empty values are used to indicate the non-presence of an option
// in some cases, namely for Alias and Translate, the empty string is represented as "=".
// Therefore when qualifying names in a Value yourself you must check if the
// input string is "=" and if so, replace it with "" first.
type Value struct {
	IP           []net.IP
	IP6          []net.IP
	NS           []string
	Alias        string
	HasAlias     bool // True if Alias was specified. Necessary as "" is a valid relative alias.
	Translate    string
	HasTranslate bool // True if Translate was specified. Necessary as "" is a valid relative value for Translate.
	DS           []*dns.DS
	TXT          [][]string
	SRV          []*dns.SRV
	Hostmaster   string    // "hostmaster@example.com"
	MX           []*dns.MX // header name is left blank
	TLSA         []*dns.TLSA
	Revocations  []*Revocation
	Map          map[string]*Value // may contain and "*", will not contain ""

	// set if the value is at the top level (alas necessary for relname interpretation)
	IsTopLevel bool
}

type Revocation struct {
	IssuerHashPrefixHex string
	SerialPrefixHex  string
}

func (v *Value) mkString(i string) string {
	s := i[1:] + "Value:"
	i += "  "
	if v.HasAlias {
		s += i + "CNAME: \"" + v.Alias + "\""
	}
	if v.HasTranslate {
		s += i + "DNAME: \"" + v.Translate + "\""
	}
	if v.Hostmaster != "" {
		s += i + "Hostmaster: " + v.Hostmaster
	}
	for _, ip := range v.IP {
		s += i + "IPv4 Address: " + ip.String()
	}
	for _, ip := range v.IP6 {
		s += i + "IPv6 Address: " + ip.String()
	}
	for _, ns := range v.NS {
		s += i + "Nameserver: " + ns
	}
	for _, ds := range v.DS {
		s += i + "DS Record: " + ds.String()
	}
	for _, txt := range v.TXT {
		s += i + "TXT Record:"
		for _, txtc := range txt {
			s += i + "  " + txtc
		}
	}
	for _, srv := range v.SRV {
		s += i + "SRV Record: " + srv.String()
	}
	for _, tlsa := range v.TLSA {
		s += i + "TLSA Record: " + tlsa.String()
	}
	if len(v.Map) > 0 {
		s += i + "Subdomains:"
		for k, v := range v.Map {
			s += i + "  " + k + ":"
			s += v.mkString(i + "    ")
		}
	}
	return s
}

func (v *Value) String() string {
	return v.mkString("\n")
}

func (v *Value) RRs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	il := len(out)
	suffix = dns.Fqdn(suffix)
	apexSuffix = dns.Fqdn(apexSuffix)

	out, _ = v.appendNSs(out, suffix, apexSuffix)
	if len(v.NS) == 0 {
		out, _ = v.appendTranslate(out, suffix, apexSuffix)
		if !v.HasTranslate {
			out, _ = v.appendAlias(out, suffix, apexSuffix)
			if !v.HasAlias {
				out, _ = v.appendIPs(out, suffix, apexSuffix)
				out, _ = v.appendIP6s(out, suffix, apexSuffix)
				out, _ = v.appendTXTs(out, suffix, apexSuffix)
				out, _ = v.appendMXs(out, suffix, apexSuffix)
				out, _ = v.appendSRVs(out, suffix, apexSuffix)
				out, _ = v.appendTLSA(out, suffix, apexSuffix)
			}
		}
	}
	out, _ = v.appendDSs(out, suffix, apexSuffix)

	xout := out[il:]
	for i := range xout {
		h := xout[i].Header()
		if rrtypeHasPrefix(h.Rrtype) {
			h.Name += suffix
		} else {
			h.Name = suffix
		}
	}

	return out, nil
}

func rrtypeHasPrefix(t uint16) bool {
	return t == dns.TypeSRV || t == dns.TypeTLSA
}

func (v *Value) appendIPs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ip := range v.IP {
		out = append(out, &dns.A{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			A: ip,
		})
	}

	return out, nil
}

func (v *Value) appendIP6s(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ip := range v.IP6 {
		out = append(out, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			AAAA: ip,
		})
	}

	return out, nil
}

func (v *Value) appendNSs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ns := range v.NS {
		qn, ok := v.qualify(ns, suffix, apexSuffix)
		if !ok {
			continue
		}

		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ns: qn,
		})
	}

	return out, nil
}

func (v *Value) appendTXTs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, txt := range v.TXT {
		out = append(out, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Txt: txt,
		})
	}

	return out, nil
}

func (v *Value) appendDSs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, ds := range v.DS {
		out = append(out, ds)
	}

	return out, nil
}

func (v *Value) appendMXs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, mx := range v.MX {
		out = append(out, mx)
	}

	return out, nil
}

func (v *Value) appendSRVs(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	for _, svc := range v.SRV {
		qn, ok := v.qualify(svc.Target, suffix, apexSuffix)
		if !ok {
			continue
		}

		out = append(out, &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   "",
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Priority: svc.Priority,
			Weight:   svc.Weight,
			Port:     svc.Port,
			Target:   qn,
		})
	}

	return out, nil
}

func (v *Value) appendAlias(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	if v.HasAlias {
		qn, ok := v.qualify(v.Alias, suffix, apexSuffix)
		if !ok {
			return out, fmt.Errorf("bad alias")
		}
		out = append(out, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Target: qn,
		})
	}

	return out, nil
}

func (v *Value) appendTranslate(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	if v.HasTranslate {
		qn, ok := v.qualify(v.Translate, suffix, apexSuffix)
		if !ok {
			return out, fmt.Errorf("bad translate")
		}
		out = append(out, &dns.DNAME{
			Hdr: dns.RR_Header{
				Name:   suffix,
				Rrtype: dns.TypeDNAME,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Target: qn,
		})
	}

	return out, nil
}

func (v *Value) RRsRecursive(out []dns.RR, suffix, apexSuffix string) ([]dns.RR, error) {
	out, err := v.RRs(out, suffix, apexSuffix)
	if err != nil {
		return nil, err
	}

	for mk, mv := range v.Map {
		if !util.ValidateOwnerLabel(mk) && mk != "" && mk != "*" {
			continue
		}

		out, err = mv.RRsRecursive(out, mk+"."+suffix, apexSuffix)
		//if err != nil {
		//	return nil, err
		//}
	}

	return out, nil
}

func (v *Value) FindSubdomainByName(subdomain string) (*Value, error) {
	if subdomain == "" {
		return v, nil
	}

	if strings.HasSuffix(subdomain, ".") {
		return nil, fmt.Errorf("a subdomain name should not be fully qualified")
	}

	head, rest := util.SplitDomainHead(subdomain)

	if sub, ok := v.Map[head]; ok {
		return sub.FindSubdomainByName(rest)
	}

	return nil, fmt.Errorf("subdomain part not found: %s", head)
}

type ResolveFunc func(name string) (string, error)
type ErrorFunc func(err error, isWarning bool)

func (ef ErrorFunc) add(err error) {
	if ef != nil && err != nil {
		ef(err, false)
	}
}

func (ef ErrorFunc) addWarning(err error) {
	if ef != nil && err != nil {
		ef(err, true)
	}
}

// parseState carries the state shared by every Value produced by one
// ParseValue call. It makes the import/delegate merge graph and the record
// count budget global rather than per-subdomain, so a malicious value cannot
// evade the limits by nesting records or re-importing names in subdomains.
type parseState struct {
	resolve     ResolveFunc
	errFunc     ErrorFunc
	mergedNames map[string]struct{}
	recordsLeft int
	budgetError bool
}

// recordReserved reserves one record against the global budget. It reports
// false (and emits a single stable error) once the budget is exhausted.
func (ps *parseState) recordReserved() bool {
	if ps.recordsLeft <= 0 {
		if !ps.budgetError {
			ps.budgetError = true
			ps.errFunc.add(fmt.Errorf("record count limit exceeded (maximum %d records per value)", maxRecordsTotal))
		}
		return false
	}

	ps.recordsLeft--
	return true
}

// validateUint returns the integer value of x if it is a whole number within
// [min, max]. JSON and CBOR numbers are decoded as float64, so fractional
// values and values outside the target field's wire-format range are rejected
// here instead of being silently truncated when cast to an unsigned integer.
func validateUint(x interface{}, min, max float64) (uint64, bool) {
	f, ok := x.(float64)
	if !ok || f != float64(int64(f)) || f < min || f > max {
		return 0, false
	}

	return uint64(f), true
}

// Call to convert a given JSON value to a parsed Namecoin domain value.
//
// If ResolveFunc is given, it will be called to obtain the values for domains
// referenced by "import" and "delegate" statements. The name passed is in
// Namecoin form (e.g. "d/example"). The JSON value or an error should be
// returned. If no ResolveFunc is passed, "import" and "delegate" statements
// always fail.
//
// Returns nil if the JSON could not be parsed. For all other errors processing
// continues and recovers as much as possible; errFunc is called for all errors
// and warnings if specified.
func ParseValue(name, jsonValue string, resolve ResolveFunc, errFunc ErrorFunc) (value *Value) {
	var rv interface{}
	v := &Value{}

	err := json.Unmarshal([]byte(jsonValue), &rv)
	if err != nil {
		errCBOR := cbor.Unmarshal([]byte(jsonValue), &rv)
		if errCBOR != nil {
			errFunc.add(err)
			errFunc.add(fmt.Errorf("failed to decode cbor (after JSON decoding failed): %v", errCBOR))
			return
		}
		// Some unmarshallers (e.g. CBOR) will create
		// map[interface{}]interface{} which is incompatible
		rv = makeJSONSafe(rv)
	}

	if resolve == nil {
		resolve = func(name string) (string, error) {
			return "", fmt.Errorf("not supported")
		}
	}

	ps := &parseState{
		resolve:     resolve,
		errFunc:     errFunc,
		mergedNames: map[string]struct{}{name: {}},
		recordsLeft: maxRecordsTotal,
	}

	parse(rv, v, ps, 0, 0, "", "")
	v.IsTopLevel = true

	value = v
	return
}

func parse(rv interface{}, v *Value, ps *parseState, depth, mergeDepth int, subdomain, relname string) {
	rvm, ok := rv.(map[string]interface{})
	if !ok {
		ps.errFunc.add(fmt.Errorf("value is not an object"))
		return
	}

	if depth > depthLimit {
		ps.errFunc.add(fmt.Errorf("depth limit exceeded"))
		return
	}

	realv := v
	if subdomain != "" {
		// substitute a dummy value. We will then parse everything into this, find the appropriate level and copy
		// the value to the argument value.
		v = &Value{}
	}

	ok, _ = parseDelegate(rvm, v, ps, depth, mergeDepth, relname)
	if ok {
		return
	}

	_ = parseImport(rvm, v, ps, depth, mergeDepth, relname)
	if ip, ok := rvm["ip"]; ok {
		parseIP(rvm, v, ps, ip, false)
	}
	if ip6, ok := rvm["ip6"]; ok {
		parseIP(rvm, v, ps, ip6, true)
	}
	parseNS(rvm, v, ps, relname)
	parseAlias(rvm, v, ps, relname)
	parseTranslate(rvm, v, ps, relname)
	parseHostmaster(rvm, v, ps)
	parseDS(rvm, v, ps)
	parseTXT(rvm, v, ps)
	parseSRV(rvm, v, ps, relname)
	parseMX(rvm, v, ps, relname)
	parseTLSA(rvm, v, ps)
	parseRevocations(rvm, v, ps)
	parseMap(rvm, v, ps, depth, mergeDepth, relname)
	v.moveEmptyMapItems()

	if subdomain != "" {
		subv, err := v.FindSubdomainByName(subdomain)
		if err != nil {
			ps.errFunc.add(fmt.Errorf("couldn't find subdomain by name in import or delegate item: %v", err))
			return
		}
		*realv = *subv
	}
}

func (v *Value) qualifyIntl(name, suffix, apexSuffix string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	if !v.IsTopLevel {
		_, suffix = util.SplitDomainTail(suffix)
	}

	if name == "" {
		return suffix
	}

	if name == "@" {
		return apexSuffix
	}

	if strings.HasSuffix(name, ".@") {
		return name[0:len(name)-2] + "." + apexSuffix
	}

	return name + "." + suffix
}

func (v *Value) qualify(name, suffix, apexSuffix string) (string, bool) {
	s := v.qualifyIntl(name, suffix, apexSuffix)
	if !util.ValidateHostName(s) {
		return "", false
	}

	return s, true
}

func parseMerge(rv map[string]interface{}, mergeValue string, v *Value, ps *parseState, depth, mergeDepth int, subdomain, relname string) error {
	var rv2 interface{}

	if mergeDepth > mergeDepthLimit {
		err := fmt.Errorf("merge depth limit exceeded")
		ps.errFunc.add(err)
		return err
	}

	err := json.Unmarshal([]byte(mergeValue), &rv2)
	if err != nil {
		err = fmt.Errorf("couldn't parse JSON to be merged: %v", err)
		ps.errFunc.add(err)
		return err
	}

	parse(rv2, v, ps, depth, mergeDepth, subdomain, relname)
	return nil
}

func parseIP(rv map[string]interface{}, v *Value, ps *parseState, ipi interface{}, ipv6 bool) {
	if ipv6 {
		v.IP6 = nil
	} else {
		v.IP = nil
	}

	if ipi == nil {
		return
	}

	if ipa, ok := ipi.([]interface{}); ok {
		for _, ip := range ipa {
			if ips, ok := ip.(string); ok {
				addIP(rv, v, ps, ips, ipv6)
			}
		}

		return
	}

	if ip, ok := ipi.(string); ok {
		addIP(rv, v, ps, ip, ipv6)
	}
}

func pickIPs(v *Value, ipv6 bool) []net.IP {
	if ipv6 {
		return v.IP6
	}
	return v.IP
}

func addIP(rv map[string]interface{}, v *Value, ps *parseState, ips string, ipv6 bool) {
	pip := net.ParseIP(ips)
	if pip == nil || (pip.To4() == nil) != ipv6 {
		ps.errFunc.add(fmt.Errorf("malformed IP: %s", ips))
		return
	}

	ips2 := pickIPs(v, ipv6)
	if len(ips2) >= maxRecordsPerField {
		ps.errFunc.add(fmt.Errorf("ip field exceeds the maximum of %d records", maxRecordsPerField))
		return
	}

	if !ps.recordReserved() {
		return
	}

	if ipv6 {
		v.IP6 = append(v.IP6, pip)
	} else {
		v.IP = append(v.IP, pip)
	}
}

func parseNS(rv map[string]interface{}, v *Value, ps *parseState, relname string) {
	// "dns" takes precedence
	if dns, ok := rv["dns"]; ok && dns != nil {
		rv["ns"] = dns
	}

	ns, ok := rv["ns"]
	if !ok || ns == nil {
		return
	}

	v.NS = nil

	if _, ok := rv["_nsSet"]; !ok {
		rv["_nsSet"] = map[string]struct{}{}
	}

	switch ns.(type) {
	case []interface{}:
		for _, si := range ns.([]interface{}) {
			s, ok := si.(string)
			if !ok {
				continue
			}
			addNS(rv, v, ps, s, relname)
		}
		return
	case string:
		s := ns.(string)
		addNS(rv, v, ps, s, relname)
		return
	default:
		ps.errFunc.add(fmt.Errorf("unknown NS field format"))
	}
}

func addNS(rv map[string]interface{}, v *Value, ps *parseState, s, relname string) {
	if !util.ValidateOwnerName(s) {
		ps.errFunc.add(fmt.Errorf("malformed domain name in NS field"))
	}
	if _, ok := (rv["_nsSet"].(map[string]struct{}))[s]; !ok {
		if len(v.NS) >= maxRecordsPerField {
			ps.errFunc.add(fmt.Errorf("ns field exceeds the maximum of %d records", maxRecordsPerField))
			return
		}
		if !ps.recordReserved() {
			return
		}
		v.NS = append(v.NS, s)
		(rv["_nsSet"].(map[string]struct{}))[s] = struct{}{}
	}
}

func parseAlias(rv map[string]interface{}, v *Value, ps *parseState, relname string) {
	alias, ok := rv["alias"]
	if !ok {
		return
	}

	if alias == nil {
		v.Alias = ""
		v.HasAlias = false
		return
	}

	if s, ok := alias.(string); ok {
		if !util.ValidateRelOwnerName(s) {
			ps.errFunc.add(fmt.Errorf("malformed alias name"))
			return
		}

		v.Alias = s
		v.HasAlias = true
		return
	}

	ps.errFunc.add(fmt.Errorf("unknown alias field format"))
}

func parseTranslate(rv map[string]interface{}, v *Value, ps *parseState, relname string) {
	translate, ok := rv["translate"]
	if !ok {
		return
	}

	if translate == nil {
		v.Translate = ""
		v.HasTranslate = false
		return
	}

	if s, ok := translate.(string); ok {
		if !util.ValidateRelOwnerName(s) {
			ps.errFunc.add(fmt.Errorf("malformed translate name"))
			return
		}
		v.Translate = s
		v.HasTranslate = true
		return
	}

	ps.errFunc.add(fmt.Errorf("unknown translate field format"))
}

func isAllArray(x []interface{}) bool {
	for _, v := range x {
		if _, ok := v.([]interface{}); !ok {
			return false
		}
	}
	return true
}

func isAllString(x []interface{}) bool {
	for _, v := range x {
		if _, ok := v.(string); !ok {
			return false
		}
	}
	return true
}

func parseImportImpl(rv map[string]interface{}, val *Value, ps *parseState, depth, mergeDepth int, relname string, delegate bool) (bool, error) {
	var err error
	succeeded := false
	xname := "import"
	if delegate {
		xname = "delegate"
	}

	src, ok := rv[xname]
	if !ok || src == nil {
		return false, nil
	}

	if s, ok := src.(string); ok {
		src = []interface{}{s}
	}

	if a, ok := src.([]interface{}); ok {
		// [..., ..., ...]

		if isAllString(a) {
			// ["s/somedomain"]
			// ["s/somedomain", "sub.domain"]
			a = []interface{}{a}
		}

		if isAllArray(a) {
			// [ ["s/somedomain", "sub.domain"], ["s/somedomain", "sub.domain"] ]
			for _, vx := range a {
				v := vx.([]interface{})
				if len(v) != 1 && len(v) != 2 {
					continue
				}

				subs := ""
				if k, ok := v[0].(string); ok {
					if len(v) > 1 {
						if sub, ok := v[1].(string); ok {
							subs = sub
						}
					}

					if _, ok := ps.mergedNames[k]; ok {
						// already merged
						continue
					}

					// ok
					var dv string
					dv, err = ps.resolve(k)
					if err != nil {
						continue
					}

					ps.mergedNames[k] = struct{}{}

					err = parseMerge(rv, dv, val, ps, depth, mergeDepth+1, subs, relname)
					if err != nil {
						ps.errFunc.add(err)
						continue
					}

					succeeded = true
				}
			}

			// ...
			return succeeded, nil
		}
		// malformed
	}

	if err == nil {
		err = fmt.Errorf("unknown import/delegate field format")
	}

	ps.errFunc.add(err)

	return succeeded, err
}

func parseImport(rv map[string]interface{}, v *Value, ps *parseState, depth, mergeDepth int, relname string) error {
	_, err := parseImportImpl(rv, v, ps, depth, mergeDepth, relname, false)
	return err
}

func parseDelegate(rv map[string]interface{}, v *Value, ps *parseState, depth, mergeDepth int, relname string) (bool, error) {
	return parseImportImpl(rv, v, ps, depth, mergeDepth, relname, true)
}

func parseHostmaster(rv map[string]interface{}, v *Value, ps *parseState) {
	hm, ok := rv["email"]
	if !ok || hm == nil {
		return
	}

	if s, ok := hm.(string); ok {
		if !util.ValidateEmail(s) {
			ps.errFunc.add(fmt.Errorf("malformed e. mail address in email field"))
			return
		}

		v.Hostmaster = s
		return
	}

	ps.errFunc.add(fmt.Errorf("unknown email field format"))
}

func parseDS(rv map[string]interface{}, v *Value, ps *parseState) {
	rds, ok := rv["ds"]
	if !ok || rds == nil {
		return
	}

	v.DS = nil

	if dsa, ok := rds.([]interface{}); ok {
		for _, ds1 := range dsa {
			if len(v.DS) >= maxRecordsPerField {
				ps.errFunc.add(fmt.Errorf("ds field exceeds the maximum of %d records", maxRecordsPerField))
				return
			}
			if ds, ok := ds1.([]interface{}); ok {
				if len(ds) < 4 {
					ps.errFunc.add(fmt.Errorf("DS item must have four items"))
					continue
				}

				a1, ok := validateUint(ds[0], 0, math.MaxUint16)
				if !ok {
					ps.errFunc.add(fmt.Errorf("First item in DS value must be an integer between 0 and %d (key tag)", math.MaxUint16))
					continue
				}

				a2, ok := validateUint(ds[1], 0, math.MaxUint8)
				if !ok {
					ps.errFunc.add(fmt.Errorf("Second item in DS value must be an integer between 0 and %d (algorithm)", math.MaxUint8))
					continue
				}

				a3, ok := validateUint(ds[2], 0, math.MaxUint8)
				if !ok {
					ps.errFunc.add(fmt.Errorf("Third item in DS value must be an integer between 0 and %d (digest type)", math.MaxUint8))
					continue
				}

				a4, ok := ds[3].(string)
				if !ok {
					ps.errFunc.add(fmt.Errorf("Fourth item in DS value must be a string (digest)"))
					continue
				}

				a4b, err := base64.StdEncoding.DecodeString(a4)
				if err != nil {
					ps.errFunc.add(fmt.Errorf("Fourth item in DS value must be valid base64: %v", err))
					continue
				}

				if !ps.recordReserved() {
					return
				}

				a4h := hex.EncodeToString(a4b)
				v.DS = append(v.DS, &dns.DS{
					Hdr:        dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: defaultTTL},
					KeyTag:     uint16(a1),
					Algorithm:  uint8(a2),
					DigestType: uint8(a3),
					Digest:     a4h,
				})
			} else {
				ps.errFunc.add(fmt.Errorf("DS item must be an array"))
			}
		}
		return
	}

	ps.errFunc.add(fmt.Errorf("malformed DS field format"))
}

func parseTXT(rv map[string]interface{}, v *Value, ps *parseState) {
	rtxt, ok := rv["txt"]
	if !ok || rtxt == nil {
		return
	}

	if txta, ok := rtxt.([]interface{}); ok {
		// ["...", "..."] or [["...", "..."], ["...", "..."]]
		for _, vv := range txta {
			if len(v.TXT) >= maxRecordsPerField {
				ps.errFunc.add(fmt.Errorf("txt field exceeds the maximum of %d records", maxRecordsPerField))
				return
			}
			if sa, ok := vv.([]interface{}); ok {
				// [["...", "..."], ["...", "..."]]
				a := []string{}
				for _, x := range sa {
					if xs, ok := x.(string); ok && len(xs) <= 255 {
						a = append(a, xs)
					}
				}
				if len(a) > 0 {
					if !ps.recordReserved() {
						return
					}
					v.TXT = append(v.TXT, a)
				}
			} else if s, ok := vv.(string); ok {
				if !ps.recordReserved() {
					return
				}
				v.TXT = append(v.TXT, segmentizeTXT(s))
			} else {
				ps.errFunc.add(fmt.Errorf("malformed TXT value"))
				return
			}
		}
	} else {
		// "..."
		if s, ok := rtxt.(string); ok {
			if !ps.recordReserved() {
				return
			}
			v.TXT = append(v.TXT, segmentizeTXT(s))
		} else {
			ps.errFunc.add(fmt.Errorf("malformed TXT value"))
			return
		}
	}

	// Make sure the content of each TXT record does not exceed 65535 bytes.
	for i := range v.TXT {
		for {
			L := 0

			for j := range v.TXT[i] {
				L += len(v.TXT[i][j]) + 1
			}

			if L <= 65535 {
				break
			}

			// Pop segments until under the limit.
			v.TXT[i] = v.TXT[i][0 : len(v.TXT[i])-1]
		}
	}
}

func segmentizeTXT(txt string) (a []string) {
	for len(txt) > 255 {
		a = append(a, txt[0:255])
		txt = txt[255:]
	}
	a = append(a, txt)
	return
}

func parseMX(rv map[string]interface{}, v *Value, ps *parseState, relname string) {
	rmx, ok := rv["mx"]
	if !ok || rmx == nil {
		return
	}

	if sa, ok := rmx.([]interface{}); ok {
		for _, s := range sa {
			parseSingleMX(rv, s, v, ps, relname)
		}
		return
	}

	ps.errFunc.add(fmt.Errorf("malformed MX value"))
}

func parseSingleMX(rv map[string]interface{}, s interface{}, v *Value, ps *parseState, relname string) {
	sa, ok := s.([]interface{})
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	if len(sa) < 2 {
		ps.errFunc.add(fmt.Errorf("malformed MX value"))
		return
	}

	prio, ok := validateUint(sa[0], 0, math.MaxUint16)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed MX value: first item must be an integer between 0 and %d (preference)", math.MaxUint16))
		return
	}

	hostname, ok := sa[1].(string)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed MX value: second item must be a string (mail exchanger)"))
		return
	}

	if len(v.MX) >= maxRecordsPerField {
		ps.errFunc.add(fmt.Errorf("mx field exceeds the maximum of %d records", maxRecordsPerField))
		return
	}
	if !ps.recordReserved() {
		return
	}

	v.MX = append(v.MX, &dns.MX{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: defaultTTL},
		Preference: uint16(prio),
		Mx:         hostname,
	})
}

func parseSRV(rv map[string]interface{}, v *Value, ps *parseState, relname string) {
	rsvc, ok := rv["srv"]
	if !ok || rsvc == nil {
		return
	}

	v.SRV = nil

	if sa, ok := rsvc.([]interface{}); ok {
		for _, s := range sa {
			parseSingleService(rv, s, v, ps, relname)
		}
	} else {
		ps.errFunc.add(fmt.Errorf("malformed service value"))
	}
}

func parseSingleService(rv map[string]interface{}, svc interface{}, v *Value, ps *parseState, relname string) {
	svca, ok := svc.([]interface{})
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed service value"))
		return
	}

	if len(svca) < 4 {
		ps.errFunc.add(fmt.Errorf("malformed service value: must have four items"))
		return
	}

	//servicesUsed[sname] = struct{}{}

	priority, ok := validateUint(svca[0], 0, math.MaxUint16)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed service value: first item must be an integer between 0 and %d (priority)", math.MaxUint16))
		return
	}

	weight, ok := validateUint(svca[1], 0, math.MaxUint16)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed service value: second item must be an integer between 0 and %d (weight)", math.MaxUint16))
		return
	}

	port, ok := validateUint(svca[2], 0, math.MaxUint16)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed service value: third item must be an integer between 0 and %d (port number)", math.MaxUint16))
		return
	}

	hostname, ok := svca[3].(string)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed service value: fourth item must be a string (target)"))
		return
	}

	if len(v.SRV) >= maxRecordsPerField {
		ps.errFunc.add(fmt.Errorf("srv field exceeds the maximum of %d records", maxRecordsPerField))
		return
	}
	if !ps.recordReserved() {
		return
	}

	v.SRV = append(v.SRV, &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   "",
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   hostname,
	})
}

func parseRevocations(rv map[string]interface{}, v *Value, ps *parseState) {
	rrev, ok := rv["revoke"]
	if !ok || rrev == nil {
		return
	}

	v.Revocations = nil

	if sa, ok := rrev.([]interface{}); ok {
		for _, s := range sa {
			parseSingleRevocation(rv, s, v, ps)
		}
	} else {
		ps.errFunc.add(fmt.Errorf("malformed revocation value"))
	}
}

func parseSingleRevocation(rv map[string]interface{}, rev interface{}, v *Value, ps *parseState) {
	reva, ok := rev.([]interface{})
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed revocation value"))
		return
	}

	if len(reva) < 2 {
		ps.errFunc.add(fmt.Errorf("malformed revocation value: must have two items"))
		return
	}

	issuerHashPrefixHex, ok := reva[0].(string)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed revocation value: first item must be a string (issuer hash prefix)"))
		return
	}

	serialPrefixHex, ok := reva[1].(string)
	if !ok {
		ps.errFunc.add(fmt.Errorf("malformed revocation value: second item must be a string (serial number prefix)"))
		return
	}

	if len(v.Revocations) >= maxRecordsPerField {
		ps.errFunc.add(fmt.Errorf("revoke field exceeds the maximum of %d records", maxRecordsPerField))
		return
	}
	if !ps.recordReserved() {
		return
	}

	v.Revocations = append(v.Revocations, &Revocation{
		IssuerHashPrefixHex: issuerHashPrefixHex,
		SerialPrefixHex: serialPrefixHex,
	})
}

func convServiceValue(x interface{}) (string, error) {
	if x == nil {
		return "", nil
	} else if f, ok := x.(float64); ok {
		return strconv.FormatInt(int64(f), 10), nil
	} else if s, ok := x.(string); ok {
		return s, nil
	} else {
		return "", fmt.Errorf("malformed value: first item must be a string (application protocol)")
	}
}

func parseMap(rv map[string]interface{}, v *Value, ps *parseState, depth, mergeDepth int, relname string) {
	rmap, ok := rv["map"]
	if !ok || rmap == nil {
		return
	}

	m, ok := rmap.(map[string]interface{})
	if !ok {
		ps.errFunc.add(fmt.Errorf("Map value must be an object"))
		return
	}

	mapEntries := 0
	for mk, mv := range m {
		if mapEntries >= maxMapEntries {
			ps.errFunc.add(fmt.Errorf("map field exceeds the maximum of %d entries", maxMapEntries))
			return
		}
		mapEntries++

		if s, ok := mv.(string); ok {
			// deprecated case: "map": { "": "127.0.0.1" }
			mv = map[string]interface{}{"ip": []interface{}{s}}
			m[mk] = mv
		}

		if mvm, ok := mv.(map[string]interface{}); ok {
			if v.Map == nil {
				v.Map = make(map[string]*Value)
			}

			v2 := &Value{}
			if v2e, ok := v.Map[mk]; ok {
				v2 = v2e
			}

			// The parseState (merge graph and record budget) is shared with the
			// whole Value tree, so subdomains cannot re-import names already
			// merged elsewhere or accumulate records beyond the global budget.
			parse(mvm, v2, ps, depth+1, mergeDepth, "", relname)

			v.Map[mk] = v2

		} else {
			ps.errFunc.add(fmt.Errorf("Value in map object must be an object or string"))
			continue
		}
	}
}

// Moves items in {"map": {"": ...}} to the object itself, then deletes the ""
// entry in the map object.
func (v *Value) moveEmptyMapItems() {
	if ev, ok := v.Map[""]; ok {
		if len(v.IP) == 0 {
			v.IP = ev.IP
		}
		if len(v.IP6) == 0 {
			v.IP6 = ev.IP6
		}
		if len(v.NS) == 0 {
			v.NS = ev.NS
		}
		if len(v.DS) == 0 {
			v.DS = ev.DS
		}
		if len(v.TXT) == 0 {
			v.TXT = ev.TXT
		}
		if len(v.SRV) == 0 {
			v.SRV = ev.SRV
		}
		if len(v.MX) == 0 {
			v.MX = ev.MX
		}
		if len(v.Alias) == 0 {
			v.Alias = ev.Alias
		}
		if len(v.Translate) == 0 {
			v.Translate = ev.Translate
		}
		if len(v.Hostmaster) == 0 {
			v.Hostmaster = ev.Hostmaster
		}
		delete(v.Map, "")
		if len(v.Map) == 0 {
			v.Map = ev.Map
		}
	}
}

// makeJSONSafe walks an interface to ensure all maps use string keys so that
// encoding to JSON (or YAML) works. Some unmarshallers (e.g. CBOR) will
// create map[interface{}]interface{} which causes problems marshalling.
// See https://github.com/fxamacker/cbor/issues/206
// The function was taken from https://github.com/danielgtaylor/restish/blob/d16bdd717c3a73efbda8ba48a3af6bf8f5995b67/cli/formatter.go#L292-L338
func makeJSONSafe(obj interface{}) interface{} {
	value := reflect.ValueOf(obj)

	for value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Slice:
		if _, ok := obj.([]byte); ok {
			// Special case: byte slices get special encoding rules in various
			// formats, so keep them as-is. Without this is breaks the base64
			// encoding for JSON and gives you an array of integers instead.
			return obj
		}
		returnSlice := make([]interface{}, value.Len())
		for i := 0; i < value.Len(); i++ {
			returnSlice[i] = makeJSONSafe(value.Index(i).Interface())
		}
		return returnSlice
	case reflect.Map:
		tmpData := make(map[string]interface{})
		for _, k := range value.MapKeys() {
			kStr := ""
			if s, ok := k.Interface().(string); ok {
				kStr = s
			} else {
				kStr = fmt.Sprintf("%v", k.Interface())
			}
			tmpData[kStr] = makeJSONSafe(value.MapIndex(k).Interface())
		}
		return tmpData
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(value.Uint())
		// case reflect.Struct:
		// 	for i := 0; i < value.NumField(); i++ {
		// 		field := value.Field(i)
		// 		spew.Dump(field, field.Kind(), field.CanSet())
		// 		switch field.Kind() {
		// 		case reflect.Slice, reflect.Map, reflect.Struct, reflect.Ptr:
		// 			if field.CanSet() {
		// 				field.Set(reflect.ValueOf(makeJSONSafe(field.Interface())))
		// 			}
		// 		}
		// 	}
	}

	return obj
}
