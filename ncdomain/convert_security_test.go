package ncdomain_test

import (
	"strings"
	"testing"

	"github.com/namecoin/ncdns/ncdomain"
)

func parseCollectErrors(jsonValue string) (*ncdomain.Value, []error) {
	errs := []error{}
	errFunc := func(err error, isWarning bool) {
		if !isWarning {
			errs = append(errs, err)
		}
	}

	v := ncdomain.ParseValue("d/example", jsonValue, nil, errFunc)
	return v, errs
}

func TestOutOfRangeIntegersRejected(t *testing.T) {
	// Values that do not fit the DNS wire-format fields must be rejected
	// with a stable error instead of being silently truncated.
	cases := []struct {
		name      string
		jsonValue string
		field     string
	}{
		{"DS key tag too large", `{"ds":[[70000,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, "ds"},
		{"DS key tag negative", `{"ds":[[-1,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, "ds"},
		{"DS key tag fractional", `{"ds":[[1.5,8,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, "ds"},
		{"DS algorithm too large", `{"ds":[[12345,256,2,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, "ds"},
		{"DS digest type too large", `{"ds":[[12345,8,256,"4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]]}`, "ds"},
		{"MX preference too large", `{"mx":[[70000,"mx.example.bit."]]}`, "mx"},
		{"MX preference negative", `{"mx":[[-1,"mx.example.bit."]]}`, "mx"},
		{"MX preference fractional", `{"mx":[[1.5,"mx.example.bit."]]}`, "mx"},
		{"SRV priority too large", `{"srv":[[70000,0,80,"www.example.bit."]]}`, "service"},
		{"SRV weight negative", `{"srv":[[0,-1,80,"www.example.bit."]]}`, "service"},
		{"SRV port too large", `{"srv":[[0,0,70000,"www.example.bit."]]}`, "service"},
		{"SRV port fractional", `{"srv":[[0,0,80.5,"www.example.bit."]]}`, "service"},
	}

	for _, tc := range cases {
		v, errs := parseCollectErrors(tc.jsonValue)
		if len(errs) == 0 {
			t.Errorf("%s: expected an error, got none (value=%+v)", tc.name, v)
			continue
		}

		if !strings.Contains(strings.ToLower(errs[0].Error()), tc.field) {
			t.Errorf("%s: error %q does not mention field %q", tc.name, errs[0].Error(), tc.field)
		}

		switch {
		case strings.Contains(tc.jsonValue, `"ds"`):
			if len(v.DS) != 0 {
				t.Errorf("%s: malformed DS record was kept: %+v", tc.name, v.DS)
			}
		case strings.Contains(tc.jsonValue, `"mx"`):
			if len(v.MX) != 0 {
				t.Errorf("%s: malformed MX record was kept: %+v", tc.name, v.MX)
			}
		case strings.Contains(tc.jsonValue, `"srv"`):
			if len(v.SRV) != 0 {
				t.Errorf("%s: malformed SRV record was kept: %+v", tc.name, v.SRV)
			}
		}
	}
}

func TestRecordCountBudgetEnforced(t *testing.T) {
	// A huge number of records must not be accepted without bound.
	var b strings.Builder
	b.WriteString(`{"srv":[`)
	for i := 0; i < 5000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`[0,0,80,"www.example.bit."]`)
	}
	b.WriteString(`]}`)

	v, errs := parseCollectErrors(b.String())
	if len(errs) == 0 {
		t.Fatalf("expected record limit error, got none (kept %d SRV records)", len(v.SRV))
	}

	if len(v.SRV) >= 5000 {
		t.Fatalf("record limit not enforced: kept %d SRV records", len(v.SRV))
	}
}

func TestValidRecordsUnaffected(t *testing.T) {
	jsonValue := `{
		"ip": ["1.2.3.4"],
		"ip6": ["::beef"],
		"ns": ["ns1.example.com."],
		"ds": [[12345, 8, 2, "4tPJFvbe6scylOgmj7WIUESoM/xUWViPSpGEz8QaV2Y="]],
		"mx": [[10, "mx.example.bit."]],
		"srv": [[0, 0, 80, "www.example.bit."]],
		"txt": ["hello world"],
		"map": {"www": {"ip": "5.6.7.8"}}
	}`

	v, errs := parseCollectErrors(jsonValue)
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid value, got: %v", errs)
	}

	if len(v.IP) != 1 || len(v.IP6) != 1 || len(v.NS) != 1 || len(v.DS) != 1 ||
		len(v.MX) != 1 || len(v.SRV) != 1 || len(v.TXT) != 1 {
		t.Fatalf("valid records were dropped or altered: %+v", v)
	}

	if v.DS[0].KeyTag != 12345 || v.MX[0].Preference != 10 ||
		v.SRV[0].Port != 80 || v.SRV[0].Target != "www.example.bit." {
		t.Fatalf("valid record fields were altered: %+v", v)
	}
}

func TestImportCycleStillRejected(t *testing.T) {
	names := map[string]string{
		"d/a": `{"import":["d/b"],"ip":"1.2.3.4"}`,
		"d/b": `{"import":["d/a"],"ip6":"::beef"}`,
	}
	resolve := func(name string) (string, error) {
		s, ok := names[name]
		if !ok {
			return "", errNotFound
		}
		return s, nil
	}

	errs := []error{}
	errFunc := func(err error, isWarning bool) {
		if !isWarning {
			errs = append(errs, err)
		}
	}

	v := ncdomain.ParseValue("d/a", names["d/a"], resolve, errFunc)
	if v == nil {
		t.Fatal("ParseValue returned nil")
	}
	if len(v.IP) != 1 {
		t.Errorf("expected own IP record to survive, got %+v", v)
	}
}

var errNotFound = parseError("not found")

type parseError string

func (e parseError) Error() string { return string(e) }
