package ncdomain_test

import "errors"
import "testing"

import "github.com/namecoin/ncdns/ncdomain"

func budgetTestResolve(name string) (string, error) {
	return `{"ip":"1.2.3.4"}`, nil
}

func TestReferenceBudgetExceeded(t *testing.T) {
	var budgetErr *ncdomain.BudgetExceededError
	errFunc := ncdomain.ErrorFunc(func(err error, isWarning bool) {
		var bee *ncdomain.BudgetExceededError
		if errors.As(err, &bee) && budgetErr == nil {
			budgetErr = bee
		}
	})

	rb := ncdomain.NewRequestBudget(ncdomain.Budget{MaxReferenceResolutions: 1})
	v := ncdomain.ParseValueWithBudget("d/example", `{"import":[["d/a"],["d/b"]]}`, budgetTestResolve, errFunc, rb)
	if v == nil {
		t.Fatalf("expected non-nil value")
	}

	if budgetErr == nil {
		t.Fatalf("expected a budget exceeded error")
	}

	if budgetErr.Category != ncdomain.BudgetCategoryReferences {
		t.Fatalf("wrong budget category: %q", budgetErr.Category)
	}

	// The first import is within budget and must still be merged.
	if len(v.IP) != 1 {
		t.Fatalf("expected first import to be merged, got %d IPs", len(v.IP))
	}
}

func TestReferenceBudgetDefaultUnaffected(t *testing.T) {
	errCount := 0
	errFunc := ncdomain.ErrorFunc(func(err error, isWarning bool) {
		errCount++
	})

	// Default budget: two imports are well within limits.
	rb := ncdomain.NewRequestBudget(ncdomain.Budget{})
	v := ncdomain.ParseValueWithBudget("d/example", `{"import":[["d/a"],["d/b"]]}`, budgetTestResolve, errFunc, rb)
	if v == nil {
		t.Fatalf("expected non-nil value")
	}

	if errCount != 0 {
		t.Fatalf("expected no errors, got %d", errCount)
	}

	if len(v.IP) != 1 {
		t.Fatalf("expected imports to be merged, got %d IPs", len(v.IP))
	}
}

func TestParseValueWithoutBudgetUnlimited(t *testing.T) {
	errCount := 0
	errFunc := ncdomain.ErrorFunc(func(err error, isWarning bool) {
		errCount++
	})

	// ParseValue (no budget) must behave as before regardless of import count.
	v := ncdomain.ParseValue("d/example", `{"import":[["d/a"],["d/b"],["d/c"]]}`, budgetTestResolve, errFunc)
	if v == nil {
		t.Fatalf("expected non-nil value")
	}

	if errCount != 0 {
		t.Fatalf("expected no errors, got %d", errCount)
	}
}

func TestRequestBudgetLimits(t *testing.T) {
	rb := ncdomain.NewRequestBudget(ncdomain.Budget{
		MaxQueryBytes:    4,
		MaxRecords:       2,
		MaxResponseBytes: 16,
	})

	if err := rb.CheckQueryBytes(4); err != nil {
		t.Fatalf("query bytes at limit should pass: %v", err)
	}

	err := rb.CheckQueryBytes(5)
	var bee *ncdomain.BudgetExceededError
	if !errors.As(err, &bee) || bee.Category != ncdomain.BudgetCategoryQueryBytes {
		t.Fatalf("expected query-bytes budget error, got %v", err)
	}

	err = rb.CheckRecords(3)
	if !errors.As(err, &bee) || bee.Category != ncdomain.BudgetCategoryRecords {
		t.Fatalf("expected records budget error, got %v", err)
	}

	err = rb.CheckResponseBytes(17)
	if !errors.As(err, &bee) || bee.Category != ncdomain.BudgetCategoryResponseBytes {
		t.Fatalf("expected response-bytes budget error, got %v", err)
	}
}

func TestRequestBudgetNilAndUnlimited(t *testing.T) {
	var rb *ncdomain.RequestBudget
	if err := rb.CheckQueryBytes(1 << 20); err != nil {
		t.Fatalf("nil budget should permit everything: %v", err)
	}
	if err := rb.AddReference(); err != nil {
		t.Fatalf("nil budget should permit everything: %v", err)
	}

	// Negative limits disable the corresponding check.
	rb = ncdomain.NewRequestBudget(ncdomain.Budget{MaxRecords: -1})
	if err := rb.CheckRecords(1 << 20); err != nil {
		t.Fatalf("disabled limit should permit everything: %v", err)
	}
}
