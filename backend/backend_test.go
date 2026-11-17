package backend

import "errors"
import "testing"

import "github.com/namecoin/ncdns/ncdomain"

func newBudgetTestBackend(t *testing.T, budget ncdomain.Budget) *Backend {
	t.Helper()

	b, err := New(&Config{
		FakeNames: map[string]string{
			"d/example":  `{"ip":["1.2.3.4","5.6.7.8","9.10.11.12"]}`,
			"d/ref1":     `{"ip":"10.0.0.1"}`,
			"d/ref2":     `{"ip":"10.0.0.2"}`,
			"d/importer": `{"import":[["d/ref1"],["d/ref2"]]}`,
		},
		Budget: budget,
	})
	if err != nil {
		t.Fatalf("couldn't create backend: %v", err)
	}

	return b
}

func expectBudgetError(t *testing.T, err error, category string) {
	t.Helper()

	var bee *ncdomain.BudgetExceededError
	if !errors.As(err, &bee) {
		t.Fatalf("expected BudgetExceededError (%s), got %v", category, err)
	}

	if bee.Category != category {
		t.Fatalf("expected budget category %q, got %q", category, bee.Category)
	}
}

func TestLookupNormalQueryUnaffected(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{})

	rrs, err := b.Lookup("example.bit.", "")
	if err != nil {
		t.Fatalf("normal query failed: %v", err)
	}

	if len(rrs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(rrs))
	}
}

func TestLookupQueryBytesBudget(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{MaxQueryBytes: 4})

	_, err := b.Lookup("example.bit.", "")
	expectBudgetError(t, err, ncdomain.BudgetCategoryQueryBytes)
}

func TestLookupRecordsBudget(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{MaxRecords: 2})

	_, err := b.Lookup("example.bit.", "")
	expectBudgetError(t, err, ncdomain.BudgetCategoryRecords)
}

func TestLookupResponseBytesBudget(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{MaxResponseBytes: 16})

	_, err := b.Lookup("example.bit.", "")
	expectBudgetError(t, err, ncdomain.BudgetCategoryResponseBytes)
}

func TestLookupReferencesBudget(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{MaxReferenceResolutions: 1})

	_, err := b.Lookup("importer.bit.", "")
	expectBudgetError(t, err, ncdomain.BudgetCategoryReferences)
}

func TestLookupReferencesWithinBudget(t *testing.T) {
	b := newBudgetTestBackend(t, ncdomain.Budget{MaxReferenceResolutions: 2})

	rrs, err := b.Lookup("importer.bit.", "")
	if err != nil {
		t.Fatalf("query within budget failed: %v", err)
	}

	// The second import's "ip" replaces the first per merge semantics.
	if len(rrs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rrs))
	}
}
