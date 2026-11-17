package ncdomain

import "fmt"
import "github.com/miekg/dns"

// Budget limit categories, used in BudgetExceededError.Category and logs.
const (
	BudgetCategoryQueryBytes    = "query-bytes"
	BudgetCategoryRecords       = "records"
	BudgetCategoryReferences    = "references"
	BudgetCategoryResponseBytes = "response-bytes"
)

// Default per-request budget limits.
const (
	DefaultMaxQueryBytes           = 512
	DefaultMaxRecords              = 512
	DefaultMaxReferenceResolutions = 64
	DefaultMaxResponseBytes        = 65536
)

// Budget describes per-request resource limits shared by the server, backend
// and ncdomain layers while processing a single DNS query. A zero field means
// "use the default"; a negative field disables that limit entirely.
type Budget struct {
	// Maximum size in bytes of the query name.
	MaxQueryBytes int

	// Maximum number of resource records produced for a single query.
	MaxRecords int

	// Maximum number of import/delegate reference resolutions per query.
	MaxReferenceResolutions int

	// Maximum total size in bytes of the response records for a single query.
	MaxResponseBytes int
}

// DefaultBudget returns a Budget with all limits set to their defaults.
func DefaultBudget() Budget {
	return Budget{
		MaxQueryBytes:           DefaultMaxQueryBytes,
		MaxRecords:              DefaultMaxRecords,
		MaxReferenceResolutions: DefaultMaxReferenceResolutions,
		MaxResponseBytes:        DefaultMaxResponseBytes,
	}
}

// Normalize replaces zero fields with their defaults and converts negative
// fields (meaning "unlimited") to zero.
func (b Budget) Normalize() Budget {
	if b.MaxQueryBytes == 0 {
		b.MaxQueryBytes = DefaultMaxQueryBytes
	} else if b.MaxQueryBytes < 0 {
		b.MaxQueryBytes = 0
	}

	if b.MaxRecords == 0 {
		b.MaxRecords = DefaultMaxRecords
	} else if b.MaxRecords < 0 {
		b.MaxRecords = 0
	}

	if b.MaxReferenceResolutions == 0 {
		b.MaxReferenceResolutions = DefaultMaxReferenceResolutions
	} else if b.MaxReferenceResolutions < 0 {
		b.MaxReferenceResolutions = 0
	}

	if b.MaxResponseBytes == 0 {
		b.MaxResponseBytes = DefaultMaxResponseBytes
	} else if b.MaxResponseBytes < 0 {
		b.MaxResponseBytes = 0
	}

	return b
}

// BudgetExceededError is returned when a per-request resource budget limit
// is exceeded. Category identifies which limit was hit.
type BudgetExceededError struct {
	Category string
	Limit    int
	Actual   int
}

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf("request resource budget exceeded (%s: %d > %d)", e.Category, e.Actual, e.Limit)
}

// RequestBudget tracks resource consumption for a single request against a
// Budget. A nil *RequestBudget permits everything, so it is safe to call its
// methods on a nil receiver.
type RequestBudget struct {
	budget     Budget
	references int
}

// NewRequestBudget creates a RequestBudget enforcing the given budget
// (normalized so that zero fields use the defaults).
func NewRequestBudget(b Budget) *RequestBudget {
	return &RequestBudget{
		budget: b.Normalize(),
	}
}

// CheckQueryBytes accounts for the size of the query name.
func (rb *RequestBudget) CheckQueryBytes(n int) error {
	if rb == nil || rb.budget.MaxQueryBytes <= 0 {
		return nil
	}

	if n > rb.budget.MaxQueryBytes {
		return &BudgetExceededError{Category: BudgetCategoryQueryBytes, Limit: rb.budget.MaxQueryBytes, Actual: n}
	}

	return nil
}

// AddReference accounts for one import/delegate reference resolution.
func (rb *RequestBudget) AddReference() error {
	if rb == nil || rb.budget.MaxReferenceResolutions <= 0 {
		return nil
	}

	rb.references++
	if rb.references > rb.budget.MaxReferenceResolutions {
		return &BudgetExceededError{Category: BudgetCategoryReferences, Limit: rb.budget.MaxReferenceResolutions, Actual: rb.references}
	}

	return nil
}

// CheckRecords accounts for the number of records produced for the response.
func (rb *RequestBudget) CheckRecords(n int) error {
	if rb == nil || rb.budget.MaxRecords <= 0 {
		return nil
	}

	if n > rb.budget.MaxRecords {
		return &BudgetExceededError{Category: BudgetCategoryRecords, Limit: rb.budget.MaxRecords, Actual: n}
	}

	return nil
}

// CheckResponseBytes accounts for the total packed size of the response
// records.
func (rb *RequestBudget) CheckResponseBytes(n int) error {
	if rb == nil || rb.budget.MaxResponseBytes <= 0 {
		return nil
	}

	if n > rb.budget.MaxResponseBytes {
		return &BudgetExceededError{Category: BudgetCategoryResponseBytes, Limit: rb.budget.MaxResponseBytes, Actual: n}
	}

	return nil
}

// ResponseBytes returns the packed size in bytes of a DNS message containing
// the given records in its answer section.
func ResponseBytes(rrs []dns.RR) int {
	msg := new(dns.Msg)
	msg.Answer = rrs
	return msg.Len()
}
