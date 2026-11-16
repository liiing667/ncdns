package namecoin

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcjson"
)

// ErrNoSuchName is returned by NameQuery when the queried name does not exist
// in the Namecoin namespace.  It is the namecoin-layer equivalent of
// merr.ErrNoSuchDomain (NXDOMAIN).
var ErrNoSuchName = errors.New("name does not exist in the Namecoin namespace")

// LookupError is the error type returned by NameQuery for failures that are
// intrinsic to the name's data rather than to the RPC transport.  Callers can
// distinguish a permanent, name-specific failure from a transient backend
// outage using errors.As.
type LookupError struct {
	// Code classifies the failure.  It is never a "not found" condition,
	// which is reported via ErrNoSuchName.
	Code LookupErrorCode

	// Detail carries the underlying error, if any.  It may be nil.
	Detail error
}

// LookupErrorCode identifies the permanent failure class reported by a
// LookupError.
type LookupErrorCode int

const (
	// LookupErrorValue indicates that the RPC call succeeded but Namecoin
	// Core reported a non-empty value_error field, i.e. the name's value is
	// malformed or otherwise unusable.
	LookupErrorValue LookupErrorCode = iota

	// LookupErrorRPC indicates a JSON-RPC application error which is not a
	// transient connectivity problem (for example, an invalid request or an
	// internal server error).
	LookupErrorRPC

	// LookupErrorDecode indicates that the data returned by the RPC server
	// could not be decoded (for example, an invalid hex-encoded value).
	LookupErrorDecode
)

// String renders the error code in a human-readable form.
func (code LookupErrorCode) String() string {
	switch code {
	case LookupErrorValue:
		return "invalid name value"
	case LookupErrorRPC:
		return "namecoin RPC error"
	case LookupErrorDecode:
		return "undecodable namecoin RPC response"
	default:
		return fmt.Sprintf("unknown namecoin lookup error code %d", int(code))
	}
}

// Error implements the error interface.
func (e *LookupError) Error() string {
	if e.Detail != nil {
		return e.Code.String() + ": " + e.Detail.Error()
	}

	return e.Code.String()
}

// Unwrap exposes the underlying error to errors.Is and errors.As.
func (e *LookupError) Unwrap() error {
	return e.Detail
}

// classifyRPCError maps a JSON-RPC error onto the layered error model.
// ErrRPCWallet (-4) from name_show is the Namecoin Core convention for a
// nonexistent name and therefore maps to ErrNoSuchName.
func classifyRPCError(err error) error {
	var rpcErr *btcjson.RPCError
	if errors.As(err, &rpcErr) {
		if rpcErr.Code == btcjson.ErrRPCWallet {
			return ErrNoSuchName
		}

		return &LookupError{Code: LookupErrorRPC, Detail: err}
	}

	// Anything which is not a structured JSON-RPC error is a transport or
	// timeout problem, i.e. potentially transient, so it is passed through
	// unaltered for the caller to retry.
	return err
}
