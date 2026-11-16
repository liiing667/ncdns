package namecoin

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/rpcclient"
	"gopkg.in/hlandau/madns.v2/merr"

	"github.com/namecoin/ncbtcjson"
	"github.com/namecoin/ncrpcclient"
)

// NameResult is the successful outcome of a name lookup.  In addition to the
// name's JSON value it carries the immutable identity of the namecoin claim
// (transaction id and output index), which serves as the claim version used by
// consumers such as the TLS PKI cache to invalidate stale entries.
type NameResult struct {
	// Value is the raw JSON value of the name, exactly as returned by
	// name_show.
	Value string

	// ClaimVersion uniquely identifies the current claim.  It is composed
	// of the funding transaction id and the output index.  Empty when the
	// server is an old Namecoin Core release which omits these fields.
	ClaimVersion string

	// TxID is the funding transaction id of the current claim.
	TxID string

	// Vout is the output index within TxID.
	Vout uint32
}

// Client represents an ncrpcclient.Client with an additional DNS-friendly
// convenience wrapper around NameShow.
type Client struct {
	*ncrpcclient.Client
}

func New(config *rpcclient.ConnConfig, ntfnHandlers *rpcclient.NotificationHandlers) (*Client, error) {
	ncClient, err := ncrpcclient.New(config, ntfnHandlers)
	if err != nil {
		return nil, err
	}

	return &Client{ncClient}, nil
}

// NameQueryResult returns the value and claim identity of a name.
//
// Errors are layered so that callers can react according to failure class:
//   - merr.ErrNoSuchDomain: the name does not exist (NXDOMAIN).
//   - *LookupError: a permanent, name-specific failure, such as a non-empty
//     value_error field or an application-level RPC error.  Such failures
//     must not be silently treated as a successful lookup.
//   - any other error: a transient transport or timeout failure, which the
//     caller may retry.
//
// The streamIsolationID is forwarded to name_show via the streamID option so
// that distinct query streams never share an upstream Namecoin Core wallet
// context.  Old Namecoin Core releases which do not understand the options
// parameter remain compatible because an empty options struct is omitted by
// ncbtcjson.
func (c *Client) NameQueryResult(name string, streamIsolationID string) (NameResult, error) {
	nameData, err := c.NameShow(name, &ncbtcjson.NameShowOptions{StreamID: streamIsolationID})
	if err != nil {
		err = classifyRPCError(err)
		if errors.Is(err, ErrNoSuchName) {
			// ErrRPCWallet from name_show indicates that the name
			// does not exist.
			return NameResult{}, merr.ErrNoSuchDomain
		}

		// A *LookupError is a permanent, name-specific failure; any
		// other error is a transient transport/timeout failure the
		// caller may retry.  Both are passed through unaltered.
		return NameResult{}, err
	}

	// The RPC succeeded, but Namecoin Core may report that the value itself
	// is unusable through the value_error field.  Discarding this previously
	// meant a malformed value could be treated as a successful lookup, so
	// surface it as a permanent, name-specific lookup error.
	if nameData.ValueError != "" {
		return NameResult{}, &LookupError{
			Code:   LookupErrorValue,
			Detail: fmt.Errorf("%s: %s", name, nameData.ValueError),
		}
	}

	// We got the name data.  Return it together with the claim identity.
	return NameResult{
		Value:        nameData.Value,
		ClaimVersion: fmt.Sprintf("%s:%d", nameData.TxID, nameData.Vout),
		TxID:         nameData.TxID,
		Vout:         nameData.Vout,
	}, nil
}

// NameQuery returns the value of a name.  If the name doesn't exist, the error
// returned will be merr.ErrNoSuchDomain.  It is a backwards-compatible wrapper
// around NameQueryResult for callers which only need the raw value; new
// callers should prefer NameQueryResult so that the claim version is available
// for cache invalidation.
func (c *Client) NameQuery(name string, streamIsolationID string) (string, error) {
	result, err := c.NameQueryResult(name, streamIsolationID)
	if err != nil {
		return "", err
	}

	return result.Value, nil
}
