package namecoin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"gopkg.in/hlandau/madns.v2/merr"
)

type rpcRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// newMockClient starts a JSON-RPC server whose behavior is driven by handle
// and returns a Client connected to it.  The recorded requests let tests
// verify that the stream isolation ID reaches name_show.
func newMockClient(t *testing.T, handle func(req *rpcRequest, recorded *[]rpcRequest) (interface{}, error)) (*Client, *[]rpcRequest) {
	t.Helper()

	recorded := &[]rpcRequest{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		*recorded = append(*recorded, req)

		result, err := handle(&req, recorded)

		response := rpcResponse{
			JSONRPC: "1.0",
			ID:      json.RawMessage(req.ID),
		}
		if err != nil {
			response.Error = btcjson.NewRPCError(btcjson.ErrRPCMisc, err.Error())
		} else {
			response.Result = result
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)

	connCfg := &rpcclient.ConnConfig{
		Host:         server.Listener.Addr().String(),
		User:         "testuser",
		Pass:         "testpass",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := New(connCfg, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	return client, recorded
}

func nameShowResult(value, valueError, txID string, vout uint32) map[string]interface{} {
	return map[string]interface{}{
		"name":           "d/example",
		"name_encoding":  "ascii",
		"name_error":     "",
		"value":          value,
		"value_encoding": "utf8",
		"value_error":    valueError,
		"txid":           txID,
		"address":        "",
		"vout":           vout,
		"height":         100,
		"expires_in":     36000,
		"ismine":         false,
		"expired":        false,
	}
}

func TestNameQueryResultSuccessCarriesClaimVersion(t *testing.T) {
	client, recorded := newMockClient(t, func(req *rpcRequest, _ *[]rpcRequest) (interface{}, error) {
		return nameShowResult(`{"ip":"192.0.2.1"}`, "", "abc123", 7), nil
	})

	result, err := client.NameQueryResult("d/example", "tenant-42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Value != `{"ip":"192.0.2.1"}` {
		t.Errorf("unexpected value: %q", result.Value)
	}

	if result.TxID != "abc123" || result.Vout != 7 || result.ClaimVersion != "abc123:7" {
		t.Errorf("claim identity not propagated: %+v", result)
	}

	if len(*recorded) != 1 {
		t.Fatalf("expected 1 RPC request, got %d", len(*recorded))
	}

	// The stream isolation ID must reach the RPC layer so distinct tenants
	// never share an upstream wallet context.
	var nameArg string
	if err := json.Unmarshal((*recorded)[0].Params[0], &nameArg); err != nil {
		t.Fatalf("could not decode name parameter: %v", err)
	}

	if nameArg != "d/example" {
		t.Errorf("unexpected name parameter: %q", nameArg)
	}

	var options struct {
		StreamID string `json:"streamID"`
	}
	if len((*recorded)[0].Params) < 2 {
		t.Fatal("name_show options parameter was not sent")
	}

	if err := json.Unmarshal((*recorded)[0].Params[1], &options); err != nil {
		t.Fatalf("could not decode options parameter: %v", err)
	}

	if options.StreamID != "tenant-42" {
		t.Errorf("stream isolation ID not forwarded: %+v", options)
	}
}

func TestNameQueryResultValueErrorIsPermanent(t *testing.T) {
	client, _ := newMockClient(t, func(req *rpcRequest, _ *[]rpcRequest) (interface{}, error) {
		// A successful RPC transport carrying an unusable value.
		return nameShowResult("garbage", "bad-cbor-value", "abc123", 0), nil
	})

	_, err := client.NameQueryResult("d/example", "")
	if err == nil {
		t.Fatal("expected an error for value_error, got nil")
	}

	var lookupErr *LookupError
	if !errors.As(err, &lookupErr) {
		t.Fatalf("expected *LookupError, got %T: %v", err, err)
	}

	if lookupErr.Code != LookupErrorValue {
		t.Errorf("expected LookupErrorValue, got %v", lookupErr.Code)
	}

	// The legacy wrapper must report the same failure instead of returning
	// the malformed value as if it were a successful lookup.
	if value, legacyErr := client.NameQuery("d/example", ""); legacyErr == nil {
		t.Errorf("NameQuery accepted a value_error result: %q", value)
	}
}

func TestNameQueryResultNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := rpcResponse{
			JSONRPC: "1.0",
			ID:      1,
			Error:   btcjson.NewRPCError(btcjson.ErrRPCWallet, "name not found"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	connCfg := &rpcclient.ConnConfig{
		Host:         server.Listener.Addr().String(),
		User:         "testuser",
		Pass:         "testpass",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := New(connCfg, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = client.NameQueryResult("d/missing", "")
	if !errors.Is(err, merr.ErrNoSuchDomain) {
		t.Fatalf("expected merr.ErrNoSuchDomain, got %T: %v", err, err)
	}

	_, err = client.NameQuery("d/missing", "")
	if !errors.Is(err, merr.ErrNoSuchDomain) {
		t.Fatalf("legacy NameQuery expected merr.ErrNoSuchDomain, got %T: %v", err, err)
	}
}

func TestNameQueryResultApplicationRPCErrorIsPermanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := rpcResponse{
			JSONRPC: "1.0",
			ID:      1,
			Error:   btcjson.NewRPCError(btcjson.ErrRPCInvalidParameter, "invalid params"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	connCfg := &rpcclient.ConnConfig{
		Host:         server.Listener.Addr().String(),
		User:         "testuser",
		Pass:         "testpass",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := New(connCfg, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = client.NameQueryResult("d/example", "")
	var lookupErr *LookupError
	if !errors.As(err, &lookupErr) {
		t.Fatalf("expected *LookupError for application RPC error, got %T: %v", err, err)
	}

	if lookupErr.Code != LookupErrorRPC {
		t.Errorf("expected LookupErrorRPC, got %v", lookupErr.Code)
	}

	if errors.Is(err, merr.ErrNoSuchDomain) {
		t.Error("an invalid-params RPC error must not be reported as NXDOMAIN")
	}
}

func TestNameQueryResultTransportFailureIsTransient(t *testing.T) {
	// An HTTP 500 with a non-JSON body fails outside the JSON-RPC error
	// layer, so it represents a transient backend failure rather than a
	// structured application error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "namecoind restarting", http.StatusInternalServerError)
	}))
	defer server.Close()

	connCfg := &rpcclient.ConnConfig{
		Host:         server.Listener.Addr().String(),
		User:         "testuser",
		Pass:         "testpass",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := New(connCfg, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = client.NameQueryResult("d/example", "")
	if err == nil {
		t.Fatal("expected a transport error, got nil")
	}

	var lookupErr *LookupError
	if errors.As(err, &lookupErr) {
		t.Errorf("transport failures must stay transient, not become *LookupError: %v", err)
	}

	if errors.Is(err, merr.ErrNoSuchDomain) {
		t.Error("a transport failure must not be reported as NXDOMAIN")
	}
}

func TestNameQueryEmptyStreamOmitsOptionsForOldCore(t *testing.T) {
	client, recorded := newMockClient(t, func(req *rpcRequest, _ *[]rpcRequest) (interface{}, error) {
		// Old Namecoin Core releases do not understand the options
		// parameter; an empty options struct must therefore be omitted
		// entirely so such servers keep working.
		return nameShowResult(`{}`, "", "", 0), nil
	})

	if _, err := client.NameQueryResult("d/example", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(*recorded) != 1 {
		t.Fatalf("expected 1 RPC request, got %d", len(*recorded))
	}

	if len((*recorded)[0].Params) != 1 {
		t.Fatalf("expected only the name parameter, got %d params", len((*recorded)[0].Params))
	}

	var nameArg string
	if err := json.Unmarshal((*recorded)[0].Params[0], &nameArg); err != nil {
		t.Fatalf("could not decode name parameter: %v", err)
	}

	if nameArg != "d/example" {
		t.Errorf("unexpected name parameter: %q", nameArg)
	}
}

func TestClassifyRPCError(t *testing.T) {
	if err := classifyRPCError(btcjson.NewRPCError(btcjson.ErrRPCWallet, "missing")); !errors.Is(err, ErrNoSuchName) {
		t.Errorf("wallet error should map to ErrNoSuchName, got %v", err)
	}

	err := classifyRPCError(btcjson.NewRPCError(btcjson.ErrRPCInternal.Code, "boom"))
	var lookupErr *LookupError
	if !errors.As(err, &lookupErr) || lookupErr.Code != LookupErrorRPC {
		t.Errorf("structured RPC error should map to LookupErrorRPC, got %v", err)
	}

	plain := errors.New("connection reset")
	if err := classifyRPCError(plain); !errors.Is(err, plain) {
		t.Errorf("non-RPC errors must pass through unaltered, got %v", err)
	}
}
