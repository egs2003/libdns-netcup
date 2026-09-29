package netcup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

// mockRestServer emulates just enough of api.netcup.com/v1 to exercise the
// REST branch of the Provider: domain lookup, adding a challenge (with
// immediate "deployed" status, so tests don't have to wait ~60s), and
// deleting a challenge.
func mockRestServer(t *testing.T, domainID int64, fqdn string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	deployed := map[string]bool{}

	mux := http.NewServeMux()
	mux.HandleFunc("/domain", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("fqdn"); got != fqdn {
			writeRestError(w, http.StatusOK, false, "resourceDoesNotExist", "not found")
			return
		}
		writeRestResult(w, http.StatusOK, []restDomain{{ID: domainID, FQDN: fqdn, IsDnsManaged: true}})
	})
	prefix := fmt.Sprintf("/domain/%d/acme/challenge/", domainID)
	mux.HandleFunc(fmt.Sprintf("/domain/%d/acme/challenge", domainID), func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Scope string `json:"scope"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		mu.Lock()
		deployed[body.Scope+"/"+body.Value] = true
		mu.Unlock()
		writeRestResult(w, http.StatusOK, map[string]any{"scope": body.Scope})
	})
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, prefix)
		mu.Lock()
		ok := deployed[key]
		mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			if !ok {
				writeRestError(w, http.StatusNotFound, false, "resourceDoesNotExist", "not found")
				return
			}
			writeRestResult(w, http.StatusOK, map[string]string{"status": "deployed"})
		case http.MethodDelete:
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			mu.Lock()
			delete(deployed, key)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return httptest.NewServer(mux)
}

func writeRestResult(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restEnvelope{
		Success: true,
		Result:  mustMarshal(result),
	})
}

func writeRestError(w http.ResponseWriter, status int, success bool, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restEnvelope{
		Success: success,
		Errors:  []restErrorEntry{{Code: code, Message: message}},
	})
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestUseRest(t *testing.T) {
	cases := []struct {
		name                                string
		customerNumber, apiKey, apiPassword string
		want                                bool
	}{
		{"legacy: all three fields set", "1", "k", "p", false},
		{"rest: only api key set", "", "k", "", true},
		{"rest: customer number set but no password", "1", "k", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{CustomerNumber: tc.customerNumber, APIKey: tc.apiKey, APIPassword: tc.apiPassword}
			if got := p.useRest(); got != tc.want {
				t.Errorf("useRest() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRestScope(t *testing.T) {
	cases := []struct {
		name      string
		relative  string
		wantScope string
		wantErr   bool
	}{
		{"apex challenge", "_acme-challenge", "@", false},
		{"subdomain challenge", "_acme-challenge.bw", "bw", false},
		{"nested subdomain challenge", "_acme-challenge.a.b", "a.b", false},
		{"unrelated record", "www", "", true},
		{"similar but wrong prefix", "_acme-challenges.bw", "", true},
		{"empty scope after prefix", "_acme-challenge.", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := restScope(tc.relative)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("restScope(%q) = %q, nil; want an error", tc.relative, scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("restScope(%q) unexpected error: %v", tc.relative, err)
			}
			if scope != tc.wantScope {
				t.Errorf("restScope(%q) = %q, want %q", tc.relative, scope, tc.wantScope)
			}
		})
	}
}

func TestAppendAndDeleteRecordsRest(t *testing.T) {
	const zone = "example.com."
	const fqdn = "example.com"
	srv := mockRestServer(t, 42, fqdn)
	defer srv.Close()

	p := &Provider{APIKey: "test-key"} // APIPassword empty -> REST mode

	// appendRecordsRest/deleteRecordsRest build their own restClient
	// pointed at restAPIURL, so redirect that at the test server for the
	// duration of the test.
	restoreBaseURL := restAPIURL
	restAPIURL = srv.URL
	defer func() { restAPIURL = restoreBaseURL }()

	record := libdns.RR{Type: "TXT", Name: "_acme-challenge.bw", Data: "dGVzdC12YWx1ZQ"}

	appended, err := p.AppendRecords(context.Background(), zone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(appended) != 1 {
		t.Fatalf("AppendRecords: got %d records, want 1", len(appended))
	}

	// A record type or name the REST API can't handle must produce an error
	// and must not be silently accepted.
	bad := libdns.RR{Type: "TXT", Name: "www", Data: "irrelevant"}
	if _, err := p.AppendRecords(context.Background(), zone, []libdns.Record{bad}); err == nil {
		t.Fatal("AppendRecords with an unsupported record name should have failed")
	}

	deleted, err := p.DeleteRecords(context.Background(), zone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("DeleteRecords: got %d records, want 1", len(deleted))
	}

	// Deleting an already-deleted (or never-existing) record is a no-op
	// success, mirroring how the legacy API behaves for records not found.
	deleted, err = p.DeleteRecords(context.Background(), zone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("DeleteRecords of an already-removed record should not error: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("DeleteRecords of an already-removed record: got %d, want 1 (404 treated as success)", len(deleted))
	}
}

func TestGetAndSetRecordsRestUnsupported(t *testing.T) {
	p := &Provider{APIKey: "test-key"}
	if _, err := p.GetRecords(context.Background(), "example.com."); err == nil {
		t.Fatal("GetRecords should be unsupported in REST mode")
	}
	if _, err := p.SetRecords(context.Background(), "example.com.", nil); err == nil {
		t.Fatal("SetRecords should be unsupported in REST mode")
	}
}
