package netcup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

// mockRestServer emulates enough of api.netcup.com/v1 to exercise the REST
// branch of the Provider end-to-end: domain lookup, applying changesets
// (create/delete), and listing revisions/records, backed by a simple
// in-memory zone so GetRecords/SetRecords round-trip realistically.
type mockRestServer struct {
	t        *testing.T
	domainID int64
	fqdn     string

	mu        sync.Mutex
	records   []restRecord
	revisions []restRevision
	nextRecID int
	nextRevID int
}

func newMockRestServer(t *testing.T, domainID int64, fqdn string) *httptest.Server {
	t.Helper()
	m := &mockRestServer{t: t, domainID: domainID, fqdn: fqdn}

	mux := http.NewServeMux()
	mux.HandleFunc("/domain", m.handleDomain)
	mux.HandleFunc(fmt.Sprintf("/domain/%d/changeset", domainID), m.handleChangeset)
	mux.HandleFunc(fmt.Sprintf("/domain/%d/dns/revision", domainID), m.handleListRevisions)
	mux.HandleFunc(fmt.Sprintf("/domain/%d/dns/revision/", domainID), m.handleRevisionSub)
	return httptest.NewServer(mux)
}

func (m *mockRestServer) handleDomain(w http.ResponseWriter, r *http.Request) {
	if got := r.URL.Query().Get("fqdn"); got != m.fqdn {
		writeRestError(w, http.StatusOK, false, "resourceDoesNotExist", "not found")
		return
	}
	writeRestResult(w, http.StatusOK, []restDomain{{ID: m.domainID, FQDN: m.fqdn, IsDnsManaged: true}})
}

func (m *mockRestServer) handleChangeset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AutoCommit bool              `json:"autoCommit"`
		Create     []restRecordInput `json:"create"`
		Delete     []restRecordInput `json:"delete"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		m.t.Fatalf("decoding changeset body: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, del := range body.Delete {
		found := false
		for i, ex := range m.records {
			if ex.Name == del.Name && ex.Type == del.Type && ex.Data == del.Data && ex.TTL == del.TTL {
				m.records = append(m.records[:i], m.records[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			writeRestError(w, http.StatusUnprocessableEntity, false, "recordDoesNotExist",
				fmt.Sprintf("no record matching %+v", del))
			return
		}
	}
	for _, cr := range body.Create {
		m.nextRecID++
		m.records = append(m.records, restRecord{
			Identifier: fmt.Sprintf("rec-%d", m.nextRecID),
			Name:       cr.Name,
			Type:       cr.Type,
			Data:       cr.Data,
			TTL:        cr.TTL,
		})
	}

	m.nextRevID++
	rev := restRevision{
		Identifier: fmt.Sprintf("rev-%d", m.nextRevID),
		CreatedAt:  fmt.Sprintf("2026-01-01T00:00:%02dZ", m.nextRevID%60),
		State:      "committed",
	}
	m.revisions = append(m.revisions, rev)

	writeRestResult(w, http.StatusOK, rev)
}

func (m *mockRestServer) handleListRevisions(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeRestResultPaginated(w, http.StatusOK, m.revisions)
}

func (m *mockRestServer) handleRevisionSub(w http.ResponseWriter, r *http.Request) {
	// Only .../record is used by this client; respond with the current
	// in-memory record set regardless of which revision ID was asked for,
	// since this mock keeps a single flat zone state rather than per-
	// revision snapshots (sufficient for exercising the client logic).
	m.mu.Lock()
	defer m.mu.Unlock()
	writeRestResultPaginated(w, http.StatusOK, m.records)
}

func writeRestResult(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restEnvelope{Success: true, Result: mustMarshal(result)})
}

func writeRestResultPaginated(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restEnvelope{
		Success: true,
		Meta:    &restMeta{Pagination: &restPagination{Page: 1, PerPage: 100, LastPage: 1}},
		Result:  mustMarshal(result),
	})
}

func writeRestError(w http.ResponseWriter, status int, success bool, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restEnvelope{Success: success, Errors: []restErrorEntry{{Code: code, Message: message}}})
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func withTestRestAPIURL(t *testing.T, url string) {
	t.Helper()
	orig := restAPIURL
	restAPIURL = url
	t.Cleanup(func() { restAPIURL = orig })
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

func TestRestFullCRUD(t *testing.T) {
	const zone = "example.com."
	const fqdn = "example.com"
	srv := newMockRestServer(t, 42, fqdn)
	defer srv.Close()
	withTestRestAPIURL(t, srv.URL)

	p := &Provider{APIKey: "test-key"} // APIPassword empty -> REST mode
	ctx := context.Background()

	// AppendRecords: a plain A record and an ACME challenge TXT record -
	// the REST path no longer restricts record type or name.
	toAppend := []libdns.Record{
		libdns.RR{Type: "A", Name: "www", Data: "203.0.113.10", TTL: 0},
		libdns.RR{Type: "TXT", Name: "_acme-challenge.bw", Data: "dGVzdC12YWx1ZQ"},
	}
	appended, err := p.AppendRecords(ctx, zone, toAppend)
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(appended) != 2 {
		t.Fatalf("AppendRecords: got %d records, want 2", len(appended))
	}

	// GetRecords should now see both.
	got, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetRecords: got %d records, want 2", len(got))
	}

	// SetRecords on the "www" A record should replace its value, leaving
	// the TXT record untouched.
	_, err = p.SetRecords(ctx, zone, []libdns.Record{
		libdns.RR{Type: "A", Name: "www", Data: "203.0.113.99", TTL: 0},
	})
	if err != nil {
		t.Fatalf("SetRecords failed: %v", err)
	}
	got, err = p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after SetRecords failed: %v", err)
	}
	var sawNewA, sawOldA, sawTXT bool
	for _, r := range got {
		rr := r.RR()
		switch {
		case rr.Type == "A" && rr.Data == "203.0.113.99":
			sawNewA = true
		case rr.Type == "A" && rr.Data == "203.0.113.10":
			sawOldA = true
		case rr.Type == "TXT":
			sawTXT = true
		}
	}
	if !sawNewA || sawOldA {
		t.Fatalf("SetRecords did not replace the A record correctly: got %+v", got)
	}
	if !sawTXT {
		t.Fatalf("SetRecords should not have touched the unrelated TXT record: got %+v", got)
	}

	// DeleteRecords removes the TXT record by its exact value.
	_, err = p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge.bw", Data: "dGVzdC12YWx1ZQ", TTL: 0},
	})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}
	got, err = p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after DeleteRecords failed: %v", err)
	}
	for _, r := range got {
		if r.RR().Type == "TXT" {
			t.Fatalf("TXT record should have been deleted, still present: %+v", got)
		}
	}

	// Deleting a record that no longer exists is an error on the REST API
	// (unlike the legacy API's forgiving behavior), and that error must
	// surface rather than being silently swallowed.
	_, err = p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge.bw", Data: "dGVzdC12YWx1ZQ", TTL: 0},
	})
	if err == nil {
		t.Fatal("DeleteRecords of an already-removed record should have returned an error")
	}
}

func TestRestDomainNotFound(t *testing.T) {
	srv := newMockRestServer(t, 42, "example.com")
	defer srv.Close()
	withTestRestAPIURL(t, srv.URL)

	p := &Provider{APIKey: "test-key"}
	_, err := p.GetRecords(context.Background(), "not-the-right-domain.com.")
	if err == nil {
		t.Fatal("expected an error for a domain the mock server doesn't know about")
	}
}
