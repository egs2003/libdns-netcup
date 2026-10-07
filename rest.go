// REST client for the new netcup API (api.netcup.com/v1), used for domains
// that are managed via CloudDNS. This is based on the OpenAPI specification
// netcup publishes at https://www.netcup.com/en/helpcenter/documentation/netcup-api
// (embedded in that page's client-side data, not a plain document at the
// time of writing), not on reverse-engineering acme.sh as an earlier version
// of this file was.
//
// The API is authenticated with a single, long-lived API key (a "Bearer"
// token), obtained in the CCP under "Master Data > API" in the "API Keys"
// section (not the "Legacy API Keys" section). No customer number, no
// session handling, unlike the legacy API.
//
// Record changes go through the "changeset" endpoint
// (POST /v1/domain/{domainId}/changeset), which accepts "create" and
// "delete" arrays of records and, with autoCommit, applies them immediately
// without a separate commit step. The API also exposes an explicit
// multi-step revision workflow (create a revision, add records to it, then
// commit it) for staged changes; this client does not use that workflow and
// always auto-commits, since Caddy's DNS-01 solver needs changes applied
// right away.
//
// To read the current records of a zone, there is no direct "list current
// records" endpoint; the closest the API offers is listing the zone's
// revisions and reading the records of one of them. This client picks the
// most recently created revision as "current". The API's "state" field on a
// revision is documented only as a plain string, with no enumerated values,
// so this is a best-effort interpretation: if a zone has an uncommitted
// draft revision newer than its last committed one (e.g. from someone
// using the manual revision workflow concurrently), GetRecords could return
// that draft's contents instead of what's actually live. This doesn't
// affect AppendRecords/DeleteRecords, which always auto-commit immediately
// rather than relying on revision lookups.
package netcup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// restAPIURL is the base URL of the new netcup REST API. It's a variable
// (rather than a constant) purely so that tests can point it at a local
// httptest server; production code must never change it.
var restAPIURL = "https://api.netcup.com/v1"

// restClient talks to the netcup REST API using an API key as bearer token.
type restClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridable for tests
}

func newRestClient(apiKey string) *restClient {
	return &restClient{
		apiKey:     apiKey,
		httpClient: http.DefaultClient,
		baseURL:    restAPIURL,
	}
}

// --- wire types, named after the OpenAPI schema components ---

type restErrorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// restEnvelope is the common response envelope of the netcup REST API.
type restEnvelope struct {
	Success bool             `json:"success"`
	Errors  []restErrorEntry `json:"errors"`
	Meta    *restMeta        `json:"meta"`
	Result  json.RawMessage  `json:"result"`
}

type restMeta struct {
	Pagination *restPagination `json:"pagination"`
}

type restPagination struct {
	Page         int `json:"page"`
	PerPage      int `json:"perPage"`
	TotalEntries int `json:"totalEntries"`
	LastPage     int `json:"lastPage"`
}

func (e *restEnvelope) errString() string {
	if len(e.Errors) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(e.Errors))
	for _, er := range e.Errors {
		if er.Code != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", er.Code, er.Message))
		} else {
			parts = append(parts, er.Message)
		}
	}
	return strings.Join(parts, "; ")
}

// restDomain corresponds to the "Domain" schema.
type restDomain struct {
	ID           int64  `json:"id"`
	FQDN         string `json:"fqdn"`
	IsDnsManaged bool   `json:"isDnsManaged"`
}

// restRecordInput corresponds to the "DnsRecordInput" schema, used in the
// "create" and "delete" arrays of a changeset request. All four fields are
// required by the API for both creating and deleting (deletion matches an
// existing record by these same fields).
type restRecordInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"rdata"`
	TTL  int64  `json:"ttl"`
}

// restRecord corresponds to the "DomainDnsRecord" schema, a record as
// returned when reading a revision's contents.
type restRecord struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Data       string `json:"rdata"`
	TTL        int64  `json:"ttl"`
	Immutable  *bool  `json:"immutable"`
}

// restRevision corresponds to the "DomainDnsRevision" schema.
type restRevision struct {
	Identifier string `json:"identifier"`
	CreatedAt  string `json:"createdAt"`
	ModifiedAt string `json:"modifiedAt"`
	State      string `json:"state"`
	Serial     *int64 `json:"serial"`
}

// --- low-level request helper ---

func (c *restClient) doRequest(ctx context.Context, method, path string, body any) (*restEnvelope, int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("%v marshalling request body: %w", loggingPrefixNetcupRest, err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/"+path, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("%v building request: %w", loggingPrefixNetcupRest, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%v performing request: %w", loggingPrefixNetcupRest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return &restEnvelope{Success: true}, resp.StatusCode, nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%v reading response body: %w", loggingPrefixNetcupRest, err)
	}

	var env restEnvelope
	if len(data) > 0 {
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("%v decoding response (HTTP %d): %s", loggingPrefixNetcupRest, resp.StatusCode, string(data))
		}
	}
	return &env, resp.StatusCode, nil
}

// --- domain lookup ---

// getDomain looks up the netcup domain object for the given zone (e.g.
// "skutt.de", without a trailing dot).
func (c *restClient) getDomain(ctx context.Context, zone string) (*restDomain, error) {
	env, status, err := c.doRequest(ctx, http.MethodGet, "domain?fqdn="+url.QueryEscape(zone), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || !env.Success {
		return nil, fmt.Errorf("%v looking up domain %q: HTTP %d: %s", loggingPrefixNetcupRest, zone, status, env.errString())
	}

	var domains []restDomain
	if err := json.Unmarshal(env.Result, &domains); err != nil {
		return nil, fmt.Errorf("%v decoding domain lookup result for %q: %w", loggingPrefixNetcupRest, zone, err)
	}
	for i := range domains {
		if domains[i].FQDN == zone {
			return &domains[i], nil
		}
	}
	return nil, fmt.Errorf("%v domain %q not found in this account", loggingPrefixNetcupRest, zone)
}

// --- changeset: the main way to create/delete records ---

// applyChangeset creates and/or deletes records in one atomic, immediately
// committed operation. Either create or del (or both) may be empty.
func (c *restClient) applyChangeset(ctx context.Context, domainID int64, create, del []restRecordInput) (*restRevision, error) {
	body := map[string]any{
		"autoCommit": true,
		"strict":     true,
	}
	if len(create) > 0 {
		body["create"] = create
	}
	if len(del) > 0 {
		body["delete"] = del
	}

	env, status, err := c.doRequest(ctx, http.MethodPost, fmt.Sprintf("domain/%d/changeset", domainID), body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 || !env.Success {
		return nil, fmt.Errorf("%v applying changeset (domain %d, %d create, %d delete): HTTP %d: %s", loggingPrefixNetcupRest, domainID, len(create), len(del), status, env.errString())
	}

	var rev restRevision
	if len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, &rev); err != nil {
			return nil, fmt.Errorf("%v decoding changeset result: %w", loggingPrefixNetcupRest, err)
		}
	}
	return &rev, nil
}

// --- reading current records, via the most recent revision ---

// listRevisions returns all DNS revisions of a domain, across all pages,
// sorted ascending by CreatedAt (oldest first) so the caller can simply take
// the last element for "most recent". Revisions with an unparsable
// CreatedAt sort last, as a defensive fallback.
func (c *restClient) listRevisions(ctx context.Context, domainID int64) ([]restRevision, error) {
	var all []restRevision
	page := 1
	const perPage = 100
	for {
		path := fmt.Sprintf("domain/%d/dns/revision?page=%d&perPage=%d", domainID, page, perPage)
		env, status, err := c.doRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK || !env.Success {
			return nil, fmt.Errorf("%v listing revisions for domain %d: HTTP %d: %s", loggingPrefixNetcupRest, domainID, status, env.errString())
		}
		var revs []restRevision
		if err := json.Unmarshal(env.Result, &revs); err != nil {
			return nil, fmt.Errorf("%v decoding revision list: %w", loggingPrefixNetcupRest, err)
		}
		all = append(all, revs...)

		if env.Meta == nil || env.Meta.Pagination == nil || page >= env.Meta.Pagination.LastPage || len(revs) == 0 {
			break
		}
		page++
	}

	sort.SliceStable(all, func(i, j int) bool {
		ti, erri := time.Parse(time.RFC3339, all[i].CreatedAt)
		tj, errj := time.Parse(time.RFC3339, all[j].CreatedAt)
		if erri != nil {
			return false // unparsable sorts last
		}
		if errj != nil {
			return true
		}
		return ti.Before(tj)
	})
	return all, nil
}

// listRevisionRecords returns all DNS records of one revision, across all
// pages.
func (c *restClient) listRevisionRecords(ctx context.Context, domainID int64, revisionID string) ([]restRecord, error) {
	var all []restRecord
	page := 1
	const perPage = 100
	for {
		path := fmt.Sprintf("domain/%d/dns/revision/%s/record?page=%d&perPage=%d", domainID, url.PathEscape(revisionID), page, perPage)
		env, status, err := c.doRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK || !env.Success {
			return nil, fmt.Errorf("%v listing records for domain %d revision %s: HTTP %d: %s", loggingPrefixNetcupRest, domainID, revisionID, status, env.errString())
		}
		var recs []restRecord
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, fmt.Errorf("%v decoding record list: %w", loggingPrefixNetcupRest, err)
		}
		all = append(all, recs...)

		if env.Meta == nil || env.Meta.Pagination == nil || page >= env.Meta.Pagination.LastPage || len(recs) == 0 {
			break
		}
		page++
	}
	return all, nil
}

// currentRecords returns the records of the most recently created revision
// of the domain, i.e. this client's best-effort notion of "the current
// state of the zone" (see the package doc comment for the caveat around
// uncommitted draft revisions). Returns an empty slice, not an error, if the
// zone has no revisions yet.
func (c *restClient) currentRecords(ctx context.Context, domainID int64) ([]restRecord, error) {
	revs, err := c.listRevisions(ctx, domainID)
	if err != nil {
		return nil, err
	}
	if len(revs) == 0 {
		return nil, nil
	}
	latest := revs[len(revs)-1]
	return c.listRevisionRecords(ctx, domainID, latest.Identifier)
}

const loggingPrefixNetcupRest = "[netcup:rest]"
