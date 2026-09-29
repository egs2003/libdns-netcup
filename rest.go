// REST client for the new netcup API (api.netcup.com/v1), used for domains
// that are managed via CloudDNS. Unlike the legacy CCP API (client.go), this
// API can only manage TXT records under "_acme-challenge", which is exactly
// what's needed to solve the ACME dns-01 challenge, but nothing more.
//
// The API is authenticated with a single, long-lived API key (a "Bearer"
// token), obtained in the CCP under "Master Data > API" in the "API Keys"
// section (not the "Legacy API Keys" section). No customer number, no
// session handling, unlike the legacy API.
//
// This implementation is derived from the acme.sh dns_netcup.sh hook
// (https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_netcup.sh),
// since netcup has not published a formal specification for this API at the
// time of writing.
package netcup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// restAPIURL is the base URL of the new netcup REST API. It's a variable
// (rather than a constant) purely so that tests can point it at a local
// httptest server; production code must never change it.
var restAPIURL = "https://api.netcup.com/v1"

// restDeployPollInterval/restDeployMaxPolls: after creating a challenge
// record, netcup deploys it to the nameservers asynchronously. We poll for
// up to restDeployMaxPolls * restDeployPollInterval (60s total, matching
// observed behavior and the acme.sh implementation) before giving up on
// waiting for confirmation. This is best-effort: if it times out we still
// return success, since Caddy performs its own DNS-based propagation check
// (propagation_timeout / propagation_delay) afterwards.
const (
	restDeployPollInterval = 5 * time.Second
	restDeployMaxPolls     = 12
)

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

// restErrorEntry is one entry of the "errors" array the API returns on failure.
type restErrorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// restEnvelope is the common response envelope of the netcup REST API.
type restEnvelope struct {
	Success bool             `json:"success"`
	Errors  []restErrorEntry `json:"errors"`
	Result  json.RawMessage  `json:"result"`
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

// restDomain is one entry of the "result" array of a domain lookup.
type restDomain struct {
	ID           int64  `json:"id"`
	FQDN         string `json:"fqdn"`
	IsDnsManaged bool   `json:"isDnsManaged"`
}

// doRequest performs a single HTTP request against the REST API and decodes
// the JSON envelope. body may be nil for GET/DELETE requests without a body.
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

	// A 204 No Content (e.g. successful DELETE) and a 404 Not Found (record
	// already gone) have no JSON body worth decoding; let the caller decide
	// what to do with the status code.
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

// getDomain looks up the netcup domain object for the given zone (e.g.
// "skutt.de", without a trailing dot). It returns an error if the domain
// cannot be found, the API key is invalid, or the account does not own it.
func (c *restClient) getDomain(ctx context.Context, zone string) (*restDomain, error) {
	env, status, err := c.doRequest(ctx, http.MethodGet, "domain?fqdn="+zone, nil)
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

// addChallenge creates (or overwrites) the "_acme-challenge.<scope>" TXT
// record with the given value and waits (best-effort, up to ~60s) for it to
// be deployed to netcup's nameservers.
func (c *restClient) addChallenge(ctx context.Context, domainID int64, scope, value string) error {
	path := fmt.Sprintf("domain/%d/acme/challenge", domainID)
	body := map[string]string{"scope": scope, "value": value}

	env, status, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 || !env.Success {
		return fmt.Errorf("%v adding challenge record (scope %q): HTTP %d: %s", loggingPrefixNetcupRest, scope, status, env.errString())
	}

	statusPath := fmt.Sprintf("domain/%d/acme/challenge/%s/%s", domainID, scope, value)
	for i := 0; i < restDeployMaxPolls; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(restDeployPollInterval):
		}

		env, status, err := c.doRequest(ctx, http.MethodGet, statusPath, nil)
		if err != nil || status != http.StatusOK || !env.Success {
			continue // keep polling; the record was already accepted above
		}
		var st struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(env.Result, &st); err == nil && st.Status == "deployed" {
			return nil
		}
	}
	// Not confirmed as deployed within the timeout, but the record was
	// accepted by the API; Caddy's own DNS propagation check (propagation_
	// timeout/propagation_delay) will catch it if it never shows up.
	return nil
}

// deleteChallenge removes the "_acme-challenge.<scope>" TXT record with the
// given value. It treats "already gone" (HTTP 404) as success.
func (c *restClient) deleteChallenge(ctx context.Context, domainID int64, scope, value string) error {
	path := fmt.Sprintf("domain/%d/acme/challenge/%s/%s", domainID, scope, value)
	env, status, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("%v removing challenge record (scope %q): HTTP %d: %s", loggingPrefixNetcupRest, scope, status, env.errString())
}

// restScope computes the REST API "scope" (the label(s) between the zone
// apex and "_acme-challenge") for a record name that is relative to zone,
// as given to the libdns interface methods (e.g. "_acme-challenge.bw", or
// "_acme-challenge" for a challenge on the zone apex itself, e.g. for a
// wildcard certificate). It returns an error if name isn't of that form,
// since the REST API can only manage "_acme-challenge.*" records.
func restScope(relativeName string) (string, error) {
	const prefix = "_acme-challenge"
	if relativeName == prefix {
		return "@", nil
	}
	if scope, ok := strings.CutPrefix(relativeName, prefix+"."); ok && scope != "" {
		return scope, nil
	}
	return "", fmt.Errorf(
		"%v the netcup REST API (used because api_password is not set) can only manage \"_acme-challenge\" records for the ACME dns-01 challenge, not %q; "+
			"set customer_number and api_password to use the legacy API for other records",
		loggingPrefixNetcupRest, relativeName)
}

var errRestNotSupported = errors.New(loggingPrefixNetcupRest + " GetRecords/SetRecords are not supported via the netcup REST API (only Append/DeleteRecords for \"_acme-challenge\" records are); set customer_number and api_password to use the legacy API instead")

const loggingPrefixNetcupRest = "[netcup:rest]"
