// The REST-API branch of the Provider methods, used when APIPassword is
// empty (see provider.go and rest.go). Only "_acme-challenge" TXT records
// are supported, which is what's needed for the ACME dns-01 challenge.
package netcup

import (
	"context"
	"errors"
	"fmt"

	"github.com/libdns/libdns"
)

// appendRecordsRest adds "_acme-challenge" TXT records via the REST API. Any
// record that isn't a TXT record under "_acme-challenge" causes an error for
// that record; the other records are still attempted.
func (p *Provider) appendRecordsRest(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}

	var appended []libdns.Record
	var errs []error
	for _, record := range records {
		rr := record.RR()
		if rr.Type != "TXT" {
			errs = append(errs, fmt.Errorf("%v cannot manage %s records via the REST API, only TXT: %q", loggingPrefixNetcupRest, rr.Type, rr.Name))
			continue
		}
		scope, err := restScope(rr.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := client.addChallenge(ctx, domain.ID, scope, rr.Data); err != nil {
			errs = append(errs, err)
			continue
		}
		appended = append(appended, record)
	}
	if len(errs) > 0 {
		return appended, errors.Join(errs...)
	}
	return appended, nil
}

// deleteRecordsRest removes "_acme-challenge" TXT records via the REST API.
// Records that are already gone (HTTP 404) are treated as successfully
// deleted, matching the behavior of the legacy implementation, where a
// record that doesn't exist is simply not returned as deleted either way.
func (p *Provider) deleteRecordsRest(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	var errs []error
	for _, record := range records {
		rr := record.RR()
		if rr.Type != "TXT" {
			errs = append(errs, fmt.Errorf("%v cannot manage %s records via the REST API, only TXT: %q", loggingPrefixNetcupRest, rr.Type, rr.Name))
			continue
		}
		scope, err := restScope(rr.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := client.deleteChallenge(ctx, domain.ID, scope, rr.Data); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted = append(deleted, record)
	}
	if len(errs) > 0 {
		return deleted, errors.Join(errs...)
	}
	return deleted, nil
}
