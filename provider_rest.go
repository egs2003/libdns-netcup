// The REST-API branch of the Provider methods, used when APIPassword is
// empty (see provider.go and rest.go). Unlike an earlier version of this
// file, this covers full record management (all four libdns operations,
// any record type), via the netcup REST API's "changeset" and "revision"
// endpoints - not just "_acme-challenge" TXT records.
package netcup

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
)

// toRestRecordInput converts a libdns record into the wire shape the
// changeset endpoint expects for both "create" and "delete" entries.
func toRestRecordInput(r libdns.Record) restRecordInput {
	rr := r.RR()
	ttl := int64(rr.TTL.Seconds())
	if ttl <= 0 {
		// The API requires a positive TTL even for delete entries (which
		// are matched by name+type+rdata); 3600s is netcup's own default
		// for records created without an explicit TTL in the CCP.
		ttl = 3600
	}
	return restRecordInput{
		Name: rr.Name,
		Type: rr.Type,
		Data: rr.Data,
		TTL:  ttl,
	}
}

// restRecordToLibdns converts a record as returned by the REST API back
// into a libdns.Record. Named distinctly from util.go's toLibdnsRecord,
// which converts the legacy API's different dnsRecord type instead.
func restRecordToLibdns(r restRecord) libdns.Record {
	return libdns.RR{
		Name: r.Name,
		Type: r.Type,
		Data: r.Data,
		TTL:  time.Duration(r.TTL) * time.Second,
	}
}

// getRecordsRest lists all current records of the zone, read from the most
// recently created DNS revision (see rest.go's package doc comment for the
// caveat this involves).
func (p *Provider) getRecordsRest(ctx context.Context, zone string) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}

	recs, err := client.currentRecords(ctx, domain.ID)
	if err != nil {
		return nil, err
	}

	out := make([]libdns.Record, 0, len(recs))
	for _, r := range recs {
		out = append(out, restRecordToLibdns(r))
	}
	return out, nil
}

// appendRecordsRest adds the given records via a single changeset "create"
// call. Unlike SetRecords, this never deletes anything, matching the
// AppendRecords contract (always add, even if a record with the same name
// and type already exists).
func (p *Provider) appendRecordsRest(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	create := make([]restRecordInput, 0, len(records))
	for _, r := range records {
		create = append(create, toRestRecordInput(r))
	}

	if _, err := client.applyChangeset(ctx, domain.ID, create, nil); err != nil {
		return nil, err
	}
	return records, nil
}

// setRecordsRest ensures the given records are present, replacing any
// existing record that shares the same name and type (matching the
// SetRecords contract: the input records become the complete set for each
// (name, type) pair they describe). It reads the zone's current records
// first to find what to delete, since the changeset endpoint's "delete"
// entries must match an existing record's name, type, rdata and ttl
// exactly - the API has no "delete by name+type, whatever the value" call.
func (p *Provider) setRecordsRest(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	existing, err := client.currentRecords(ctx, domain.ID)
	if err != nil {
		return nil, err
	}

	// Which (name, type) pairs are being set.
	touched := make(map[[2]string]bool, len(records))
	for _, r := range records {
		rr := r.RR()
		touched[[2]string{rr.Name, rr.Type}] = true
	}

	var del []restRecordInput
	for _, ex := range existing {
		if touched[[2]string{ex.Name, ex.Type}] {
			del = append(del, restRecordInput{Name: ex.Name, Type: ex.Type, Data: ex.Data, TTL: ex.TTL})
		}
	}

	create := make([]restRecordInput, 0, len(records))
	for _, r := range records {
		create = append(create, toRestRecordInput(r))
	}

	if _, err := client.applyChangeset(ctx, domain.ID, create, del); err != nil {
		return nil, err
	}
	return records, nil
}

// deleteRecordsRest removes the given records via a single changeset
// "delete" call. Each record must match an existing one's name, type, rdata
// and ttl; if the caller doesn't know the exact TTL (e.g. it only has
// name/type/data from an ACME challenge value it created earlier without
// tracking the TTL), toRestRecordInput's 3600s default is used, which
// matches what AppendRecords would have created it with by default.
// Deleting a record that no longer exists is reported as an error by the
// API (unlike the legacy API's forgiving behavior); this is surfaced as-is,
// since silently swallowing it could hide a real mismatch (e.g. a TTL this
// client guessed wrong).
func (p *Provider) deleteRecordsRest(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newRestClient(p.APIKey)

	domain, err := client.getDomain(ctx, unFQDN(zone))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	del := make([]restRecordInput, 0, len(records))
	for _, r := range records {
		del = append(del, toRestRecordInput(r))
	}

	if _, err := client.applyChangeset(ctx, domain.ID, nil, del); err != nil {
		return nil, fmt.Errorf("%w (note: deleting via the netcup REST API requires an exact name+type+rdata+ttl match; if the TTL wasn't tracked by the caller, this client assumed 3600s)", err)
	}
	return records, nil
}
