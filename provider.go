// Package netcup implements a DNS record management client compatible
// with the libdns interfaces for netcup.
package netcup

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with netcup.
//
// netcup exposes two different DNS APIs, and which one is used is chosen
// automatically based on which fields are set:
//
//   - Legacy API (for domains using "classic" DNS, shown as the "DNS" tab
//     in the CCP): set CustomerNumber, APIKey and APIPassword. This is the
//     original behavior of this package and supports full record management
//     (GetRecords, AppendRecords, SetRecords, DeleteRecords) for any record
//     type.
//   - REST API (for domains using CloudDNS, shown as the "CloudDNS" tab in
//     the CCP): set only APIKey (the key from the "API Keys" section of the
//     CCP, not "Legacy API Keys"), and leave APIPassword empty. This mode
//     also supports full record management (GetRecords, AppendRecords,
//     SetRecords, DeleteRecords) for any record type, via the REST API's
//     "changeset" and "revision" endpoints. CustomerNumber is not used and
//     can be left empty. See rest.go's package doc comment for a caveat
//     around GetRecords and concurrent use of netcup's own manual-revision
//     workflow outside of this client.
//
// The legacy API requires a session ID for all requests, so at the beginning
// of each legacy method call a login is performed to receive the session ID
// and at the end the session is stopped with a logout. The REST API is
// stateless and uses the API key as a bearer token for every request.
//
// The mutex locks concurrent access on all four implemented methods to make
// sure there is no race condition in the netcup zone and record configuration.
type Provider struct {
	CustomerNumber string `json:"customer_number,omitempty"`
	APIKey         string `json:"api_key"`
	APIPassword    string `json:"api_password,omitempty"`
	mutex          sync.Mutex
}

// useRest reports whether this Provider is configured for the new netcup
// REST API (CloudDNS) rather than the legacy CCP API. It is determined
// purely by the absence of APIPassword, so that existing configurations
// (which always set all three fields) keep using the legacy API unchanged.
func (p *Provider) useRest() bool {
	return p.APIPassword == ""
}

// const loggingPrefixLibdnsNetcup = "[libdns_netcup]"

// GetRecords lists all the records in the zone.
//
// When the Provider is configured for the new netcup REST API (i.e.
// APIPassword is empty; see the Provider docs), this reads the records of
// the zone's most recently created DNS revision; see rest.go's package doc
// comment for a caveat around concurrent use of netcup's manual-revision
// workflow outside of this client.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.useRest() {
		return p.getRecordsRest(ctx, zone)
	}
	return p.getRecordsLegacy(ctx, zone)
}

func (p *Provider) getRecordsLegacy(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// possibly useful with a variable to switch on debug logging
	// fmt.Printf("%v Getting records of zone %v\n", loggingPrefixLibdnsNetcup, zone)

	apiSessionID, err := p.login(ctx)
	if err != nil {
		return nil, err
	}
	defer p.logout(ctx, apiSessionID)

	shortZone := unFQDN(zone)

	dnsZone, err := p.infoDNSZone(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	recordSet, err := p.infoDNSRecords(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	return toLibdnsRecords(recordSet.DnsRecords, dnsZone.TTL)
}

// AppendRecords adds records to the zone. It returns the records that were added.
// netcup records cannot have individual TTLs, there is one TTL for all records in the zone
//
// For each input record, if no ID is given, the first record that matches the host name and type is searched.
// If none is found or the search result doesn't equal the input, a new one is appended.
// For MX records the priority is needed as an additional search parameter.
//
// When the Provider is configured for the new netcup REST API (i.e.
// APIPassword is empty; see the Provider docs), this always adds the given
// records via the changeset endpoint's "create" list, even if a record with
// the same name and type already exists (matching this method's contract);
// use SetRecords instead to replace rather than add.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.useRest() {
		return p.appendRecordsRest(ctx, zone, records)
	}
	return p.appendRecordsLegacy(ctx, zone, records)
}

func (p *Provider) appendRecordsLegacy(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// fmt.Printf("%v Appending records %+v to zone %v\n", loggingPrefixLibdnsNetcup, records, zone)

	apiSessionID, err := p.login(ctx)
	if err != nil {
		return nil, err
	}
	defer p.logout(ctx, apiSessionID)

	shortZone := unFQDN(zone)

	dnsZone, err := p.infoDNSZone(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	existingRecordSet, err := p.infoDNSRecords(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	netcupRecords := toNetcupRecords(records)
	recordsToAppend := getRecordsToAppend(netcupRecords, existingRecordSet.DnsRecords)
	if len(recordsToAppend) == 0 {
		return []libdns.Record{}, nil
	}
	recordSetToAppend := dnsRecordSet{
		DnsRecords: recordsToAppend,
	}
	updatedRecordSet, err := p.updateDNSRecords(ctx, shortZone, recordSetToAppend, apiSessionID)
	if err != nil {
		return nil, err
	}

	// the netcup API always returns all records, so the ones before the update have to be compared to the ones after to return only the appended records
	appendedRecords := difference(updatedRecordSet.DnsRecords, existingRecordSet.DnsRecords)

	return toLibdnsRecords(appendedRecords, dnsZone.TTL)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
//
// netcup records cannot have individual TTLs, there is one TTL for all records in the zone. So these can not be set.
//
// For each input record, if no ID is given, the first record that matches the host name and type is searched.
// If none is found, the input is appended. If one is found, it is updated accordingly.
// For MX records the priority is needed as an additional search parameter.
//
// When the Provider is configured for the new netcup REST API (i.e.
// APIPassword is empty; see the Provider docs), this reads the zone's
// current records first to find what to replace, since the REST API's
// delete calls require an exact existing match (name, type, rdata and ttl)
// rather than supporting "delete by name+type, whatever the value".
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.useRest() {
		return p.setRecordsRest(ctx, zone, records)
	}
	return p.setRecordsLegacy(ctx, zone, records)
}

func (p *Provider) setRecordsLegacy(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// fmt.Printf("%v Setting records %+v for zone %v\n", loggingPrefixLibdnsNetcup, records, zone)

	apiSessionID, err := p.login(ctx)
	if err != nil {
		return nil, err
	}
	defer p.logout(ctx, apiSessionID)

	shortZone := unFQDN(zone)

	dnsZone, err := p.infoDNSZone(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	existingRecordSet, err := p.infoDNSRecords(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	netcupRecords := toNetcupRecords(records)
	recordsToSet := getRecordsToSet(netcupRecords, existingRecordSet.DnsRecords)
	if len(recordsToSet) == 0 {
		return []libdns.Record{}, nil
	}
	recordSetToSet := dnsRecordSet{
		DnsRecords: recordsToSet,
	}
	updatedRecordSet, err := p.updateDNSRecords(ctx, shortZone, recordSetToSet, apiSessionID)
	if err != nil {
		return nil, err
	}

	// the netcup API always returns all records, so the ones before the update have to be compared to the ones after to return only the updated records
	updatedRecords := difference(updatedRecordSet.DnsRecords, existingRecordSet.DnsRecords)

	return toLibdnsRecords(updatedRecords, dnsZone.TTL)
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
//
// For each input record, if no ID is given, the first record that matches the host name and type is searched and deleted.
// For MX records the priority is needed as an additional search parameter.
// To be safe, the records to delete should include the IDs (for example from GetRecords)
//
// When the Provider is configured for the new netcup REST API (i.e.
// APIPassword is empty; see the Provider docs), each record must match an
// existing one's name, type, rdata and ttl exactly, since the REST API has
// no "delete by name+type, whatever the value" call; a record whose TTL
// wasn't tracked by the caller is assumed to be 3600s (netcup's own
// default), which matches what AppendRecords on this Provider would have
// created it with.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if p.useRest() {
		return p.deleteRecordsRest(ctx, zone, records)
	}
	return p.deleteRecordsLegacy(ctx, zone, records)
}

func (p *Provider) deleteRecordsLegacy(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// fmt.Printf("%v Deleting records %+v from zone %v\n", loggingPrefixLibdnsNetcup, records, zone)

	apiSessionID, err := p.login(ctx)
	if err != nil {
		return nil, err
	}
	defer p.logout(ctx, apiSessionID)

	shortZone := unFQDN(zone)

	dnsZone, err := p.infoDNSZone(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	existingRecordSet, err := p.infoDNSRecords(ctx, shortZone, apiSessionID)
	if err != nil {
		return nil, err
	}

	netcupRecords := toNetcupRecords(records)
	recordsToDelete := getRecordsToDelete(netcupRecords, existingRecordSet.DnsRecords)
	if len(recordsToDelete) == 0 {
		return []libdns.Record{}, nil
	}
	recordSetToDelete := dnsRecordSet{
		DnsRecords: recordsToDelete,
	}
	updatedRecordSet, err := p.updateDNSRecords(ctx, shortZone, recordSetToDelete, apiSessionID)
	if err != nil {
		return nil, err
	}

	// the netcup API always returns all records, so the ones before the deletion have to be compared to the ones after to return only the deleted records
	deletedRecords := difference(existingRecordSet.DnsRecords, updatedRecordSet.DnsRecords)

	return toLibdnsRecords(deletedRecords, dnsZone.TTL)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
