# netcup for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/netcup)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for the [netcup DNS API](https://ccp.netcup.net/run/webservice/servers/endpoint.php), allowing you to manage DNS records.

## Configuration

netcup exposes two different DNS APIs, and this package picks the right one automatically based on which fields you set on `netcup.Provider`:

- **Legacy API**, for domains using "classic" DNS (shown as the **DNS** tab in the CCP): set `CustomerNumber`, `APIKey` and `APIPassword`. This is the original, full-featured implementation of this package.
- **REST API**, for domains using **CloudDNS** (shown as the **CloudDNS** tab in the CCP): set only `APIKey` — the key from the **API Keys** section of the CCP (*not* **Legacy API Keys**) — and leave `APIPassword` empty. `CustomerNumber` isn't used in this mode and can be left empty too.

You can tell which kind of DNS your domain uses by opening it in the CCP: **Domains → 🔍 next to the domain → CloudDNS tab present** means REST API, **DNS tab present** means legacy API. See netcup's [API guide](https://www.netcup-wiki.de/wiki/CCP_API) for how to create the keys, and netcup's [API documentation](https://www.netcup.com/en/helpcenter/documentation/netcup-api) (an OpenAPI spec embedded in that page) for the REST API itself.

Both modes support all four operations (`GetRecords`, `AppendRecords`, `SetRecords`, `DeleteRecords`) for any record type; see [Usage](#usage) below for a caveat specific to the REST API around how `GetRecords` determines "the current records" and how deletion matching works.

Here is a minimal working example to get all DNS records of a domain on the legacy API, using environment variables for the credentials:

```go
import (
	"context"
	"fmt"
	"os"

	"github.com/libdns/netcup"
)

func main() {
	provider := netcup.Provider{
		CustomerNumber: os.Getenv("LIBDNS_NETCUP_CUSTOMER_NUMBER"),
		APIKey:         os.Getenv("LIBDNS_NETCUP_API_KEY"),
		APIPassword:    os.Getenv("LIBDNS_NETCUP_API_PASSWORD"),
	}
	ctx := context.TODO()
	zone := os.Getenv("LIBDNS_NETCUP_ZONE")

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for _, record := range records {
		fmt.Printf("%+v\n", record)
	}
}
```

For a CloudDNS domain, solving the ACME dns-01 challenge (the main use case for the REST API) looks like this:

```go
provider := netcup.Provider{
	APIKey: os.Getenv("LIBDNS_NETCUP_API_KEY"), // the "API Keys" key, not "Legacy API Keys"
}

_, err := provider.AppendRecords(ctx, zone, []libdns.Record{
	libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "<challenge value>"},
})
// ... after validation ...
_, err = provider.DeleteRecords(ctx, zone, []libdns.Record{
	libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "<challenge value>"},
})
```

## Usage

**:warning: The netcup API does not offer setting the TTL for individual records.**

**:warning: As the ID attribute has been removed in the libdns record structs, using the ID field is not possible.**

### Legacy API

Updating and deleting records can be done by either filling all struct fields of the dnsRecord, or just Name and Type (+ Priority for MX records). Then the first record matching these criteria is updated/deleted.

All four methods (`GetRecords`, `AppendRecords`, `SetRecords`, `DeleteRecords`) are supported for any record type.

### REST API (CloudDNS)

All four operations work for any record type, via the REST API's `changeset` endpoint (which creates and/or deletes records in one atomically-applied, immediately-committed call):

- `AppendRecords` always adds the given records, even if a record with the same name and type already exists (matching the method's contract) — it never deletes anything.
- `SetRecords` first reads the zone's current records (see the `GetRecords` caveat below) to find existing records sharing the input's (name, type) pairs, then replaces them in a single changeset call (delete the old, create the new).
- `DeleteRecords` requires each input record to match an existing one's name, type, rdata **and ttl** exactly — the REST API has no "delete by name+type, whatever the value" call. If the caller doesn't know a record's TTL (e.g. it only tracked name/type/data, as Caddy's ACME solver does), this client assumes 3600s, matching what `AppendRecords` on this Provider creates by default. Unlike the legacy API, deleting a record that doesn't exist is an **error**, not a silent no-op; this is surfaced rather than swallowed, since it usually means the assumed TTL didn't match.
- `GetRecords` has no direct "list current records" endpoint to call; instead it lists the zone's DNS revisions and reads the records of the most recently *created* one. netcup's own manual, multi-step revision workflow (draft a revision, add records, commit it) is a separate feature this client doesn't use — but if something else uses it concurrently on the same zone, `GetRecords` could see an uncommitted draft's contents instead of what's actually live. `AppendRecords`/`DeleteRecords`/`SetRecords` aren't affected by this, since they always auto-commit immediately rather than relying on revision lookups.

This REST API's OpenAPI spec is published by netcup at <https://www.netcup.com/en/helpcenter/documentation/netcup-api> (embedded in that page's client-side data rather than a plain document, so viewing the page's source alone won't show it) but has no accompanying prose documentation at the time of writing, so some details above (e.g. the exact semantics of a revision's `state` field) are this client's best-effort interpretation rather than confirmed behavior.
