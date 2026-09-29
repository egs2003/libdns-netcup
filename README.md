# netcup for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/netcup)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for the [netcup DNS API](https://ccp.netcup.net/run/webservice/servers/endpoint.php), allowing you to manage DNS records.

## Configuration

netcup exposes two different DNS APIs, and this package picks the right one automatically based on which fields you set on `netcup.Provider`:

- **Legacy API**, for domains using "classic" DNS (shown as the **DNS** tab in the CCP): set `CustomerNumber`, `APIKey` and `APIPassword`. This is the original, full-featured implementation of this package.
- **REST API**, for domains using **CloudDNS** (shown as the **CloudDNS** tab in the CCP): set only `APIKey` — the key from the **API Keys** section of the CCP (*not* **Legacy API Keys**) — and leave `APIPassword` empty. `CustomerNumber` isn't used in this mode and can be left empty too.

You can tell which kind of DNS your domain uses by opening it in the CCP: **Domains → 🔍 next to the domain → CloudDNS tab present** means REST API, **DNS tab present** means legacy API. See netcup's [API guide](https://www.netcup-wiki.de/wiki/CCP_API) for how to create the keys.

**:warning: The REST API can currently only manage `_acme-challenge` TXT records** (i.e. exactly what's needed to solve the ACME dns-01 challenge), not arbitrary records; see [Usage](#usage) below.

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

Only `AppendRecords` and `DeleteRecords` are supported, and only for TXT records whose name (relative to the zone) is `_acme-challenge` or `_acme-challenge.<anything>` — exactly the records ACME's dns-01 challenge needs. `GetRecords` and `SetRecords` return an error, since netcup's REST API has no endpoint to list or overwrite arbitrary records.

Deploying a record to netcup's nameservers happens asynchronously; `AppendRecords` polls for up to about 60 seconds for confirmation before returning, but doesn't fail if that times out — it relies on the caller's own propagation check (e.g. Caddy's `propagation_timeout`/`propagation_delay`) to catch a record that never shows up. Deleting a record that's already gone (or never existed) is treated as success, matching the legacy API's forgiving behavior.

This REST API is not formally documented by netcup at the time of writing; this implementation is derived from netcup's own [acme.sh integration](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_netcup.sh).
