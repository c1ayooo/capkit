# oastkit

Out-of-band interaction helpers backed by **dnslog.cn** (or a compatible
self-hosted dnslog service). No interactsh dependency.

- `oast_get_domain`: obtain a fresh callback domain; the session cookie is kept
  in memory for follow-up queries.
- `oast_get_records`: fetch DNS interaction records, optionally waiting a few
  seconds for the target to resolve.

Uses the external `Fetcher` port: requests are rate-limited and audited but are
not checked against the project's target scope (the callback service is not the
target). Default base URL is `http://dnslog.cn`; a host can override it.
