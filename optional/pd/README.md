# optional/pd

Optional adapter module for ProjectDiscovery libraries (all MIT):

- `subfinder` — passive subdomain enumeration
- `dnsx` — DNS resolution / wildcard checks
- `naabu` — port scanning
- `katana` — crawling

## Rules

- The public `capkit` core must never import this module.
- Import this module only from the host or from a future `reconkit/pd` adapter.
- Keep the interfaces in `capkit` (`ScopeChecker`, `Limiter`, `HTTPDoer`,
  `EvidenceSink`) as the gate boundary; do not bypass them in adapters.
- Record which upstream versions are used in `go.mod`/`NOTICE`.

A typical adapter implements a small provider interface and maps results into
`capkit` models; it must not write assets directly.
