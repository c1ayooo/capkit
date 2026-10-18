# Dependencies

`capkit` is embedded by many hosts, so the dependency contract is about
portability — not about a short allowlist. Third-party libraries are allowed
where they buy real protocol or format work (SSH, Postgres wire protocol, JSON
with drifting field names). What is *not* negotiable is the **kit/host
boundary**: a kit must stay host-independent.

## Rules

1. `capkit` root package: **standard library only**. The contracts and ports
   must stay trivially importable.
2. `kits/*`: third-party dependencies are allowed. Prefer the standard library;
   reach for a dependency when it implements a protocol, signature scheme or
   format you would otherwise hand-roll wrong.
3. Kits must not import:
   - another top-level kit (same-kit subpackages are allowed)
   - any host module (`github.com/c1ayooo/4zrec/...` or another platform)
4. Host services are reached through ports, never directly:
   - HTTP: `capkit.HTTPDoer` / `capkit.Fetcher` (no kit-owned `http.Client` to
     a project target)
   - subprocess: `capkit.ProcessRunner`
   - storage: a host Store adapter
   - logging: `capkit.Logger`

   The `sessionkit` transports obey this rule too: WinRM rides `HTTPDoer` (its
   WSMan calls are ordinary scoped HTTP requests), while SMB and the local CLI
   opener ride `ProcessRunner`, so a host can gate, audit and sandbox them.
5. Heavy engines live under `optional/` in the same module and are not imported
   by core kits:
   - `optional/nuclei-library` (nuclei as a library)
   - `optional/pd` (subfinder/dnsx/naabu/katana)
   - `optional/report-docx` (external renderer)
6. Adding a dependency requires updating this file in the same change.

## Enforcement

```bash
./scripts/check-imports.sh   # kit/host boundary + copyleft license gate
go mod tidy
go test ./...
```

`scripts/check-imports.sh` fails if a kit imports another kit or a host module,
and if any transitive import resolves to a copyleft (GPL/AGPL/SSPL) module root
listed in `scripts/copyleft.txt` (docs §8: "无 GPL/AGPL 代码被 import"). Those
tools are reached by invoking the binary as a subprocess through
`capkit.ProcessRunner`, never by importing their source.

## Single module

`capkit` is one Go module. It contains the contracts, runtime, gates, benign
kits, and `kits/shellkit`. No cross-kit imports: a kit may import its own
subpackages, but not another kit.

## Current dependencies

| Dependency | Used by | Why |
|---|---|---|
| `gopkg.in/yaml.v3` | `templatekit`, `fingerprintkit` | pack/template and dddd rule parsing |
| `github.com/tidwall/gjson` | `enterprisekit` | AQC/TYC/Kuaicha/Fengniao JSON whose field names drift across upstream versions |
| `golang.org/x/crypto` | `credkit`, `sessionkit` | SSH handshake + auth methods (live credential verification, session transport) |
| `github.com/jackc/pgx/v5` | `credkit` | `database/sql` driver for the Postgres liveness/permission probe |

Everything else is standard library only.

Everything else is standard library only.
