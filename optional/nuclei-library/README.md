# optional/nuclei-library

Optional in-process nuclei engine module.

The public `nucleikit` executes the nuclei binary through
`core.ProcessRunner`, which keeps the core dependency-light. This module is
the alternative: it imports `github.com/projectdiscovery/nuclei/v3/lib`
(MIT) and implements `core.TemplateEngine` for `kind: nuclei`.

## Rules

- Never import this module from `capkit` or `capkit/kits/...`.
- The host chooses binary mode or library mode; both must satisfy the same
  `core.TemplateEngine` contract.
- Keep scope/approval/rate/audit in the runtime gates; the library adapter must
  use the injected `ScopeChecker`/`Limiter` and not open its own unrestricted
  target loop.
- Record the upstream nuclei version in `go.mod` and `NOTICE`.
