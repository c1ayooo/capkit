# playbookkit

Deterministic verification playbooks ported from 4zreco's `verifyrunner`.

- Steps: `http` (default), `tcp`, `dns`
- Assertions: status/status_in, body contains/contains_any/not_contains/regex,
  response headers, duration thresholds, TCP connect/banner, DNS resolution/TXT/CNAME
- Variables: `{{name}}` closure validated at parse time
- Verdicts: `confirmed` / `refuted` / `blocked`
- Hard limits: 16 steps, 32 requests, repeat ≤ 4, serial only, cross-host
  redirects stopped
- `Scope` is checked per step when supplied (hosts should always supply one)

Preset playbooks are under `kits/playbookkit/presets/`. Inline steps are
supported; both go through the same validation. This package is an execution
primitive, not a scanner: it only sends the minimum requests needed to assert a
hypothesis and keeps evidence for each step.
