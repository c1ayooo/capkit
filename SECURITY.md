# Security policy

`capkit` is intended for authorized security testing and research only.

- Hosts must provide a real `ScopeChecker` and `Approver`. The runtime fails
  construction when high-risk tools have no approval gate, and `gates` fails
  closed when scope or rate limiting is missing.
- Offensive implementations live in `kits/shellkit` (same module). They require
  host-provided delivery/execution sinks and explicit authorization for every
  target.
- Do not add default targets, default credentials, default payloads, wordlists,
  or one-click exploit chains to the module.
- Treat every tool result as untrusted input. Do not log secrets; use the
  `Sealer` port and redact before audit/evidence.
- Report vulnerabilities privately to the maintainer. Do not open a public
  issue with an exploit chain or live target data.
