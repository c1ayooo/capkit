# shellkit

Authorized-use-only offensive WebShell capability. This package lives inside
the single `capkit` module (no separate `go.mod`); it is imported alongside the
benign kits when a host needs WebShell capability.

```
shellkit/protocol   plain / Behinder / Godzilla codecs (stdlib only)
shellkit/payload    PHP/ASP/ASPX/JSP payload renderer (stdlib only)
shellkit/memshell   Tomcat/Spring/ASP.NET/PHP memory-shell generator + host Deployer
shellkit/tunnel     target-side JSP/PHP SOCKS page generator + host Sink/PageDeployer
shellkit/plan       DeliveryPlan + host-provided DeliverySink/Verifier
shellkit/session    Session + host-provided Executor
shellkit/delivery   pure state machine (pending → delivered → verified → registered → cleaned)
```

## Host boundaries

- `plan.DeliverySink` must perform the actual upload. This package has **no
  default HTTP uploader**.
- `session.Executor` must perform command/file operations. This package has
  **no default command executor**.
- The host must enforce project scope, approval, evidence and cleanup before
  calling these interfaces.
- The host must ensure it has explicit authorization for every target.

## Rules

- Never add default targets, credentials, payloads, wordlists, or one-click
  exploit chains.
- Keep protocol/payload free of I/O and host dependencies.
- Do not import benign kits from shellkit or vice versa; both depend on the
  `capkit` root contracts only (shellkit subpackages may import each other).

## License

Apache-2.0, same as the rest of the `capkit` module. Use only in authorized
security testing and research.
