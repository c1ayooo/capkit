# enterprisekit

Enterprise-information providers and BFS collector ported from 4zrec's
`internal/platform/enterprise`.

Providers:

- `aqc` (爱企查, cookie)
- `tyc` (天眼查, cookie / x-auth-token)
- `kuaicha` (快查, cookie)
- `fengniao` (风鸟, cookie or username/password auto-login)

All HTTP goes through `capkit.Fetcher`; provider config (cookie/token) is
injected by the host and never stored by the kit.

## Capability surface

`NewKit(resolver)` exposes:

- `enterprise_search` — keyword -> stable `ext_id` references
- `enterprise_detail` — company detail + ICP/domain hints
- `enterprise_providers` — supported sources + auth mode

`ProviderResolver` is host-defined (e.g. a datasource vault). The kit does not
read cookies from settings.

## BFS collector

`Collector` is a library, not a registry capability, because it needs job
persistence and fingerprint callbacks:

```go
type Store interface {
    CreateJob(ctx, Job) (Job, error)
    FinishJob(ctx, id, status, errMsg string) error
    SetFingerprintStatus(ctx, id, status, errMsg string, stats FingerprintStats) error
    SaveEntity(ctx, *Entity) (bool, error)
    SaveDomain(ctx, jobID, domain, site, icp, entityName string) (bool, error)
    BumpJob(ctx, id string, nodes, entities, domains int) error
}

c := enterprisekit.NewCollector(store, 200, logger)
job, _ := c.Start(ctx, provider, enterprisekit.Job{...}, rootRef)
```

Candidates collected by the BFS are hints, not authorized scope. Importing them
into project assets must remain a host approval step.
