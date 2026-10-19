# spacemapkit

Five-engine space-mapping client ported from 4zrec/4zreco:

- FOFA, ZoomEye, Quake, Shodan, Hunter
- unified `SearchResponse` + per-engine field/row normalization
- domain query syntax per engine (`domain="..."`, `domain:"..."`,
  `hostname:...`, `domain.suffix="..."`)
- key lookup: injected resolver -> environment -> `core.Settings`
- all HTTP through `core.Fetcher` (rate limit + audit; external scope)

Capability tools:

- `space_search`
- `space_domain_search`
- `space_providers`

Host wiring:

```go
kit := spacemapkit.NewClient(core.Deps{Fetcher: fetch})
kit.KeyResolver = func(provider string) string { return myVault.Key(provider) }
rt, _ := runtime.New(runtime.Config{Fetcher: fetch, Settings: settings}, reg)
```

Normalized `spacemapkit.Result` rows are candidates only; importing them into
assets/projects remains a host responsibility (4zrec keeps its approval and
noise-filtering logic in `spacemap_api.go`).

The engine clients do not send project targets directly; they query external
provider APIs, so project scope is not applied here. The host should still
record which project/query produced each imported asset.
