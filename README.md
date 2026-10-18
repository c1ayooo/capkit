# capkit

Platform-independent capability kernels for authorized security testing
platforms. Hosts implement ports (scope, approval, evidence, audit, storage,
secrets); kits contain the reusable domain logic.

This is **not** a scanner or an agent framework. It is the contract layer that
lets a Go host mount reusable capabilities without re-porting them.

## Design rules

1. **Contracts at module root.** No `capkit/capkit/` nesting.
2. **Registry is static.** `*capkit.Registry` holds declarations and validation
   only. It never holds instances.
3. **Runtime is an instance container.** `runtime.New(cfg, registry)` builds
   capabilities and wraps every call with gates. It has no `Register` method.
4. **Kits depend only on the `capkit` root package.** Kit-to-kit imports are
   forbidden; composition happens in `all`.
5. **Gates are mandatory.** Every tool call goes through:
   `scope -> approval -> rate limit -> audit`.
6. **memstore first.** Contract tests run against in-memory adapters; Postgres
   is an optional adapter, not the reference implementation.
7. **Contracts only cross the boundary.** Shared JSON Schema lives in
   `contracts/`; internal models are not serialized.

## Layout

```
capkit.go / port.go / manifest.go / registry.go   contracts at the root
gates/        scope, approval, per-host rate limit, audit chain
runtime/      builds capabilities from a registry; routes calls through gates
runtime/httpapi  generic /tools, /manifests, /call surface
adapters/     httpx (gate-aware HTTP + external Fetcher), exec, sealer, ...
kits/         httpkit, nucleikit, templatekit, fingerprintkit, verifykit,
              githubkit, reconkit, spacemapkit, enterprisekit, playbookkit,
              toolparse, oastkit, exploitkit, shellkit, sessionkit, identitykit,
              privesckit, latkit, persistkit, cleanupkit, internalnetkit,
              containerkit, avkit
              (protocol/payload/memshell/tunnel/plan/session/delivery/listener)
optional/     heavy implementations (pd, nuclei-library); none imported by core
all/          registration helpers (Register / RegisterFull)
harness/      fake targets for contract tests
contracts/    cross-boundary JSON Schema
examples/     minimal integration
```

## Docs

| 文档 | 给谁看 |
|---|---|
| [宿主接线指南](docs/宿主接线指南.md) | 把 capkit 挂进宿主平台的工程师：端口清单、三种注册粒度、门禁与运行参数、BFF 写法、接线自检、常见错误 |
| [工具调用协议](docs/工具调用协议.md) | 调用方（agent / 宿主 / 前端 / CLI）：发现 schema、调用、信封逐字段读法、六态决策表、错误码表、幂等、证据、截断分页、异步轮询 |
| [前端展示设计方案](docs/前端展示设计方案.md) | 前端：schema 驱动的工具台、路由与 BFF 接口、信封→界面映射、与已有页面的衔接、分期落地 |
| [究极渗透能力包实现方案](docs/究极渗透能力包实现方案.md) | 本模块的规格来源（§3.1 kit 划分、§5.5 输出契约、§8 验收标准） |

接线最短路径：`宿主接线指南` §0 复制一分钟版 → §1 对齐端口 → `工具调用协议` §2-§4 确认调用形状。

## Quick start

```bash
go run ./examples/minimal
```

The example registers `httpkit`, builds a runtime with in-memory gates, and
calls `http_probe` against a local `httptest` server.

Minimal host wiring:

```go
reg := capkit.NewRegistry()
if err := all.RegisterHTTP(reg); err != nil { ... }

scope := myScope       // implements capkit.ScopeChecker
approval := myApproval // implements capkit.Approver
limiter := gates.NewLimiter()
audit := auditlog.NewMemory()
httpClient := httpx.New(scope, limiter, audit)

rt, err := runtime.New(runtime.Config{
    Scope: scope, Approval: approval, Limiter: limiter, Audit: audit,
    HTTP: httpClient, Settings: mySettings, Sealer: mySealer,
}, reg)

res, err := rt.Call(ctx, "http_probe", input, capkit.CallContext{
    ProjectID: 1, Actor: "operator",
})
```

Optional generic HTTP surface:

```go
import "github.com/c1ayooo/capkit/runtime/httpapi"

http.ListenAndServe(":8080", httpapi.New(rt))
// GET /tools, GET /manifests, POST /call {tool,input,context}
```

## Adding a capability

1. Write a one-page capability brief: tools, inputs/outputs, risk, ports,
   settings, events.
2. Implement `capkit.Capability`:
   - `Manifest()` declares tools, `Requires`, settings and events.
   - `Call()` switches on `call.Tool`.
3. Every target-bearing tool must implement `ToolSpec.ExtractTargets`.
4. Use only injected ports:
   - `HTTPDoer` for HTTP, `ProcessRunner` for subprocesses,
   - `EvidenceSink`, `Settings`, `Sealer`, `Logger`, `IDs`.
5. Add a fake target in `harness/` and contract tests.
6. Register it in `all` or import it directly from the host.
7. Add any new dependency to `DEPENDENCIES.md` in the same change.

## Single module

`capkit` is one Go module. Benign kits and `kits/shellkit` are all importable
with one `go get`; there is no separate private module. Shellkit is
authorized-use-only and requires host-provided delivery/execution sinks.
Optional heavy implementations live under `optional/` as subpackages of the
same module (currently placeholders) and are not imported by core kits.
`spacemapkit` and `enterprisekit` are canonical: 4zrec's local packages are
thin aliases/wrappers so the engine/provider logic is not duplicated.

## Verification

```bash
go test ./...
go vet ./...
./scripts/check-imports.sh
```

`check-imports.sh` enforces the kit boundary and the dependency allowlist.

## Status

Implemented:

- `capkit` contracts, registry, runtime, gates (scope/approval/rate/audit/redaction)
- adapters: gate-aware HTTP, gate-aware process runner, AES-GCM sealer,
  in-memory settings/audit
- `runtime/httpapi`: generic `GET /tools`, `GET /manifests`, `POST /call`
- `httpkit`: `http_probe` + `TemplateEngine` for `kind: http`
- `nucleikit`: `nuclei_scan`, `nuclei_status`, JSONL parsing + `TemplateEngine`
  for `kind: nuclei` (writes each template artifact to a temp file)
- `templatekit`: engine-neutral model, pack loader (YAML/JSON), catalog search,
  validation, provenance/checksum; no execution
- `fingerprintkit`: rule model, matcher, favicon mmh3, wappalyzer/webanalyze/dddd
  sync, `Provider` implementing `capkit.FingerprintProvider`; no asset writes
- `verifykit`: `verify_plan` / `verify_execute`, depending only on
  `FingerprintProvider` + `TemplateCatalog` + `TemplateEngine`
- `githubkit`: GitHub Code Search secret dorks, token/rate-limited client,
  secret-type classification and static credibility scoring; uses the external
  `Fetcher` port (not target-scoped HTTP)
- `reconkit`: engine-neutral subdomain → resolve → ports → HTTP pipeline with
  host-provided providers and an `AssetSink`; no asset-graph writes
- `playbookkit`: deterministic HTTP/TCP/DNS verification playbooks with
  assertions, variable extraction, hard limits and confirmed/refuted/blocked
  verdicts; preset playbooks are embedded via `EmbeddedPresets()`
- `toolparse`: structured parsers for httpx/ffuf/katana/nuclei/nmap/sqlmap/
  dalfox/arjun/fscan/hydra/etc.; produces fields + normalized fact candidates
- `exploitkit`: bounded cmdi/SSTI/LFI/SQLi/SSRF probes with baseline diffs,
  LFI log-poison proof, Redis gopher payload builder, ysoserial/phpggc payload
  generation and an optional msfconsole runner; no built-in targets or
  one-click chains
- `spacemapkit`: FOFA/ZoomEye/Quake/Shodan/Hunter search, per-engine field and
  row normalization, domain query syntax; external API keys via resolver/env/
  settings and all HTTP through `Fetcher`
- `enterprisekit`: AQC/TYC/Kuaicha/Fengniao providers, provider factory,
  enterprise search/detail capability and a host-store-backed BFS collector
- `oastkit`: dnslog.cn callback domain/records (no self-hosted OAST required)
- `sessionkit`: the `Session`/`SessionManager` contract plus four transports —
  SSH (x/crypto/ssh: exec/upload/download/tunnel), WinRM (WSMan SOAP carried
  over the `HTTPDoer` port, so scope/rate/audit apply to every call), SMB
  (smbclient via `ProcessRunner`, its password passed in `PASSWD` rather than
  argv) and CLI (local process via `ProcessRunner`, allowlisted)
- `identitykit`: target-side identity — cookie jar, CSRF token extraction,
  proactive OAuth/JWT token refresh (`capkit.Identity`)
- `shellkit` session tools: `session_open/exec/upload/download`, `tunnel_open`,
  `session_list`, `session_close` — every transport is driven identically
- `privesckit`: read-only Linux/Windows privilege-escalation enumeration and
  ranked candidate advice (identify & decide only; no payload)
- `latkit`: impacket/NetExec/Kerberos argv builders (psexec/wmiexec/smbexec,
  pass-the-hash, WinRM, Kerberoast/AS-REP/DCSync) invoked only as subprocesses
- `persistkit`: Linux (cron/systemd/ssh-key/bashrc/ldpreload/pam) and Windows
  (schtasks/service/registry-run/WMI-subscription/COM-hijack) placement, split
  into `persist_enum` / `persist_plan` / `persist_apply` (apply needs confirm)
- `cleanupkit`: trace cleanup as `cleanup_preview` → `cleanup_apply`; the apply
  requires the preview's `plan_id`, refuses a widened scope and never wipes
  unbounded selectors ("禁止一键清空")
- `internalnetkit`: from a foothold — host survey, live discovery, port scan,
  domain info and SMB share enumeration, all bounded and through `Session`
- `containerkit`: kubelet/apiserver/etcd/docker API probes plus container-escape
  triage (identify & rank; no escape payload)
- `avkit`: AV/EDR identification fingerprint database (process/driver/service/
  registry/file signatures) — identify & decide only, no bypass artifact
- `shellkit/listener`: Go TCP reverse-shell listener, multi-session registry,
  command exec, chunked upload/download (no C2 features)
- `Fetcher` port: external rule/intel/search downloads with rate limit + audit,
  without project target scope
- contracts (tool/result/output/target/evidence/event/settings/manifest/template/
  fingerprint/session/identity), the agent-facing `Result` envelope (six-state
  `Status`, bounded `Summary`/`Data`, `Findings`, `Next`, `Meta` with a
  runtime-counted `Requests` budget, idempotency), `Planner`, harness fake
  nuclei, shared root helpers (`FirstNonEmpty`, `TimeoutFromMS`, `Truncate`,
  `PreviewRunes`, `EvidenceRefs`, `PageWindow` — kits may only import the root,
  so the root is where a helper is defined once), three runnable examples
  (`minimal`, `verify-chain`, `session`)
- long tasks: any tool input may set `"async": true`; the runtime still runs the
  gate chain synchronously (a scope denial is reported immediately, not via a
  poll) and then returns `StatusPartial` with a `JobRef` in `Data`. The
  runtime-owned `job_status` tool polls it and finally returns the tool's own
  envelope (docs §5.5.5)
- list output: tools whose list can exceed 100 items take a `cursor` and return
  `Page{Total, Cursor, HasMore}` via `capkit.PageWindow`, so an agent pages
  through instead of losing rows (docs §5.5.4)
- `.github/workflows/capkit-ci.yml`: tests/vet/import boundaries for the module

Shellkit (same module, imported explicitly):

- `capkit/kits/shellkit`: `protocol`, `payload`, `memshell` (generator +
  probe + host Deployer), `tunnel` (page generator + host Sink/PageDeployer),
  `plan` (DeliverySink), `session` (Executor), `delivery` state machine.
- 4zrec's shell flow is wired through `delivery.Manager` + a DB-backed
  `delivery.Store` adapter; the host adapter is covered by the end-to-end test.

Optional subpackages (same module, dependency-heavy implementations only):

- `capkit/optional/pd`: subfinder/dnsx/naabu/katana adapters
- `capkit/optional/nuclei-library`: in-process nuclei engine

Next: host adapters for `reconkit`/template packs, large-file chunking for the
WebShell delivery path, and the optional ProjectDiscovery/nuclei-library
implementations.

### Known gaps against the spec

- **privesckit is identify-and-advise only.** §4.6/P2.1 also ask for
  exploitation; this module stops at enumeration plus ranked candidates, keeping
  the delimiter the spec itself draws in §4.12/§9.2 ("识别与决策进 capkit；成品
  载荷不进内核"). Escalation payloads stay host-side or in a private layer.
- **More list tools could page.** `inet_portscan` and `github_secret_search`
  take a `cursor`; the remaining list-shaped tools (dnslog records, spacemap
  hits, dork templates) return bounded sets today, so they set `Truncated` only.
  `capkit.PageWindow` is the helper for any that grows past 100 rows.
- **`session_exec` keeps its (clamped) stdout in `Data`.** §5.5.4's rule that
  response bodies live only in evidence would leave the tool unable to show the
  agent a command's output, so the runtime's 8 KB ceiling applies and an
  `EvidenceRef` is always attached for the full text.
- **`Result.Text`/`EvidenceIDs` and four extra error codes** (`not_found`,
  `conflict`, `unavailable`, `need_human`) extend §5.5.1/§5.5.3. `need_human` is
  required by the six-state `Status`; the rest are kept because collapsing them
  into `internal` would tell an agent to retry something it should not.

`all.RegisterFull` registers the whole surface; `all.RegisterSession`,
`all.RegisterPostExploitation`, `all.RegisterContainer` and `all.RegisterLateral`
are the same kits split out for hosts that register them selectively. The
session-driven kits declare the `sessions` port and latkit declares `process`, so
a host that registers them must supply a `capkit.SessionManager` /
`capkit.ProcessRunner` — `runtime.New` fails closed otherwise. `reconkit` and
`enterprisekit` are not in `RegisterFull`: both need host-injected collaborators
that `capkit.Deps` cannot carry (an `AssetSink`/provider set, a
`ProviderResolver`), so hosts use `RegisterRecon` / `RegisterEnterprise`.

## License

Apache-2.0. See `LICENSE` and `DEPENDENCIES.md`.
