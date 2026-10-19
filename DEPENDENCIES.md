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
   - HTTP: `core.HTTPDoer` / `core.Fetcher` (no kit-owned `http.Client` to
     a project target)
   - subprocess: `core.ProcessRunner`
   - storage: a host Store adapter
   - logging: `core.Logger`

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
`core.ProcessRunner`, never by importing their source.

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

Cloud provider SDKs (all Apache-2.0 unless noted, all used by `cloudkit`).
Signing, endpoint resolution, paging and retry are the SDKs' job — rule 2 is
the reason these exist instead of hand-rolled HTTP signatures:

| Dependency | Version | Why |
|---|---|---|
| `github.com/aws/aws-sdk-go-v2` | v1.47.3 | AWS v2 core: SigV4 signing, endpoint resolution, retry policy |
| `github.com/aws/aws-sdk-go-v2/credentials` | v1.20.9 | static AK/SK credential provider for the caller's key pair |
| `github.com/aws/aws-sdk-go-v2/service/sts` | v1.51.4 | `GetCallerIdentity` — `cloud_ak_verify` |
| `github.com/aws/aws-sdk-go-v2/service/ec2` | v1.339.0 | `DescribeInstances` — `cloud_asset_list` (compute) |
| `github.com/aws/aws-sdk-go-v2/service/rds` | v1.130.3 | `DescribeDBInstances` — `cloud_asset_list` (database) |
| `github.com/aws/aws-sdk-go-v2/service/iam` | v1.64.4 | `ListUsers` / `ListAttachedUserPolicies` — `cloud_iam_list` admin probing |
| `github.com/aws/aws-sdk-go-v2/service/s3` | v1.114.3 | `ListBuckets` — `cloud_storage_list` |
| `github.com/aws/aws-sdk-go-v2/service/ssm` | v1.79.3 | `SendCommand` — `cloud_run_command` |
| `github.com/alibabacloud-go/tea` | v1.5.3 | Alibaba Cloud client core (request model + credential) |
| `github.com/alibabacloud-go/darabonba-openapi/v2` | v2.2.4 | Alibaba Cloud OpenAPI runtime used by the product SDKs |
| `github.com/alibabacloud-go/sts-20150401/v2` | v2.1.0 | `GetCallerIdentity` — `cloud_ak_verify` |
| `github.com/alibabacloud-go/ecs-20140526/v4` | v4.26.10 | `DescribeInstances` — `cloud_asset_list` (compute) |
| `github.com/alibabacloud-go/rds-20140815/v6` | v6.1.0 | `DescribeDBInstances` — `cloud_asset_list` (database) |
| `github.com/alibabacloud-go/ram-20150501/v2` | v2.2.1 | `ListUsers` / `ListPoliciesForUser` — `cloud_iam_list` admin probing |
| `github.com/aliyun/alibabacloud-oss-go-sdk-v2` | v1.6.1 | `ListBuckets` — `cloud_storage_list` |
| `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common` | v1.3.193 | Tencent Cloud client core (TC3-HMAC-SHA256 signing, profile) |
| `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts` | v1.1.11 | `GetCallerIdentity` — `cloud_ak_verify` |
| `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm` | v1.3.183 | `DescribeInstances` — `cloud_asset_list` (compute) |
| `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdb` | v1.3.183 | `DescribeDBInstances` — `cloud_asset_list` (database) |
| `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam` | v1.3.186 | `ListUsers` / `ListAttachedUserPolicies` — `cloud_iam_list` admin probing |
| `github.com/tencentyun/cos-go-sdk-v5` | v0.7.75 (MIT) | `GetService` — `cloud_storage_list` |
| `github.com/huaweicloud/huaweicloud-sdk-go-v3` | v0.1.219 | single module covering STS, ECS, RDS and IAM v3 — `cloud_ak_verify`, `cloud_asset_list`, `cloud_iam_list` |

Huawei Cloud is deliberately narrower than the other three: `cloud_storage_list`
and `cloud_run_command` report `unsupported`. OBS lives in the separate
`huaweicloud-sdk-go-obs` (not imported) and the ECS v2 service in
huaweicloud-sdk-go-v3 v0.1.219 exposes no cloud-assistant command API, so neither
capability is fabricated with a hand-rolled signature.

Everything else is standard library only.
