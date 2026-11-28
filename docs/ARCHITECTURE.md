# Architecture Governance & System Map (`dex`)

## 1. Layered Acyclic Dependency Architecture (DAG)

Dependencies strictly flow **downward** from transport layers to leaf infrastructure:

```text
Layer 5 (Transport / UI):     cmd/dex  -->  internal/cli
                                              |--> internal/web (never imports cli)
Layer 4 (Background Runtime):               internal/daemon
Layer 3 (Control-Plane Engine):             internal/reconcile
Layer 2 (Pure Compilers):       internal/render         internal/migrate
Layer 1b (Leaf Adapters):       internal/cert           internal/socks5out
Layer 1 (Domain Root):                      internal/state
Layer 0 (Leaf Foundation):      internal/version  internal/fsutil  internal/cryptoext  internal/doh
```

### Package Ownership & Responsibilities
| Layer | Package | Authoritative Responsibility | Forbidden Imports |
|---|---|---|---|
| 0 | `internal/version` | Build/release version metadata | Any `internal/*` |
| 0 | `internal/fsutil` | Fsync-safe atomic file/JSON/copy & root prefix mapping | Any `internal/*` |
| 0 | `internal/cryptoext` | UUID, X25519/WG/Reality keys, PBKDF2 password hashing | Any `internal/*` |
| 0 | `internal/doh` | RFC 8484 DNS-over-HTTPS HTTP<->UDP relay | Any `internal/*` |
| 1 | `internal/state` | `State` schema, pure validators, normalization, domain constants, flock `Store` | Layer 1b+ (`socks5out`, `cert`, `render`, `reconcile`, `daemon`, `web`, `cli`) |
| 1b | `internal/cert` | X.509 inspection, self-signed generation, ACME/import lifecycle | Layer 2+ |
| 1b | `internal/socks5out` | SOCKS5 endpoint parser, RFC 1928 client dialer, HTTP exit prober | Layer 2+ |
| 2 | `internal/render` | Pure `State -> RenderBundle` compiler, canonical `ServicePlan`, share URIs | `os/exec`, `net/http`, Layer 3+ |
| 2 | `internal/migrate` | Importers for legacy `de_GWD` v2 / `des` / `dexs` configs | Layer 3+ |
| 3 | `internal/reconcile` | Atomic apply/rollback transactions, `Manifest`, cert/tproxy ops | Layer 4+ |
| 4 | `internal/daemon` | Failover, DDNS, webhook/TG notify, auto cert renewal, `TaskHub` | Layer 5 |
| 5 | `internal/web` | Embedded HTTPS panel, auth/CSRF, client DoH mux, REST `/api/v1/*` | `internal/cli` |
| 5 | `internal/cli` | Thin CLI command dispatch, TUI menu, binary/rule ops, bootstrap | — |

## 2. State & File Ownership Map

| Artifact Path | Authoritative Owner | Writers / Mutators |
|---|---|---|
| `/etc/dex/state.json`, `.bak`, `.txn` | `state.Store` | `state.Store` (flock `state.lock`) via `fsutil.WriteJSONAtomic` |
| `/etc/dex/generated/manifest.json` | `reconcile` | `reconcile.SaveManifest` via `fsutil.WriteJSONAtomic` |
| `/etc/dex/ssl/dex.{cer,key}` | `cert` + `reconcile` | `cert` via `fsutil.WriteFileAtomic` (only in `imported`/`acme_*`/`self_signed`) |
| `/etc/dex/generated/*`, `/etc/nginx/conf.d/dex-server.conf`, `/etc/haproxy/haproxy.cfg`, `/etc/wireguard/wg0.conf`, systemd/OpenRC units | `render` (generates) + `reconcile` (writes) | `reconcile.Reconcile` |
| `/etc/resolv.conf` | `reconcile` | Owned only when `client` role owns local `:53` (`mosdns`); backed up & restored on teardown/rollback |
| `/etc/dex/rules/*` | `cli` (`ops.go`) + `web` | Rule updater & initial bootstrap |

## 3. Preserved External Contracts

1. **Installer Triplet**: `scripts/install.sh`, `dex`, and `i` MUST stay byte-identical, begin with `#!/bin/sh`, and end with `main "$@"` (required by `scripts/cloudflare-worker.js` and CI `cmp -s` checks).
2. **CI Security Invariants**: Zero occurrences of insecure TLS skip flags or apt lock removal across shell scripts and Go sources.
3. **JSON Schema Compatibility**: `/etc/dex/state.json` `version: 3` fields and zero-version test fixtures remain accepted cleanly.
4. **REST API & CLI Surface**: All `/api/v1/*` routes, JSON payloads, CLI flags (`-c/-s/-r/-l`, `--state-dir`, `vless://` quick init), and subcommands remain backward compatible.

## 4. Governance Progress & Quantitative Impact

| Wave | Scope | Commit | Status |
|---|---|---|---|
| Wave 0 | Worktree isolation (`dex-arch-gov` / `arch/governance`), baseline gate, `CONTEXT.md`, `ARCHITECTURE.md`, `ADR-0001` | `b4c4a40` | Done |
| Wave 1 | Extract `internal/fsutil`; break `state -> socks5out` & `render -> socks5out`; purify `State.Validate()`; consolidate domain constants | `76471cd` | Done |
| Wave 2 | Canonical `render.ComputeServicePlan` SSOT (fixing missing `dex-nft` on host-fw VPS roles), `ManagedNFTTables`, data-plane constants, `BuildExtraURI`, delete pass-throughs | `938df08` | Done |
| Wave 3 | Unify Web/CLI cert workflows (`reconcile/cert_ops.go`), `State` credential/ID/WG mutations (`state/mutations.go`), TPROXY route teardown | `eafa081` | Done |
| Wave 4 | Decompose monoliths (`reconcile/apply.go`, `web/server.go`, `cli/cli.go`, `cli/menu.go`, `ui/app.js`) into cohesive domain-scoped files | `bb7feb6` | Done |
| Wave 5 | Enforceable architecture AST/contract tests (`internal/arch/arch_test.go`), file ceiling checks, CI parity audit | Commit in progress (`arch_test.go` verified) | Done |

### Before vs After Architecture Metrics
- **Domain Dependency Inversion Eliminated**: Removed `internal/state -> internal/socks5out` and `internal/render -> internal/socks5out`; `state` now imports only `internal/fsutil` and `internal/cryptoext`, and `render` never executes processes or HTTP calls.
- **Duplicate Infrastructure Unified**: Replaced 6 separate atomic file / root-prefix writers with `internal/fsutil`; unified `OutboundNode` / `UpstreamExitProfile` validation and `Validate` / `AllocateViaNginxInternalPorts` port enumeration; merged Web & CLI cert/WG/ExtraURI/DoH/TPROXY flows into `state` / `render` / `reconcile`.
- **Production Drift Bug Fixed**: Unified service-expectation checks into `render.ComputeServicePlan`, resolving missing `dex-nft` in status outputs when `system.firewall.enabled=true` on `server`/`landing`/`relay` without relay forwards.
- **Largest Non-Test Go File**: Reduced from `3,218` lines (`internal/cli/cli.go`) / `2,347` lines (`internal/web/server.go`) / `1,816` lines (`internal/cli/menu.go`) / `1,272` lines (`internal/reconcile/apply.go`) to a maximum of `1,344` lines (`internal/render/xray.go`), enforced at `<= 1,500` lines by `TestNoGodFiles`.
- **Automated Architectural Enforcement (`internal/arch/arch_test.go`)**: Enforces layered DAG, atomic-write centralization, UI `NODESM_META` parity with `state.NodeSMServices`, installer triplet & CI security invariants, and the monolith line ceiling.

## 5. Pending Product / Breaking Decisions (Recorded Only, Not Auto-Broken)

- **Root `dex` / `i` Shell Script Copies**: Maintaining three identical files (`scripts/install.sh`, `dex`, `i`) in Git creates triplicated churn on installer edits, but external `curl -fsSL https://raw.githubusercontent.com/stuinxo/dex/main/i` users and `cloudflare-worker.js` rely on those URLs. *Status*: Preserved as-is and guarded by CI + Go test checks unless deprecated upstream with Worker redirects.
- **Role Compatibility Flag Names**: Legacy field names in `state.json` (e.g., `rproxys`, `service_map`, `fwd0`/`fwd1`, `via_nginx`) remain unchanged to guarantee seamless upgrades from deployed v3 nodes.
