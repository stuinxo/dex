# Architecture Governance & System Map (`dex`)

## 1. Layered Acyclic Dependency Architecture (DAG)

Dependencies strictly flow **downward** from transport adapters to leaf infrastructure across 14 internal packages plus `cmd/dex`. `internal/arch` enforces exact permitted direct imports (across all OS build-tag files):

```text
Layer 5 (Transport / UI):     cmd/dex  -->  internal/cli
                                              |--> internal/web (never imports cli/update)
Layer 4 (Runtime / Ops):      internal/daemon          internal/update
Layer 3 (Control-Plane Txn):            internal/reconcile
Layer 2 (Pure Compilers):     internal/render          internal/migrate
Layer 1b (Leaf Adapters):     internal/cert            internal/socks5out
Layer 1 (Domain Root):                  internal/state (imports only fsutil, cryptoext)
Layer 0 (Leaf Foundation):    internal/version  internal/fsutil  internal/cryptoext  internal/doh  internal/arch
```

### Package Ownership & Direct Dependencies

| Layer | Package | Authoritative Responsibility | Permitted Direct `internal/*` Imports |
|---|---|---|---|
| 0 | `internal/arch` | Executable DAG, AST ownership, UI parity, installer & line-ceiling guards | `(none in prod)` |
| 0 | `internal/version` | Build/release version metadata (`0.0.8`) | `(none)` |
| 0 | `internal/fsutil` | `fsync`-safe `WriteFileAtomic`, `WriteJSONAtomic`, `CopyFileAtomic`, `MapRootPrefix` | `(none)` |
| 0 | `internal/cryptoext` | UUID, X25519/WG/Reality keys, PBKDF2-SHA256 & legacy v2 password auth | `(none)` |
| 0 | `internal/doh` | RFC 8484 DNS-over-HTTPS HTTP<->UDP relay handler | `(none)` |
| 1 | `internal/state` | Schema, side-effect-free `Validate`, `Normalize`, `mutations`, `CertConfig` transitions, `Store` | `cryptoext`, `fsutil` |
| 1b | `internal/cert` | X.509 inspection, self-signed generation, ACME/import pair management | `fsutil` |
| 1b | `internal/socks5out` | SOCKS5 endpoint normalization, RFC 1928 client dialer, exit prober | `state` |
| 2 | `internal/render` | Pure `State -> RenderBundle` compiler (`os/exec`/`net/http` forbidden), `ServicePlan`, share URIs | `cryptoext`, `state` |
| 2 | `internal/migrate` | Importers for legacy `de_GWD` v2 / `des` / `dexs` configs | `cryptoext`, `render`, `state` |
| 3 | `internal/reconcile` | Declarative apply/rollback transactions, `Manifest`, cert/tproxy orchestration | `cert`, `fsutil`, `render`, `state` |
| 4 | `internal/update` | Verified downloads, mirror/trust boundary, rule & binary updates with backup retention | `fsutil`, `reconcile`, `state` |
| 4 | `internal/daemon` | Failover, probes, `NodeMetricsTracker`, DDNS, webhook/TG notify, auto cert renewal | `reconcile`, `render`, `socks5out`, `state` |
| 5 | `internal/web` | Embedded HTTPS UI, credential-bound sessions, `clientDoHCache`, REST `/api/v1/*` | `cert`, `cryptoext`, `daemon`, `doh`, `migrate`, `reconcile`, `render`, `socks5out`, `state`, `version` |
| 5 | `internal/cli` | CLI dispatch, interactive TUI menu, system dependency bootstrap | `cert`, `cryptoext`, `daemon`, `doh`, `fsutil`, `migrate`, `reconcile`, `render`, `socks5out`, `state`, `update`, `version`, `web` |

## 2. Concurrency, Lock Ordering & Ownership Map

- **Lock Hierarchy**: `sessMu` (Web) -> `apply.lock` (`Store.WithApplyLock`) -> `state.lock` (`state.Store` internal flock).
- **Scoped `Store` Rule**: `Store.Save` and `Store.Update` acquire `apply.lock` before `state.lock`. `Store.WithApplyLock` supplies a synchronous scoped `*state.Store` marked `applyLocked=true`; nested `Update`, `Save`, `Reconcile`, and `UpdateRules` calls inside that scope reuse the lock without re-acquiring `apply.lock` and must never retain the scoped pointer asynchronously.
- **Dual-Restore Rollback**: `UpdateAndReconcile` and `reconcileUnlocked` own error-path rollback via `defer rollbackState(store, retErr)`, joining rollback errors with operation errors via `errors.Join`. `Store.RollbackTxn` atomically restores `state.json.bak` **before** `state.json` from `state.json.txn` so fallback reads never resurrect rejected intermediate states.

| Artifact / Runtime State | Authoritative Owner | Key Invariant |
|---|---|---|
| `/etc/dex/state.json`, `.bak`, `.txn` | `state.Store` | Atomic `fsutil.WriteJSONAtomic`; `.bak` restored first on rollback |
| `/etc/dex/generated/manifest.json` | `reconcile.Manifest` | `fsutil.WriteJSONAtomic` (`fsync` before rename) |
| `/etc/dex/ssl/dex.{cer,key}` & external paths | `Store.ActiveCertPaths`, `CertConfig.Use*`, `reconcile/cert_ops` | Single atomic cert state update + conditional reconcile inside `WithApplyLock`, single consumer reload |
| `/etc/dex/rules/*` & binaries | `internal/update` | Serialized under `WithApplyLock`; per-file `restoreRulesFiles` joins failures and retains `.rules-bak-*` on error |
| Active service plan & `nft` tables | `render.ComputeServicePlan` | Single Source of Truth across `render`, `reconcile`, `cli status`, TUI badges, and `/api/v1/status` |
| Web sessions & passwords | `internal/web/auth.go` | Immutable request snapshots bound to `PasswordHash`; CAS `errCredentialsChanged` on rehash/password change |
| Web state secrets & migrations | `internal/web/handlers_state.go` | Masked secrets & fallback hashes resolved inside serialized `UpdateAndReconcile` / `Store.Update` |
| Client DoH route cache | `web.clientDoHCache` | Tracks primary & backup `os.SameFile`/size/mtime + upstream key under one mutex |
| Node metrics ring buffer | `daemon.NodeMetricsTracker` (`metrics.go`) | Configured node inventory defines output order and visibility; empty inventory yields `[]` |
| Bootstrap installer entrypoints | `scripts/install.sh` + `scripts/sync-install.sh` | Single editable source; `dex` & `i` generated identically (`--check` gated in `scripts/test-install.sh` and CI) |

## 3. Automated Enforcement (`internal/arch/arch_test.go` + CI)

1. **`TestLayeredDependencyDAG`** & **`TestDependencyGuardRejectsLayerViolation`**: Enforces direct internal imports across all Go files (including platform-specific files) and rejects `os/exec` / `net/http` in `render`.
2. **`TestAtomicWriteCentralization`**: Prohibits direct `os.CreateTemp` calls outside `internal/fsutil/atomic.go`, `internal/update/download.go`, and `internal/update/operations.go`.
3. **`TestCertificateTransitionOwnership`**: Rejects direct `.Cert.{Mode,CertFile,KeyFile,AutoRenew}` assignments in `cli`, `web`, and `reconcile`.
4. **`TestPortAllocationOwnership`**: Rejects re-introduction of `ExtraInternalPort` / `AllocateViaNginxInternalPorts` pass-throughs in `render`.
5. **`TestNodeSMServiceCatalogParity`**: Verifies UI `NODESM_META` keys match `state.NodeSMServices` 1:1.
6. **`TestInstallerTripletAndSecurityInvariants`** & `scripts/test-install.sh`: Enforces `scripts/install.sh` == `dex` == `i` sync, POSIX syntax, and zero forbidden TLS-skip / apt-lock patterns.
7. **`TestNoGodFiles`**: Enforces `<= 1,500` lines across all non-test `.go` files (current maximum is `1,344` lines in `internal/render/xray.go`).
