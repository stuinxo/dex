# Architecture Decision Records (`dex`)

## ADR-001 — Strict Layered DAG & Pure Domain Root (`state`, `render`, `fsutil`)
- **Decision**: Extract leaf package `internal/fsutil` for `fsync`-before-rename writes (`WriteFileAtomic`, `WriteJSONAtomic`, `CopyFileAtomic`) and `MapRootPrefix`. Move pure address/rule/name validators and domain constants from `socks5out` and `render` into `internal/state`, make `State.Validate()` side-effect-free (separating `State.Normalize()`), and move state mutations (`mutations.go`) and certificate path/mode rules into `state`.
- **Outcome**: Eliminates `state -> socks5out` and `render -> socks5out` dependency inversions; deduplicates 6 separate temp-file atomic writers (including missing `fsync` in `reconcile.SaveManifest`).

## ADR-002 — Canonical Service Topology (`render.ComputeServicePlan`)
- **Decision**: Compute active services and nftables tables once via `render.ComputeServicePlan`, `ManagedServiceUnits`, `ManagedNFTTables`, and `WireGuardUnitName` across `render`, `reconcile`, `cli`, and `web`. Delete thin port pass-through wrappers (`ExtraInternalPort`, `AllocateViaNginxInternalPorts`) and unify extra-inbound sharing in `render.BuildExtraURI`.
- **Outcome**: Resolves a real defect where `dex-nft` was omitted from CLI/TUI/Web status on `server`/`landing`/`relay` hosts with `system.firewall.enabled=true` and zero relay forwards.

## ADR-003 — Unified Apply-Lock Serialization & Dual-Source Rollback
- **Decision**: Serialize `Store.Save` and `Store.Update` under `Store.WithApplyLock` (`apply.lock -> state.lock`) passing a synchronous `applyLocked` scoped `*Store`. Restore `state.json.bak` **before** `state.json` from `state.json.txn` in `RollbackTxn`, and centralize error-path state rollback in `UpdateAndReconcile` / `reconcileUnlocked` via `defer rollbackState(store, retErr)` (`errors.Join`).
- **Outcome**: Prevents concurrent writes from being lost during transaction rollback and prevents `.bak` fallback from resurrecting rejected intermediate transaction states.

## ADR-004 — Certificate Path, Mode Transition & Orchestration Ownership
- **Decision**: Place `Store.ActiveCertPaths`, `Store.HasCustomExternalCert`, and `CertConfig.{UseSelfSigned,UseImported,UseACME}` in `state`; place end-to-end atomic state-update + conditional `Reconcile` + single-shot `ReloadFn` workflows in `internal/reconcile/cert_ops.go`; reject direct `.Cert.*` transition field writes in adapters/reconcile via AST guard.
- **Outcome**: Removes 6 duplicated CLI/Web certificate transition blocks and eliminates double consumer reloads on Web certificate changes.

## ADR-005 — Independent `internal/update` Package & Rule Recovery Retention
- **Decision**: Extract verified downloads, rule updates, and component binary upgrades out of `internal/cli` into `internal/update`, serialized via `Store.WithApplyLock`, backed by `fsutil.CopyFileAtomic` and `state.ManagedRuleFiles`. Attempt every file during `restoreRulesFiles`, join per-file errors, and retain `.rules-bak-*` on restoration failure with path reporting. Delete dead `FindLocalPackage`.
- **Outcome**: Decouples operational updates from CLI parsing, prevents concurrent update/apply interleaving, and preserves recovery backups on failed rule restoration.

## ADR-006 — Credential-Bound Session Snapshots & Serialized Web Secret Merge
- **Decision**: Bind `sessionRecord` snapshots to `PasswordHash`, re-verify on each `getSession`, enforce CAS (`errCredentialsChanged`) on legacy rehash and password change while holding `sessMu` across store update and session replacement. Merge masked/omitted secrets (`preserveStateSecrets`) inside `PUT /api/v1/state`'s serialized `UpdateAndReconcile` mutator (keeping dry-run side-effect-free on a cloned preview), and re-resolve fallback hashes inside `handleMigrate`.
- **Outcome**: Invalidates sessions immediately when stored credentials change externally and eliminates stale-lock overwrites of credentials or tokens.

## ADR-007 — Coherent DoH Route Cache (`web.clientDoHCache`) & Configured-Inventory Metrics
- **Decision**: Replace 8 scattered `Server` DoH cache fields with `web.clientDoHCache` tracking `os.SameFile`, size, and mtime on both `state.json` and `state.json.bak` plus upstream keys. Extract `NodeMetricsTracker` into `internal/daemon/metrics.go` with strict configured-inventory visibility.
- **Outcome**: Detects equal-size/equal-mtime atomic state replacements across both primary and backup files and stops `/api/v1/metrics/nodes` from leaking deleted nodes when inventory becomes empty.

## ADR-008 — Canonical Bootstrap Source & Executable Architecture Guards
- **Decision**: Make `scripts/install.sh` the sole editable bootstrap source, publish byte-identical `dex`/`i` via `scripts/sync-install.sh`, and consolidate all AST/dependency/contract/ceiling checks into `internal/arch/arch_test.go` alongside `scripts/test-install.sh`.
- **Outcome**: Preserves all external raw installer URLs and CI contracts while enforcing architecture invariants automatically on `go test ./...`.
