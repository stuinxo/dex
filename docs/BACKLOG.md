# Architecture Governance Backlog (`dex`)

## Closed High-Value Work
- [x] **Layered Dependency DAG & Domain Purification**: Severed `state -> socks5out` and `render -> socks5out`; pure side-effect-free `State.Validate()`; `render` free of `os/exec` and `net/http`.
- [x] **Atomic I/O & Manifest Durability**: `internal/fsutil` (`fsync`-before-rename) enforced across `state.Store`, `reconcile.SaveManifest`, `cert`, `update`, and `cli`.
- [x] **Service Topology SSOT**: `render.ComputeServicePlan` + fixed `dex-nft` host-firewall status reporting bug.
- [x] **Store & Apply Serialization + Dual Rollback**: `Store.Save`/`Update` ordered `apply.lock -> state.lock` with scoped `*Store`; `RollbackTxn` restores `.bak` before primary; `reconcile` joins rollback errors.
- [x] **Certificate Workflow & Transition Ownership**: `Store.ActiveCertPaths`, `Store.HasCustomExternalCert`, `CertConfig.Use*`, atomic `reconcile/cert_ops.go` with single-shot `ReloadFn`.
- [x] **Operational Update Module**: Extracted `internal/update` serialized under `WithApplyLock`, with per-file rule restoration errors and backup retention.
- [x] **Web Auth, Secrets, DoH Cache & Metrics**: Credential-bound session snapshots + CAS, serialized `preserveStateSecrets`, dual-source `clientDoHCache`, configured-inventory `NodeMetricsTracker`.
- [x] **Installer Authority & Domain Decomposition**: `scripts/sync-install.sh` + `test-install.sh`; monolithic Go files decomposed below 1,500 lines; `internal/arch` AST/contract CI gates.
- [x] **Live Linux VM/LXC Acceptance & Control-Plane Hardening (Wave 10)**: Verified all 4 roles (`server`, `client`, `relay`, `landing`), both init systems (`systemd` on Debian 13 KVM + `OpenRC` on Alpine 3.22 LXC), real kernel `nftables`/TPROXY/WireGuard/`/dq` DoH/HAProxy relay data planes, Web auth/CSRF/secret retention/`clientDoHCache` hot-swap, unmanaged drift/`--force` recovery, and VM reboot persistence. Fixed two live-discovered defects (`ApplyResult.Bundle` `json:"-"` secret/payload guard in `internal/reconcile/apply.go`; small-body draining on `Connection: close` responses in `internal/web/server.go`).

## Pending Product Decisions / External Environment Verification
1. **Optimistic Concurrency Revision Token for `PUT /api/v1/state` (Wire-contract change)**: Masked secrets and auth credentials are serialized against concurrent mutations, but ordinary non-secret configuration fields replaced wholesale via `PUT /api/v1/state` still follow last-writer-wins semantics unless an explicit state revision/ETag contract is introduced across Web UI and API clients.
2. **Cross-State-Directory Shared Binary Lock Identity (Design decision)**: `update.UpdateComponents` serializes per `store.Dir` (`apply.lock`), whereas default binary targets (`/usr/local/bin/{dex,xray,mosdns}`) are host-global if two independent `--state-dir` instances update binaries concurrently. Needs explicit global binary lock path only if multi-instance coexistence on one host becomes a supported topology.
3. **Root `dex` / `i` Raw URL Alias Deprecation (External contract)**: `scripts/sync-install.sh` eliminates manual drift between `scripts/install.sh`, `dex`, and `i`. Deletion of `dex`/`i` should only happen once external `raw.githubusercontent.com` references and `cloudflare-worker.js` routes are retired.
