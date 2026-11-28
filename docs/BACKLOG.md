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

## Pending Product Decisions / External Environment Verification
1. **Live Linux VM Acceptance (Environment-gated)**: End-to-end runtime verification on fresh Debian 12/13 (systemd) and Alpine 3.x (OpenRC) hosts (installing packages, enabling `dex-xray`/`dex-mosdns`/`dex-nft`/`nginx`, applying `wg0`, and verifying reboot persistence). Mocked/POSIX installer tests pass on macOS; no live production host has been mutated.
2. **Optimistic Concurrency Revision Token for `PUT /api/v1/state` (Wire-contract change)**: Masked secrets and auth credentials are serialized against concurrent mutations, but ordinary non-secret configuration fields replaced wholesale via `PUT /api/v1/state` still follow last-writer-wins semantics unless an explicit state revision/ETag contract is introduced across Web UI and API clients.
3. **Cross-State-Directory Shared Binary Lock Identity (Design decision)**: `update.UpdateComponents` serializes per `store.Dir` (`apply.lock`), whereas default binary targets (`/usr/local/bin/{dex,xray,mosdns}`) are host-global if two independent `--state-dir` instances update binaries concurrently. Needs explicit global binary lock path only if multi-instance coexistence on one host becomes a supported topology.
4. **Root `dex` / `i` Raw URL Alias Deprecation (External contract)**: `scripts/sync-install.sh` eliminates manual drift between `scripts/install.sh`, `dex`, and `i`. Deletion of `dex`/`i` should only happen once external `raw.githubusercontent.com` references and `cloudflare-worker.js` routes are retired.
