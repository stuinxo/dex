# ADR-0001: Layered Declarative Control-Plane Architecture

- **Status**: Accepted
- **Date**: 2026-11-28
- **Context**: `dex` evolved rapidly from shell scripts (`de_GWD` v2) to a zero-dependency Go binary (`v0.0.1`–`v0.0.8`). While its core design cleanly separated `state`, `render`, and `reconcile`, accumulated cross-cutting growth introduced an inverted dependency (`state -> socks5out`), six duplicate atomic file writers, divergent Web/CLI/Render service-status checks, and 1,200–3,200 line monolithic files that increase merge contention and maintenance cost.
- **Decision**:
  1. Enforce a strict 6-layer acyclic dependency graph (Layer 0 `version`/`fsutil`/`cryptoext`/`doh` -> Layer 1 `state` -> Layer 1b `cert`/`socks5out` -> Layer 2 `render`/`migrate` -> Layer 3 `reconcile` -> Layer 4 `daemon` -> Layer 5 `web`/`cli`).
  2. Keep `internal/state` free of adapter dependencies and make `State.Validate()` side-effect-free.
  3. Treat `internal/render` as a pure, deterministic compiler (no `os/exec`, no `net/http`) and the Single Source of Truth for active service topology, managed nftables tables, data-plane marks, and client share URIs.
  4. Consolidate duplicated Web/CLI control-plane operations (certificate lifecycle, TPROXY teardown, WG peer/credential generation) into `internal/reconcile` and `internal/state`.
  5. Decompose monolithic files along domain seams within existing packages so multiple agents can modify independent commands or HTTP surfaces concurrently without conflicts.
  6. Enforce layer boundaries, UI service parity, installer invariants, atomic-write centralization, and monolith line ceilings via automated tests in `go test ./...`.
- **Consequences**:
  - `main` branch behavior, `/etc/dex/state.json` compatibility, `/api/v1/*` endpoints, and CLI contracts remain 100% preserved.
  - Future violations of layer DAG or duplicate infrastructure fail `go test` immediately.
