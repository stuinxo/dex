# Ubiquitous Domain Language (`dex`)

This document defines the canonical domain terms and invariants for `dex` (`github.com/stuinxo/dex`). All code, packages, CLI subcommands, and Web UI labels use these terms with their exact meanings below.

## Core Concepts

- **Role (`RoleClient` | `RoleServer` | `RoleLanding` | `RoleRelay`)**:
  The operating mode declared in `State.Role`:
  - `client`: Transparent gateway / router node running Xray + MosDNS + nftables TPROXY/routing (`dex_client`), optional WireGuard, DDNS, FWD0/FWD1, RproxyC, and client DoH server.
  - `server`: Proxy node serving Xray main inbound (direct TLS or Nginx-fronted) + optional Nginx-hosted DoH (`dex-doh`), RproxyS, ExtraInbounds, Socks5Outbounds, UpstreamOutbounds, and optional `HostFirewall`.
  - `landing`: Minimal Xray exit node terminating inbound proxy traffic directly with TLS (`tls_mode=direct` default) and optional ExtraInbounds / `HostFirewall`.
  - `relay`: Pure port/traffic forwarder operating without client routing/TPROXY, using `nft` (`dex_relay`), `haproxy`, or `xray` engines plus optional `HostFirewall`.

- **Declarative `State` (`/etc/dex/state.json`, schema `CurrentSchemaVersion = 3`)**:
  The Single Source of Truth for node configuration. Mutated atomically through `state.Store` (`Load` / `Save` / `Update`), normalized via `State.Normalize()`, and verified read-only via `State.Validate()`.

- **Reconcile Transaction (`reconcile.UpdateAndReconcile` / `reconcile.Reconcile`)**:
  Transactional control-plane apply cycle: acquires `apply.lock`, opens `state.json.txn`, compiles `State -> RenderBundle` via `render.RenderAll`, performs dry-run & binary preflight, checks `Manifest` for manual edits, atomically promotes generated configs, reconciles init services (`systemd` or `openrc`), manages `/etc/resolv.conf` if client DNS owns `:53`, verifies core service health, commits `manifest.json` + `state.json`, or rolls back configs, `/etc/resolv.conf`, services, and state on failure.

- **Manifest (`/etc/dex/generated/manifest.json`)**:
  SHA-256 inventory of every file declaratively managed by `dex` (`xray.json`, `nftables.conf`, `mosdns/config.yaml`, `nginx`, `haproxy`, `wg0.conf`, systemd/OpenRC units). Prevents silent overwrite of manual operator edits unless `--force` is passed.

- **`OutboundNode` (`client.nodes[]`)**:
  A configured upstream proxy exit (`vless-xhttp`, `vless-reality`, `vless-ws`, `vmess-ws`, `vmess-tcp`, `socks5`) addressable by `ID`. Client routing references nodes exclusively by ID (`active_node_id`, `routing.service_map`, `routing.apple_node_id`, `routing.divert.node_id`, `routing.custom.node_id`, `fwd1.upstream_node_id`). Deleting a node always invokes `ClientConfig.PruneNodeRefs(id)`.

- **Service Routing & Shunting (`NodeSM`, `NodeDT`, `NodeCU`, Apple, Steam)**:
  - **`NodeSM` (`routing.service_map`)**: 16 canonical streaming/AI/social services (`state.NodeSMServices`) each mapped to a selected `OutboundNode` ID.
  - **`NodeDT` (`routing.divert`)**: LAN-subnet / client-IP split policies (`chn_proxy_lan_ips`, `global_proxy_lan_ips`, `direct_lan_ips`) and divert target node.
  - **`NodeCU` (`routing.custom`)**: Custom domain and IP/CIDR rules routed to a designated node.

- **Proxy Relay Chains (`FWD0`, `FWD1`)**:
  Client-role inbound listeners exposed on the LAN: `FWD0` connects direct/default; `FWD1` chains inbound connections out through `UpstreamNodeID`.

- **Reverse Proxy Tunnel (`RproxyC` / `RproxyS`)**:
  Xray portal/bridge reverse tunnel pairing: `RproxyS` (`server` role) accepts tunnel & external port traffic and maps `port/proto` pairs to `RproxyC` (`client` role) internal targets (`int_ip:int_port`).

- **`ExtraInbound` (`extra_inbounds[]`) & `ViaNginx`**:
  Additional inbound listeners (`vless-reality`, `vless-xhttp`, `vless-ws`, `vmess-ws`, `socks5`, `dokodemo`) on `server` / `landing` / `relay`. When `via_nginx` is true, Nginx terminates external TLS on `listen_port` and proxies HTTP/WS/XHTTP to a deterministic collision-free loopback port (`state.AllocateViaNginxInternalPorts`).

- **`UpstreamExitProfile` (`server.upstream_outbounds[]`) & `Socks5Profile` (`server.socks5_outbounds[]`)**:
  Server-role outbound chaining profiles that route matching domains/IPs (e.g., via residential/unlocking exits) instead of server direct egress.

- **`HostFirewall` (`system.firewall`, nft table `inet dex_host_fw`)**:
  Optional declarative host-level nftables hardening for VPS roles (`server`, `landing`, `relay`) enforcing management/data-plane separation (`mgmt_interfaces`, `mgmt_sources`, optional `cloudflare_origin_lock` on 80/443).

- **Data-Plane Packet Marks & Tables**:
  - `0x9` (`TProxyMark`): TPROXY redirected LAN/gateway traffic routed via Linux policy routing table `220`.
  - `0x8` (`QUICRejectMark`): UDP/443 QUIC packets rejected by nftables to force TCP fallback cleanly.
  - `0xff` (`DirectBypassMark`): Self-originated proxy/daemon traffic (`xray`, `dex-daemon` failover/probe/DoH, `mosdns`) marked so nftables returns instead of re-capturing into TPROXY.

## Core System Invariants

1. **Lock Ordering Invariant**: `Store.WithApplyLock` (`apply.lock`) is strictly outer to `Store.withLock` (`state.lock`). Never call `WithApplyLock` while holding `state.lock`.
2. **Pure Compilation (`render`)**: `internal/render` deterministically transforms `(State, RenderOptions) -> RenderBundle` with zero process execution (`os/exec`) and zero network I/O (`net/http`).
3. **Pure Validation (`State.Validate`)**: `State.Validate()` inspects invariants without mutating `*State`; structural defaulting belongs strictly in `State.Normalize()` / `State.EnsureGeneratedDefaults()`.
4. **Control-Plane Single Ownership**: Only `reconcile` mutates managed system configs and service states; `web` and `cli` mutate `State` through `reconcile.UpdateAndReconcile` or `Store.Update`.
5. **Zero External Go Dependencies**: `go.mod` uses standard library only; `CGO_ENABLED=0` cross-builds for `linux/amd64` and `linux/arm64`.
