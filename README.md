# DEX（寒月）

双端自建透明代理旁路网关与轻量落地/中转统一控制面。**基于零依赖 Go 单二进制（`dex`）彻底重写**，保留并升格了 `des` 的声明式事务引擎与 `de_GWD v2` 的全部核心协议/安全不变量，支持从 `de_GWD v2`、`des`、`dexs` 无损平滑迁移。

## 核心变化（相比 de_GWD v2 / des / dexs）

- **单二进制控制面（`CGO_ENABLED=0`）**：彻底取代 11,000+ 行巨石 Bash、80 个 `ui-script`、PHP-FPM + 75 个 `act/*.php`、`sudoers` 白名单与 `ttyd`。
- **统一声明式状态 + 事务回滚**：唯一状态源 `/etc/dex/state.json`（`flock` 排他锁 + `.bak`/`.txn`）；所有配置由纯函数渲染至 `/etc/dex/generated/`，经 `xray run -test` / `nft -c` / `haproxy -c` / `nginx -t` 预检通过后原子替换，失败自动回滚；支持托管文件 SHA256 防误覆盖检查。
- **单核收敛**：
  - **Client 旁路网关**：单一 `dex-xray` 进程承载 TPROXY 主代理、NodeSM（16 项服务 + Apple/Steam）、NodeDT、NodeCU、FWD0/FWD1 与 RproxyC；单一 `dex-mosdns` 完成 `resp_ip` `chnroute` 防污染分流（移除 Docker Pi-hole 与 78 MB CoreDNS）；保留内置 **WireGuard 回家**（纯 Go X25519 密钥与二维码配置）与 **Cloudflare DDNS**；内置支持 **TLS SNI** 的节点探测与故障转移/切回。
  - **Server / Landing / Relay**：支持同端口 Nginx 反代模式（内置纯 Go RFC 8484 `/dq` DoH 服务，移除 14 MB `doh-server`）与直连 TLS 模式（适配 128 MiB LXC）；完整保留 Option 35 多 Profile SOCKS5 出站分流（含防自环与冲突拦截）、Option 44 三引擎转发（`nft` / `haproxy` / `xray`）、Option 22 RproxyS 与 Option 55 附加协议。
- **零二进制大包进 Git**：仓库仅保留纯源码，运行核心按架构按需拉取（支持离线包优先与 SHA256 + ELF 校验）。

## 快速安装

支持 **Debian 12/13 / Ubuntu**（`apt + systemd`）与 **Alpine 3.x**（`apk + OpenRC`），`amd64` / `arm64`：

```sh
# 方式一：短域名极简安装（国内直连，安装后自动进入交互菜单）
curl -Lso- dex.stuinx.net | sh
wget -qO- dex.stuinx.net | sh

# 指定角色一键直装（client / server / landing / relay）
curl -Lso- dex.stuinx.net/client | sh
curl -Lso- dex.stuinx.net/server | sh

# 方式二：GitHub 原生短路径
curl -Lso- github.com/stuinxo/dex/raw/main/dex | sh
wget -qO- github.com/stuinxo/dex/raw/main/dex | sh
```

离线部署需显式指定本地二进制或压缩包路径环境变量（不隐式扫描 `.` 或 `/tmp`）：`DEX_BIN=/root/dex-linux-amd64 XRAY_ZIP=/root/Xray-linux-64.zip MOSDNS_ZIP=/root/mosdns-linux-amd64.zip sh dex [client|server|landing|relay]`。

## 四种运行角色

| 角色 (`role`) | 适用场景 | 默认 Web UI 监听 | 核心组件 |
| :--- | :--- | :--- | :--- |
| `client` | 局域网旁路透明代理网关 | `:443`（HTTPS，同时在 `:80` 自动 301 跳转 HTTPS） | `dex-daemon` + `dex-xray` + `dex-mosdns` + `dex-nft` + 可选 `wg0` |
| `server` | 完整服务端（含 `/dq` DoH 与伪装站） | `127.0.0.1:8443`（`80`/`443` 由 Nginx 托管） | `dex-daemon` + `dex-xray` + `dex-doh` + `nginx` |
| `landing` | 128 MiB LXC 极简直连 TLS 落地 | `:8443` | `dex-xray`（直连 TLS，零 nginx/DoH 开销） |
| `relay` | 纯中转节点（三引擎端口转发 + RproxyS） | `:8443` | `dex-nft` / `haproxy` / `dex-xray` |

## 从旧版平滑迁移

支持一键无损导入 `v2` Client（`/opt/de_GWD/0conf`）、`v2` Server、`des` 与 `dexs` 配置：

```sh
# 从 v2 Client 迁移、校验并清理旧版服务后应用
dex migrate --kind v2_client --from /opt/de_GWD/0conf
dex apply --dry-run
dex migrate --kind v2_client --from /opt/de_GWD/0conf --cleanup-v2 --apply

# 从 v2 Server / des / dexs 迁移
dex migrate --kind v2_server --from /
dex migrate --kind des --from /etc/des/state.json
dex migrate --kind dexs --from /etc/vless-lite/state.json
```

> 迁移 `v2` `0conf` 时会保留旧版 Web 登录口令，并在首次通过 Web 控制台成功登录后自动升级为 `PBKDF2-HMAC-SHA256`。

## 常用 CLI 速查

```sh
dex                                # 打开交互式编号菜单
dex init --role landing --domain land.example.com --port 20001 --apply
dex status                         # 查看角色、服务状态与证书信息
dex server show | set              # 查看或修改服务端/Landing 主入站配置
dex apply [--dry-run [--out-dir <dir>]] [--force] [--restart-all]    # 校验、渲染并原子对账系统配置
dex node list | add [--from-uri ...] | edit | move | select | probe | show
dex cert inspect | self-sign [--force] | import <cer> <key> | issue [--mode cf|http]
dex wg enable | disable | keygen-server | peer-add <name> | peer-regen <name> | peer-del <name> | show [name]
dex ddns set --domain <d> --token <tok> | sync
dex socks5 list | add | del | toggle | test
dex relay list | add | del
dex rproxy show | set | map-add | map-del | disable
dex rproxy client-set | client-map-add | client-map-del | client-disable
dex extra list | add-reality | add-xhttp | add-vless-ws | add-vmess-ws | add-dokodemo | add-socks5 | del | disable-all
dex rules status | update          # 查看/更新 geodata 与分流规则列表
dex update [--component all|dex|xray|mosdns|rules]
dex migrate --kind ... --from ... [--cleanup-v2 --apply]
dex daemon                         # 启动内嵌 HTTPS Web 控制台、故障转移与 DDNS 协程
dex serve-doh                      # 启动 RFC 8484 /dq DoH 服务
```

## 内嵌 Web 控制台安全特性

- Fail-closed 会话认证（`HttpOnly`, `SameSite=Lax`, HTTPS 下自动 `Secure`）
- 按客户端 IP 滑动窗口防爆破限流（60s 内连续失败 10 次触发 `429` + `Retry-After: 60`）
- 所有状态变更接口强制 `X-CSRF-Token` 校验，API 响应自动脱敏密码哈希与 Token
- 原生 SSE 实时日志流（`/api/v1/logs/stream`）与零外链离线 SVG 二维码生成

## 本地开发与交叉编译

```sh
go vet ./...
go test -race -count=1 ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-amd64 ./cmd/dex
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-arm64 ./cmd/dex
```
