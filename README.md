# DEX

零依赖 Go 单二进制网关与服务端统一控制面（支持 Debian / Ubuntu / Alpine，`amd64` / `arm64`）。

## 安装

```sh
curl -Lso- dex.stuinx.net | sh
# 或
wget -qO- dex.stuinx.net | sh
```

指定角色直装（推荐先装 `server`，再拿 `server` 输出的节点链接与 DoH 一键对接 `client`）：

```sh
# 1. 先在 VPS 安装 Server（完成后自动输出节点 URI、DoH 地址及 Client 一键对接命令）
curl -Lso- dex.stuinx.net | sh -s -- -s

# 2. 在旁路网关安装 Client（直接传入 Server 输出的 vless:// 链接，自动解析节点与同源 /dq DoH）
curl -Lso- dex.stuinx.net | sh -s -- -c 'vless://...'
# 短路径同样支持：dex.stuinx.net/s · dex.stuinx.net/c · dex.stuinx.net/l · dex.stuinx.net/r
```

GitHub 备用入口：`curl -Lso- github.com/stuinxo/dex/raw/main/dex | sh`

## 角色

| 角色 | 用途 | 默认面板 | 组件 |
| :--- | :--- | :--- | :--- |
| `client` | 透明代理旁路网关 / 公网中转 | `:443` | `xray` · `mosdns` · `doh` · `nft` · `wg0` |
| `server` | 服务端（Nginx 伪装 + `/dq` DoH） | `127.0.0.1:8443` | `xray` · `doh` · `nginx` |
| `landing` | 极简直连 TLS 落地 | `127.0.0.1:8443` | `xray` |
| `relay` | 端口转发 / 内网穿透 | `127.0.0.1:8443` | `nft` · `haproxy` · `xray` |

## 常用命令

```sh
dex              # 交互菜单
dex -c/-s/-r/-l  # 指定角色向导或直装并自动生效（如 dex -c 'vless://...'）
dex status       # 查看状态
dex apply        # 校验并应用配置
dex update       # 更新组件与规则
dex --help       # 完整命令帮助
```

## 编译

```sh
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-amd64 ./cmd/dex
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-arm64 ./cmd/dex
```
