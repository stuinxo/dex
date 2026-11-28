# DEX

零依赖 Go 单二进制网关与服务端统一控制面（支持 Debian / Ubuntu / Alpine，`amd64` / `arm64`）。

## 安装

```sh
wget -qO- dex.stuinx.net | sh
# 或
curl -Lso- dex.stuinx.net | sh
```

指定角色直装（零附加参数，推荐先装 `server`，再拿输出的 `vless://` 链接装 `client`）：

```sh
wget -qO- dex.stuinx.net/server | sh
wget -qO- dex.stuinx.net/client | sh
wget -qO- dex.stuinx.net/landing | sh
wget -qO- dex.stuinx.net/relay | sh
```

GitHub 备用入口：`wget -qO- github.com/stuinxo/dex/raw/main/dex | sh`

## 角色

| 角色 | 用途 | 默认面板 | 组件 |
| :--- | :--- | :--- | :--- |
| `client` | 透明代理旁路网关 / 公网中转 | `:443` | `xray` · `mosdns` · `doh` · `nft` · `wg0` |
| `server` | 服务端（Nginx 伪装 + `/dq` DoH） | `127.0.0.1:8443` | `xray` · `doh` · `nginx` |
| `landing` | 极简直连 TLS 落地 | `127.0.0.1:8443` | `xray` |
| `relay` | 端口转发 / 内网穿透 | `127.0.0.1:8443` | `nft` · `haproxy` · `xray` |

## 常用命令

```sh
dex                 # 交互菜单（首次打开可直接粘贴 vless:// 链接直装 Client）
dex 'vless://...'   # 一步初始化 Client 节点 + 同源 /dq DoH 并自动生效
dex -c/-s/-r/-l     # 指定角色向导或直装并自动生效（如 dex -s srv.example.com）
dex status          # 查看状态
dex apply           # 校验并应用配置
dex update          # 更新组件与规则
dex --help          # 完整命令帮助
```

## 编译

```sh
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-amd64 ./cmd/dex
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/dex-linux-arm64 ./cmd/dex
```

安装脚本的唯一编辑源为 `scripts/install.sh`。修改后运行 `sh scripts/sync-install.sh`，生成兼容原始下载地址的 `dex` 和 `i`。提交前运行 `sh scripts/test-install.sh`，CI 使用同一入口校验同步、语法和安装行为。
