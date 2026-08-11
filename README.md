# xboard-node

> **给 lb-panel 用时装出来的是 `lb-node`。** `install.sh` 里的安装名已经和现网
> 老 agent 分开，为的是同一台机器上能并存、老的不用停：
>
> | | 老 agent | 本仓库 install.sh |
> |---|---|---|
> | 二进制 | `/usr/local/bin/xboard-node` | `/usr/local/bin/lb-node` |
> | 服务 | `xboard-node.service` | `lb-node.service` |
> | 配置 / 证书 | `/etc/xboard-node/` | `/etc/lb-node/` |
> | CLI | `xbctl` | `lbctl` |
> | 健康端口 | 65530 | 65531 |
>
> Release 产物名（`xboard-node-linux-amd64` / `xbctl-linux-amd64`）没改，装到
> 机器上时才改名 —— CI 和已发布的包都不用动。`make install` 仍按老名字装，
> **别用它装新 agent**。两套并存时记得节点的 `server_port` 也不要撞。

Node backend for [Xboard](https://github.com/cedar2025/Xboard). Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/cedar2025/xboard-node:latest
```

### Docker Compose

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
