# Server TUIC (Agent Mode)

基于 TUIC 协议的代理服务器，通过 Connect RPC (HTTP/3 QUIC) 与控制面板集成，支持动态用户管理。

Fork 自 https://github.com/tuic-protocol/tuic

---

## 特性

- Connect RPC over QUIC (HTTP/3) 控制面板通信
- 动态用户管理与实时流量统计上报
- **ACL 引擎路由**：基于规则的流量路由，支持域名/IP/CIDR/通配符匹配
- 多出站类型：直连 (Direct)、SOCKS5 代理、拒绝 (Reject)
- TLS 证书热重载
- 支持公链 CA 和自签 CA 证书

---

## 编译

```bash
# 默认 (aws-lc-rs)
cargo build --release -p server-tuic-agent

# 使用 ring
cargo build --release -p server-tuic-agent --no-default-features --features ring

# 启用 JEMalloc
cargo build --release -p server-tuic-agent --features jemallocator
```

编译产物: `target/release/server-tuic-agent`

---

## 运行

```bash
server-tuic-agent --server_host panel.example.com --port 8082 --node 1
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--node <ID>` | 节点 ID | **必需** |
| `--server_host <HOST>` | 面板服务器地址 | `127.0.0.1` |
| `--port <PORT>` | 面板服务器端口 | `8082` |
| `--server_name <NAME>` | TLS SNI 服务器名称 | 同 `--server_host` |
| `--ca_cert <PATH>` | CA 证书路径（自签证书时使用，不指定则使用系统信任链） | - |
| `--ext_conf_file <PATH>` | 外部配置文件路径 (TOML) | - |
| `--acl_conf_file <PATH>` | ACL 路由配置文件路径 (YAML) | - |
| `--cert_file <PATH>` | TLS 证书文件路径 | `/root/.cert/server.crt` |
| `--key_file <PATH>` | TLS 私钥文件路径 | `/root/.cert/server.key` |
| `--log_mode <LEVEL>` | 日志级别 | `info` |
| `--timeout <SECS>` | 请求超时时间 | `15` |
| `--fetch_users_interval <SECS>` | 用户列表刷新间隔 | `60` |
| `--report_traffics_interval <SECS>` | 流量上报间隔 | `100` |
| `--heartbeat_interval <SECS>` | 心跳间隔 | `180` |
| `--data_dir <PATH>` | 数据目录路径 | `/var/lib/tuic-agent-node` |
| `--refresh_geodata` | 启动时强制刷新 GeoIP/GeoSite 数据库 | `false` |
| `--init` | 生成示例配置文件 | - |

### CA 证书配置

面板通信使用 QUIC (HTTP/3) 传输，TLS 证书验证方式：

- **公链 CA**：不指定 `--ca_cert`，自动使用系统信任链
- **自签 CA**：`--ca_cert /path/to/ca.crt`
- **SNI**：`--server_name my-server.com`（不填默认使用 `--server_host` 的值）

```bash
# 公链 CA（系统信任链）
server-tuic-agent --server_host panel.example.com --port 8082 --node 1

# 自签 CA
server-tuic-agent --server_host 10.0.0.1 --port 8082 --node 1 \
  --server_name panel.example.com \
  --ca_cert /path/to/ca.crt
```

### 快速开始

1. 生成示例配置文件:
```bash
server-tuic-agent --init
```

2. 根据需要修改配置文件:
   - `config.toml.example` → `config.toml` (TUIC 服务器配置)
   - `acl.yaml.example` → `acl.yaml` (ACL 路由规则)

3. 启动服务:
```bash
server-tuic-agent --node 1 --ext_conf_file config.toml --acl_conf_file acl.yaml
```

详细配置请参阅 [server-tuic-agent/README.md](server-tuic-agent/README.md)

---

## 许可证

[GNU General Public License v3.0](LICENSE)
