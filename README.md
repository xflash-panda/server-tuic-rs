# Server TUIC (Agent Mode)

基于 TUIC 协议的代理服务器，通过 gRPC 与控制面板集成，支持动态用户管理。

Fork 自 https://github.com/tuic-protocol/tuic

---

## 特性

- gRPC 控制面板集成，动态用户管理
- 实时流量统计与上报
- **ACL 引擎路由**：基于规则的流量路由，支持域名/IP/CIDR/通配符匹配
- 多出站类型：直连 (Direct)、SOCKS5 代理、拒绝 (Reject)
- TLS 证书热重载

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
server-tuic-agent --server_host 127.0.0.1 --port 8082 --node 1
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--node <ID>` | 节点 ID | **必需** |
| `--server_host <HOST>` | gRPC 服务器地址 | `127.0.0.1` |
| `--port <PORT>` | gRPC 服务器端口 | `8082` |
| `--ext_conf_file <PATH>` | 外部配置文件路径 (TOML) | - |
| `--acl_conf_file <PATH>` | ACL 路由配置文件路径 (YAML) | - |
| `--cert_file <PATH>` | TLS 证书文件路径 | `/root/.cert/server.crt` |
| `--key_file <PATH>` | TLS 私钥文件路径 | `/root/.cert/server.key` |
| `--log_mode <LEVEL>` | 日志级别 | `info` |
| `--fetch_users_interval <SECS>` | 用户列表刷新间隔 | `60` |
| `--report_traffics_interval <SECS>` | 流量上报间隔 | `100` |
| `--heartbeat_interval <SECS>` | 心跳间隔 | `180` |
| `--data_dir <PATH>` | 数据目录路径 | `/var/lib/tuic-agent-node` |
| `--init` | 生成示例配置文件 (config.toml.example 和 acl.yaml.example) | - |

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
