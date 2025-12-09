# Server TUIC

基于 TUIC 协议的代理服务器，支持控制面板集成和动态用户管理。

Fork 自 https://github.com/tuic-protocol/tuic

---

## 特性

- 控制面板 API 集成，动态用户管理
- 实时流量统计与上报
- ACL 访问控制规则
- 多出站模式 (直连 / SOCKS5)
- TLS 证书热重载

---

## 编译

```bash
# 默认 (aws-lc-rs)
cargo build --release -p server

# 使用 ring
cargo build --release -p server --no-default-features --features ring

# 启用 JEMalloc
cargo build --release -p server --features jemallocator
```

编译产物: `target/release/server`

---

## 运行

```bash
server --api https://api.example.com --token YOUR_TOKEN --node 1
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--api <URL>` | API 服务器地址 | **必需** |
| `--token <TOKEN>` | API 认证令牌 | **必需** |
| `--node <ID>` | 节点 ID | **必需** |
| `--ext_conf_file <PATH>` | 外部配置文件路径 | - |
| `--cert_file <PATH>` | TLS 证书文件路径 | `/root/.cert/server.crt` |
| `--key_file <PATH>` | TLS 私钥文件路径 | `/root/.cert/server.key` |
| `--log_mode <LEVEL>` | 日志级别 | `info` |
| `--fetch_users_interval <SECS>` | 用户列表刷新间隔 | `60` |
| `--report_traffics_interval <SECS>` | 流量上报间隔 | `80` |
| `--heartbeat_interval <SECS>` | 心跳间隔 | `180` |
| `--data_dir <PATH>` | 数据目录路径 | `/var/lib/tuic-node` |
| `--init` | 生成示例配置文件 | - |

详细配置请参阅 [server/README.md](server/README.md)

---

## 许可证

[GNU General Public License v3.0](LICENSE)
