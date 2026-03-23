# tuic-server

基于 TUIC 协议的高性能代理服务器实现，支持控制面板集成和动态用户管理。

## 特性

- **0-RTT 代理**: 基于 QUIC 协议，最小化连接延迟
- **完全多路复用**: 单连接承载多个流
- **控制面板集成**: 动态获取用户列表、上报流量、心跳检测
- **灵活 ACL**: 支持域名、IP、CIDR、GeoIP/GeoSite 等多种匹配规则
- **多出站模式**: 直连、SOCKS5 代理
- **拥塞控制**: 支持 BBR、BBR3、CUBIC、NewReno 算法（从控制面板 API 获取）
- **流量统计**: 实时跟踪每用户的发送/接收字节数和连接数

## 安装

```bash
git clone https://github.com/xflash-panda/server-tuic.git
cd server-tuic

# 编译 (默认使用 aws-lc-rs)
cargo build --release -p tuic-server

# 或使用 ring 密码库
cargo build --release -p tuic-server --no-default-features --features ring

# 启用 JEMalloc 内存分配器
cargo build --release -p tuic-server --features jemallocator
```

## 快速开始

```bash
# 零配置启动（使用默认参数）
tuic-server --api https://api.example.com --token YOUR_TOKEN --node 1

# 生成示例配置文件
tuic-server --init
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--api <URL>` | API 服务器地址 | **必需** |
| `--token <TOKEN>` | API 认证令牌 | **必需** |
| `--node <ID>` | 节点 ID | **必需** |
| `--ext_conf_file <PATH>` | 外部配置文件路径 (.toml) | - |
| `--acl_conf_file <PATH>` | ACL 配置文件路径 (.yaml) | - |
| `--cert_file <PATH>` | TLS 证书文件路径 | `/root/.cert/server.crt` |
| `--key_file <PATH>` | TLS 私钥文件路径 | `/root/.cert/server.key` |
| `--log_mode <LEVEL>` | 日志级别: trace/debug/info/warn/error/off | `info` |
| `--fetch_users_interval <SECS>` | 用户列表刷新间隔 | `60` |
| `--report_traffics_interval <SECS>` | 流量上报间隔 | `80` |
| `--heartbeat_interval <SECS>` | 心跳间隔 | `180` |
| `--data_dir <PATH>` | 数据目录路径 | `/var/lib/tuic-node` |
| `--refresh_geodata` | 启动时强制刷新 GeoIP/GeoSite 数据库 | `false` |
| `--init` | 生成示例配置文件 | - |

## 配置文件

配置文件使用 TOML 格式，通过 `--ext_conf_file` 指定。所有字段均有默认值，大多数场景无需配置。

> **注意**: `server_port`、`zero_rtt_handshake`、`congestion_control` 从控制面板 API 动态获取，不在配置文件中设置。

### 基础配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `udp_relay_ipv6` | bool | `true` | 为 IPv6 UDP 创建单独套接字 |
| `dual_stack` | bool | `true` | 启用双栈 (IPv4/IPv6) |
| `auth_timeout` | duration | `3s` | 客户端认证超时 |
| `task_negotiation_timeout` | duration | `3s` | 任务协商超时 |
| `gc_interval` | duration | `10s` | UDP 片段垃圾回收间隔 |
| `gc_lifetime` | duration | `30s` | UDP 片段保留时间 |
| `stream_timeout` | duration | `60s` | 流超时 |
| `max_external_packet_size` | int | `1500` | 外部 UDP 数据包最大大小 (字节) |

### QUIC 配置 `[quic]`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `initial_window` | int | `1048576` | 初始拥塞窗口 (字节) |
| `initial_mtu` | int | `1200` | 初始 MTU |
| `min_mtu` | int | `1200` | 最小 MTU (至少 1200) |
| `gso` | bool | `true` | 启用通用分段卸载 |
| `pmtu` | bool | `true` | 启用路径 MTU 发现 |
| `send_window` | int | `16777216` | 发送窗口大小 (字节) |
| `receive_window` | int | `8388608` | 接收窗口大小 (字节) |
| `max_idle_time` | duration | `30s` | 空闲连接超时 |

### 实验性功能 `[experimental]`

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `drop_loopback` | bool | `true` | 禁止连接到环回地址 (127.0.0.1, ::1) |
| `drop_private` | bool | `true` | 禁止连接到私有地址 |

### 完整示例

```toml
udp_relay_ipv6 = true
dual_stack = true
auth_timeout = "3s"
task_negotiation_timeout = "3s"
gc_interval = "10s"
gc_lifetime = "30s"
stream_timeout = "60s"
max_external_packet_size = 1500

[quic]
initial_window = 1048576
initial_mtu = 1200
min_mtu = 1200
gso = true
pmtu = true
send_window = 16777216
receive_window = 8388608
max_idle_time = "30s"

[experimental]
drop_loopback = true
drop_private = true
```

## ACL 路由规则

ACL 配置使用 YAML 格式，通过 `--acl_conf_file` 指定。不指定时使用默认规则（所有流量直连）。

### 基本结构

```yaml
outbounds:
  - name: default
    type: direct
    direct:
      mode: auto

acl:
  inline:
    - default(all)
```

### 出站类型

**直连出站:**

```yaml
- name: default
  type: direct
  direct:
    mode: auto    # auto / 4 (仅IPv4) / 6 (仅IPv6)
```

**SOCKS5 代理出站:**

```yaml
- name: proxy
  type: socks5
  socks5:
    addr: 127.0.0.1:1080
    username: user    # 可选
    password: pass    # 可选
    allow_udp: false
```

### 规则语法

格式: `outbound_name(matcher[, protocol/port])`

**地址匹配器:**

| 匹配器 | 示例 | 说明 |
|--------|------|------|
| `all` / `*` | `default(all)` | 匹配所有地址 |
| IP | `default(1.2.3.4)` | 单个 IP 地址 |
| CIDR | `default(192.168.0.0/16)` | CIDR 网段 |
| 域名 | `proxy(example.com)` | 精确域名匹配 |
| 通配符 | `proxy(*.google.com)` | 通配符域名 |
| suffix | `proxy(suffix:google.com)` | 后缀匹配 |
| GeoIP | `default(geoip:cn)` | GeoIP 国家代码 |
| GeoSite | `proxy(geosite:openai)` | GeoSite 分类 |

**协议/端口过滤 (可选):**

| 格式 | 说明 |
|------|------|
| `tcp/80` | TCP 端口 80 |
| `udp/443` | UDP 端口 443 |
| `tcp/80-443` | TCP 端口范围 |
| `tcp` | 所有 TCP |
| `udp` | 所有 UDP |

### 规则示例

```yaml
acl:
  inline:
    - reject(all, udp/443)           # 阻止 QUIC
    - reject(all, tcp/25)            # 阻止 SMTP
    - proxy(geosite:openai)          # OpenAI 走代理
    - proxy(suffix:google.com)       # Google 走代理
    - default(geoip:cn)              # 中国 IP 直连
    - default(all)                   # 兜底规则
```

> 规则按顺序匹配，首次匹配生效。最后一条应为兜底规则。

## 控制面板集成

服务器通过 API 与控制面板通信：

1. 启动时从 API 获取节点配置（端口、zero_rtt_handshake、拥塞控制算法）
2. 定期获取用户列表（默认 60s）
3. 定期上报流量统计（默认 80s）
4. 定期发送心跳（默认 180s）

状态持久化到 `data_dir/state.json`，重启后可复用注册 ID。

## TLS 证书

TLS 是必需的。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh)：

```bash
acme.sh --issue -d www.yourdomain.org --standalone
acme.sh --install-cert -d www.yourdomain.org \
  --key-file       /root/.cert/server.key \
  --fullchain-file /root/.cert/server.crt
```

服务器支持证书热重载，更新证书后无需重启。

## 许可证

GNU General Public License v3.0。详见 [LICENSE](../LICENSE)。
