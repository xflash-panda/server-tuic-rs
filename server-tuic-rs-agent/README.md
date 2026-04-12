# tuic-server

基于 TUIC 协议的高性能代理服务器实现，支持控制面板集成和动态用户管理。

---

## 目录

- [概述](#概述)
- [特性](#特性)
- [安装](#安装)
- [使用方法](#使用方法)
- [配置说明](#配置说明)
- [出站配置](#出站配置)
- [控制面板集成](#控制面板集成)
- [TLS 证书](#tls-证书)
- [许可证](#许可证)

---

## 概述

`tuic-server` 是 TUIC 协议服务器的 Rust 实现，由 xflash-panda 维护。TUIC 是一个专注于最小化中继延迟的 0-RTT 代理协议，基于 QUIC 构建。

本项目 fork 自原始 TUIC 项目，增加了以下增强功能：
- 控制面板 API 集成，支持动态用户管理
- 实时流量统计与上报
- 多种出站代理模式
- TLS 证书热重载

---

## 特性

- **0-RTT 代理**: 基于 QUIC 协议，最小化连接延迟
- **完全多路复用**: 单连接承载多个流
- **控制面板集成**: 动态获取用户列表、上报流量、心跳检测
- **多出站模式**: 直连、SOCKS5 代理
- **拥塞控制**: 支持 BBR、CUBIC、NewReno 算法
- **流量统计**: 实时跟踪每用户的发送/接收字节数和连接数

---

## 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/xflash-panda/server-tuic-rs.git
cd server-tuic-rs

# 编译 (默认使用 aws-lc-rs)
cargo build --release -p tuic-server

# 或使用 ring 密码库
cargo build --release -p tuic-server --no-default-features --features ring

# 启用 JEMalloc 内存分配器
cargo build --release -p tuic-server --features jemallocator
```

编译产物位于 `target/release/tuic-server`

---

## 使用方法

```bash
# 运行服务器 (必需参数)
tuic-server --api https://api.example.com --token YOUR_TOKEN --node 1

# 指定外部配置文件
tuic-server --api https://api.example.com --token YOUR_TOKEN --node 1 \
  --ext_conf_file /path/to/config.toml

# 自定义证书路径
tuic-server --api https://api.example.com --token YOUR_TOKEN --node 1 \
  --cert_file /path/to/cert.pem --key_file /path/to/key.pem

# 生成示例配置文件
tuic-server --init
# 生成 config.toml.example 和 acl.yaml.example
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
| `--log_mode <LEVEL>` | 日志级别 (trace/debug/info/warn/error/off) | `info` |
| `--fetch_users_interval <SECS>` | 用户列表刷新间隔 (秒) | `60` |
| `--report_traffics_interval <SECS>` | 流量上报间隔 (秒) | `100` |
| `--heartbeat_interval <SECS>` | 心跳间隔 (秒) | `180` |
| `--data_dir <PATH>` | 数据目录路径 | `/var/lib/tuic-node` |
| `--acl_conf_file <PATH>` | ACL 配置文件路径 (YAML) | - |
| `--init` | 生成示例配置文件 (.example 后缀) | - |

---

## 配置说明

配置文件使用 TOML 格式。服务器端口和 zero_rtt_handshake 设置从控制面板 API 动态获取。

### 基础配置

```toml
# UDP 配置
udp_relay_ipv6 = true          # 为 IPv6 UDP 创建单独套接字
dual_stack = true              # 启用双栈 (IPv4/IPv6)

# 超时配置
auth_timeout = "3s"            # 客户端认证超时
task_negotiation_timeout = "3s" # 任务协商超时
gc_interval = "10s"            # UDP 片段垃圾回收间隔
gc_lifetime = "30s"            # UDP 片段保留时间
stream_timeout = "60s"         # 流超时

# 数据包配置
max_external_packet_size = 1500 # 外部 UDP 数据包最大大小
```

### QUIC 配置

```toml
[quic]
initial_mtu = 1200             # 初始 MTU
min_mtu = 1200                 # 最小 MTU (至少 1200)
gso = true                     # 启用通用分段卸载
pmtu = true                    # 启用路径 MTU 发现
send_window = 16777216         # 发送窗口大小 (字节)
receive_window = 8388608       # 接收窗口大小 (字节)
max_idle_time = "30s"          # 空闲连接超时

[quic.congestion_control]
controller = "bbr"             # 拥塞控制算法: bbr / cubic / new_reno
initial_window = 1048576       # 初始拥塞窗口 (字节)
```

### 实验性功能

```toml
[experimental]
drop_loopback = true           # 禁止连接到环回地址 (127.0.0.1, ::1)
drop_private = true            # 禁止连接到私有地址
```

---

## ACL 配置

ACL (Access Control List) 提供基于规则的流量路由功能，支持 GeoIP、GeoSite、域名匹配等高级特性。

### 启用 ACL

```bash
# 使用 ACL 配置文件运行
tuic-server --node 1 --acl-conf-file /path/to/acl.yaml
```

### ACL 配置格式

ACL 配置使用 YAML 格式，包含两个主要部分：

1. **outbounds**: 定义出站连接类型
2. **acl.inline**: 定义路由规则（按顺序匹配）

### 示例配置

```yaml
# 定义出站
outbounds:
  - name: direct
    type: direct
    direct:
      mode: auto  # auto, 4 (IPv4 only), 6 (IPv6 only)

  - name: proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user  # 可选
      password: pass  # 可选
      allow_udp: false

# 定义规则 (按顺序匹配)
acl:
  inline:
    # 拒绝 QUIC 协议
    - reject(all, udp/443)

    # 通过代理路由特定域名
    - proxy(suffix:google.com)
    - proxy(geosite:openai)
    - proxy(geosite:netflix)

    # 私有网络直连
    - direct(192.168.0.0/16)
    - direct(10.0.0.0/8)

    # 中国大陆 IP 直连
    - direct(geoip:cn)

    # 默认规则 (必须放在最后)
    - direct(all)
```

### 规则语法

规则格式：`outbound_name(matcher[, protocol/port])`

**地址匹配器**:
- `all` 或 `*`: 匹配所有地址
- `1.2.3.4`: 单个 IP 地址
- `192.168.0.0/16`: CIDR 网段
- `example.com`: 精确域名匹配
- `*.example.com`: 通配符域名
- `suffix:example.com`: 后缀匹配
- `geoip:cn`: GeoIP 国家代码匹配
- `geosite:google`: GeoSite 分类匹配

**协议/端口过滤** (可选):
- `tcp/80`: TCP 端口 80
- `udp/443`: UDP 端口 443
- `tcp/80-443`: TCP 端口范围
- `tcp`: 所有 TCP
- `udp`: 所有 UDP

**示例规则**:
```yaml
# 拒绝特定端口
- reject(all, tcp/25)      # 阻止 SMTP
- reject(all, udp/443)     # 阻止 QUIC

# 域名路由
- proxy(*.google.com)
- proxy(suffix:youtube.com)

# IP 路由
- direct(192.168.0.0/16)
- proxy(geoip:us)

# 组合规则
- proxy(example.com, tcp/443)  # 仅 HTTPS
```

### 默认行为

如果未指定 `--acl-conf-file`，服务器将使用默认直连模式（所有流量直接路由）。

完整配置示例请参考 [acl-example.yaml](acl-example.yaml)。

---

## 控制面板集成

服务器通过 API 与控制面板通信，实现：

- **用户管理**: 动态获取用户列表 (UUID -> user_id 映射)
- **流量上报**: 定期上报每用户的流量统计
- **心跳检测**: 保持节点在线状态
- **状态持久化**: 将状态保存到 `state.json`

### 工作流程

1. 启动时从 API 获取节点配置 (端口、zero_rtt_handshake 等)
2. 定期获取用户列表 (默认每 60 秒)
3. 定期上报流量统计 (默认每 80 秒)
4. 定期发送心跳 (默认每 180 秒)

---

## TLS 证书

TLS 是必需的。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 获取证书：

```bash
# 申请证书
acme.sh --issue -d www.yourdomain.org --standalone

# 安装证书
acme.sh --install-cert -d www.yourdomain.org \
  --key-file       /path/to/key.pem  \
  --fullchain-file /path/to/cert.pem
```

服务器支持证书热重载，更新证书后无需重启。

---

## 许可证

GNU General Public License v3.0。详见 [LICENSE](../LICENSE)。
