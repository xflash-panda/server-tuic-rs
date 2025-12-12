# tuic-server

基于 TUIC 协议的高性能代理服务器实现，支持控制面板集成和动态用户管理。

---

## 目录

- [概述](#概述)
- [特性](#特性)
- [安装](#安装)
- [使用方法](#使用方法)
- [配置说明](#配置说明)
- [ACL 规则](#acl-规则)
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
- 灵活的 ACL 规则系统
- 多种出站代理模式
- TLS 证书热重载

---

## 特性

- **0-RTT 代理**: 基于 QUIC 协议，最小化连接延迟
- **完全多路复用**: 单连接承载多个流
- **控制面板集成**: 动态获取用户列表、上报流量、心跳检测
- **灵活 ACL**: 支持域名、IP、CIDR、端口等多种匹配规则
- **多出站模式**: 直连、SOCKS5 代理
- **拥塞控制**: 支持 BBR、CUBIC、NewReno 算法
- **流量统计**: 实时跟踪每用户的发送/接收字节数和连接数

---

## 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/xflash-panda/server-tuic.git
cd server-tuic

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
| `--init` | 生成示例配置文件 | - |

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

## ACL 规则

ACL (访问控制列表) 支持两种配置格式：

### 格式一：表数组格式

```toml
[[acl]]
addr = "127.0.0.1"             # 地址
ports = "udp/53"               # 端口
outbound = "default"           # 出站规则
hijack = "1.1.1.1"             # 劫持地址 (可选)

[[acl]]
addr = "localhost"
outbound = "drop"

[[acl]]
addr = "private"               # 匹配所有私有地址
outbound = "drop"
```

### 格式二：多行字符串格式

```toml
acl = '''
# 格式: <outbound> <address> [<ports>] [<hijack>]
direct localhost tcp/80,tcp/443,udp/443
drop localhost
drop private
default 8.8.4.4 udp/53 1.1.1.1
'''
```

### 地址类型

| 类型 | 示例 | 说明 |
|------|------|------|
| localhost | `localhost` | 本地主机 |
| private | `private` | 所有私有/LAN 地址 |
| IPv4 | `192.168.1.1` | IPv4 地址 |
| IPv6 | `::1` | IPv6 地址 |
| CIDR | `192.168.0.0/16` | CIDR 网络 |
| 域名 | `example.com` | 精确域名匹配 |
| 通配符 | `*.google.com` | 通配符域名匹配 |
| 任意 | `*` | 匹配所有地址 |

### 端口格式

| 格式 | 示例 | 说明 |
|------|------|------|
| 单端口 | `80` | 匹配 TCP/UDP 80 端口 |
| 协议端口 | `tcp/80` | 仅匹配 TCP 80 端口 |
| 端口范围 | `80-8080` | 端口范围 |
| 端口列表 | `tcp/80,udp/53` | 多端口组合 |
| 任意 | `*` | 匹配所有端口 |

---

## 出站配置

### 直连出站

```toml
[outbound.default]
type = "direct"
ip_mode = "v4first"            # v4first / v6first / v4only / v6only
bind_ipv4 = "1.2.3.4"          # 绑定 IPv4 地址 (可选)
bind_ipv6 = "::1"              # 绑定 IPv6 地址 (可选)
bind_device = "eth0"           # 绑定网卡 (可选)
```

### SOCKS5 出站

```toml
[outbound.socks5_proxy]
type = "socks5"
addr = "127.0.0.1:1080"        # SOCKS5 代理地址
username = "user"              # 用户名 (可选)
password = "pass"              # 密码 (可选)
allow_udp = false              # 是否允许 UDP (默认 false)
```

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
