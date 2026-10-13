# rust-frpc

[English](README.md)

一个超低内存的 Rust 版 frp 客户端，与 Go 版 [`frps`](https://github.com/fatedier/frp) 线协议兼容。

目标是做成可直接替换的 `frpc`：同一套配置文件、同一套命令行、同一套管理 API、
以及相同线协议字节。go 版 frps 不会察觉对面不是 go 版 frpc。

## 当前状态

仍属早期，但「与 go 版兼容」这一核心主张现在已经可验证：`frpc verify --server`
能对一台标准的 go 版 `frps` 完成真实登录，`tests/real_frps.rs` 会对这一点做断言。

| 层次 | 状态 |
| :--- | :--- |
| frp 加密（PBKDF2 → AES-128-CFB、snappy 分帧） | 已完成 |
| 消息集与 v1/v2 分帧 | 已完成 |
| 配置（TOML + legacy INI，严格/宽松两档） | 已完成 |
| 对真实 `frps` 的登录握手 | 已完成 |
| yamux（`tcpMux`，默认开启） | 已完成 |
| 控制循环（心跳、代理注册、work conn） | 下一步 |
| 纯 TCP 之外的传输 | 下一步 |

`frpc` 目前仍不能承载流量——它会完成登录并如实说明这一点。见[路线图](#路线图)。

## 试用

```bash
# 解析配置并打印默认值归一化后的结果。
cargo run -- --check-config -c conf/frpc.toml

# 校验配置，再连接其中配置的服务端完成一次登录并报告结果。
cargo run -- verify -c conf/frpc.toml --server
```

`verify --server` 刻意只做到登录为止：注册代理意味着在别人的服务器上占用一个公网端口，
健康检查不该有这种副作用。`Login` 这一步已经能证明分帧、加密与 token 签名都是正确的，
而这些正是必须对齐的部分。

要跑通一条隧道，在配置里加一个代理然后启动即可：

```toml
serverAddr = "example.com"
serverPort = 7000
auth.token = "secret"

webServer.port = 7400        # 可选：管理 API

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
```

```bash
frpc -c frpc.toml            # 隧道常驻，直到被中断
```

配置了 `webServer.port` 后，运行中的客户端可以像 go 版一样被管理：

```bash
frpc status -c frpc.toml     # 按代理类型分表输出
frpc reload -c frpc.toml     # 重新读取配置文件
frpc stop    -c frpc.toml    # 停止客户端

curl localhost:7400/healthz  # 无需认证，供守护进程探活
curl localhost:7400/api/status
curl localhost:7400/metrics  # 纯文本计数器
```

`reload` 会重新读取文件，并**通过一条新的控制会话**生效，与 go 版行为一致，耗时约一秒。
解析失败的文件不会被部分应用：记录一条日志后忽略。

## 兼容性

* **基线**：`fatedier/frp` 的 `dev` 分支，版本 `0.71.0`。行为对齐的是源码树本身，
  不是发布说明。`tests/real_frps.rs` 会对你指定的 `frps` 二进制做端到端验证，
  目前已在 `0.61.0` 上跑通。
* 线协议为 **v1**（默认值，也是旧版服务端唯一认识的取值），`transport.tcpMux` 开或关都支持。
* 传输方式：`tcp`（`tcpMux` 开或关），以及建立在它之上的 TLS——`transport.tls`
  **默认开启**，所以一份普通配置走的就是 TLS。`kcp`、`websocket`、`wss` 下一步支持；
  `quic` 暂不在范围内，见路线图。
* `transport.tls` 已完整生效：`enable`、`serverName`（为空时回退到 `serverAddr`）、
  `certFile`/`keyFile`、`trustedCaFile`、`disableCustomTLSFirstByte`。有两个默认值直接决定
  线上字节，容易记反：`0x17` 首字节**只有**在 `disableCustomTLSFirstByte` 显式设为 `false`
  时才发送；服务端证书**默认不校验**，除非配置了 `trustedCaFile`——与 go 版的
  `InsecureSkipVerify = true` 一致。`tests/fixtures/frps-integration-tls.toml` 起了一个
  `tls.force = true` 的服务端，它会直接拒绝明文客户端，测试套件既对它完成登录，也通过它
  跑通整条回环。
* 代理类型：目前支持 `tcp`、`udp`、`http`、`https`、`tcpmux`、`stcp` 与 `sudp`。
  `xtcp` 在配置层可解析，注册时会明确拒绝。
* visitor：支持 `stcp` 与 `sudp`——这两类代理不在服务端暴露任何端口，因此需要 visitor 在本地
  绑定一个端口（`sudp` 为 UDP）并指名它要访问的代理。`xtcp` visitor 会记录警告并跳过。
  `sudp` 的会话属于 visitor 而非某个用户：第一个数据报开启会话，之后任意用户的数据报都走同一条
  会话，每条都带着自己的来源地址——回答正是靠它回到正确的人手上。
* legacy INI 里 `role = visitor` 的段会真正转换成 visitor 并启动（`stcp`/`sudp`），只有
  `xtcp` 会被记录并跳过。未指定 `bindAddr` 的 visitor 默认 `127.0.0.1`，与
  `CompleteVisitorConfigurers` 一致——否则空主机名会把端口绑到所有网卡上。
* `udpPacketSize` 已生效，它的含义是**数据报被截断到的长度**，而不是缓冲区大小：本地服务回一个
  2000 字节的应答，在默认值下到达时是 1500 字节——本客户端与 go 版行为一致。取值超出
  `1..=65507` 会被夹紧并给出警告，而不是照办：go 版的 `0` 会把每个数据报都读成空的。
  另一处有意为之的差异记在 `doc/compatibility.md`。
* 本地侧跑不了的代理（`xtcp`、未实现的插件、或本客户端不支持的 `wireType`）会被记录并跳过，
  不会因为其中一个而让配置文件里的其它隧道一起失效。`--check-config` 在部署前就会给出同样的提示。
* 日志与 `golib` 对齐：`2006-01-02 15:04:05.000 [I] [service.go:332] [runID] …`，级别是单字母，
  带上游 Go 的调用位置，以及 runID / proxyName 前缀。`log.to` 会写按天轮转的文件并遵守
  `maxDays`，`log.disablePrintColor` 关闭控制台配色。legacy INI 的 `log_file`、`log_level`、
  `log_max_days`、`disable_log_color` 含义相同，Go 的转换器也是这么处理的。
* 以下能力尚未接通，且都是**明确拒绝而非半成品**：线协议 `v2`（`msg.rs` 里有分帧实现，
  但 `ClientHello` 交换未实现）、工作连接的 `useCompression`、以及 `udp` 代理上的
  `useEncryption`/`useCompression`。
* 管理 API 提供 `/healthz`、`/api/status`、`/api/config`（GET 与 PUT）、
  `/api/proxy/{name}/config`、`/api/reload`、`/api/stop`、`/metrics`，路径与响应结构与
  go 版一致。尚未实现：`/api/visitor/{name}/config`、`/api/store/*`、以及静态面板资源。
* `transport.tcpMux` **既是客户端也是服务端的决定**：只要 frps 自己的开关是开的，它就会把
  接到的每条连接都套上 yamux，与客户端怎么配无关。两端必须一致，所以 `tests/fixtures/`
  为两种取值各提供了一份 frps 配置。

## 测试

```bash
cargo test                       # 单元测试 + 针对 go 仓库示例配置的解析对照
```

`tests/config_parity.rs` 直接解析 go 仓库自带的 `frpc_full_example.toml` 与
`frpc_legacy_full.ini`：上游新增了本客户端不认识的键时，测试会失败，而不是等到生产环境才发现。

端到端测试需要真实的 `frps`，默认忽略：

```bash
RUN_REAL_FRPS_TESTS=1 \
FRPS_BIN=/path/to/frps \
FRPS_CONFIG=tests/fixtures/frps-integration.toml \
cargo test --test real_frps -- --ignored --test-threads=1
```

它会断言：标准 `frps` 接受本客户端的登录（`tcpMux` 开与关各一次）、拒绝错误的 token、
在加密的控制连接上回应心跳、接受带上次 run id 的重连，以及最关键的——注册一个 `tcp`
代理后，真实字节能从 `frps` 公布的端口经由本地服务往返，`tcpMux` 开与关各验一次。
管理 API 也会被真实 HTTP 调用驱动一遍，包含 `stop` 与凭据校验。

## 内存

这是本项目存在的理由。目标是空闲常驻内存低于 5 MB、承载 100 个 TCP 代理时低于 20 MB；
作为对照，go 版 frpc 通常在 20–40 MB。达成路径记录在
[`doc/memory.md`](doc/memory.md)。

内存预算是**被门限拦住**的，而不是 README 里的一句话：

```bash
RUN_REAL_FRPS_TESTS=1 \
FRPS_BIN=/path/to/frps \
FRPS_CONFIG=tests/fixtures/frps-integration.toml \
FRPC_BIN=target/release/frpc \
cargo test --test memory -- --ignored --nocapture
```

它会把 release 二进制作为独立进程拉起，对真实 `frps` 注册 1 个或 100 个代理，然后以常驻
内存为准做断言。实测数字、以及必须参照的平台基线，都记在
[`doc/memory.md`](doc/memory.md)。

## 构建

```bash
cargo build --release
```

release profile 面向体积（`opt-level = "z"`、fat LTO、`strip`、`panic = "abort"`）。
本地开发用 `--profile release-fast`，形态相同但链接快得多。

**fat LTO 值这个钱，而且任何一条构建路径都不该关掉它。** `armv7-unknown-linux-musleabihf`
上它把 2.67 MB 变成 2.06 MB，代价是大约多四十秒链接时间。交叉编译脚本和发布 workflow
过去都关掉了它——理由是「ARM 上的 fat LTO 可能耗时无上限」——而这一处覆盖省下的体积，
比文件里其它所有体积决策加起来还多。实测 `frpc` 体积：

| 构建 | 体积 |
| :--- | ---: |
| `x86_64-pc-windows-msvc`，fat LTO | 2.24 MB |
| `armv7-unknown-linux-musleabihf`，fat LTO | 2.06 MB |
| `armv7-unknown-linux-gnueabihf`，fat LTO | 2.07 MB |
| `aarch64-unknown-linux-musl`，fat LTO | 2.22 MB |
| `armv7-unknown-linux-musleabihf`，关掉 LTO | 2.67 MB |

其中约 500–850 kB 是 TLS 栈——`transport.tls` 需要它，而 `enable = true` 让它成为默认路径。
它就是 `rustls` + `ring`，而且压不下去：`opt-level = "s"` 反而**更大**，关掉 `tls12` 只省
37 kB，把密码套件列表裁到 Go 服务端真正能协商的那九个**一点都不省**——链接器本来就已经
把其余的丢掉了。

### 不带 TLS 构建

有一个默认开启的 `tls` feature，关掉它是去掉这部分的唯一办法：

```bash
cargo build --release --no-default-features   # 本机 1.41 MB
scripts/build-arm.sh --no-tls                 # armv7: 2.06 MB -> 1.56 MB
```

| 目标 | 含 TLS | `--no-tls` |
| :--- | ---: | ---: |
| `armv7-unknown-linux-musleabihf` | 2.06 MB | **1.56 MB** |
| `armv7-unknown-linux-gnueabihf` | 2.07 MB | 1.56 MB |
| `aarch64-unknown-linux-musl` | 2.22 MB | 1.54 MB |
| `x86_64-pc-windows-msvc` | 2.24 MB | 1.41 MB |

它默认开启，是因为 frp 自己的默认值就是 `transport.tls.enable = true`，标准配置必须开箱
可用。不带这个 feature 的构建遇到这种配置会**在启动时拒绝**，而不是明文连出去：

```
error: transport.tls.enable = true (frp's default) but this build was made
without TLS support. Set `transport.tls.enable = false` to connect in the clear,
or use a build with the `tls` feature.
```

这条拒绝就是这个选项全部的安全论证：静默降级会把一次体积优化变成没人要求的明文隧道。
`transport.protocol = "wss"` 同样被拒绝，因为它就是 TLS 里的 websocket。

两套测试在两种配置下都跑——含 TLS 时 246 个单元测试 + 26 个真实 frps 端到端，不含时
242 + 23——因为只跑过默认 feature 的构建，另一半是没测过的。

同一个 crate 产出两个行为完全一致的二进制：

```bash
target/release/frpc        # 可直接替换的名字
target/release/rust-frpc   # 同一程序，用于两者共存于同一 PATH 的场景
```

面向 ARM Linux 板子的交叉编译见
[`doc/build-linux-arm.md`](doc/build-linux-arm.md)：`scripts/build-arm.sh` 与
`scripts/build-arm.ps1` 可交叉编译到 `armv7` 与 `aarch64` 的 musl 目标。整个 crate
没有任何 C 依赖，因此 zig 只用来提供链接器，也无需安装交叉 gcc 工具链。

## 配置

支持 TOML，以及旧的 `[common]` INI 格式。格式**按内容判断而非扩展名**——能解析成 INI
且含 `[common]` 段即按 INI 处理，与 go 版行为一致——所以既有的 `frpc.ini` 改名后仍然可用。

YAML 与 JSON 在 go 版的支持路径上，本项目尚未支持：YAML 配置会以 TOML 解析错误报出，
而不会被误读。

最小示例与完整示例见 [`conf/`](conf/)。

## 路线图

1. ~~**M0** —— 骨架、配置解析、`--check-config`。~~ 已完成
2. ~~**M1** —— 对真实 `frps` 完成登录握手。~~ 已完成
3. ~~**M2** —— 代理注册、跑通 TCP 回环。~~ 已完成
4. ~~**M3** —— 管理 API、`frpc reload|status|stop`。~~ 已完成
5. **0.1.0** —— CI、发布产物，把内存预算变成真正的门限而非 README 里的一句话。
6. 之后：补齐其余代理类型、客户端插件、visitor、xtcp，以及 `tls`/`websocket`/`kcp`
   传输与管理 API 的剩余部分。

## 许可

Apache-2.0。
