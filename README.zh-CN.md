# Argus

**面向渗透测试的现代化端口扫描器**

作者：**guaidao2 & coolmoon** · 许可证：MIT · 单一静态二进制 · 跨平台

Argus 是用 Go 写的 TCP/UDP 端口扫描器。它以单个静态二进制交付，不依赖任何运行
时组件；输出兼容 nmap 风格（并且能生成可被现有工具链直接导入的 nmap 兼容 XML）；
服务识别由 YAML 指纹库驱动；功能可通过 YAML 插件扩展——插件只需注册一次，之后长期
复用。

[English](README.md)

---

## 为什么再造一个扫描器

- **单个静态二进制。** `CGO_ENABLED=0`，不需要 libpcap、不需要 Npcap、不需要驱动。
  拷到跳板机上就能跑。
- **nmap 兼容输出。** `-oX` 生成的 `nmaprun` 文档沿用 nmap 的元素与属性命名，
  `msf db_import`、Faraday 以及多数报告流水线可以直接消费；`-oJ` 提供结构化输出，
  方便 `jq` 处理。
- **发第一个包之前先做能力探测。** SYN 扫描会先打开原始套接字，并用回环地址验证它
  **既能发也能收**（全程不出本机），然后才碰任何目标。扫到一半才发现收不到回包，等于
  前面白跑，还会给你一份看着合理、实际错误的结果。
- **模式写进结果。** TCP connect 与 SYN 的结果集本来就不等价：connect 会完成三次握手，
  应用层可以留下日志，有状态防火墙的回应也可能不同。因此每份报告都会写明实际用的是
  哪一种——精确到每台主机、每个端口，一次扫描里两种都用了也会说清楚。
- **数据驱动的识别。** 服务指纹写在 YAML 里而不是 Go 代码里。内置库覆盖了最先遇
  到的一批服务，没覆盖到的，写个插件就行。
- **会优雅失败的插件。** 已注册的插件被删掉时只给警告并退出加载，绝不会连累整个
  扫描。
- **`--findings`。** 显式开启的检测：给出的是**判定结论**而非识别结果——未授权访问、
  暴露的管理接口、默认凭据——并与服务描述分开报告；XML 中使用 nmap 自己的 `<script>`
  元素，现有工具链可直接消费。
- **`--hack-reason`。** 为每个探测到的端口附上值得检查的渗透切入点，中英双语知识
  库，可插件扩展。
- **双语，英语优先。** 中文需要显式 `--lang zh`；你的界面语言不会被 `LANG` 环境变量
  替你决定。
- **无遥测。** Argus 不会回连、不会上传结果。本仓库中除扫描本身以外不会打开任何
  对外连接。

## 安装

```bash
# 从源码安装（需要 Go 1.24+）
go install github.com/guaidao2/argus/cmd/argus@latest

# 或构建静态二进制
make build

# 交叉编译全部支持平台到 ./dist
make cross
```

## 快速上手

```bash
argus 10.0.0.1                             # 扫描内置常用端口表
argus -sV -p 22,80,443 10.0.0.0/24         # 服务与版本识别
argus -sS -T4 -p- --open 10.0.0.5          # Linux SYN 扫描，全端口，只显示开放
argus --top-ports 100 --hack-reason 10.0.0.1
argus -oA scan1 10.0.0.1 10.0.0.2          # 生成 scan1.nmap、scan1.xml、scan1.json
argus --lang zh -sV --hack-reason 10.0.0.1
```

中文输出示例：

```
$ argus --lang zh -Pn -sV --hack-reason --reason -p 22,18080 127.0.0.1
启动 Argus 1.0.1（ https://github.com/guaidao2/argus ）时间 2025-04-01 17:12:44 CST
Argus 扫描报告 127.0.0.1
主机在线（延迟 0.00003 秒）。
端口      状态  服务 原因        版本
22/tcp    open  ssh  syn-ack     OpenSSH 8.9p1 (Ubuntu-3ubuntu0.4)
| 渗透姿势：SSH 远程管理
| 先枚举服务器允许的认证方式；开启密码认证的机器就重新具备了凭据爆破面
| 留意复用密码与默认口令，以及可达家目录中未设密码的私钥
| 常用工具：ssh-audit, nxc, hydra, ssh-keygen
|_参考：https://attack.mitre.org/techniques/T1021/004/
18080/tcp open  http syn-ack     nginx 1.24.0
| 渗透姿势：HTTP 应用
| ...

Argus 完成：扫描 1 个 IP 地址（1 台主机在线），耗时 1.24 秒
```

## 能力边界（请务必看这一段）

把边界讲清楚，比堆功能列表更重要。

| 能力 | 状态 |
| --- | --- |
| TCP connect 扫描 | 默认方式。无需权限，可走 SOCKS5，各平台行为一致。 |
| TCP SYN 扫描 | 仅 Linux，基于 `AF_INET/SOCK_RAW` 的纯 Go 实现，需要 `root` 或 `CAP_NET_RAW`，并在扫描开始前通过一次回环预检。**argus 绝不会静默降级为 connect**：要么报错，要么你用 `--fallback-connect` 明确允许。 |
| UDP 扫描 | 在 Linux 上无需权限：connected socket 会把 ICMP port-unreachable 作为错误暴露出来，因此能区分 `closed` 与 `open\|filtered`。若平台吞掉了该错误，静默端口保持 `open\|filtered`，这与 nmap 在同一情形下的结论一致。 |
| 主机发现 | 对 80/443/22 做 TCP ping。收到 RST 与完成握手一样能证明主机在线。刻意不使用 ICMP echo：它在所有平台都需要原始套接字权限，且比 TCP 更容易被过滤。`-Pn` 跳过发现。 |
| 操作系统探测 | 未实现。 |
| Idle/zombie 扫描、FTP bounce、诱饵 | 未实现，也没有计划：实际收益不抵复杂度。 |
| IPv6 | connect 与 UDP 扫描支持；SYN 扫描仅 IPv4，并会明确报错。 |
| nmap NSE 脚本 | 不兼容。argus 使用自己的 YAML 探测 schema，模型更接近 `nmap-service-probes`。 |

内置端口表与 nmap 默认的 top-1000 扫描使用同一份公开扫描统计，服务名取自 IANA 注册，
因此默认运行 `argus` 覆盖的端口与默认运行 `nmap` 一致——已对照 `nmap-services` 验证：
1000/1000，`--top-ports 100` 与 nmap top-100 完全一致。在这 1000 个端口之外，表里还保留了
argus 为渗透测试补充的端口（OT 协议、容器与队列 API、数据库端口）。

其他与 nmap 的差异：`-oG`（grepable）未实现，请用 `-oJ`。默认重试次数低于 nmap，因为
nmap 的取值是针对它自己的 RTT 估算机制调校的。

## 语言

Argus 英语优先。它**不会**因为你的 shell 里 `LANG=zh_CN.UTF-8` 就自动切成中文——
输出语言取决于环境变量的扫描器，其输出没有人能可靠地解析。

解析顺序：

1. `--lang zh`
2. `ARGUS_LANG=zh`
3. `config.yaml` 里的 `lang:`（见“状态目录”）
4. 英语

`--list-langs` 输出可用语言。机器可读输出（`-oX`、`-oJ`）在设计上保持语言中立：
元素名、属性名与端口状态值一律为英文，解析器不受 `--lang` 影响。

## 输出

| 参数 | 格式 |
| --- | --- |
| `-oN/--output-normal FILE` | nmap 风格文本。始终同时写 stdout；用 `-` 表示只写 stdout。 |
| `-oX/--output-xml FILE` | 兼容 nmap 的 `nmaprun` XML（`xmloutputversion 1.05`）。 |
| `-oJ/--output-json FILE` | JSON；加 `--jsonl` 则每行一个主机，末尾一行汇总。 |
| `-oA/--output-all BASE` | 一次输出三种：`BASE.nmap`、`BASE.xml`、`BASE.json`。 |

进度与警告一律走 stderr，因此 `argus ... | jq` 是安全的。

退出码：`0` 成功，`1` 运行时错误，`2` 用法错误，`130` 被中断（`Ctrl-C` 仍会打印
已有的部分结果）。

## 扫描方式

```bash
argus -sT -p 80 10.0.0.1                  # connect（默认）
argus -sS -p 80 10.0.0.1                  # SYN，Linux，需要 CAP_NET_RAW
argus --scan-type auto -p 80 10.0.0.1      # 启动时由 argus 自行选择
```

不想用 root 跑 SYN：

```bash
sudo setcap cap_net_raw+ep "$(command -v argus)"
```

### 能力探测在扫描之前完成

原始套接字能打开，并不代表 SYN 扫描能工作。受限的容器网络命名空间、本机防火墙或异常
的 BPF 过滤，都可能留下一个"能发包、永远收不到包"的套接字——那会把每一个被扫端口都
变成假的 `filtered`。所以 argus 会先做预检：向回环地址上几个几乎必然关闭的端口发三个
SYN，必须收到 RST 或 SYN/ACK。整个过程不出本机。

预检失败时你会得到一条写明原因的报错，而不是一份看着合理、实际错误的扫描结果。等到
扫到一半才发现，前面那部分就白跑了。

### 模式是怎么选定的

| 情况 | 实际执行 |
| --- | --- |
| `-sS`，套接字与预检正常，目标是可路由的 IPv4 | SYN |
| `--scan-type auto`，套接字与预检正常 | SYN |
| `--scan-type auto`，SYN 不可用 | TCP connect，报告会说明这是自动选择并给出原因 |
| `-sS`，目标是回环地址或本机自身地址 | 这些目标用 TCP connect，且报告会写明 |
| `-sS`，目标是 IPv6 | 该目标用 TCP connect，且报告会写明 |
| `-sS` 不可用（无权限、非 Linux、预检失败） | 直接报错，给出原因与修复方法 |
| `-sS` 不可用，**且**加了 `--fallback-connect` | 改用 TCP connect，stderr 警告并在报告中写明 |

`--scan-type auto` 适用于"用当前环境能跑的最强方式，我不关心是哪种"：argus 在启动时
探测并选定。`--fallback-connect` 则适用于"我要 SYN，但实在不行就继续"——它只对显式
指定的 `-sS` 生效。

两者都需要显式开启，都不是默认行为。connect 扫描会完成握手并留下应用层日志，SYN 扫描
两者都不会。在"安静"本身就是硬要求的项目里，不问一声就把前者换成后者，是个相当糟糕的
惊喜。

### 模式是结果的一部分

既然两种模式不可互换，模式就会写进每一种输出；一次扫描用了两种也会说明：

```
启动 Argus 1.0.1（ https://github.com/guaidao2/argus ）时间 2025-04-01 17:12:44 CST
扫描技术：SYN 扫描（原始套接字，半开）；回环与本机地址使用 TCP connect 探测
```

`-oX` 里体现为 `scaninfo/@type` 加上每台主机的 `technique` 属性（非标准扩展，不认识
它的解析器会忽略）；`-oJ` 里则是 `scan_type`、`requested_scan_type`、
`technique_mixed`，以及每台主机、每个端口上的 `technique` 字段。

## 服务与版本识别

`-sV` 执行 YAML 指纹：建立连接、发送探针、用正则匹配响应、提取命名字段。

```bash
argus -sV -p 22,80,443,6379,3306 10.0.0.1
argus -sV -sU -p U:161,U:111 10.0.0.1     # 数据报服务
```

内置规则覆盖 SSH、FTP、SMTP/POP3/IMAP、HTTP/HTTPS、MySQL/MariaDB、PostgreSQL、
MongoDB、Redis、Memcached、Elasticsearch、VNC、Telnet、RDP、RTSP、X11，以及一个
通用兜底规则。TLS 端口会做一次握手，取得版本、加密套件、ALPN 与证书信息
（subject、issuer、有效期、SAN、自签名与过期标记）——`-v` 时在文本输出中展示，
`-oX`/`-oJ` 中始终保留。

数据报服务同样会被识别，而且必须被识别：SNMP 与 ONC RPC 以 UDP 为主，
叫不出名字的服务也就不会被检查。规则用 `proto: udp` 声明协议，被判定为开放的
UDP 端口与 TCP 端口一样会进入识别流程。

```
161/udp open  snmp    SNMP agent (Linux 6.19.14+kali-amd64 #1 SMP ... x86_64)
111/tcp open  rpcbind ONC RPC portmapper
2049/tcp open nfs     NFS 3
```

SNMP 用团体名 `public` 请求 `sysDescr.0`，默认配置的代理会返回操作系统及其版本。
ONC RPC 则请它 `DUMP` 自己的注册表——一次调用，与 `rpcinfo -p` 所做的完全相同——
它会列出所有注册到 portmapper 的服务，包括那些在任何端口表里都查不到的端口。

## 检测与判定结论

```bash
argus -sV --findings 10.0.0.1
```

`--findings` 会运行 `kind: check` 的规则：它们请求管理端点、发送数据库命令或尝试默认
凭据，并把判定结论与服务识别结果**分开**报告。

```
6379/tcp open  redis   Redis 7.2.4
| 检测：Redis：未授权访问 [HIGH]
| 服务器在无凭据情况下响应了 INFO，任何能访问该端口的客户端都可读取其配置与键值。
|_参考：https://redis.io/docs/latest/operate/oss_and_stack/management/security/
```

它**默认关闭**是刻意的。检测探针在链路上是可被识别的入侵行为，argus 不会因为你开了服务
识别就顺手发出去。结论在 `-oX` 中以 nmap 的 `<script>` 元素呈现（Metasploit 的
`db_import` 与 Faraday 已能理解），在 `-oJ` 中是 `findings[]`，并在
`summary.findings` 中计数。

一条检测规则会报告**所有命中**的 match，而不只是第一条，因为一个响应里可能同时包含
若干互不相关的事实：一次 RPC `DUMP` 的回复会列出注册到 portmapper 的每一个服务，
每一个都成为独立结论。

内置检测覆盖 Redis、Elasticsearch、MongoDB、Memcached、CouchDB 的未授权访问，
Docker 守护进程 API、Kubelet API 与 Kubernetes API Server 的未授权访问，RabbitMQ
管理接口的默认凭据，FTP 匿名登录，SNMP 响应默认团体名 `public` 与 `private`，
注册到 portmapper 的 RPC 服务（NFS、mountd、NIS、锁管理器等，每条都附上后续动作），
两条 SMB 加固结论（仍启用 SMBv1、未强制签名），
以及三条版本跟随型检测（OpenSSH 位于 CVE-2024-6387 区间、vsftpd 2.3.4、ProFTPD 1.3.5）。

版本跟随型检测把 banner 里的版本与区间做比较，因此不需要任何协议状态，一个 probe 即可：

```yaml
matches:
  - id: affected
    fields: {version: '(?i)vsftpd[ /]([0-9][^\s]*)'}
    affected: {range: "==2.3.4"}
    finding: {title: "vsftpd 2.3.4 backdoor", severity: high}
```

这类结论的措辞与 severity 都定位为"版本**匹配**"而非确认：发行版常以 backport 修补而
不改动版本号。

`affected` 也接受**列表**，其中每个条件都必须成立——这就是"交集"的写法，例如"既是 SMBv1
响应**又**属于受影响家族的 Windows 内核版本"。当协议对每条消息独立应答时，多个信号可以从
同一个 probe 里取出：SMB 的规则把 NEGOTIATE 与 SESSION SETUP 流水线进同一次写入，因此
一次读取就同时拿到 dialect（协议版本）与 `NativeOS` 字符串（操作系统版本）。对一台真实的
Samba 主机（上报 `Windows 6.1`）：

```
445/tcp open  microsoft-ds SMB (Samba 4.24.3-Debian-4.24.3+dfsg-1; 6.1)
| 检测：SMB：SMBv1 且 Windows 版本属于 MS17-010 家族 [MEDIUM]
| 主机以 SMBv1 应答，且报告的 Windows 内核版本位于 5.0 至 6.1 之间……
| 这是两个观察结果的交集，不是确认：打补丁不会改变内核版本号，已完全
| 修补的主机看起来完全一样。请用 nmap 的 smb-vuln-ms17-010 或 Metasploit 确认。
```

SMB 那两条刻意写成"加固建议"而非 MS17-010 的证据：修补 MS17-010 **并不会**关闭
SMBv1，因此完全打过补丁的主机对 SMBv1 negotiate 的响应一模一样。要确认 MS17-010 本身
需要四步有状态的 SMB 交互，声明式 probe 无法表达——请用 nmap 的 smb-vuln-ms17-010 或
Metasploit 来做。自行编写检测的完整说明见
[docs/plugin-guide.zh-CN.md](docs/plugin-guide.zh-CN.md)。

一条 finding 是模式匹配的结果，不是证明：放进报告前请先确认。内置的每条检测都匹配只在
成功响应中才出现的内容，绝不只看状态码。

## 插件

插件就是一份 YAML 文档。argus 不会执行插件代码——恶意插件最坏的结果是给你错误的
指纹。

完整 schema、每个字段的含义、匹配规则、调试方法与当前能力边界，见
**[docs/plugin-guide.zh-CN.md](docs/plugin-guide.zh-CN.md)**（其中每个示例都由测试
套件解析验证）。

```yaml
apiVersion: argus.plugin/v1
name: my-fingerprints
version: 1.0.0
author: you
license: MIT
argus_min_version: 0.1.0
description: 额外的服务指纹

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-fingerprints
  rules:
    - id: my-app
      ports: [9000]
      probes:
        - id: get
          send: "GET /status HTTP/1.0\r\nHost: {{host}}\r\n\r\n"
          read_timeout: 3s
      matches:
        - id: my-app-server
          pattern: '(?im)^Server:\s*(?P<product>[\w.-]+)/(?P<version>[\w.-]+)'
          set: {service: http}

hack_reasons:
  apiVersion: argus.hackreason/v1
  id: my-notes
  entries:
    - id: my-app-note
      ports: [9000]
      service: http
      any_port: true
      title:
        en: "My application"
        zh: "我的应用"
      points:
        en: ["Check the admin endpoint on /admin"]
        zh: ["检查 /admin 管理端点"]
      tools: [curl]
      refs: ["https://example.invalid/docs"]
```

注册一次，argus 就记住它在哪里：

```bash
argus --register-plugin ./my-fingerprints.yaml
argus --list-plugins
argus --unregister-plugin my-fingerprints
argus --unregister-all
```

注册表语义：

- 路径会被解析为绝对路径（含符号链接），并记录注册时的 SHA-256。
- 同名再次注册视为**更新**：以新路径为准。
- 插件文件后来被删除：给出警告、退回无插件状态运行，**退出码不变**；用新路径再次
  注册即可修复，或加 `--strict-plugins` 让它变成致命错误。
- 内容自注册后被改动：警告后仍然加载（`--strict-plugins` 时改为拒绝运行）。
- 插件规则优先于内置库，确保你的指纹有机会命中；覆盖了内置规则 id 会给出提示。
- `--plugin-dir PATH` 只对本次运行从指定路径加载并忽略注册表；`--no-plugins` 完全
  关闭插件加载。
- 注册表用原子写（临时文件 + rename），写入中断不会损坏文件。

### hack-reason 条目的匹配规则

- `ports: [...]` —— 只对这些端口生效。
- `service: X` 且不写 `ports` —— 凡是以该服务运行的地方都生效。
- `service: X` 且 `any_port: true` —— 该服务在任何端口上都生效，这正是“41395 端口
  上的 HTTP”所需要的。

## `--hack-reason`

`--hack-reason` 会为每个开放端口附上值得检查的侦察切入点，内容来自一份中英双语的
YAML 知识库。它**默认关闭**，只在你显式要求时才运行。

范围是刻意划定的：这些是“检查清单 + 常用工具 + 参考链接”，不是现成的利用载荷。
这样既能在授权测试中真正有用，也能让项目保持可分发性。全部内容都是数据，可以用
插件增补或替换。

## 状态目录

注册表与可选的配置文件放在各平台约定位置：

| 平台 | 路径 |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/argus` 或 `~/.config/argus` |
| macOS | `~/Library/Application Support/argus` |
| Windows | `%AppData%\argus` |

可用 `ARGUS_CONFIG_DIR` 覆盖（适合放在 U 盘里做便携版）。`config.yaml` 目前支持
一个键：

```yaml
lang: zh
```

## 代理

```bash
argus --proxy socks5://127.0.0.1:1080 -sV -p 445 10.10.10.20
```

SOCKS5 作用于 TCP connect 探测，也就是通过已控主机做跳板所需的那条路径。SYN 与 UDP
探测始终直连，argus 会明确告知，而不是静默忽略该参数。

## 法律提示

请仅扫描你本人拥有、或已获得明确书面授权的系统。未经授权的端口扫描在多数司法辖区
可能构成违法。argus 以 MIT 许可证提供，不附带任何形式的担保。

## 开发

```bash
make            # fmt、vet、test、build
make test-race
make cover
make cross      # 生成 linux/darwin/windows 静态二进制
```

目录结构：

```
cmd/argus              入口
internal/cli           参数解析、流程编排、插件子命令
internal/scan          引擎：connect、Linux SYN、UDP、主机发现、时序
internal/detect        服务识别：探针、TLS、YAML 指纹
internal/hackreason    中英双语渗透姿势知识库
internal/plugins       插件注册表与文档校验
internal/report        普通输出、nmap 兼容 XML、JSON 渲染器
internal/ports         端口规格解析与内置服务表
internal/targets       目标规格解析（地址、CIDR、区间、主机名）
internal/i18n          消息目录与语言解析
internal/model         全流程共享的结果模型
```

`make check-fmt` 与 `go vet ./...` 应保持全绿。插件手册位于 `docs/`，其中可直接复制
的示例由 `internal/plugins/document_test.go` 提取并校验，因此文档不会与 schema 脱节。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。Copyright (c) 2025 guaidao2 & coolmoon。
