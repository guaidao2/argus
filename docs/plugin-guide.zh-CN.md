# 编写 argus 插件

[English](plugin-guide.md)

插件让你不重新编译 argus 就为它增加服务指纹和渗透姿势提示。本文档描述的是**当前构建
真正支持的** schema——文中的每个示例都由测试套件解析，因此不会和代码脱节。

---

## 1. 插件是什么

插件就是**一份 YAML 文档**。argus 只是解析它，不会做别的：没有插件代码、没有脚本语言，
插件也无法执行任何东西。恶意插件最坏的结果是给你错误的指纹。

插件可以贡献两类内容，任意组合：

| 段 | 作用 |
| --- | --- |
| `fingerprints` | 探测开放端口并识别对端是什么服务 |
| `hack_reasons` | 为端口或服务附上侦察检查清单 |

## 2. 文件、目录与插件包

```bash
argus --register-plugin ./my-plugin.yaml       # 单个文件
argus --register-plugin ./my-pack/             # 目录 = 一个插件包
argus --plugin-dir ./my-pack/ -sV 10.0.0.1     # 仅本次运行，忽略注册表
```

目录会作为**一个条目**注册，名称取目录名，并且**递归**遍历：

```
my-pack/
├── top.yaml             载入
├── web/a.yaml           载入
├── db/nested/b.yaml     载入
├── .hidden/c.yaml       跳过（隐藏）
└── values.yaml          报告但不致命（不是插件文档）
```

读取规则：

- 只认 `*.yaml` 和 `*.yml`。隐藏文件与隐藏目录一律忽略，所以插件包里的 `.git` 不会
  把它弄坏。
- 在**目录**里，不是插件文档的文件会被报告出来（注册时是警告，扫描时 `-v` 可见），
  其余文件照常载入。真实的插件包里挨着放置 README 或 values 文件是很常见的。
- 当你明确指定**单个文件**时，它不是插件文档就是硬错误。是你指名的，argus 不会悄悄
  跳过。
- 目录里没有任何可用文档 → 报错。

注册时会记住绝对路径（解析符号链接）与内容 SHA-256。之后插件被删除或被改动怎么办，
见主 README 的"注册表语义"一节。

## 3. 文档外层结构

```yaml
apiVersion: argus.plugin/v1     # 必填，必须恰好是这个值
name: my-plugin                 # 必填
version: 1.0.0                  # 可选，仅作展示
author: you                     # 可选
license: MIT                    # 可选
description: 这是什么            # 可选
argus_min_version: 1.0.0        # 可选，低于此版本的构建会拒绝加载
vars:                           # 可选，可用 {{var:NAME}} 引用
  status_path: /status

fingerprints: { ... }           # 这两段至少要有其一
hack_reasons: { ... }
```

字段说明：

- `apiVersion` 是**校验**而非猜测。为更新 schema 写的文档会被拒绝，并告知当前构建支持
  的版本号。
- `argus_min_version` 用简单的点分比较（`1.10.0` > `1.9.0`），预发布后缀会被忽略。
- `vars` 的值会替换进探测载荷。命令行上的 `--plugin-var key=value` 覆盖这里的声明，
  这就是一个插件包服务多套环境的方式。

## 4. 指纹

<!-- testable -->
```yaml
apiVersion: argus.plugin/v1
name: my-app-fingerprints
version: 1.0.0
argus_min_version: 1.0.0
vars:
  status_path: /status

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-fingerprints
  description: 可选
  rules:
    - id: my-rule
      description: 可选
      ports: [9000, 9001]     # 省略则在每个开放端口上尝试
      tunnel: ""              # "" 表示明文，"ssl" 表示 TLS 之上
      conf: 10                # 置信度 0-10，默认 10
      probes:
        - id: get-status
          send: "GET {{var:status_path}} HTTP/1.0\r\nHost: {{host}}\r\nUser-Agent: {{agent}}/{{argus_version}}\r\n\r\n"
          read_timeout: 3s
          read_bytes: 8192
      matches:
        - id: json-service
          pattern: '(?is)"service"\s*:\s*\{'
          set:
            service: my-app
            product: My App
          fields:
            version: '"version"\s*:\s*"([^"]+)"'
```

### 规则如何被求值

1. argus 为**每个 probe 单独建立一条连接**（probe 之间从不复用连接）；当
   `tunnel: ssl` 时会先完成 TLS 握手；随后发送 `send`，再持续读取，直到
   `read_timeout`、`read_bytes` 或 EOF。
2. `matches` 中的每一条按顺序与响应比对。**第一条** `pattern` 命中的即为结果，该规则
   结束。
3. 若没有任何规则命中，则使用端口表的服务名，端口仍会作为开放端口报告。

规则的尝试顺序：

1. 声明了该端口的规则（`ports: [9000]`）。
2. 未声明 `ports` 的规则，它们在所有端口上生效。
3. 插件规则优先于内置规则，确保你的规则有机会胜出。

`send` 为空的 probe 只做读取：SSH、FTP、SMTP、VNC、MySQL 这类"先发 banner"的协议就是
这样识别的。被动读取的响应会在多个 banner 规则之间共享，因此只消耗一次连接，而不是
每条规则一次。

### probe 字段

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `send` | `""` | 要发送的字节。为空表示"只监听"。 |
| `read_timeout` | `3s` | 超过此时长停止读取。 |
| `read_bytes` | `8192` | 累计读到这么多字节就停止。 |
| `wait` | `0` | 读取前先停顿，适用于需要一点时间的服务。 |

收到第一块数据后，argus 最多再等 200ms 收尾便关闭连接，因此话痨型服务不会把 probe
拖满整个超时时间。

### `send` 中可用的占位符

| 占位符 | 值 |
| --- | --- |
| `{{host}}` | 目标地址（扫描时的写法） |
| `{{port}}` | 目标端口 |
| `{{agent}}` | User agent（默认 `argus`） |
| `{{argus_version}}` | 当前 argus 版本 |
| `{{var:NAME}}` | `vars` 中的条目，或 `--plugin-var NAME=...` |

### match 字段

| 字段 | 含义 |
| --- | --- |
| `pattern` | Go 正则（RE2）。必须命中，规则才会生效。 |
| `set` | 赋予结果字段的常量值。 |
| `fields` | `字段: 正则` 对，在**整个响应**上执行；取第一个捕获组（无捕获组则取整个匹配）。 |
| `conf` | 该 match 的置信度，默认继承规则的 `conf`。 |

`pattern` 中名为已知字段的命名捕获组也会被提取。优先级：先 `set`，再命名捕获组，最后
`fields` —— 后写入者覆盖前者。

### 可提取的字段

| 字段 | 落到哪里 |
| --- | --- |
| `service` | SERVICE 列，如 `http` |
| `product` | VERSION 的第一部分，如 `nginx` |
| `version` | VERSION 的第二部分，如 `1.24.0` |
| `info` | 括号内的附加信息 |
| `os` / `ostype` | 括号内的系统提示（两种拼写都可） |
| `device` | 括号内的设备提示 |
| `cpe` | 逗号分隔的 CPE，写入 XML |
| `hostname` | 追加到附加信息 |

其它字段名会在加载时被拒绝，并在报错里指出该字段名——拼错会响亮地失败，而不是被忽略。

### TLS 之上的服务

`tunnel: ssl` 会让 argus 先完成一次 TLS 握手（目标是域名时带上 SNI，ALPN 提供
`h2`/`http/1.1`），然后在其中执行 probe。握手同时会取回证书，`-v` 时出现在文本输出里，
`-oX`/`-oJ` 中则始终保留。当被动读取的内容看起来像 TLS 记录、或该端口绑定了 `ssl`
规则时，argus 会自动认定这是 TLS 端口——无需你额外配置。

## 5. 检测与判定结论（check / finding）

`kind: check` 的规则给出的不是"识别"，而是**判定结论**：不是"这是 nginx"，而是
"该端口无需凭据即可访问"。判定结论与服务描述**分开报告**——"nginx 1.24.0" 是观察结果，
"无凭据即可读取索引列表" 是判断，两者在报告里不能混为一谈。

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-checks
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-checks
  rules:
    - id: my-service-unauthenticated
      description: The service answers administrative requests without credentials
      kind: check
      ports: [9000]
      service: my-service
      probes:
        - id: probe
          send: "GET /admin/status HTTP/1.0\r\nHost: {{host}}\r\n\r\n"
          read_timeout: 3s
          read_bytes: 8192
      matches:
        - id: unauth
          pattern: '(?im)^HTTP/1\.[01] 200\b.*server_status'
          finding:
            title:
              en: "My Service: unauthenticated admin access"
              zh: "My Service：管理接口未授权访问"
            severity: high
            description:
              en: "The status endpoint answered without credentials, so administrative data is readable by anyone who can reach the port."
              zh: "状态端点在无凭据情况下作出了响应，任何能访问该端口的人都能读取管理数据。"
            refs:
              - "https://example.invalid/docs/security"
          set: {service: my-service, product: My Service}
```

### 检测何时运行

**只在加了 `--findings` 时运行。** 检测探针在链路上是可被识别的入侵行为——它会请求
管理端点、发送数据库命令、尝试默认凭据——所以 argus 不会因为你开了服务识别就顺手发出去。
没有这个开关，`kind: check` 规则根本不会交给探测器。

检测有两条命中路径，二者都会被求值：

| 绑定方式 | 生效条件 |
| --- | --- |
| `ports: [...]` | 被扫端口在列表中，无论是否识别出服务。 |
| `service: X` | 识别阶段认出服务 X，无论它跑在哪个端口。 |

第二条让跑在 19300 端口上的 Redis 依然会被检测。但它只对服务名**足够独特**的服务有效：
把检测绑到 `http` 上会让它在扫描中的每个 Web 端口都运行。argus 会拒绝几个明显过于宽泛的
绑定，内置检测也只在服务名明确时绑定（`redis`、`memcached`、`mongodb`、`couchdb`）。

注意这对非常规端口的推论：如果没有东西识别出该服务，按服务绑定的检测同样无从匹配。若你
扫描的范围内服务可能藏在随机端口上，请为它补一条不带 `ports` 的识别规则（见第 4 节），
与检测规则配套使用。

### 一个 probe 里完成两次交互

一个 probe 只发送一次、读取一次，但这并不限制你只能做一次协议交互。行式协议对每一行独立
应答，因此多条命令可以流水线进同一次写入：

```yaml
probes:
  - id: anonymous-login
    send: "USER anonymous\r\nPASS anonymous@example.com\r\n"
```

响应里就同时包含两个答复，pattern 则要求两者都出现：

```yaml
pattern: '(?s)331 [^\r\n]*\r\n230 '
```

要求 `230` 之前必须先有 `331`，才能把"我们的 PASS 被接受"与"会话中其它环节产生的
`230`"区分开。少了这个约束，检测就退化成一次 grep。

内置的 FTP 匿名登录检测就是这样实现的，也是当前声明式 probe 能表达的**最宽的"多步"流程**：
真正的双会话流程（先登录、再用该会话）需要第 8 节描述的状态机。

### 匹配二进制响应

pattern 是拿响应的 **latin-1 解码**去匹配的，因此 `\xNN` 表示**字节 NN**，偏移量按字节计。
协议指纹就可以按线路格式原样书写：

```yaml
pattern: '(?s)^....\xffSMB\x72\x00\x00\x00\x00.{23}\x11[\x00-\x05]'
```

这就是内置的 SMBv1 检测：4 字节 NetBIOS 头、`\xffSMB` 签名、NEGOTIATE（0x72）、成功状态、
固定 23 字节尾、WordCount 0x11，随后是小于 6 的 dialect 索引——索引为 0xffff 表示"没有
共同方言"，也就是关闭了 SMBv1 的服务器会给出的答复。

纯 ASCII 响应会跳过转换，因此最常见的情况不付出任何代价。

### finding 字段

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `title` | 是 | 一行说明这条结论。 |
| `severity` | 否 | `critical`、`high`、`medium`、`low`、`info`，默认 `info`。 |
| `description` | 否 | 为什么重要、意味着什么。 |
| `refs` | 否 | 参考：厂商文档、安全公告、技术编号。 |
| `id` | 否 | 稳定标识，默认取 match 的 id。 |

`title` 与 `description` 接受纯字符串或语言映射（`{en: ..., zh: ...}`）。纯字符串对所有
语言生效；请求的语言缺失时回退英语。

在 `kind` 不是 `check` 的规则上写 `finding` 会在加载时被拒绝；缺少 title 或 severity
取值非法同样会被拒绝。severity 与上面的固定列表比对，拼错会响亮地失败。

### 版本跟随型检测

现实中相当一部分结论是"banner 里的版本落在某个区间内"——OpenSSH 低于 9.8、vsftpd 恰好
2.3.4、httpd 是 2.4.49 或 2.4.50。正则表达式无法表达这种判断，而它也不需要任何协议状态：
一个 banner 就够。`affected` 补上的正是缺失的那次比较。

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-version-checks
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-version-checks
  rules:
    - id: my-daemon-range
      description: A daemon version inside a known affected range
      kind: check
      ports: [9000]
      probes:
        - id: banner
          send: ""
          read_timeout: 3s
          read_bytes: 512
      matches:
        - id: affected
          pattern: '(?i)example-daemon'
          fields:
            version: '(?i)example-daemon[ /]([0-9][^\s\r\n]*)'
          affected:
            range: ">=1.2.0 <1.4.7"
          finding:
            title:
              en: "Example daemon: version in an affected range"
              zh: "Example daemon：版本位于受影响区间"
            severity: medium
            description:
              en: "The banner reports a version between 1.2.0 and 1.4.6. This is a version match rather than a confirmation."
              zh: "banner 报告的版本位于 1.2.0 至 1.4.6 之间。这是版本匹配，而非确认。"
```

| 字段 | 含义 |
| --- | --- |
| `field` | 哪个已提取字段承载版本，默认 `version`。 |
| `range` | 一个或多个约束，以 AND 组合，用空格或逗号分隔：`">=8.5p1 <9.8"`、`"==2.3.4"`、`"1.3.5"`。 |

操作符为 `<`、`<=`、`>`、`>=`、`==`、`!=`，只写版本号表示相等。未知字段或无法解析的
区间会在加载时报错。

**版本是怎么比的。** 每个版本被切成数字段与字母段，分隔符只起到切分作用。数字段按数值
比较，所以 `1.24.0` 高于 `1.9.0`；尾随字母排在纯数字之上，所以 `1.3.5` 低于 `1.3.5a`。
当一个是另一个的前缀时，短的更小：`9.8` 低于 `9.8p1`。发行版后缀不会造成困扰：
`8.9p1-3ubuntu0.4` 高于 `8.5p1` 且低于 `9.8`。

这里**刻意不是** semver：banner 本来就不是 semver。`2.3.4-rc1` 在此高于 `2.3.4`，
而 semver 会判为更低——因为猜测哪些后缀代表"尚未发布"，引入的错误比解决的多。

**版本匹配不等于确认。** 发行版通常以 backport 方式修补而不改动版本字符串，因此"版本落在
区间内"是值得去看一眼的理由，不是结论。请在 finding 文案里让读者不会漏看这一点，并如实
设置 severity：内置的版本检测一律用 `medium`，即便底层漏洞本身是 critical。`affected`
的匹配同样是"取保守值"——如果版本压根没提取出来，规则不会生效，因为"版本未知"不构成证据。

### 交集：协议版本与操作系统版本

很多结论不是"某个字段落在某个区间"，而是"这些观察同时成立"。MS17-010 就是典型：**既是**
SMBv1 响应，**又**属于受影响家族的操作系统版本。任何一个单独看都是噪音，合在一起才值得
去看。

`affected` 接受列表，其中每个条件都必须成立：

```yaml
<!-- testable -->
apiVersion: argus.plugin/v1
name: my-intersection
version: 1.0.0

fingerprints:
  apiVersion: argus.fingerprint/v1
  id: my-intersection
  rules:
    - id: legacy-smb-candidate
      kind: check
      ports: [445]
      probes:
        - id: negotiate
          send: "\x00\x00\x00\x45\xffSMB\x72"
          read_timeout: 4s
      matches:
        - id: candidate
          pattern: '(?s)\\xffSMB'
          fields:
            protocol: '(\xffSMB|\xfeSMB)'
            os_version: 'Windows ([0-9][0-9.]*)'
            implementation: '(Samba|Windows NT|Windows 2000)'
          affected:
            - {field: protocol, equals: "\xffSMB"}
            - {field: os_version, range: ">=5.0 <6.2"}
            - {field: implementation, oneof: ["Windows NT", "Samba"]}
          finding:
            title:
              en: "SMBv1 on a legacy Windows version"
              zh: "SMBv1 且 Windows 版本较旧"
            severity: medium
            description:
              en: "Two observations hold at once. This is an intersection, not a confirmation."
              zh: "两个观察同时成立。这是交集，不是确认。"
```

| 选择器 | 含义 |
| --- | --- |
| `range: ">=5.0 <6.2"` | 该值视为版本，需落在区间内。 |
| `equals: "SMB1"` | 该值与之相等（不区分大小写）。 |
| `oneof: [a, b]` | 该值等于其中之一（不区分大小写）。 |

引用了"没有任何东西提取"的字段的条件会在加载时被拒绝，因为这样的规则永远不会生效。而
字段提取为空的条件同样不会生效：读不到的值不构成证据。

**从一个 probe 里取出多个信号。** probe 依然只发送一次、读取一次，但只要各次交互彼此独立
应答，多轮协议交互就可以流水线进同一次写入。FTP 的 `USER`/`PASS` 如此，SMB 也一样——
这正是上面那条 SMB 检测得以成立的原因：

```yaml
send: "<NEGOTIATE 消息><SESSION SETUP 消息>"
```

服务器会把两个都答了，一次读取即可拿到两个响应：第一个携带 dialect（协议版本），第二个
携带 `NativeOS` 字符串（操作系统版本）。内置的 `smb1-legacy-windows-family` 正是用这个
方式，从单个 probe 里取到它那段交集的两半。

其中的 session setup 使用空账户与空密码的 LM 响应，也就是 null session。要求凭据的服务器
会返回错误，pattern 不匹配，于是什么都不报——宁可漏报也不误报，在这个场景下是正确的一侧。

只为参与比较而存在的字段是允许的：上面的 `os_version` 会被提取但从不报告。既不可报告、
又没有被任何条件引用的字段名仍然是错误，因此拼写错误依旧会响亮地失败。

### 结论如何呈现

- **普通输出**沿用 nmap 的脚本惯例，位于该端口的块内：

  ```
  6379/tcp open  redis   Redis 7.2.4
  | 检测：Redis：未授权访问 [HIGH]
  | 服务器在无凭据情况下响应了 INFO，任何能访问该端口的客户端都可读取其配置与键值。
  |_参考：https://redis.io/docs/latest/operate/oss_and_stack/management/security/
  ```

- **XML** 使用 nmap 自己的 `<script id="rule:match" output="...">` 元素，因此已经能解析
  NSE 输出的工具链（Metasploit 的 `db_import`、Faraday、各类报告生成器）无需特殊适配即可
  读到结论。
- **JSON** 放在端口的 `findings[]` 中，并在 `summary.findings` 里计数。
- 机器可读输出不做翻译：XML 与 JSON 中 finding 的标题与描述保持作者书写时的语言。

### 一条 finding 不是什么

finding 是模式匹配的结果，不是证明。`--findings` 通过"必须显式开启"和"把结论与识别分开"
缩小了误差，但一条只匹配 `200 OK` 的规则，在"对任何请求都返回 200"的服务上必然误报。因此
内置的每条检测都匹配只在**成功响应中才出现的内容**——索引列表、Pod 列表、版本字段——绝不
只看状态码。自己写检测时请遵循同一标准，并把结论放进报告之前先人工确认一遍。

## 6. 渗透姿势（hack reason）

<!-- testable -->
```yaml
apiVersion: argus.plugin/v1
name: my-app-notes
version: 1.0.0

hack_reasons:
  apiVersion: argus.hackreason/v1
  id: my-notes
  entries:
    - id: my-service
      ports: [9000, 9001]     # 对这些端口生效
      service: my-app         # ...以及该服务
      any_port: true          # ...即使它跑在非标准端口上
      proto: tcp              # 默认 tcp
      title:
        en: My service
        zh: 我的服务
      points:
        en: ["Check the admin endpoint"]
        zh: ["检查管理端点"]
      tools: [curl]
      refs: ["https://example.invalid/docs"]
```

三种匹配模式，这个区分很重要：

| 声明方式 | 何时生效 |
| --- | --- |
| `ports: [...]` | 被扫端口在列表中。 |
| `service: X` 且不写 `ports` | 探测到的服务是 X，任意端口。 |
| `service: X` 且 `any_port: true` | 探测到的服务是 X，任意端口——即便同时声明了 `ports`。 |

不写 `any_port` 时，`ports` 列表只对这些端口成立。这是刻意的：曾经凡是提到
`service: http` 的条目都会在任意开放 Web 端口上生效，结果一个端口就刷出一整屏无关建议。

`title` 与 `points` 是语言映射表；请求的语言缺失时回退到英语。`tools` 与 `refs` 不翻译。

## 7. 调试插件

```bash
# 不碰注册表直接加载，并观察探测器实际做了什么
argus --plugin-dir ./my-pack -d -Pn -sV -p 9000 10.0.0.1

# 注册前先校验插件是否有效
argus --register-plugin ./my-pack

# 查看已注册内容，以及是否仍与记录的哈希一致
argus --list-plugins
```

`-d` 会打印哪个规则命中了哪个端口：

```
DEBUG: detect 10.0.0.1:9000 -> rule my-rule/json-service service=my-app product=My App version=2.1.0
```

常见错误：

| 报错 | 原因 |
| --- | --- |
| `missing apiVersion, expected argus.plugin/v1` | 缺少或拼错了 `apiVersion`。 |
| `unsupported apiVersion` | 为比当前构建更新的 schema 所写。 |
| `needs argus >= X` | `argus_min_version` 高于当前运行的构建。 |
| `sets unknown field "produkt"` | `set` 或 `fields` 里拼错了字段名。 |
| `has an invalid pattern` | 正则无法编译（RE2，不支持前瞻与反向引用）。 |
| `defines no matches` | 规则缺少或留空了 `matches:`。 |
| `declares a finding but the rule kind is "fingerprint"` | 使用了 `finding:` 但规则不是 `kind: check`。 |
| `has a finding without a title` | 每条 finding 都必须有 `title`。 |
| `has severity "catastrophic"` | severity 只能是 critical/high/medium/low/info。 |
| `defines neither fingerprints nor hack_reasons` | 没有任何可贡献的内容。 |
| `no usable plugin documents in <path>` | 插件包里每个文件都被跳过了。 |

## 8. 插件做不到什么

这些是刻意划定的边界，不是待填补的空白。它们都源自同一个决定：**插件是数据，不是代码**。

- **probe 之间没有状态。** 每个 probe 各开一条连接。规则无法"先登录、再拿这个会话发
  第二个请求"，因此"先认证后验证"与挑战应答类流程无法表达。
- **没有计算能力。** 没有算术、没有哈希、没有循环、没有条件分支。任何需要从响应中
  计算出一个值的检查都无法表达。
- **没有时序与并发逻辑。** 做不了竞态条件，也做不了时间盲注类判定。
- **除被扫端口外没有文件或网络访问。** 插件不能读文件、不能呼叫其它主机、不能当中转。
- **无法给出需要计算或状态的结论。** `kind: check` 规则可以报出判定结论，但仅限于
  "响应里出现了这个特征"这类结论。需要把两个响应结合起来判断，或需要从响应中算出某个值的
  结论，无法表达。

在这些边界之内仍然能表达很多：版本与构建指纹、默认配置检测、未授权访问检测、信息泄露，
以及任何"判定标准就是响应里有没有这个特征"的单请求检查。

## 9. 完整示例

见 [`examples/example-plugin.yaml`](../examples/example-plugin.yaml)——一个可用的插件，
包含一条指纹和一条双语姿势笔记，每次构建都由测试套件解析校验。
