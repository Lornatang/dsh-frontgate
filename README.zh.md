---
description: "为 dsh Web profile 提供密码保护：一个独立端口、一个密码、一个签名会话 Cookie，并把流量反向代理到回环地址上的 harness。"
kind: "package-bundle"
---

# @lornatang/dsh-frontgate

[English](README.md) | 中文

## 概要

`dsh-frontgate` 为 dsh Web UI 加一道密码。它监听独立端口，校验一次密码后签发签名会话 Cookie，把通过认证的 HTTP 与 WebSocket 流量转发到回环地址上的 harness。把它装进任意 Web profile，就能从局域网、VPN 或容器访问 GUI，而不必把 harness 本身暴露出去。状态文件只保存 scrypt 哈希，首次启动会把生成的密码打印一次。边界：每个 profile 只有一个密码、没有多用户账号，明文 HTTP 在链路上不提供任何保护。

## 目录

- [使用本包](#use-this-package)
- [理解实现](#understand-the-implementation)
- [延伸阅读](#further-exploration)
- [模型体验](#model-experience)
- [已知限制与后续工作](#known-limitations-and-deferred-work)
- [开发者注记](#dev-note)

-----

<a id="use-this-package"></a>
## 使用本包

浏览器访问门禁，门禁访问回环地址上的 harness，因此 harness 监听端口不会从网络可达。请把这一层装进你想保护 GUI 的那个 Web profile。

### 安装到 profile

```text
dsh plugin --profile web add @lornatang/dsh-frontgate
dsh plugin --profile web remove @lornatang/dsh-frontgate
```

npm 仓库与 GitHub Release 均已发布 0.1.10。如需直接安装 GitHub 归档，请运行 `dsh plugin --profile web add https://github.com/Lornatang/dsh-frontgate/releases/download/v0.1.10/lornatang-dsh-frontgate-0.1.10.tgz`，或运行本版本的 `install.sh`。

`add` 会把这一层组合进 profile：它的 `cordis.patch.yml` 中新增一条 insert 条目，row id 为 `frontgate`，其 `config` 以下面的回环默认值为起点。清单中没有 `dsh.bundle.patch` 声明的包会在这一步失败，而不是静默地什么都不挂载。安装后重启 DSH，再打开 <http://127.0.0.1:3090> 登录。

如果既没有配置密码、也没有已保存的密码，首次启动会生成一个并打印一次：

```text
[dsh-frontgate] PASSWORD: xxxx-xxxx-xxxx-xxxx
```

请在它出现时保存：只有 scrypt 哈希会写入状态文件，明文之后无法找回。

`--profile web` 指随 dsh 发布的 Web profile；如果你给 profile 起了别的名字，两条命令都换成你的名字。升级使用同样的 `add` 命令，profile 条目和已保存的密码会保留。0.1.6 之前的版本以无 scope 的 `dsh-frontgate` 发布，因此先加上带 scope 的包，再移除旧包名，然后重启一次；同一个 profile 本来也只能运行一个门禁实例。

### 你会得到什么

这一层不添加任何模型工具，也不添加客户端 UI 行：它接管的是 harness 前面的传输。装入后 profile 会得到 `/__gate/login` 登录页、配套的 `POST /__gate/login`、`POST /__gate/logout` 与 `GET /__gate/health` 路由，以及一枚每个被代理请求都必须携带的签名会话 Cookie（`dsh_gate`）。未认证的 API 请求收到 `401 {"error":"unauthorized"}` 与登录提示，其余路径重定向到登录页并带上 `next` 目标。未知的 `/__gate/*` 路径由门禁直接应答，永远不会被代理。

profile 原本提供的东西在门禁之后保持不变：Cookie 校验通过后，Web GUI、会话 API 与 WebSocket 流都被代理到 harness 源站，逐跳头会被丢弃，harness 的 launch cookie 在服务端完成交换。

### 配置

本包已经带上了下面这条条目，所以 profile 只写与默认值不同的部分：profile 自己的条目在层之后应用，优先生效。

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: frontgate
  config:
    listenHost: '0.0.0.0' # 仅在需要远程访问时
    listenPort: 30010
    # password: '至少 12 个字符的密码'
```

loader 会按 `src/config.ts` 校验每个字段，非法值在启动时直接报错，而不会退化为默认值。不带 `config` 的 `frontgate` 条目按以下默认值启动：

| 字段 | 默认值 | 含义 |
|---|---|---|
| `listenHost` | `127.0.0.1` | 门禁监听的网卡地址。 |
| `listenPort` | `3090` | 门禁端口；`0` 表示临时端口。必须与 harness 端口不同。 |
| `sessionDays` | `7` | 会话绝对有效期，1–365 天。 |
| `title` | `DeepSeek Harness` | 登录页标题。 |
| `password` | 空 | 明文密码，至少 12 个字符；启动时哈希，明文不落盘。 |
| `passwordHash` | 空 | scrypt 哈希；优先级高于其他所有密码来源。 |
| `tlsCertFile` / `tlsKeyFile` | 空 | 两者同时设置时由门禁直接提供 HTTPS。 |
| `publicOrigin` | 空 | 使用主机名、NAT 或反向代理时浏览器实际访问的完整 origin，例如 `https://gate.example.com`。 |
| `trustProxy` | `false` | 是否采信 `X-Forwarded-For`；仅在监听端口只对可信代理开放时启用。 |
| `maxAttempts` | `5` | 同一客户端 IP 锁定前允许的失败次数，1–50。 |
| `lockMinutes` | `5` | 锁定时长，1–1440 分钟。 |
| `exchangeTimeoutMs` | `5000` | harness 启动令牌交换的超时时间。 |
| `maxConnectionsPerPeer` | `64` | 每个对端的并发 TCP 连接数，0–1024；`0` 表示不限制。 |
| `maxPendingLoginsPerIp` | `4` | 单个客户端 IP 正在接收的登录表单数，1–128。 |
| `maxHttpRequestsPerSession` | `32` | 每个已登录会话的并发 HTTP 请求数，1–128，包含等待 harness 的请求。 |
| `upstreamHeaderTimeoutMs` | `0` | 上游响应头的超时（含排队时间）；`0` 表示关闭。 |
| `upstreamIdleTimeoutMs` | `0` | 上游响应的空闲超时；`0` 表示关闭。 |
| `websocketHandshakeTimeoutMs` | `10000` | 上游 WebSocket 握手的超时；升级成功后不再适用。 |
| `upstreamCaFile` / `upstreamServerName` | 空 | 以 IP 访问私有 HTTPS harness 时使用的 CA 文件与 TLS 主机名。 |

### 密码与会话

密码按以下顺序取值：`passwordHash`、`password`、`DSH_FRONTGATE_PASSWORD_HASH`、`DSH_FRONTGATE_PASSWORD`、已保存的哈希，最后是新生成的密码。明文密码至少 12 个字符。修改配置中的密码会替换已保存的哈希，并使现有会话退出登录。

同一客户端 IP 失败 `maxAttempts` 次后会被锁定 `lockMinutes`，锁定期间即使密码正确也会被拒绝。同一 NAT 后的客户端共享该地址，因此一次锁定会影响它们全部。门禁最多记录 1,024 个有失败记录的客户端；记录满时新客户端要等条目过期，而不是挤掉仍然生效的锁定；过期失败计数在锁定窗口结束后不再计入。

会话有效期固定为 `sessionDays`，不因活跃而延长。Cookie 名为 `dsh_gate`，带 `HttpOnly`、`SameSite=Lax`，当公共 origin 是 HTTPS 时还会带 `Secure`。`/__gate/logout` 会吊销会话、关闭该会话的 HTTP 流与 WebSocket，并用 `Clear-Site-Data` 请求浏览器清理缓存内容；其他会话保持连接。吊销记录在重启后依然有效。

状态位于 `$DSH_HOME/profiles/<name>/data/dsh-frontgate.json`。在 POSIX 系统上文件权限会被收紧为 `0600`；在 Windows 上需要使用 Windows ACL 限制对 profile 数据目录的访问。每个 profile 只允许一个门禁实例，由同目录下基于 SQLite 的操作系统级锁保证，进程退出（包括崩溃）时自动释放；因此数据目录必须支持 SQLite 锁，且门禁运行期间不能删除或替换锁文件。需要启用 Node.js 内置的 `node:sqlite` 模块，这也是本包要求 Node.js 22.19 或更高版本的原因。

### 远程访问

使用 Docker 时把门禁绑到所有网卡并发布端口；映射的容器侧端口必须等于 `listenPort`，宿主机侧可以不同：

```yaml
# profile patch
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
    publicOrigin: 'http://<host-ip>:30190' # 替换为浏览器实际访问的 origin
```

```yaml
# Docker Compose
ports:
  - '30190:30010'
```

之后访问 `http://<host-ip>:30190`。当 NAT、反向代理或主机名使浏览器地址与门禁本地地址和端口不同时，将 `publicOrigin` 设置为浏览器实际访问的完整 origin。未配置时，门禁只接受连接的本地地址和端口（回环连接还允许 `localhost`）。直接走 HTTP 访问时让 `trustProxy` 保持关闭，并把 harness 本身保持在回环地址上，避免在宿主机上绕过门禁。

在 HTTPS 反向代理之后，把 `publicOrigin` 设为对外 origin，并保留原始 `Host` 头（含可能的非默认端口；Nginx: `proxy_set_header Host $http_host;`）。门禁监听端口应只对代理开放。启用 `trustProxy` 时，代理必须用真实客户端地址覆盖客户端自带的 `X-Forwarded-For`（Nginx: `proxy_set_header X-Forwarded-For $remote_addr;`），否则门禁会采信客户端伪造的值。`maxConnectionsPerPeer` 统计的是 TCP 对端，经过代理的流量共享代理的额度；按客户端限流请在代理上做。

上游 HTTPS 的证书与主机名都会被校验。使用私有 CA 时把 `upstreamCaFile` 指向其 PEM 文件；若 harness origin 是 IP、但证书写的是 DNS 主机名，还要把 `upstreamServerName` 设为该主机名。

门禁最多同时放行 128 个上游 HTTP 请求。超过该上限的请求收到 503，可以重试；超过单会话上限的请求收到 429。长连接流在关闭前一直占用这些额度。上游响应超时默认关闭，以便安静的 Agent 会话继续运行；需要限制挂起请求时再开启，并一并检查反向代理自身的超时。已认证响应带 `Cache-Control: private, no-store`。

请为门禁使用独立的主机名或 IP。浏览器 Cookie 在同一主机名或 IP 的所有端口间共享，因此该主机其他端口上的不可信服务可能收到会话 Cookie，即使双方都用 HTTPS。

### 故障排查

- **日志里没有密码** — 正在复用已保存的哈希或已配置的密码。设置 `password` 并清空 `passwordHash` 来轮换；这会令现有会话退出登录。
- **无法连接** — 检查 `listenHost`、门禁启动日志，以及映射的容器端口是否等于 `listenPort`。
- **Origin 或 Host 校验失败** — 检查 `publicOrigin`，并确认代理转发了原始 `Host`。
- **状态文件错误** — 恢复可信备份；或者停止 DSH，把损坏的文件移开，然后重启以生成新密钥并使会话失效。文件必须属于 DSH 用户、权限为 `0600`。
- **profile 状态被锁定** — 还有另一个门禁在使用该 profile。先停掉它；从旧版本升级时也必须先停旧进程。

-----

<a id="understand-the-implementation"></a>
## 理解实现

<details>
<summary>实现细节 — 点击展开</summary>

本层只有一条：向目标 profile `insert` 一条 `frontgate`，配置为回环默认值。没有任何平台门控，因为门禁是宿主侧监听器；它保护的客户端 UI 属于 harness，而不属于本包。

`apply` 等待 `webServer` 与 `connection` 服务，从 `ctx.webServer.getOrigin()` 取得 harness origin，并在 `listenPort` 与 harness 端口冲突时拒绝启动。TLS 必须同时提供两个文件；在提供 TLS 时，非 HTTPS 的 `publicOrigin` 会被拒绝。密码选择、会话存储、门禁处理器与代理都在监听器启动前由这些值构建。

门禁自己处理 `/__gate/login`、`/__gate/logout` 与 `/__gate/health`；对未认证的 `/api` 请求返回 401 JSON，对其他未认证请求重定向到登录页，并把原路径作为 `next` 传入。harness 的 index 文档会注入幂等的 `crypto.randomUUID` polyfill，因为局域网上的明文 HTTP origin 不是安全上下文。

代理会丢弃逐跳头与浏览器相关头，把 `Host` 与 `Origin` 改写成 harness origin，并在服务端完成启动 Cookie 交换，使浏览器始终看不到该 Cookie；交换得到的 Cookie 复用 25 分钟。WebSocket 升级在握手超时通过后于 TCP 层直接拼接。连接计数器在请求进入 harness 队列前限制准入。

状态文件保存密码哈希、Cookie 签名密钥与吊销列表，以 `0600` 写入，并在密码变化时重写。其旁边的 SQLite 锁文件保证每个 profile 只有一个门禁，退出时释放。

| 源码 | 内容 |
|---|---|
| `cordis.patch.yml` | 本层：一条 insert 条目，row id `frontgate`，回环默认值。 |
| `src/index.ts` | `apply`：配置解析、密码选择、监听器与 TLS、门禁与代理装配。 |
| `src/gate.ts` | 门禁路由、登录登出、重定向、`/api` 拒绝、放行请求的转发。 |
| `src/proxy.ts` | 头部改写、启动 Cookie 交换、WebSocket 拼接、上游准入上限。 |
| `src/auth.ts` | 密码哈希与校验、12 字符下限、`dsh_gate` Cookie。 |
| `src/state.ts` | profile 状态文件、`0600` 收紧、盐复用。 |
| `src/state-lock.ts` | 基于 `node:sqlite` 的锁，保证每个 profile 只有一个门禁实例。 |
| `src/sessions.ts` | 会话有效性、过期、吊销、流拆除。 |
| `src/polyfill.ts` | 注入 harness index 文档的 `crypto.randomUUID` 兜底。 |
| `tests/*.test.mjs` | 门禁、浏览器与安装测试。 |

</details>

-----

<a id="further-exploration"></a>
## 延伸阅读

- [CHANGELOG.md](CHANGELOG.md) — 版本历史与 0.1.x 升级说明。
- [install.sh](install.sh) — 发布流程使用的一键安装脚本。
- [DeepSeek Harness 配置目录](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/config-catalog.md) — 本层条目所遵循的 loader 语义。
- [Apache-2.0 许可证](LICENSE)。

-----

<a id="model-experience"></a>
## 模型体验

无，因为门禁在 harness 看到请求之前完成连接认证；每个放行的请求仍然走组合好的 Web 各层，行为不变。

#### KV Cache 影响

门禁不向请求前缀添加任何内容：它认证的是连接而不是改写对话，因此 token 计费与缓存行为与不带门禁的同一 profile 一致。

<a id="known-limitations-and-deferred-work"></a>
## 已知限制与后续工作

这些限制说明门禁在什么情况下不适用，以及它对周围 profile 的依赖。

- **一个密码、没有账号体系** — 门禁后的所有用户共享同一身份，它是边界而不是授权系统；知道密码的人能看到该 profile 保存的所有会话。
- **明文 HTTP 不保护链路** — 密码、Cookie 与流量对路径上任何人都可读。请使用 VPN、可信局域网，或通过 `tlsCertFile` 与 `tlsKeyFile` 或反向代理提供 TLS。
- **会话 Cookie 是主机粒度的** — 同一主机名或 IP 的所有端口共享它，因此该主机其他端口上的不可信服务可能拿到 Cookie。
- **锁定按地址生效** — 同一 NAT 后的客户端共享锁定，恶意客户端可以一直锁住共享地址直到窗口结束。
- **每个 profile 只有一个门禁** — 同一 profile 上第二个门禁会因状态锁失败；请改用独立 profile 或独立主机。
- **上游超时默认关闭** — 安静的 Agent 会话不会被误杀，但挂起的请求会一直占着准入额度直到关闭，门禁自身的上限是唯一约束。
- **证书只校验、不绕过** — 私有 CA 需要 `upstreamCaFile`，IP origin 需要 `upstreamServerName`；没有跳过校验的开关。
- **门禁不是沙箱** — 它保护的是 harness 监听端口，而不是主机：把 harness 保持在回环地址上，并把门禁密码当作唯一屏障。

<a id="dev-note"></a>
### 开发者注记

<details>
<summary>维护者工作上下文 — 点击展开</summary>

`npm run build` 用 esbuild 把 `src/index.ts` 打成 `lib/index.js`；`npm test` 先构建再运行 `node --test tests/*.test.mjs`；`npm run test:dsh` 检查面向 profile 的表面，`npm run pack:verify` 检查打包文件列表。`node:sqlite` 把最低运行时固定在 Node.js 22.19。改动状态文件格式前先读 `CHANGELOG.md`，已保存的哈希与签名密钥必须能跨升级保留。

</details>
