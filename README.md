# dsh-frontgate

给 DeepSeek Harness Web UI 加一道**密码门**的 DSH 插件：单文件、零运行时依赖、异步 scrypt 校验、无状态可撤销会话，自带反向代理与 WebSocket 直通。

远程访问时把 `dsh` 继续绑在 `127.0.0.1`，只把本插件暴露出去，即可同时解决三个问题：

1. **身份验证**——端口映射本身零认证，任何人都能打开 UI；
2. **Host/Origin 栅栏**——DSH 的 `/api` 只接受回环 Host，经本插件代理后上游看到的是 `127.0.0.1:3080`，无需给 DSH 加 `--trusted-host`；
3. **启动 token**——DSH 每次重启都会换 `?token=`，本插件在服务端兑换并缓存，浏览器只需记住网关密码。

## 与 dsh-guard 的对比

| 维度 | dsh-guard | dsh-frontgate |
| --- | --- | --- |
| 代码体量 | 8 个模块 / 约 1500 行 | 单文件 766 行（含注释） |
| 运行时依赖 | 0 | 0 |
| 密码校验 | `scryptSync`，登录时阻塞事件循环 | 异步 `scrypt`（N=32768, r=8, p=1），并发上限 2 |
| 会话存储 | 内存 Map + 10 分钟定时清扫 | 无状态 HMAC token，无表、无定时器 |
| 撤销会话 | 逐个踢或全踢 | 改密码 / 删状态文件即全部立即失效 |
| 登录限速 | 每 IP 失败计数 | 每 IP 失败计数 + 全局 2 个 scrypt 槽位（满则 429）+ 4 KiB 请求体上限 + 8 s 读取超时 |
| CSRF 防护 | Origin 与 Host 的 hostname 相同 | `Sec-Fetch-Site` + Origin 同源 |
| 管理页 / i18n / 角标 | 有 | 无（配置走 profile patch，攻击面更小） |
| scrypt 代价 | N=16384 | N=32768（更抗离线爆破，耗时翻倍） |
| 明文 HTTP 下的 `crypto.randomUUID` | polyfill | polyfill |
| 原生 TLS | 可选 | 可选 |
| 依赖的 DSH 版本 | — | `>=0.2.2-rc.1`，Node `>=22.19` |

功能取舍：本插件**不做**多用户、角色、管理后台和逐个会话撤销。它就是一道门——改密码或删状态文件即全体下线。

## 工作原理

```
浏览器 ──HTTP──> dsh-frontgate :30010 ──HTTP──> dsh 127.0.0.1:3080
   │                    │
   │  dsh_gate cookie   │  服务端兑换的 harness cookie（浏览器不可见）
   └────────────────────┘
```

- **未登录**：页面请求 302 到 `/__gate/login?next=…`；`/api/*` 返回 `401 {"error":"unauthorized","login":"/__gate/login"}`。
- **登录**：`POST /__gate/login` 校验密码（异步 scrypt），成功后种 `dsh_gate` 并 303 回 `next`。
- **已登录代理**：改写 `Host`/`Origin` 为上游地址，丢弃浏览器 Cookie，注入服务端兑换的 harness Cookie（缓存 25 分钟）；响应剥离 `Set-Cookie`，把指向上游的绝对 `Location` 改回相对路径。
- **WebSocket**：升级请求先验 `dsh_gate`，通过后按原始 TCP 双向拼接。
- **HTML 注入**：在 `</head>` 前插入 `crypto.randomUUID` polyfill（`http://内网IP` 不是安全上下文）。

## 安装

要求 Node `>=22.19`、DSH `>=0.2.2-rc.1`。

```bash
# 从 GitHub（推荐，锁定 tag）
dsh plugin --profile <name> add github:Lornatang/dsh-frontgate#v1.0.0

# 网络受限、连不上 github.com:443 时用归档 tarball URL
dsh plugin --profile <name> add https://codeload.github.com/Lornatang/dsh-frontgate/tar.gz/refs/tags/v1.0.0

# 完全离线：本地 tarball / 目录
dsh plugin --profile <name> add ./dsh-frontgate-1.0.0.tgz
```

`dsh plugin` 会调用 pnpm 装包，并把声明了 `dsh.bundle` 的包自动追加到该 profile 的 `dsh.profile.bundles`，无需手改。装完**重启该 profile** 生效。

## 配置

默认值针对本机安全场景（只监听回环）。**远程访问必须显式改 `listenHost`**。

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listenHost` | `'127.0.0.1'` | 监听地址；远程部署改 `'0.0.0.0'` |
| `listenPort` | `3090` | 监听端口；不得与 DSH 自身端口相同（`0` 表示由系统分配，仅测试用） |
| `sessionDays` | `7` | 会话有效期（1–365 天，绝对过期，不滑动） |
| `title` | `'DeepSeek Harness'` | 登录页标题 |
| `password` | `''` | 明文密码，启动时哈希，**不会**以明文写盘 |
| `passwordHash` | `''` | `scrypt$…` 哈希，优先级高于 `password` |
| `maxAttempts` | `5` | 每 IP 失败几次后锁定（1–50） |
| `lockMinutes` | `5` | 锁定时长（1–1440 分钟） |
| `tlsCertFile` / `tlsKeyFile` | `''` | 同时提供才启用 HTTPS（PEM）；只有一项会启动报错 |
| `trustProxy` | `false` | 是否信任 `X-Forwarded-For`/`X-Forwarded-Proto`（仅在你自己的反代后面开） |

覆盖方式：在 profile 的 `cordis.patch.yml`（如 `/root/.dsh/profiles/web/cordis.patch.yml`）追加：

```yaml
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
    password: '换成你的密码'
```

本插件自带的 bundle 默认值（`cordis.patch.yml`）是 `127.0.0.1:3090`，profile 条目会覆盖它。

### 密码从哪来

优先级：`passwordHash` 配置 > `password` 配置 > profile 的 `data/dsh-frontgate.json` > 随机生成（启动日志打印 `PASSWORD: xxxx-xxxx-xxxx-xxxx`，随后可从日志里取走）。

生成一个可粘贴进配置的哈希：

```bash
node -e 'const c=require("node:crypto");const s=c.randomBytes(16);const k=c.scryptSync(process.argv[1],s,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});console.log("scrypt$32768$8$1$"+s.toString("hex")+"$"+k.toString("hex"))' '你的密码'
```

状态文件 `<profile>/data/dsh-frontgate.json`（权限 0600）保存密码哈希与会话签名密钥。删掉它 = 作废所有已发会话；若没有配置密码，重启后会重新生成随机密码。

## Docker / 远程部署 runbook

以“宿主 `30190` → 容器 `30010`”的映射为例，容器内原本是 `socat 30010 → dsh-guard 3081` 的老链路：

1. **安装插件**（见上），确认 profile 的 `dsh.profile.bundles` 里有 `dsh-frontgate`。
2. **停用 guard**，避免两道门叠加：从 profile 的 `dsh.profile.bundles` 去掉 `@lvxianchao/dsh-guard`（或保留但在其 patch 里 `disable`）。本插件与 guard 都能独立工作，但没必要串联。
3. **改监听**：profile 的 `cordis.patch.yml` 追加 `- id: frontgate` + `listenHost: '0.0.0.0'` + `listenPort: 30010`（见上节示例）。
4. **清掉 socat**：`kill <socat pid>`（容器重启后这条手工链路本来也会失效）。宿主映射 `30190:30010` 不动。
5. **重启该 profile**（当前会话会断）：`dsh web --port 3080 --host 127.0.0.1`。
6. **自检**：
   ```bash
   curl -s http://127.0.0.1:30010/__gate/health          # {"ok":true,"service":"dsh-frontgate"}
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:30010/   # 302
   ```
   然后从其它设备打开 `http://<宿主IP>:30190/`，应看到中文登录页；登录后进入完整 UI，会话保留 `sessionDays` 天。
7. **回滚**：删掉 patch 里的 `frontgate` 条目并重启；如需旧链路再把 socat 拉起来即可。

**安全提醒**：`listenHost: '0.0.0.0'` 是明文 HTTP，只适合内网 / VPN。要上公网请二选一：

- 用 `tlsCertFile`/`tlsKeyFile` 让网关自己上 HTTPS（注意 DSH 上游仍是 HTTP 回环，属正常）；
- 或前置 Caddy/Nginx 终止 TLS，并设置 `trustProxy: true`（只有在你自己的反代后面才开）。

启动时若 DSH 绑定在非回环地址，日志会警告“可不经网关直连”；若网关监听非回环且未开 TLS，也会警告明文暴露。

## 安全设计要点

- **会话**：`v1.<iat>.<exp>.<nonce>.<pv>.<mac>`，HMAC-SHA256 签名；`pv` 是当前密码哈希的截断指纹，改密码（或删状态文件）→ 所有旧 token 立即失效，无需会话表。
- **密码**：`scrypt` N=32768 / r=8 / p=1 / 32 字节 key，盐 16 字节，参数随哈希存储；所有秘密比较走 `timingSafeEqual`。
- **限速与资源上限**：每 IP 5 次失败锁 5 分钟；全局同时最多 2 个 scrypt 校验，超出直接 429；登录表单最大 4 KiB、8 s 读完；客户端条目上限 1024，防内存涨。
- **登录页**：CSP `default-src 'none'`、`frame-ancestors 'none'`、`X-Frame-Options: DENY`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer`，无任何脚本。
- **CSRF / 开放重定向**：POST 只认同源（`Sec-Fetch-Site` + Origin hostname 与 Host 一致）；`next` 只接受站内绝对路径，拒绝 `//evil`、反斜杠与控制字符。
- **代理边界**：上游目标固定为 `ctx.webServer.getOrigin()`，不解析用户输入；剥离 hop-by-hop 头与 `x-forwarded-*`；`X-Forwarded-For` 默认取 socket 地址，只有 `trustProxy` 才信请求头。
- **浏览器只见 `dsh_gate`**：harness 的 launch-token Cookie 由服务端兑换并缓存 25 分钟，上游 `Set-Cookie` 一律剥离。

已知取舍：单密码、无多用户；不能单独踢某个会话（改密码 = 全体下线）；没有管理后台（改配置 = 改 patch + 重启）。

## 开发与测试

```bash
npm test          # node --test test/e2e.mjs → 18 tests / 18 pass
npm pack          # prepack 会先跑测试
```

`test/e2e.mjs` 用假 harness + 假 `ctx` 覆盖：健康检查、未登录跳转与 401、登录页 CSP、错密码、跨站 Origin 403、成功登录 Cookie 属性、代理头改写与 `Set-Cookie` 剥离、launch-token 只兑换一次、Location 改写、登出、篡改 token、`next` 开放重定向、锁定 429、超大请求体 413、WebSocket 401/101 双向数据、polyfill 注入幂等、改密码后旧会话失效。

真实 DSH 集成（2026-11-10 实测，临时 profile）：插件随 bundle 加载并打印 `listening on http://127.0.0.1:3099 -> http://127.0.0.1:3098`；未登录 `/` 302、`/api/*` 401；登录后 `GET /` 返回 200（40485 字节，含 polyfill），`/api/*` 已穿过 DSH 的 Host/Origin 栅栏由上游应答，响应中无 `Set-Cookie` 泄漏。

## 目录

```
lib/index.js       插件本体（apply / hashPassword / verifyPassword / injectPolyfill）
cordis.patch.yml   作为 bundle 时的默认配置
test/e2e.mjs       端到端测试
package.json       包元数据（dsh.bundle.patch 指向 cordis.patch.yml）
CHANGELOG.md
LICENSE
```

## License

MIT © 2026 Lornatang
