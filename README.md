# dsh-frontgate

给 DeepSeek Harness Web UI 加一道**密码门**的 DSH 插件：单文件、零运行时依赖、自带反向代理与 WebSocket 直通。

远程访问时让 `dsh` 继续绑在 `127.0.0.1`，只暴露本插件即可：未登录进不了 UI 和 `/api`；代理会自动处理 Host/Origin 与启动 token，无需改 DSH 启动参数。

## 特性

- 单密码登录：未登录的页面请求跳登录页，`/api/*` 直接返回 401。
- 反向代理到本机 `dsh`，启动 token 在服务端兑换并缓存，浏览器只持有网关自己的会话 Cookie。
- 无状态会话：改密码（或删除状态文件）即全部下线，无会话表、无后台定时器。
- 异步 scrypt 校验，每 IP 失败锁定，并发数 / 请求体 / 读取超时都有上限。
- 默认只监听回环地址；可选原生 TLS；为明文 HTTP 页面补上 `crypto.randomUUID`。

## 安装

需要 Node `>=22.19`、DSH `>=0.2.2-rc.1`。

```bash
# 从 GitHub 安装（锁定版本 tag）
dsh plugin --profile <name> add github:Lornatang/dsh-frontgate#v1.0.0
```

离线安装：在能联网的机器上取包（`npm pack`，或下载仓库里的 `dsh-frontgate-1.0.0.tgz`），拷到目标机器后：

```bash
dsh plugin --profile <name> add ./dsh-frontgate-1.0.0.tgz
```

装完**重启该 profile** 生效。

## 快速开始

- 默认监听 `127.0.0.1:3090`，转发到本机 `dsh`。
- 首次启动未配置密码时，日志会打印 `PASSWORD: xxxx-xxxx-xxxx-xxxx`；登录后在 profile 的 `cordis.patch.yml` 里换成固定密码。
- 浏览器打开 `http://127.0.0.1:3090`。

## 配置

在 profile 的 `cordis.patch.yml`（如 `/root/.dsh/profiles/web/cordis.patch.yml`）追加：

```yaml
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
    password: '换成你的密码'
```

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `listenHost` | `'127.0.0.1'` | 监听地址；远程访问改 `'0.0.0.0'` |
| `listenPort` | `3090` | 监听端口；不得与 DSH 自身端口相同 |
| `sessionDays` | `7` | 会话有效期（1–365 天） |
| `title` | `'DeepSeek Harness'` | 登录页标题 |
| `password` | `''` | 明文密码，启动时哈希，**不会**写盘 |
| `passwordHash` | `''` | `scrypt$…` 哈希，优先级高于 `password` |
| `maxAttempts` / `lockMinutes` | `5` / `5` | 每 IP 失败几次后锁定、锁定多少分钟 |
| `tlsCertFile` / `tlsKeyFile` | `''` | 同时提供才启用 HTTPS（PEM） |
| `trustProxy` | `false` | 是否信任反代传来的 `X-Forwarded-*` |

状态文件 `<profile>/data/dsh-frontgate.json`（权限 0600）保存密码哈希与会话签名密钥，删除它等于作废所有已发会话。

## 远程 / Docker 部署

- 容器内把 `listenHost` 改为 `'0.0.0.0'`、`listenPort` 改成映射进去的端口；宿主只映射这一个端口，不要直接映射 `dsh` 的端口。
- 明文 HTTP 只适合内网 / VPN。要上公网请启用 `tlsCertFile`/`tlsKeyFile`，或前置 Caddy/Nginx 终止 TLS 并设置 `trustProxy: true`。
- 若 `dsh` 绑定在非回环地址，日志会警告可不经网关直连；请让它留在 `127.0.0.1`。

## 安全说明

- 会话 Cookie 用由密码哈希派生的密钥签名；改密码或删状态文件即全体下线。
- 所有秘密比较走常量时间，密码只保存 scrypt 哈希。
- 登录页无脚本，带 CSP、`no-store`、`no-referrer`、`X-Frame-Options`。
- 代理目标固定为本机 DSH，不解析用户输入；上游 `Set-Cookie` 一律剥离。

已知取舍：单密码、无多用户、不能单独踢某个会话；没有管理后台，改配置 = 改 patch 后重启。

## 开发

```bash
npm test    # node --test test/e2e.mjs，18 项全过
npm pack    # 打包（prepack 会先跑测试）
```

## License

MIT © 2026 Lornatang
