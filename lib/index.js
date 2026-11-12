// src/index.ts
import http2 from "node:http";
import https2 from "node:https";
import { randomBytes as randomBytes2 } from "node:crypto";
import { readFileSync as readFileSync2 } from "node:fs";

// src/config.ts
import z from "@deepseek-ai/schemastery";
var DEFAULTS = {
  listenHost: "127.0.0.1",
  listenPort: 3090,
  sessionDays: 7,
  title: "DeepSeek Harness",
  password: "",
  passwordHash: "",
  tlsCertFile: "",
  tlsKeyFile: "",
  trustProxy: false,
  maxAttempts: 5,
  lockMinutes: 5
};
var Config = z.object({
  listenHost: z.string().default(DEFAULTS.listenHost),
  listenPort: z.natural().max(65535).default(DEFAULTS.listenPort),
  sessionDays: z.natural().min(1).max(365).default(DEFAULTS.sessionDays),
  title: z.string().default(DEFAULTS.title),
  password: z.string().default(DEFAULTS.password),
  passwordHash: z.string().default(DEFAULTS.passwordHash),
  tlsCertFile: z.string().default(DEFAULTS.tlsCertFile),
  tlsKeyFile: z.string().default(DEFAULTS.tlsKeyFile),
  trustProxy: z.boolean().default(DEFAULTS.trustProxy),
  maxAttempts: z.natural().min(1).max(50).default(DEFAULTS.maxAttempts),
  lockMinutes: z.natural().min(1).max(1440).default(DEFAULTS.lockMinutes)
});

// src/auth.ts
import { createHash, createHmac, randomBytes, scrypt, scryptSync, timingSafeEqual } from "node:crypto";
var COOKIE = "dsh_gate";
var TOKEN_VERSION = "v1";
var MAX_TOKEN_LENGTH = 256;
var MIN_PASSWORD_LENGTH = 12;
var SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keylen: 32 });
var PASSWORD_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
var HASH_RE = /^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{32,64}\$[0-9a-f]{32,128}$/;
var scryptMaxmem = (N, r) => Math.max(64 * 1024 * 1024, 256 * N * r);
function assertStrongPassword(password, source) {
  const length = [...String(password)].length;
  if (length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      "dsh-frontgate: " + source + " must be at least " + MIN_PASSWORD_LENGTH + " characters; got " + length
    );
  }
  return String(password);
}
function hashPassword(password, params = {}) {
  const { N = SCRYPT.N, r = SCRYPT.r, p = SCRYPT.p, keylen = SCRYPT.keylen } = params;
  const salt = randomBytes(16);
  const key = scryptSync(String(password), salt, keylen, { N, r, p, maxmem: scryptMaxmem(N, r) });
  return "scrypt$" + N + "$" + r + "$" + p + "$" + salt.toString("hex") + "$" + key.toString("hex");
}
function scryptAsync(password, salt, keylen, params) {
  return new Promise((resolve) => {
    scrypt(
      password,
      salt,
      keylen,
      { ...params, maxmem: scryptMaxmem(params.N, params.r) },
      (err, key) => resolve(err ? void 0 : key)
    );
  });
}
function parseStored(stored) {
  if (typeof stored !== "string") return void 0;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return void 0;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(N) || N < 1024 || N > 1048576 || (N & N - 1) !== 0) return void 0;
  if (!Number.isInteger(r) || r < 1 || r > 32) return void 0;
  if (!Number.isInteger(p) || p < 1 || p > 4) return void 0;
  let salt;
  let want;
  try {
    salt = Buffer.from(parts[4], "hex");
    want = Buffer.from(parts[5], "hex");
  } catch {
    return void 0;
  }
  if (salt.length < 8 || salt.length > 32 || want.length < 16 || want.length > 64) return void 0;
  return { N, r, p, salt, want };
}
async function verifyPassword(password, stored) {
  const parsed = parseStored(stored);
  if (!parsed) return false;
  const { N, r, p, salt, want } = parsed;
  const got = await scryptAsync(String(password), salt, want.length, { N, r, p });
  return got !== void 0 && got.length === want.length && timingSafeEqual(got, want);
}
function verifyPasswordSync(password, stored) {
  const parsed = parseStored(stored);
  if (!parsed) return false;
  const { N, r, p, salt, want } = parsed;
  try {
    const got = scryptSync(String(password), salt, want.length, { N, r, p, maxmem: scryptMaxmem(N, r) });
    return got.length === want.length && timingSafeEqual(got, want);
  } catch {
    return false;
  }
}
function randomPassword() {
  const bytes = randomBytes(16);
  let out = "";
  for (let i = 0; i < 16; i++) out += PASSWORD_ALPHABET[bytes[i] & 31];
  return out.slice(0, 4) + "-" + out.slice(4, 8) + "-" + out.slice(8, 12) + "-" + out.slice(12, 16);
}
var passwordVersion = (passwordHash) => createHash("sha256").update(passwordHash).digest("base64url").slice(0, 12);
function signToken(secret, pv, ttlSeconds) {
  const now = Math.floor(Date.now() / 1e3);
  const body = TOKEN_VERSION + "." + now + "." + (now + ttlSeconds) + "." + randomBytes(16).toString("base64url") + "." + pv;
  return body + "." + createHmac("sha256", secret).update(body).digest("base64url");
}
function verifyToken(secret, pv, token) {
  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) return false;
  const parts = token.split(".");
  if (parts.length !== 6) return false;
  const [version, iat, exp, nonce, tokenPv, mac] = parts;
  if (version !== TOKEN_VERSION || tokenPv !== pv) return false;
  const now = Math.floor(Date.now() / 1e3);
  const issued = Number(iat);
  const expires = Number(exp);
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) return false;
  if (expires <= now || issued > now + 300) return false;
  const body = version + "." + iat + "." + exp + "." + nonce + "." + tokenPv;
  const want = createHmac("sha256", secret).update(body).digest();
  let got;
  try {
    got = Buffer.from(mac, "base64url");
  } catch {
    return false;
  }
  return got.length === want.length && timingSafeEqual(got, want);
}
function sessionCookie(value, seconds, useTls) {
  const attrs = [COOKIE + "=" + value, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=" + seconds];
  if (useTls) attrs.push("Secure");
  return attrs.join("; ");
}
var clearCookie = () => [COOKIE + "=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"].join("; ");

// src/context.ts
function resolveLogger(ctx) {
  void ctx;
  const write = (message) => {
    process.stderr.write("[dsh-frontgate] " + message + "\n");
  };
  return { info: write, warn: write };
}

// src/http.ts
var MAX_FORM = 4 * 1024;
var FORM_TIMEOUT = 8 * 1e3;
var intOr = (value, fallback, min, max) => {
  const n = Number.parseInt(String(value), 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
};
function cookieValue(header, name2) {
  if (typeof header !== "string") return "";
  for (const part of header.split(";")) {
    const at = part.indexOf("=");
    if (at !== -1 && part.slice(0, at).trim() === name2) return part.slice(at + 1).trim();
  }
  return "";
}
function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded) return (forwarded.split(",")[0] ?? "").trim().slice(0, 64);
  }
  return String(req.socket.remoteAddress || "").replace(/^::ffff:/, "") || "unknown";
}
function hostnameOf(value) {
  const host = String(value || "").trim().toLowerCase();
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end === -1 ? host : host.slice(0, end + 1);
  }
  return host.split(":")[0] ?? host;
}
function explicitPort(authority) {
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end === -1) return "";
    const rest = authority.slice(end + 1);
    return rest.startsWith(":") ? rest.slice(1) : "";
  }
  const at = authority.lastIndexOf(":");
  return at === -1 ? "" : authority.slice(at + 1);
}
function originMatchesHost(req) {
  const origin = req.headers.origin;
  if (origin === void 0) return true;
  try {
    const url = new URL(origin);
    const host = String(req.headers.host || "").trim().toLowerCase();
    if (url.hostname.toLowerCase() !== hostnameOf(host)) return false;
    const port = url.port || (url.protocol === "https:" ? "443" : "80");
    const declared = explicitPort(host);
    return declared === "" || declared === port;
  } catch {
    return false;
  }
}
function sameOrigin(req) {
  const site = req.headers["sec-fetch-site"];
  if (site !== void 0 && site !== "same-origin" && site !== "none") return false;
  return originMatchesHost(req);
}
function safeNext(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  if (value.includes("\\") || /[\u0000-\u001f\u007f]/.test(value)) return "/";
  return value;
}
var ENTITIES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
var escapeHtml = (text2) => String(text2).replace(/[&<>"']/g, (ch) => ENTITIES[ch] ?? ch);
var CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
var GATE_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": CSP,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY"
};
var LOGIN_REFERRER_POLICY = "same-origin";
function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}
var html = (res, status, body) => send(res, status, { ...GATE_HEADERS, "referrer-policy": LOGIN_REFERRER_POLICY, "content-type": "text/html; charset=utf-8" }, body);
var json = (res, status, payload) => send(res, status, { ...GATE_HEADERS, "content-type": "application/json; charset=utf-8" }, JSON.stringify(payload));
var text = (res, status, body, extra = {}) => send(res, status, { ...GATE_HEADERS, "content-type": "text/plain; charset=utf-8", ...extra }, body);
var redirect = (res, location, status = 302) => send(res, status, { ...GATE_HEADERS, location }, "");
function readForm(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks = [];
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const timer = setTimeout(() => {
      fail(new Error("timeout"));
      req.destroy();
    }, FORM_TIMEOUT);
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_FORM) {
        fail(new Error("too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(resolve, Buffer.concat(chunks).toString("utf8")));
    req.on("error", (err) => fail(err));
    req.on("close", () => {
      if (!req.complete) fail(new Error("aborted"));
    });
  });
}
var isLoopbackHost = (host) => host === "localhost" || host === "::1" || /^127\./.test(host);
var connectHost = (hostname) => hostname.replace(/^\[/, "").replace(/\]$/, "");

// src/polyfill.ts
var POLYFILL = '<script data-dsh-frontgate>(function(){var c=globalThis.crypto;if(!c||typeof c.randomUUID==="function")return;c.randomUUID=function(){var b=c.getRandomValues(new Uint8Array(16));b[6]=b[6]&15|64;b[8]=b[8]&63|128;var s="";for(var i=0;i<16;i++)s+=(b[i]+256).toString(16).slice(1);return s.slice(0,8)+"-"+s.slice(8,12)+"-"+s.slice(12,16)+"-"+s.slice(16,20)+"-"+s.slice(20)}})();</script>';
function injectPolyfill(htmlText) {
  if (typeof htmlText !== "string" || htmlText.includes("data-dsh-frontgate")) return htmlText;
  const at = htmlText.indexOf("</head>");
  return at === -1 ? htmlText : htmlText.slice(0, at) + POLYFILL + htmlText.slice(at);
}

// src/proxy.ts
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
var HARNESS_COOKIE_TTL = 25 * 60 * 1e3;
var REQUEST_DROP = /* @__PURE__ */ new Set([
  "host",
  "origin",
  "cookie",
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
  "te",
  "trailer",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host"
]);
var RESPONSE_DROP = /* @__PURE__ */ new Set([
  "set-cookie",
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
  "trailer"
]);
function sendUpstreamError(res) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  text(res, 502, "dsh-frontgate: upstream unreachable\n");
}
function createProxy(options) {
  const { targetOrigin, publicProto, trustProxy, authenticatedUrl, log } = options;
  const target = new URL(targetOrigin);
  const secureUpstream = target.protocol === "https:";
  const transport = secureUpstream ? https : http;
  const AgentClass = secureUpstream ? https.Agent : http.Agent;
  const upstreamAgent = new AgentClass({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 1e3 });
  function exchangeHarnessCookie() {
    const url = new URL(authenticatedUrl(targetOrigin + "/"));
    return new Promise((resolve, reject) => {
      const req = transport.request({
        host: connectHost(url.hostname),
        port: Number(url.port) || (secureUpstream ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        headers: { host: target.host, accept: "text/html" },
        ...secureUpstream ? { rejectUnauthorized: false } : {}
      }, (res) => {
        res.resume();
        const lines = res.headers["set-cookie"] || [];
        const cookie = lines.map((line) => line.split(";")[0]).filter(Boolean).join("; ");
        if (!cookie) reject(new Error("launch-token exchange returned " + res.statusCode + " without set-cookie"));
        else resolve(cookie);
      });
      req.on("error", reject);
      req.end();
    });
  }
  let harnessCache = { value: "", at: 0 };
  let harnessInflight = null;
  function harnessCookie() {
    if (harnessCache.value && Date.now() - harnessCache.at < HARNESS_COOKIE_TTL) return Promise.resolve(harnessCache.value);
    if (harnessInflight) return harnessInflight;
    harnessInflight = (async () => {
      try {
        const cookie = await exchangeHarnessCookie();
        harnessCache = { value: cookie, at: Date.now() };
        return cookie;
      } finally {
        harnessInflight = null;
      }
    })();
    return harnessInflight;
  }
  function upstreamHeaders(req, cookie) {
    const out = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (!REQUEST_DROP.has(key)) out[key] = value;
    }
    out.host = target.host;
    if (req.headers.origin !== void 0) out.origin = target.origin;
    if (cookie) out.cookie = cookie;
    out["x-forwarded-for"] = clientIp(req, trustProxy);
    out["x-forwarded-proto"] = publicProto;
    out["x-forwarded-host"] = String(req.headers.host || "");
    return out;
  }
  function rewriteLocation(value) {
    if (!value.startsWith(targetOrigin)) return value;
    const rest = value.slice(targetOrigin.length);
    if (rest === "") return "/";
    if (rest.startsWith("//") || rest.startsWith("/\\")) return "/";
    return rest.startsWith("/") ? rest : value;
  }
  function forward(req, res, cookie) {
    const started = Date.now();
    const proxyReq = transport.request({
      agent: upstreamAgent,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, cookie),
      ...secureUpstream ? { rejectUnauthorized: false } : {}
    }, (proxyRes) => {
      const headers = {};
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (!RESPONSE_DROP.has(key)) headers[key] = value;
      }
      const location = proxyRes.headers["location"];
      if (location !== void 0) headers.location = rewriteLocation(location);
      const status = proxyRes.statusCode || 502;
      res.writeHead(status, headers);
      proxyRes.pipe(res);
      proxyRes.on("error", () => res.destroy());
      const elapsed = Date.now() - started;
      if (status >= 400 || elapsed > 1e3) {
        log.info(req.method + " " + String(req.url || "/").split("?")[0] + " " + status + " " + elapsed + "ms");
      }
    });
    proxyReq.on("error", (err) => {
      log.warn("upstream error: " + err.message);
      sendUpstreamError(res);
    });
    res.on("close", () => proxyReq.destroy());
    req.pipe(proxyReq);
  }
  function forwardUpgrade(req, socket, head, cookie) {
    const port = Number(target.port) || (secureUpstream ? 443 : 80);
    const host = connectHost(target.hostname);
    const lines = [req.method + " " + (req.url || "/") + " HTTP/1.1"];
    const raw = req.rawHeaders || [];
    for (let i = 0; i + 1 < raw.length; i += 2) {
      const lower = raw[i].toLowerCase();
      if (lower === "host" || lower === "origin" || lower === "cookie" || lower === "proxy-connection") continue;
      if (lower === "x-forwarded-for" || lower === "x-forwarded-proto" || lower === "x-forwarded-host") continue;
      if (lower === "transfer-encoding") continue;
      lines.push(raw[i] + ": " + raw[i + 1]);
    }
    lines.push("Host: " + target.host);
    if (req.headers.origin !== void 0) lines.push("Origin: " + target.origin);
    if (cookie) lines.push("Cookie: " + cookie);
    lines.push("X-Forwarded-For: " + clientIp(req, trustProxy));
    lines.push("X-Forwarded-Proto: " + publicProto);
    lines.push("X-Forwarded-Host: " + String(req.headers.host || ""));
    lines.push("", "");
    const payload = lines.join("\r\n");
    const backend = secureUpstream ? tls.connect({ host, port, rejectUnauthorized: false }) : net.connect(port, host);
    let closed = false;
    const teardown = (message) => {
      if (closed) return;
      closed = true;
      if (message) log.warn("websocket " + String(req.url || "/").split("?")[0] + ": " + message);
      socket.destroy();
      backend.destroy();
    };
    const start = () => {
      backend.setTimeout(0);
      backend.write(payload);
      if (head && head.length) backend.write(head);
      backend.pipe(socket);
      socket.pipe(backend);
    };
    backend.setTimeout(1e4, () => teardown("connect timeout"));
    if (secureUpstream) backend.once("secureConnect", start);
    else backend.once("connect", start);
    backend.on("error", (err) => teardown(err.message));
    socket.on("error", (err) => teardown(err.message));
    socket.on("end", () => teardown());
    backend.on("end", () => teardown());
    socket.on("close", () => teardown());
    backend.on("close", () => teardown());
  }
  return {
    harnessCookie,
    forward,
    forwardUpgrade,
    destroy: () => upstreamAgent.destroy()
  };
}

// src/page.ts
function loginPage(title, next, error) {
  const action = "/__gate/login?next=" + encodeURIComponent(next);
  const message = error ? '<p class="err">' + escapeHtml(error) + "</p>" : "";
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="referrer" content="' + LOGIN_REFERRER_POLICY + '">',
    "<title>" + escapeHtml(title) + " - Sign in</title>",
    "<style>",
    "  :root{color-scheme:dark}",
    '  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e1014;color:#e6e8ee;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}',
    "  form{width:min(360px,calc(100vw - 48px));padding:28px 26px 24px;border:1px solid #262b36;border-radius:14px;background:#151922;box-shadow:0 20px 60px rgba(0,0,0,.45)}",
    "  h1{margin:0 0 6px;font-size:16px;font-weight:600}",
    "  p{margin:0 0 18px;color:#8b93a5;font-size:12.5px}",
    "  .err{padding:9px 11px;margin:0 0 14px;border-radius:8px;background:rgba(240,92,92,.12);border:1px solid rgba(240,92,92,.3);color:#ff9b9b}",
    "  input{width:100%;box-sizing:border-box;padding:10px 12px;margin:0 0 14px;border-radius:9px;border:1px solid #2c3341;background:#0f131a;color:inherit;font:inherit;outline:none}",
    "  input:focus{border-color:#3f6df0;box-shadow:0 0 0 3px rgba(63,109,240,.18)}",
    "  button{width:100%;padding:10px 12px;border:0;border-radius:9px;background:#3f6df0;color:#fff;font:inherit;font-weight:600;cursor:pointer}",
    "  button:hover{background:#4b78ff}",
    "</style></head>",
    "<body>",
    '<form method="post" action="' + action + '">',
    "  <h1>" + escapeHtml(title) + "</h1>",
    "  <p>This instance is protected by a password gate. Enter the access password.</p>",
    "  " + message,
    '  <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">',
    '  <button type="submit">Sign in</button>',
    "</form>",
    "</body></html>"
  ].join("\n");
}

// src/gate.ts
var MAX_TRACKED_CLIENTS = 1024;
var CHECK_CONCURRENCY = 2;
function createHandler(options) {
  const { runtime, harnessCookie, forward, log } = options;
  const { title, passwordHash, secret, pv, sessionSeconds, maxAttempts, lockMs, trustProxy, useTls } = runtime;
  const failures = /* @__PURE__ */ new Map();
  let checksInFlight = 0;
  function lockRemaining(ip) {
    const entry = failures.get(ip);
    if (!entry || !entry.until) return 0;
    if (entry.until > Date.now()) return entry.until - Date.now();
    failures.delete(ip);
    return 0;
  }
  function recordFailure(ip) {
    let entry = failures.get(ip);
    if (!entry) {
      if (failures.size >= MAX_TRACKED_CLIENTS) {
        const oldest = failures.keys().next().value;
        if (oldest !== void 0) failures.delete(oldest);
      }
      entry = { count: 0, until: 0 };
      failures.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count >= maxAttempts) {
      entry.count = 0;
      entry.until = Date.now() + lockMs;
    }
  }
  function sessionOf(req) {
    const token = cookieValue(req.headers.cookie, COOKIE);
    return Boolean(token) && verifyToken(secret, pv, token);
  }
  async function handleLogin(req, res, search) {
    const next = safeNext(new URLSearchParams(search).get("next") || "/");
    if (req.method === "POST") {
      if (!sameOrigin(req)) return html(res, 403, loginPage(title, next, "Origin check failed."));
      const declared = Number(req.headers["content-length"] || 0);
      if (declared > MAX_FORM) return text(res, 413, "request body too large\n");
      const ip = clientIp(req, trustProxy);
      let form;
      try {
        form = await readForm(req);
      } catch (err) {
        if (err.message === "too large") return text(res, 413, "request body too large\n");
        return text(res, 400, "bad request\n");
      }
      if (checksInFlight >= CHECK_CONCURRENCY) return text(res, 429, "busy, retry shortly\n", { "retry-after": "1" });
      checksInFlight += 1;
      let ok = false;
      try {
        ok = await verifyPassword(new URLSearchParams(form).get("password") || "", passwordHash);
      } finally {
        checksInFlight -= 1;
      }
      if (!ok) {
        const locked = lockRemaining(ip) > 0;
        recordFailure(ip);
        log.info("login failed from " + ip);
        if (locked) {
          const wait = lockRemaining(ip);
          return text(res, 429, "too many attempts\n", { "retry-after": String(Math.ceil(wait / 1e3)) });
        }
        return html(res, 401, loginPage(title, next, "Wrong password."));
      }
      failures.delete(ip);
      log.info("login from " + ip);
      res.setHeader("set-cookie", sessionCookie(signToken(secret, pv, sessionSeconds), sessionSeconds, useTls));
      return redirect(res, next, 303);
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      return text(res, 405, "method not allowed\n", { allow: "GET, POST" });
    }
    if (sessionOf(req)) return redirect(res, "/");
    return html(res, 200, loginPage(title, next, ""));
  }
  return async function handle(req, res) {
    const raw = req.url || "/";
    if (!raw.startsWith("/")) return text(res, 400, "bad request\n");
    const queryAt = raw.indexOf("?");
    const path = queryAt === -1 ? raw : raw.slice(0, queryAt);
    const search = queryAt === -1 ? "" : raw.slice(queryAt);
    if (path === "/__gate/health") return json(res, 200, { ok: true, service: "dsh-frontgate" });
    if (path === "/__gate/login") return handleLogin(req, res, search);
    if (path === "/__gate/logout") {
      res.setHeader("set-cookie", clearCookie());
      return redirect(res, "/__gate/login");
    }
    if (path.startsWith("/__gate/")) return text(res, 404, "not found\n");
    if (!sessionOf(req)) {
      if (path === "/api" || path.startsWith("/api/")) {
        return json(res, 401, { error: "unauthorized", login: "/__gate/login" });
      }
      return redirect(res, "/__gate/login?next=" + encodeURIComponent(raw));
    }
    if (!originMatchesHost(req)) {
      log.warn("cross-origin request blocked: " + String(req.method) + " " + path);
      if (path === "/api" || path.startsWith("/api/")) return json(res, 403, { error: "forbidden" });
      return text(res, 403, "forbidden\n");
    }
    let cookie;
    try {
      cookie = await harnessCookie();
    } catch (err) {
      log.warn("harness cookie exchange failed: " + err.message);
      return json(res, 503, { error: "harness_unavailable" });
    }
    forward(req, res, cookie);
  };
}

// src/state.ts
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
function readState(path) {
  try {
    const value = JSON.parse(readFileSync(path, "utf8"));
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}
function tightenState(path) {
  try {
    chmodSync(path, 384);
  } catch {
  }
}
function writeState(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 384 });
  tightenState(path);
}
function statePathFor(patchPath) {
  const file = patchPath ?? join(process.env.DSH_HOME || join(homedir(), ".dsh"), "profiles", "web", "cordis.patch.yml");
  return join(dirname(file), "data", "dsh-frontgate.json");
}
function hashFor(plain, state) {
  return state.passwordHash && verifyPasswordSync(plain, state.passwordHash) ? state.passwordHash : hashPassword(plain);
}

// src/index.ts
var name = "dsh-frontgate";
var inject = ["webServer", "connection"];
function apply(ctx, config = {}) {
  const logger = resolveLogger(ctx);
  const cfg = { ...DEFAULTS, ...config };
  const listenHost = String(cfg.listenHost);
  const listenPort = intOr(cfg.listenPort, DEFAULTS.listenPort, 0, 65535);
  const sessionSeconds = intOr(cfg.sessionDays, DEFAULTS.sessionDays, 1, 365) * 86400;
  const maxAttempts = intOr(cfg.maxAttempts, DEFAULTS.maxAttempts, 1, 50);
  const lockMs = intOr(cfg.lockMinutes, DEFAULTS.lockMinutes, 1, 1440) * 6e4;
  const statePath = statePathFor(ctx.profileContext?.patchPath);
  const state = readState(statePath);
  tightenState(statePath);
  const configuredPassword = typeof cfg.password === "string" ? cfg.password : "";
  const envPassword = typeof process.env.DSH_FRONTGATE_PASSWORD === "string" ? process.env.DSH_FRONTGATE_PASSWORD : "";
  const envPasswordHash = typeof process.env.DSH_FRONTGATE_PASSWORD_HASH === "string" && HASH_RE.test(process.env.DSH_FRONTGATE_PASSWORD_HASH) ? process.env.DSH_FRONTGATE_PASSWORD_HASH : "";
  let passwordHash = "";
  let generatedPassword = "";
  if (typeof cfg.passwordHash === "string" && cfg.passwordHash) passwordHash = cfg.passwordHash;
  else if (configuredPassword) passwordHash = hashFor(assertStrongPassword(configuredPassword, 'the "password" option'), state);
  else if (envPasswordHash) passwordHash = envPasswordHash;
  else if (envPassword) passwordHash = hashFor(assertStrongPassword(envPassword, "DSH_FRONTGATE_PASSWORD"), state);
  else if (typeof state.passwordHash === "string" && HASH_RE.test(state.passwordHash)) passwordHash = state.passwordHash;
  if (!passwordHash) {
    generatedPassword = randomPassword();
    passwordHash = hashPassword(generatedPassword);
  }
  const secret = typeof state.secret === "string" && state.secret.length >= 64 ? state.secret : randomBytes2(32).toString("hex");
  const pv = passwordVersion(passwordHash);
  if (state.passwordHash !== passwordHash || state.secret !== secret) {
    writeState(statePath, { passwordHash, secret, createdAt: state.createdAt || (/* @__PURE__ */ new Date()).toISOString() });
  }
  if (generatedPassword) {
    logger.info("no password configured - generated a random one and saved its hash to " + statePath);
    logger.info("PASSWORD: " + generatedPassword);
    logger.info("save this password now; it will not be shown again");
  }
  const targetOrigin = ctx.webServer.getOrigin();
  const target = new URL(targetOrigin);
  if (listenPort !== 0 && listenPort === Number(target.port)) {
    throw new Error("dsh-frontgate: listenPort " + listenPort + " collides with the harness listener " + targetOrigin);
  }
  const useTls = Boolean(cfg.tlsCertFile || cfg.tlsKeyFile);
  if (useTls && !(cfg.tlsCertFile && cfg.tlsKeyFile)) {
    throw new Error("dsh-frontgate: tlsCertFile and tlsKeyFile must be set together");
  }
  const publicProto = useTls ? "https" : "http";
  const tlsOptions = useTls ? { cert: readFileSync2(String(cfg.tlsCertFile)), key: readFileSync2(String(cfg.tlsKeyFile)) } : void 0;
  const proxy = createProxy({
    targetOrigin,
    publicProto,
    trustProxy: Boolean(cfg.trustProxy),
    authenticatedUrl: (baseUrl) => ctx.connection.authenticatedUrl(baseUrl),
    log: logger
  });
  const handler = createHandler({
    runtime: {
      title: cfg.title,
      passwordHash,
      secret,
      pv,
      sessionSeconds,
      maxAttempts,
      lockMs,
      trustProxy: Boolean(cfg.trustProxy),
      useTls
    },
    harnessCookie: proxy.harnessCookie,
    forward: proxy.forward,
    log: logger
  });
  const requestListener = (req, res) => {
    if (useTls) res.setHeader("strict-transport-security", "max-age=31536000");
    handler(req, res).catch((err) => {
      logger.warn("handler error: " + (err instanceof Error && err.stack ? err.stack : String(err)));
      if (!res.headersSent) text(res, 500, "dsh-frontgate: internal error\n");
      else res.destroy();
    });
  };
  const serverOptions = { connectionsCheckingInterval: 5e3, headersTimeout: 1e4, requestTimeout: 3e4 };
  const server = tlsOptions ? https2.createServer({ ...tlsOptions, ...serverOptions }, requestListener) : http2.createServer(serverOptions, requestListener);
  server.maxConnections = 1024;
  server.on("upgrade", (req, socket, head) => {
    socket.on("error", () => socket.destroy());
    try {
      if (!sessionOf(req)) {
        socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        return;
      }
      if (!originMatchesHost(req)) {
        logger.warn("websocket blocked: cross-origin upgrade from " + String(req.headers.origin || ""));
        socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
      }
      proxy.harnessCookie().then((cookie) => proxy.forwardUpgrade(req, socket, head, cookie)).catch((err) => {
        logger.warn("websocket blocked: " + err.message);
        socket.end("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
      });
    } catch (err) {
      logger.warn("upgrade error: " + err.message);
      socket.destroy();
    }
  });
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    socket.destroy();
  });
  server.on("error", (err) => logger.warn("listener error: " + err.message));
  function sessionOf(req) {
    const token = cookieValue(req.headers.cookie, COOKIE);
    return Boolean(token) && verifyToken(secret, pv, token);
  }
  const shutdown = () => {
    proxy.destroy();
    const withConnections = server;
    if (typeof withConnections.closeAllConnections === "function") withConnections.closeAllConnections();
    server.close();
  };
  ctx.effect(() => ctx.webServer.tapIndex(injectPolyfill), "dsh-frontgate: secure-context polyfill");
  let ready;
  ctx.effect(() => {
    ready = new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(listenPort, listenHost, () => {
        server.removeListener("error", reject);
        const address = server.address();
        const port = address && typeof address === "object" ? address.port : listenPort;
        logger.info("listening on " + publicProto + "://" + listenHost + ":" + port + " -> " + targetOrigin);
        if (!isLoopbackHost(listenHost) && !useTls) {
          logger.warn("plaintext HTTP is exposed on " + listenHost + "; terminate TLS or use a VPN");
        }
        const bound = ctx.webServer.config?.host;
        if (typeof bound === "string" && !isLoopbackHost(bound)) {
          logger.warn("harness is bound to " + bound + ", so it is reachable without this gate");
        }
        resolve();
      });
    });
    ready.catch((err) => logger.warn("listen failed on " + listenHost + ":" + listenPort + ": " + err.message));
    return shutdown;
  }, "dsh-frontgate: listener");
  return {
    ready: () => ready ?? Promise.resolve(),
    address: () => server.address(),
    stop: shutdown
  };
}
export {
  Config,
  apply,
  hashPassword,
  inject,
  injectPolyfill,
  name,
  verifyPassword
};
