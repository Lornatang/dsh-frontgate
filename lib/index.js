// src/index.ts
import http2 from "node:http";
import https2 from "node:https";
import { randomBytes as randomBytes3 } from "node:crypto";
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
  publicOrigin: "",
  trustProxy: false,
  maxAttempts: 5,
  lockMinutes: 5,
  exchangeTimeoutMs: 5e3,
  maxConnectionsPerPeer: 64,
  maxPendingLoginsPerIp: 4,
  upstreamHeaderTimeoutMs: 6e4,
  upstreamIdleTimeoutMs: 3e5,
  upstreamCaFile: "",
  upstreamServerName: ""
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
  publicOrigin: z.string().default(DEFAULTS.publicOrigin),
  trustProxy: z.boolean().default(DEFAULTS.trustProxy),
  maxAttempts: z.natural().min(1).max(50).default(DEFAULTS.maxAttempts),
  lockMinutes: z.natural().min(1).max(1440).default(DEFAULTS.lockMinutes),
  exchangeTimeoutMs: z.natural().min(100).max(6e4).default(DEFAULTS.exchangeTimeoutMs),
  maxConnectionsPerPeer: z.natural().max(1024).default(DEFAULTS.maxConnectionsPerPeer),
  maxPendingLoginsPerIp: z.natural().min(1).max(128).default(DEFAULTS.maxPendingLoginsPerIp),
  upstreamHeaderTimeoutMs: z.natural().max(36e5).default(DEFAULTS.upstreamHeaderTimeoutMs),
  upstreamIdleTimeoutMs: z.natural().max(36e5).default(DEFAULTS.upstreamIdleTimeoutMs),
  upstreamCaFile: z.string().default(DEFAULTS.upstreamCaFile),
  upstreamServerName: z.string().default(DEFAULTS.upstreamServerName)
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
function validPasswordHash(value) {
  return typeof value === "string" && HASH_RE.test(value) && parseStored(value) !== void 0;
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
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce) || !/^[A-Za-z0-9_-]{43}$/.test(mac)) return false;
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
  return got.length === want.length && got.toString("base64url") === mac && timingSafeEqual(got, want);
}
function sessionCookie(value, seconds, useTls) {
  const attrs = [COOKIE + "=" + value, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=" + seconds];
  if (useTls) attrs.push("Secure");
  return attrs.join("; ");
}
var clearCookie = (secure) => sessionCookie("", 0, secure);

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
function normalizePublicOrigin(value) {
  if (!value) return "";
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("invalid origin");
    return url.origin;
  } catch {
    throw new Error("dsh-frontgate: publicOrigin must be an HTTP(S) origin without a path, query, or credentials");
  }
}
function requestOrigin(req, publicOrigin, useTls) {
  const host = req.headers.host;
  if (typeof host !== "string" || !host || /[\s/@?#\\]/.test(host)) return void 0;
  try {
    const protocol = publicOrigin ? new URL(publicOrigin).protocol : useTls ? "https:" : "http:";
    const url = new URL(protocol + "//" + host);
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return void 0;
    if (publicOrigin && url.origin !== publicOrigin) return void 0;
    return url.origin;
  } catch {
    return void 0;
  }
}
var hostMatchesPublicOrigin = (req, publicOrigin, useTls) => requestOrigin(req, publicOrigin, useTls) !== void 0;
function originMatchesHost(req, publicOrigin, useTls) {
  const expected = requestOrigin(req, publicOrigin, useTls);
  if (!expected) return false;
  const origin = req.headers.origin;
  if (origin === void 0) return true;
  try {
    const url = new URL(origin);
    return origin === url.origin && url.origin === expected;
  } catch {
    return false;
  }
}
function sameOrigin(req, publicOrigin, useTls) {
  const site = req.headers["sec-fetch-site"];
  if (site !== void 0 && site !== "same-origin" && site !== "none") return false;
  return originMatchesHost(req, publicOrigin, useTls);
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
      req.resume();
    }, FORM_TIMEOUT);
    req.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_FORM) {
        fail(new Error("too large"));
        req.resume();
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
  const {
    targetOrigin,
    publicProto,
    trustProxy,
    exchangeTimeoutMs,
    upstreamHeaderTimeoutMs,
    upstreamIdleTimeoutMs,
    upstreamCa,
    upstreamServerName,
    authenticatedUrl,
    log
  } = options;
  const target = new URL(targetOrigin);
  const secureUpstream = target.protocol === "https:";
  const transport = secureUpstream ? https : http;
  const AgentClass = secureUpstream ? https.Agent : http.Agent;
  const upstreamAgent = new AgentClass({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 1e3 });
  const tlsOptions = secureUpstream ? { ...upstreamCa ? { ca: upstreamCa } : {}, ...upstreamServerName ? { servername: upstreamServerName } : {} } : {};
  const exchanges = /* @__PURE__ */ new Set();
  function exchangeHarnessCookie() {
    const url = new URL(authenticatedUrl(targetOrigin + "/"));
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, cookie) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        exchanges.delete(req);
        if (error) reject(error);
        else resolve(cookie);
      };
      const req = transport.request({
        host: connectHost(url.hostname),
        port: Number(url.port) || (secureUpstream ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        headers: { host: target.host, accept: "text/html" },
        ...tlsOptions
      }, (res) => {
        res.resume();
        const lines = res.headers["set-cookie"] || [];
        const cookie = lines.map((line) => line.split(";")[0]).filter(Boolean).join("; ");
        if (!cookie) finish(new Error("launch-token exchange returned " + res.statusCode + " without set-cookie"));
        else finish(void 0, cookie);
      });
      const timer = setTimeout(() => req.destroy(new Error("launch-token exchange timed out")), exchangeTimeoutMs);
      exchanges.add(req);
      req.on("error", (err) => finish(err));
      req.end();
    });
  }
  let harnessCache = { value: "", at: 0 };
  let harnessInflight = null;
  function invalidateHarnessCookie(cookie) {
    if (harnessCache.value === cookie) harnessCache = { value: "", at: 0 };
  }
  function harnessCookie() {
    if (harnessCache.value && Date.now() - harnessCache.at < HARNESS_COOKIE_TTL) return Promise.resolve(harnessCache.value);
    if (harnessInflight) return harnessInflight;
    harnessInflight = Promise.resolve().then(exchangeHarnessCookie).then((cookie) => {
      harnessCache = { value: cookie, at: Date.now() };
      return cookie;
    }).finally(() => {
      harnessInflight = null;
    });
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
    let headerTimer;
    let idleTimer;
    let timedOut = false;
    const clearTimers = () => {
      if (headerTimer) clearTimeout(headerTimer);
      if (idleTimer) clearTimeout(idleTimer);
      headerTimer = void 0;
      idleTimer = void 0;
    };
    const proxyReq = transport.request({
      agent: upstreamAgent,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, cookie),
      ...tlsOptions
    }, (proxyRes) => {
      if (headerTimer) clearTimeout(headerTimer);
      headerTimer = void 0;
      if (res.destroyed) {
        proxyRes.destroy();
        return;
      }
      const headers = {};
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (!RESPONSE_DROP.has(key)) headers[key] = value;
      }
      const location = proxyRes.headers["location"];
      if (location !== void 0) headers.location = rewriteLocation(location);
      const status = proxyRes.statusCode || 502;
      if (status === 401) invalidateHarnessCookie(cookie);
      res.writeHead(status, headers);
      const armIdle = () => {
        if (idleTimer) clearTimeout(idleTimer);
        if (!upstreamIdleTimeoutMs) return;
        idleTimer = setTimeout(() => {
          if (proxyRes.isPaused() || res.writableNeedDrain) {
            armIdle();
            return;
          }
          timedOut = true;
          proxyRes.destroy(new Error("upstream response idle timeout"));
        }, upstreamIdleTimeoutMs);
      };
      proxyRes.on("data", armIdle);
      proxyRes.once("end", clearTimers);
      res.on("drain", armIdle);
      armIdle();
      proxyRes.pipe(res);
      proxyRes.on("error", () => {
        clearTimers();
        res.destroy();
      });
      const elapsed = Date.now() - started;
      if (status >= 400 || elapsed > 1e3) {
        log.info(req.method + " " + String(req.url || "/").split("?")[0] + " " + status + " " + elapsed + "ms");
      }
    });
    if (upstreamHeaderTimeoutMs) {
      headerTimer = setTimeout(() => {
        timedOut = true;
        proxyReq.destroy(new Error("upstream response headers timeout"));
      }, upstreamHeaderTimeoutMs);
    }
    proxyReq.on("error", (err) => {
      clearTimers();
      if (res.destroyed) return;
      log.warn("upstream error: " + err.message);
      if (timedOut && !res.headersSent) return text(res, 504, "dsh-frontgate: upstream timeout\n");
      sendUpstreamError(res);
    });
    res.on("close", () => {
      clearTimers();
      proxyReq.destroy();
    });
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
    const backend = secureUpstream ? tls.connect({ host, port, ...tlsOptions }) : net.connect(port, host);
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
      let statusLine = "";
      let statusRead = false;
      backend.on("data", (chunk) => {
        if (statusRead) return;
        statusLine += chunk.toString("latin1", 0, Math.max(0, 256 - statusLine.length));
        const end = statusLine.indexOf("\r\n");
        if (end !== -1 || statusLine.length >= 256) {
          statusRead = true;
          if (/^HTTP\/1\.[01] 401(?:\s|$)/.test(statusLine.slice(0, end === -1 ? void 0 : end))) {
            invalidateHarnessCookie(cookie);
          }
        }
      });
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
    destroy: () => {
      for (const request of exchanges) request.destroy(new Error("proxy stopped"));
      upstreamAgent.destroy();
    }
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
  const { runtime, harnessCookie, validSession, revokeSession, forward, log } = options;
  const { title, passwordHash, secret, pv, sessionSeconds, maxAttempts, maxPendingLoginsPerIp, lockMs, trustProxy, useTls, publicOrigin, secureCookie } = runtime;
  const failures = /* @__PURE__ */ new Map();
  const clientsInFlight = /* @__PURE__ */ new Set();
  const pendingForms = /* @__PURE__ */ new Map();
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
    return Boolean(token) && validSession(token);
  }
  async function handleLogin(req, res, search) {
    const next = safeNext(new URLSearchParams(search).get("next") || "/");
    if (req.method === "POST") {
      if (!sameOrigin(req, publicOrigin, useTls)) {
        req.resume();
        res.setHeader("connection", "close");
        return html(res, 403, loginPage(title, next, "Origin check failed."));
      }
      const declared = Number(req.headers["content-length"] || 0);
      if (declared > MAX_FORM) {
        req.resume();
        return text(res, 413, "request body too large\n", { connection: "close" });
      }
      const ip = clientIp(req, trustProxy);
      const wait = lockRemaining(ip);
      if (wait > 0) {
        req.resume();
        return text(res, 429, "too many attempts\n", { "retry-after": String(Math.ceil(wait / 1e3)), connection: "close" });
      }
      const pending = pendingForms.get(ip) ?? 0;
      if (pending >= maxPendingLoginsPerIp) {
        req.resume();
        return text(res, 429, "too many pending logins\n", { "retry-after": "1", connection: "close" });
      }
      pendingForms.set(ip, pending + 1);
      let form;
      try {
        form = await readForm(req);
      } catch (err) {
        if (res.destroyed) return;
        if (err.message === "too large") return text(res, 413, "request body too large\n", { connection: "close" });
        if (err.message === "timeout") return text(res, 408, "request timeout\n", { connection: "close" });
        return text(res, 400, "bad request\n", { connection: "close" });
      } finally {
        const count = pendingForms.get(ip) ?? 1;
        if (count <= 1) pendingForms.delete(ip);
        else pendingForms.set(ip, count - 1);
      }
      const remaining = lockRemaining(ip);
      if (remaining > 0) return text(res, 429, "too many attempts\n", { "retry-after": String(Math.ceil(remaining / 1e3)) });
      if (clientsInFlight.has(ip) || checksInFlight >= CHECK_CONCURRENCY) {
        return text(res, 429, "busy, retry shortly\n", { "retry-after": "1" });
      }
      clientsInFlight.add(ip);
      checksInFlight += 1;
      let ok = false;
      try {
        ok = await verifyPassword(new URLSearchParams(form).get("password") || "", passwordHash);
      } finally {
        checksInFlight -= 1;
        clientsInFlight.delete(ip);
      }
      if (!ok) {
        recordFailure(ip);
        log.info("login failed from " + ip);
        return html(res, 401, loginPage(title, next, "Wrong password."));
      }
      failures.delete(ip);
      log.info("login from " + ip);
      res.setHeader("set-cookie", sessionCookie(signToken(secret, pv, sessionSeconds), sessionSeconds, secureCookie));
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
    if (!hostMatchesPublicOrigin(req, publicOrigin, useTls)) return text(res, 403, "invalid host\n");
    if (path === "/__gate/login") return handleLogin(req, res, search);
    if (path === "/__gate/logout") {
      if (!sameOrigin(req, publicOrigin, useTls)) return text(res, 403, "forbidden\n");
      const token2 = cookieValue(req.headers.cookie, COOKIE);
      if (token2 && validSession(token2)) {
        try {
          revokeSession(token2);
        } catch (err) {
          log.warn("could not revoke session: " + err.message);
          return text(res, 503, "could not sign out; retry later\n");
        }
      }
      res.setHeader("set-cookie", clearCookie(secureCookie));
      return redirect(res, "/__gate/login");
    }
    if (path.startsWith("/__gate/")) return text(res, 404, "not found\n");
    const token = cookieValue(req.headers.cookie, COOKIE);
    const unauthorized = () => {
      if (path === "/api" || path.startsWith("/api/")) {
        return json(res, 401, { error: "unauthorized", login: "/__gate/login" });
      }
      return redirect(res, "/__gate/login?next=" + encodeURIComponent(raw));
    };
    if (!token || !validSession(token)) return unauthorized();
    if (!sameOrigin(req, publicOrigin, useTls)) {
      log.warn("cross-origin request blocked: " + String(req.method) + " " + path);
      if (path === "/api" || path.startsWith("/api/")) return json(res, 403, { error: "forbidden" });
      return text(res, 403, "forbidden\n");
    }
    let cookie;
    try {
      cookie = await harnessCookie();
    } catch (err) {
      if (res.destroyed) return;
      log.warn("harness cookie exchange failed: " + err.message);
      return json(res, 503, { error: "harness_unavailable" });
    }
    if (req.aborted || res.destroyed || !res.writable) return;
    if (!validSession(token)) return unauthorized();
    forward(req, res, cookie);
  };
}

// src/state.ts
import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomBytes as randomBytes2 } from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
var MAX_REVOKED_SESSIONS = 1e4;
function readState(path, mustExist = false) {
  let data;
  try {
    data = readFileSync(path, "utf8");
  } catch (err) {
    if (!mustExist && err.code === "ENOENT") return {};
    throw new Error("dsh-frontgate: cannot read state file " + path, { cause: err });
  }
  try {
    const value = JSON.parse(data);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid state");
    const state = value;
    if (!validPasswordHash(state.passwordHash) || typeof state.secret !== "string" || state.secret.length < 64) {
      throw new Error("invalid credentials");
    }
    if (state.revokedSessions !== void 0 && (!Array.isArray(state.revokedSessions) || state.revokedSessions.length > MAX_REVOKED_SESSIONS || state.revokedSessions.some((entry) => !entry || typeof entry !== "object" || typeof entry.digest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(entry.digest) || !Number.isSafeInteger(entry.expires) || entry.expires <= 0))) {
      throw new Error("invalid revoked sessions");
    }
    return state;
  } catch (err) {
    throw new Error("dsh-frontgate: invalid state file " + path + "; restore it from a backup before restarting", { cause: err });
  }
}
function tightenState(path) {
  let info;
  try {
    info = lstatSync(path);
  } catch (err) {
    if (err.code === "ENOENT") return false;
    throw new Error("dsh-frontgate: cannot inspect state file " + path, { cause: err });
  }
  if (!info.isFile()) throw new Error("dsh-frontgate: state file must be a regular file: " + path);
  if (process.platform === "win32") return true;
  if (typeof process.geteuid === "function" && info.uid !== process.geteuid()) {
    throw new Error("dsh-frontgate: state file must be owned by the service user: " + path);
  }
  try {
    chmodSync(path, 384);
  } catch (err) {
    if ((info.mode & 63) !== 0) {
      throw new Error("dsh-frontgate: cannot secure state file permissions for " + path, { cause: err });
    }
  }
  try {
    info = lstatSync(path);
  } catch (err) {
    throw new Error("dsh-frontgate: cannot inspect state file " + path, { cause: err });
  }
  if (!info.isFile() || (info.mode & 63) !== 0 || typeof process.geteuid === "function" && info.uid !== process.geteuid()) {
    throw new Error("dsh-frontgate: state file must be owner-only: " + path);
  }
  return true;
}
function writeState(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = path + "." + randomBytes2(12).toString("hex") + ".tmp";
  let fd;
  try {
    fd = openSync(temporary, "wx", 384);
    writeFileSync(fd, JSON.stringify(value, null, 2) + "\n");
    fsyncSync(fd);
    closeSync(fd);
    fd = void 0;
    renameSync(temporary, path);
  } finally {
    if (fd !== void 0) closeSync(fd);
    try {
      unlinkSync(temporary);
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }
}
function statePathFor(patchPath) {
  const file = patchPath ?? join(process.env.DSH_HOME || join(homedir(), ".dsh"), "profiles", "web", "cordis.patch.yml");
  return join(dirname(file), "data", "dsh-frontgate.json");
}
function hashFor(plain, state) {
  return state.passwordHash && verifyPasswordSync(plain, state.passwordHash) ? state.passwordHash : hashPassword(plain);
}

// src/sessions.ts
import { createHash as createHash2 } from "node:crypto";
var sessionDigest = (token) => createHash2("sha256").update(token).digest("base64url");
function createSessionStore(path, state, pv, onRevoke) {
  const secret = state.secret;
  const passwordHash = state.passwordHash;
  let revoked = new Map((state.revokedSessions ?? []).map(({ digest, expires }) => [digest, expires]));
  const valid = (token) => {
    if (!verifyToken(secret, pv, token)) return false;
    const digest = sessionDigest(token);
    const expires = revoked.get(digest);
    if (expires === void 0) return true;
    if (expires * 1e3 > Date.now()) return false;
    revoked.delete(digest);
    return true;
  };
  const revoke = (token) => {
    if (!valid(token)) return false;
    if (!tightenState(path)) throw new Error("state file is missing");
    const latest = readState(path, true);
    if (latest.secret !== secret || latest.passwordHash !== passwordHash) {
      throw new Error("state changed; restart the gate before signing out");
    }
    const now = Math.floor(Date.now() / 1e3);
    const next = /* @__PURE__ */ new Map();
    for (const entry of latest.revokedSessions ?? []) if (entry.expires > now) next.set(entry.digest, entry.expires);
    for (const [digest2, expires] of revoked) if (expires > now) next.set(digest2, expires);
    const digest = sessionDigest(token);
    if (next.size > MAX_REVOKED_SESSIONS || !next.has(digest) && next.size >= MAX_REVOKED_SESSIONS) {
      throw new Error("revocation store is full");
    }
    next.set(digest, Number(token.split(".")[2]));
    writeState(path, { ...latest, revokedSessions: [...next].map(([digest2, expires]) => ({ digest: digest2, expires })) });
    revoked = next;
    onRevoke(digest);
    return true;
  };
  return { valid, revoke };
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
  const exchangeTimeoutMs = intOr(cfg.exchangeTimeoutMs, DEFAULTS.exchangeTimeoutMs, 100, 6e4);
  const maxConnectionsPerPeer = intOr(cfg.maxConnectionsPerPeer, DEFAULTS.maxConnectionsPerPeer, 0, 1024);
  const maxPendingLoginsPerIp = intOr(cfg.maxPendingLoginsPerIp, DEFAULTS.maxPendingLoginsPerIp, 1, 128);
  const upstreamHeaderTimeoutMs = intOr(cfg.upstreamHeaderTimeoutMs, DEFAULTS.upstreamHeaderTimeoutMs, 0, 36e5);
  const upstreamIdleTimeoutMs = intOr(cfg.upstreamIdleTimeoutMs, DEFAULTS.upstreamIdleTimeoutMs, 0, 36e5);
  const useTls = Boolean(cfg.tlsCertFile || cfg.tlsKeyFile);
  if (useTls && !(cfg.tlsCertFile && cfg.tlsKeyFile)) {
    throw new Error("dsh-frontgate: tlsCertFile and tlsKeyFile must be set together");
  }
  const publicOrigin = normalizePublicOrigin(String(cfg.publicOrigin || ""));
  if (useTls && publicOrigin && !publicOrigin.startsWith("https://")) {
    throw new Error("dsh-frontgate: publicOrigin must use HTTPS when the gate serves TLS");
  }
  const publicProto = publicOrigin ? new URL(publicOrigin).protocol.slice(0, -1) : useTls ? "https" : "http";
  const tlsOptions = useTls ? { cert: readFileSync2(String(cfg.tlsCertFile)), key: readFileSync2(String(cfg.tlsKeyFile)) } : void 0;
  const statePath = statePathFor(ctx.profileContext?.patchPath);
  const stateExists = tightenState(statePath);
  const state = readState(statePath, stateExists);
  const configuredPassword = typeof cfg.password === "string" ? cfg.password : "";
  const envPassword = typeof process.env.DSH_FRONTGATE_PASSWORD === "string" ? process.env.DSH_FRONTGATE_PASSWORD : "";
  const envPasswordHash = process.env.DSH_FRONTGATE_PASSWORD_HASH || "";
  if (cfg.passwordHash && !validPasswordHash(cfg.passwordHash)) {
    throw new Error("dsh-frontgate: invalid passwordHash");
  }
  if (!cfg.passwordHash && !configuredPassword && envPasswordHash && !validPasswordHash(envPasswordHash)) {
    throw new Error("dsh-frontgate: invalid DSH_FRONTGATE_PASSWORD_HASH");
  }
  let passwordHash = "";
  let generatedPassword = "";
  if (typeof cfg.passwordHash === "string" && cfg.passwordHash) passwordHash = cfg.passwordHash;
  else if (configuredPassword) passwordHash = hashFor(assertStrongPassword(configuredPassword, 'the "password" option'), state);
  else if (envPasswordHash) passwordHash = envPasswordHash;
  else if (envPassword) passwordHash = hashFor(assertStrongPassword(envPassword, "DSH_FRONTGATE_PASSWORD"), state);
  else if (validPasswordHash(state.passwordHash)) passwordHash = state.passwordHash;
  if (!passwordHash) {
    generatedPassword = randomPassword();
    passwordHash = hashPassword(generatedPassword);
  }
  const passwordChanged = stateExists && state.passwordHash !== passwordHash;
  const secret = !passwordChanged && typeof state.secret === "string" && state.secret.length >= 64 ? state.secret : randomBytes3(32).toString("hex");
  const pv = passwordVersion(passwordHash);
  const persistedState = {
    passwordHash,
    secret,
    createdAt: state.createdAt || (/* @__PURE__ */ new Date()).toISOString(),
    revokedSessions: passwordChanged ? [] : state.revokedSessions ?? []
  };
  if (state.passwordHash !== passwordHash || state.secret !== secret) {
    writeState(statePath, persistedState);
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
  const upgrades = /* @__PURE__ */ new Map();
  const sessions = createSessionStore(statePath, persistedState, pv, (digest) => {
    for (const [socket, entry] of upgrades) if (entry.digest === digest) socket.destroy();
  });
  const proxy = createProxy({
    targetOrigin,
    publicProto,
    trustProxy: Boolean(cfg.trustProxy),
    exchangeTimeoutMs,
    upstreamHeaderTimeoutMs,
    upstreamIdleTimeoutMs,
    upstreamCa: cfg.upstreamCaFile ? readFileSync2(String(cfg.upstreamCaFile)) : void 0,
    upstreamServerName: String(cfg.upstreamServerName || ""),
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
      maxPendingLoginsPerIp,
      lockMs,
      trustProxy: Boolean(cfg.trustProxy),
      useTls,
      publicOrigin,
      secureCookie: publicProto === "https"
    },
    harnessCookie: proxy.harnessCookie,
    validSession: sessions.valid,
    revokeSession: sessions.revoke,
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
  const peers = /* @__PURE__ */ new Map();
  if (maxConnectionsPerPeer > 0) server.on("connection", (socket) => {
    const peer = String(socket.remoteAddress || "unknown").replace(/^::ffff:/, "");
    const count = peers.get(peer) ?? 0;
    if (count >= maxConnectionsPerPeer) {
      socket.destroy();
      return;
    }
    peers.set(peer, count + 1);
    socket.once("close", () => {
      const remaining = (peers.get(peer) ?? 1) - 1;
      if (remaining <= 0) peers.delete(peer);
      else peers.set(peer, remaining);
    });
  });
  let shuttingDown = false;
  function trackUpgrade(socket, token) {
    const expiresAt = Number(token.split(".")[2]) * 1e3;
    const entry = { digest: sessionDigest(token) };
    upgrades.set(socket, entry);
    const arm = () => {
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        socket.destroy();
        return;
      }
      entry.timer = setTimeout(arm, Math.min(remaining, 2147483647));
    };
    arm();
    socket.once("close", () => {
      if (entry.timer) clearTimeout(entry.timer);
      upgrades.delete(socket);
    });
  }
  server.on("upgrade", (req, socket, head) => {
    socket.on("error", () => socket.destroy());
    try {
      const token = cookieValue(req.headers.cookie, COOKIE);
      if (!token || !sessions.valid(token)) {
        socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        return;
      }
      if (!sameOrigin(req, publicOrigin, useTls)) {
        logger.warn("websocket blocked: cross-origin upgrade from " + String(req.headers.origin || ""));
        socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
      }
      trackUpgrade(socket, token);
      const chunks = head.length ? [head] : [];
      let pendingBytes = head.length;
      const onEarlyData = (chunk) => {
        pendingBytes += chunk.length;
        if (pendingBytes > 65536) {
          socket.destroy();
          return;
        }
        chunks.push(chunk);
      };
      const onEarlyEnd = () => {
        socket.destroy();
      };
      socket.on("data", onEarlyData);
      socket.once("end", onEarlyEnd);
      if (pendingBytes > 65536) {
        socket.destroy();
        return;
      }
      socket.resume();
      proxy.harnessCookie().then((cookie) => {
        if (shuttingDown || socket.destroyed || !sessions.valid(token)) return;
        socket.pause();
        socket.off("data", onEarlyData);
        socket.off("end", onEarlyEnd);
        proxy.forwardUpgrade(req, socket, Buffer.concat(chunks, pendingBytes), cookie);
      }).catch((err) => {
        if (socket.destroyed) return;
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
  const shutdown = () => {
    shuttingDown = true;
    for (const socket of upgrades.keys()) socket.destroy();
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
        logger.info("listening on " + (useTls ? "https" : "http") + "://" + listenHost + ":" + port + " -> " + targetOrigin);
        if (!isLoopbackHost(listenHost) && !useTls) {
          logger.warn("plaintext HTTP is exposed on " + listenHost + "; terminate TLS or use a VPN");
        }
        if (!isLoopbackHost(listenHost)) {
          logger.warn("use a dedicated hostname or IP: browser cookies are shared across ports");
        }
        if (cfg.trustProxy) {
          logger.warn("trustProxy is enabled; restrict access to this listener to trusted proxies; TCP peer limits apply to the proxy");
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
