// _worker.js — Cloudflare Pages Advanced Mode.
//
// This file MUST live at the root of the deployed output (Next's static
// export copies everything under /public verbatim to /out, so keeping the
// source here as public/_worker.js means every `npm run build` produces
// out/_worker.js automatically — no extra build step needed).
//
// What this does: gates EVERY request (HTML, _next/* JS/CSS, /data/*.json,
// /data/*.csv, fonts, images, every page path) behind a server-side password
// check. Nothing is served from the real static site until a valid,
// HMAC-signed session cookie is presented. This is enforced entirely in this
// Worker — there is no client-side bypass, because the protected files are
// never returned to the browser at all until the Worker decides to call
// env.ASSETS.fetch(request).
//
// Required Cloudflare Pages environment secrets (set in the dashboard, never
// committed to the repo):
//   SITE_PASSWORD   — the shared password shown on the login screen
//   SESSION_SECRET  — random key used to HMAC-sign session cookies
// Optional binding for real distributed rate limiting:
//   RATE_LIMIT_KV   — a KV namespace bound under this name
// See README.md "NDA 密碼保護" section for exact dashboard steps.

const COOKIE_NAME = "site_auth";
const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_SECONDS = 5 * 60; // 5 minutes

// Best-effort fallback rate limiter used ONLY when no RATE_LIMIT_KV binding
// is configured. It's per-isolate (not shared across Cloudflare's edge), so
// it's not a real guarantee at scale — bind RATE_LIMIT_KV for that. It still
// helps against a single abusive client hitting a single edge location.
const memoryAttempts = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---- Always-allowed, unauthenticated routes ----
    if (path === "/favicon.ico") {
      return decorate(await env.ASSETS.fetch(request), path);
    }
    if (path === "/api/login") {
      return decorate(await handleLogin(request, env, url), path);
    }
    if (path === "/api/logout") {
      return decorate(handleLogout(), path);
    }

    // ---- Everything else requires a valid session (fail closed) ----
    const authed = await hasValidSession(request, env);
    if (authed) {
      const assetRes = await env.ASSETS.fetch(request);
      return decorate(assetRes, path, { authed: true });
    }

    if (request.method === "GET" || request.method === "HEAD") {
      const redirectTarget = safeRedirectPath(url.pathname + url.search);
      return decorate(renderLoginPage({ redirect: redirectTarget }), path);
    }

    // Non-GET request to a protected path without a session: fail closed,
    // no HTML, no data — just a generic 401.
    return decorate(jsonResponse({ error: "unauthorized" }, 401), path);
  },
};

// ---------------------------------------------------------------------------
// Login / logout handlers
// ---------------------------------------------------------------------------

async function handleLogin(request, env, url) {
  if (request.method === "GET" || request.method === "HEAD") {
    const redirectTarget = safeRedirectPath(url.searchParams.get("redirect") || "/");
    return renderLoginPage({ redirect: redirectTarget });
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "method not allowed" }, 405);
  }

  if (!env.SITE_PASSWORD || !env.SESSION_SECRET) {
    // Misconfigured deployment: never fall back to "open site" — fail closed.
    return renderLoginPage(
      { error: "Incorrect password. Please try again." },
      500
    );
  }

  if (await isRateLimited(request, env)) {
    return renderLoginPage(
      { error: "Too many attempts. Please wait a few minutes and try again." },
      429
    );
  }

  let password = "";
  let redirectTarget = "/";
  try {
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      const body = await request.json();
      password = typeof body.password === "string" ? body.password : "";
      redirectTarget = safeRedirectPath(typeof body.redirect === "string" ? body.redirect : "/");
    } else {
      const form = await request.formData();
      password = String(form.get("password") || "");
      redirectTarget = safeRedirectPath(String(form.get("redirect") || "/"));
    }
  } catch {
    // Malformed body -> treat as a failed login attempt below.
  }

  const ok = password.length > 0 && (await passwordMatches(password, env.SITE_PASSWORD));

  if (!ok) {
    await recordFailedAttempt(request, env);
    // Generic message only — never echo back the submitted or real password.
    return renderLoginPage({ error: "Incorrect password. Please try again.", redirect: redirectTarget }, 401);
  }

  await clearFailedAttempts(request, env);
  const token = await createSessionToken(env);

  const headers = new Headers();
  headers.append("Set-Cookie", buildSessionCookie(token));
  headers.set("Location", redirectTarget);
  headers.set("Cache-Control", "no-store");
  return new Response(null, { status: 302, headers });
}

function handleLogout() {
  const headers = new Headers();
  headers.append("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  headers.set("Location", "/");
  headers.set("Cache-Control", "no-store");
  return new Response(null, { status: 302, headers });
}

// ---------------------------------------------------------------------------
// Session cookie: HMAC-SHA256 signed, short-lived, HttpOnly/Secure/Strict.
// The cookie value is "<base64url payload>.<base64url signature>" — the
// payload only ever contains an expiry timestamp, never the password.
// ---------------------------------------------------------------------------

function buildSessionCookie(token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...bytes));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBytes(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function createSessionToken(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify({ exp })));
  const key = await hmacKey(env.SESSION_SECRET);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${base64url(new Uint8Array(sig))}`;
}

async function verifySessionToken(token, env) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) return false;
  try {
    const key = await hmacKey(env.SESSION_SECRET);
    // crypto.subtle.verify performs a constant-time comparison internally —
    // this is the safe way to check an HMAC, no manual byte compare needed.
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlToBytes(sigB64),
      new TextEncoder().encode(payloadB64)
    );
    if (!valid) return false;
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(payloadB64)));
    return typeof payload.exp === "number" && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function hasValidSession(request, env) {
  if (!env.SESSION_SECRET) return false; // misconfigured -> fail closed
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return false;
  return verifySessionToken(token, env);
}

// ---------------------------------------------------------------------------
// Password check: compare SHA-256 digests byte-by-byte (constant time),
// never a plain `===` string comparison, and never log/echo the value.
// ---------------------------------------------------------------------------

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function passwordMatches(submitted, expected) {
  const [a, b] = await Promise.all([sha256(submitted), sha256(expected)]);
  return timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Rate limiting (per client IP). Uses RATE_LIMIT_KV if bound; otherwise falls
// back to a best-effort in-memory map (see comment at top of file).
// ---------------------------------------------------------------------------

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

async function isRateLimited(request, env) {
  const ip = getClientIp(request);
  if (env.RATE_LIMIT_KV) {
    const raw = await env.RATE_LIMIT_KV.get(`rl:${ip}`);
    return (raw ? parseInt(raw, 10) : 0) >= RATE_LIMIT_MAX_ATTEMPTS;
  }
  const entry = memoryAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() > entry.resetAt) {
    memoryAttempts.delete(ip);
    return false;
  }
  return entry.count >= RATE_LIMIT_MAX_ATTEMPTS;
}

async function recordFailedAttempt(request, env) {
  const ip = getClientIp(request);
  if (env.RATE_LIMIT_KV) {
    const key = `rl:${ip}`;
    const raw = await env.RATE_LIMIT_KV.get(key);
    const count = (raw ? parseInt(raw, 10) : 0) + 1;
    await env.RATE_LIMIT_KV.put(key, String(count), { expirationTtl: RATE_LIMIT_WINDOW_SECONDS });
    return;
  }
  const entry = memoryAttempts.get(ip);
  if (!entry || Date.now() > entry.resetAt) {
    memoryAttempts.set(ip, { count: 1, resetAt: Date.now() + RATE_LIMIT_WINDOW_SECONDS * 1000 });
  } else {
    entry.count += 1;
  }
}

async function clearFailedAttempts(request, env) {
  const ip = getClientIp(request);
  if (env.RATE_LIMIT_KV) {
    await env.RATE_LIMIT_KV.delete(`rl:${ip}`);
  } else {
    memoryAttempts.delete(ip);
  }
}

// ---------------------------------------------------------------------------
// Open-redirect protection: only same-origin, single-leading-slash paths are
// ever honored for post-login redirects.
// ---------------------------------------------------------------------------

function safeRedirectPath(path) {
  if (typeof path !== "string" || path.length === 0) return "/";
  if (!path.startsWith("/")) return "/";
  if (path.startsWith("//")) return "/"; // protocol-relative external URL
  if (path.includes("://")) return "/";
  if (path.startsWith("/api/login") || path.startsWith("/api/logout")) return "/";
  return path;
}

// ---------------------------------------------------------------------------
// Login page (self-contained HTML/CSS/JS — no dependency on the protected
// static bundle, so it can always render even though everything else is
// gated). Visual style intentionally mirrors the site's existing look
// (slate/sky palette, rounded-2xl cards, soft shadow) without touching the
// Next.js app itself.
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderLoginPage({ error, redirect = "/" } = {}, status = 200) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Private Preview</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f8fafc;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    padding: 24px;
  }
  .card {
    width: 100%;
    max-width: 380px;
    background: #ffffff;
    border: 1px solid rgba(148, 163, 184, 0.35);
    border-radius: 16px;
    box-shadow: 0 1px 2px rgba(15,23,42,0.04), 0 1px 12px rgba(15,23,42,0.06);
    padding: 32px 28px;
  }
  h1 { font-size: 20px; font-weight: 600; margin: 0 0 6px; letter-spacing: -0.01em; }
  p.desc { font-size: 14px; color: #64748b; margin: 0 0 24px; }
  label { font-size: 13px; font-weight: 500; color: #334155; display: block; margin-bottom: 6px; }
  .field { position: relative; margin-bottom: 18px; }
  input[type="password"], input[type="text"] {
    width: 100%;
    padding: 10px 52px 10px 12px;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    font-size: 14px;
    outline: none;
    background: #f8fafc;
    color: #0f172a;
  }
  input:focus { border-color: #38bdf8; background: #ffffff; box-shadow: 0 0 0 3px rgba(56,189,248,0.15); }
  .toggle {
    position: absolute;
    right: 6px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: #0284c7;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    padding: 6px 8px;
  }
  .toggle:hover { text-decoration: underline; }
  button.submit {
    width: 100%;
    padding: 11px 12px;
    border: none;
    border-radius: 8px;
    background: #0284c7;
    color: #fff;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.15s ease;
  }
  button.submit:hover { background: #0369a1; }
  .error {
    background: #fef2f2;
    color: #b91c1c;
    border: 1px solid #fecaca;
    border-radius: 8px;
    padding: 9px 12px;
    font-size: 13px;
    margin-bottom: 16px;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #0b1120; color: #e2e8f0; }
    .card { background: #0f172a; border-color: rgba(51,65,85,0.6); }
    p.desc { color: #94a3b8; }
    label { color: #cbd5e1; }
    input[type="password"], input[type="text"] { background: #1e293b; border-color: #334155; color: #e2e8f0; }
    input:focus { background: #1e293b; }
    .error { background: rgba(127,29,29,0.3); border-color: rgba(153,27,27,0.5); color: #fca5a5; }
  }
</style>
</head>
<body>
  <form class="card" method="POST" action="/api/login" autocomplete="off">
    <h1>Private Preview</h1>
    <p class="desc">This website is password protected.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <input type="hidden" name="redirect" value="${escapeHtml(redirect)}" />
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autofocus />
      <button type="button" class="toggle" id="toggleBtn" aria-label="Show password">Show</button>
    </div>
    <button type="submit" class="submit">Enter Site</button>
  </form>
  <script>
    document.getElementById("toggleBtn").addEventListener("click", function () {
      var input = document.getElementById("password");
      var btn = document.getElementById("toggleBtn");
      if (input.type === "password") { input.type = "text"; btn.textContent = "Hide"; }
      else { input.type = "password"; btn.textContent = "Show"; }
    });
  </script>
</body>
</html>`;

  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
    },
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

// ---------------------------------------------------------------------------
// Applies site-wide security headers + Cache-Control to every response this
// Worker returns (login page, API responses, and proxied static assets).
// ---------------------------------------------------------------------------

function decorate(response, path, { authed = false } = {}) {
  const headers = new Headers(response.headers);
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  headers.set("X-Content-Type-Options", "nosniff");

  if (authed) {
    // Content-hashed Next.js chunks are safe to cache in the individual
    // user's own browser (private = never a shared/proxy/CDN cache).
    // Everything else (HTML pages, /data/*.json, /data/*.csv, etc.) is
    // NDA-sensitive and must never be cached at all.
    if (path.startsWith("/_next/static/")) {
      headers.set("Cache-Control", "private, max-age=31536000, immutable");
    } else {
      headers.set("Cache-Control", "private, no-store");
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
