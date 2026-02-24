const express = require("express");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const { Ollama } = require("ollama");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "32kb", strict: true }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  );
  next();
});
app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.static(path.join(__dirname, "public")));

const ENV_PATH = path.join(__dirname, ".env");
const CFG = {
  OLLAMA_API_KEY: "",
  OLLAMA_LOCAL_HOST: "http://localhost:11434",
  OLLAMA_SESSION_COOKIE: "",
  CLAUDE_SESSION_KEY: "",
  CHATGPT_ACCESS_TOKEN: "",
  GITHUB_TOKEN: "",
  ZAI_AUTH_TOKEN: "",
  ADMIN_TOKEN: "",
  BIND_HOST: "127.0.0.1",
  PORT: "3456",
};

function loadEnv() {
  if (fs.existsSync(ENV_PATH)) {
    for (const line of fs.readFileSync(ENV_PATH, "utf-8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const k = t.slice(0, eq).trim();
      let v = t.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (k in CFG) CFG[k] = v;
    }
  }
  for (const k of Object.keys(CFG)) if (process.env[k]) CFG[k] = process.env[k];
  if (!CFG.CHATGPT_ACCESS_TOKEN) {
    const codexAuth = path.join(os.homedir(), ".codex", "auth.json");
    try {
      if (fs.existsSync(codexAuth)) {
        const auth = JSON.parse(fs.readFileSync(codexAuth, "utf-8"));
        if (auth.access_token) CFG.CHATGPT_ACCESS_TOKEN = auth.access_token;
        else if (auth.token) CFG.CHATGPT_ACCESS_TOKEN = auth.token;
      }
    } catch {}
  }
}
loadEnv();
if (!CFG.ADMIN_TOKEN) CFG.ADMIN_TOKEN = crypto.randomBytes(24).toString("hex");

function isValidPort(v) {
  const n = Number.parseInt(String(v), 10);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

function isValidHost(v) {
  return /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)$/.test(String(v || "").trim());
}

function sanitizeConfigValue(key, value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length > 8192) return null;
  if (key === "PORT") return isValidPort(trimmed) ? String(Number.parseInt(trimmed, 10)) : null;
  if (key === "BIND_HOST") return isValidHost(trimmed) ? trimmed : null;
  return trimmed;
}

function sameToken(a, b) {
  if (!a || !b) return false;
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function isTrustedBrowserRequest(req) {
  const host = String(req.headers.host || "").toLowerCase();
  if (!host) return false;
  const allowed = new Set([`http://${host}`, `https://${host}`]);
  const origin = String(req.headers.origin || "").toLowerCase();
  if (origin) return allowed.has(origin);
  const referer = String(req.headers.referer || "").toLowerCase();
  if (!referer) return false;
  for (const base of allowed) {
    if (referer === base || referer.startsWith(base + "/")) return true;
  }
  return false;
}

function isLoopbackRequest(req) {
  const remote = req.socket?.remoteAddress || "";
  return remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1";
}

function requireAdmin(req, res, next) {
  const provided = req.headers["x-admin-token"];
  if (sameToken(provided, CFG.ADMIN_TOKEN)) return next();
  if (isLoopbackRequest(req) && isTrustedBrowserRequest(req)) return next();
  return res.status(403).json({ ok: false, error: "Forbidden" });
}

function saveEnv() {
  const lines = ["# AI Usage Dashboard Configuration"];
  for (const [k, v] of Object.entries(CFG)) {
    if (k === "PORT" || k === "ADMIN_TOKEN" || k === "BIND_HOST") continue;
    lines.push(`${k}=${v}`);
  }
  lines.push(`BIND_HOST=${CFG.BIND_HOST}`);
  lines.push(`PORT=${CFG.PORT}`, "");
  fs.writeFileSync(ENV_PATH, lines.join("\n"), { mode: 0o600 });
}

const OLLAMA_USAGE_PATH = path.join(__dirname, "data", "ollama-usage.json");
function loadOllamaUsage() {
  try {
    if (fs.existsSync(OLLAMA_USAGE_PATH)) {
      return JSON.parse(fs.readFileSync(OLLAMA_USAGE_PATH, "utf-8"));
    }
  } catch {}
  return { entries: [] };
}
function saveOllamaUsage(data) {
  const cutoff = Date.now() - 7 * 24 * 3600 * 1000;
  data.entries = (data.entries || []).filter(e => e.ts > cutoff);
  fs.mkdirSync(path.dirname(OLLAMA_USAGE_PATH), { recursive: true });
  fs.writeFileSync(OLLAMA_USAGE_PATH, JSON.stringify(data), "utf-8");
}
function computeOllamaWindows(entries) {
  const now = Date.now();
  const fiveH = entries.filter(e => e.ts > now - 5 * 3600 * 1000);
  const sevenD = entries.filter(e => e.ts > now - 7 * 24 * 3600 * 1000);
  const sum = (arr, key) => arr.reduce((s, e) => s + (e[key] || 0), 0);
  return {
    five_hour: {
      requests: fiveH.length,
      prompt_tokens: sum(fiveH, "pt"),
      eval_tokens: sum(fiveH, "et"),
      total_tokens: sum(fiveH, "pt") + sum(fiveH, "et"),
      total_duration_ms: Math.round(sum(fiveH, "dur") / 1e6),
      resets_at: fiveH.length ? new Date(Math.min(...fiveH.map(e => e.ts)) + 5 * 3600 * 1000).toISOString() : null,
    },
    seven_day: {
      requests: sevenD.length,
      prompt_tokens: sum(sevenD, "pt"),
      eval_tokens: sum(sevenD, "et"),
      total_tokens: sum(sevenD, "pt") + sum(sevenD, "et"),
      total_duration_ms: Math.round(sum(sevenD, "dur") / 1e6),
      resets_at: sevenD.length ? new Date(Math.min(...sevenD.map(e => e.ts)) + 7 * 24 * 3600 * 1000).toISOString() : null,
    },
  };
}

async function apiFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), opts.timeout || 10000);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    clearTimeout(timeout);
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      return { ok: false, status: r.status, error: `${r.status} ${r.statusText}`, body };
    }
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      const data = await r.json();
      return { ok: true, data };
    }
    const text = await r.text();
    try { return { ok: true, data: JSON.parse(text) }; } catch {}
    return { ok: true, data: text };
  } catch (e) {
    clearTimeout(timeout);
    return { ok: false, error: e.name === "AbortError" ? "Timeout" : e.message };
  }
}

async function scrapeOllamaUsage() {
  if (!CFG.OLLAMA_SESSION_COOKIE) return null;
  try {
    const r = await apiFetch("https://ollama.com/settings", {
      headers: {
        "Cookie": `__Secure-session=${CFG.OLLAMA_SESSION_COOKIE}`,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      timeout: 15000,
    });
    if (!r.ok) return { error: r.error || `HTTP ${r.status}` };
    const html = typeof r.data === "string" ? r.data : "";
    if (!html || html.length < 200) return { error: "Empty or redirect response (cookie may be expired)" };
    if (html.includes("/signin") && !html.includes("Session usage")) return { error: "Redirected to signin (cookie expired)" };
    const sessionMatch = html.match(/Session usage[\s\S]*?(\d+\.?\d*)% used/);
    const weeklyMatch = html.match(/Weekly usage[\s\S]*?(\d+\.?\d*)% used/);
    const resetTimes = [...html.matchAll(/data-time="([^"]+)"/g)].map(m => m[1]);
    const planMatch = html.match(/Cloud Usage[\s\S]*?capitalize[^>]*>(\w+)</);
    return {
      session_pct: sessionMatch ? parseFloat(sessionMatch[1]) : null,
      weekly_pct: weeklyMatch ? parseFloat(weeklyMatch[1]) : null,
      session_resets_at: resetTimes[0] || null,
      weekly_resets_at: resetTimes[1] || null,
      plan: planMatch ? planMatch[1].toLowerCase() : null,
      scraped: true,
    };
  } catch (e) {
    return { error: e.message };
  }
}

function ollamaCloud() {
  if (!CFG.OLLAMA_API_KEY) return null;
  return new Ollama({ host: "https://ollama.com", headers: { Authorization: "Bearer " + CFG.OLLAMA_API_KEY } });
}
function ollamaLocal() {
  return new Ollama({ host: CFG.OLLAMA_LOCAL_HOST });
}

app.get("/api/config", (_req, res) => {
  res.json({
    ollama: { configured: !!CFG.OLLAMA_API_KEY, local: CFG.OLLAMA_LOCAL_HOST, hasSessionCookie: !!CFG.OLLAMA_SESSION_COOKIE },
    claude: { configured: !!CFG.CLAUDE_SESSION_KEY },
    chatgpt: { configured: !!CFG.CHATGPT_ACCESS_TOKEN, source: CFG.CHATGPT_ACCESS_TOKEN ? "token" : "none" },
    copilot: { configured: !!CFG.GITHUB_TOKEN },
    zai: { configured: !!CFG.ZAI_AUTH_TOKEN },
  });
});

app.post("/api/config", requireAdmin, (req, res) => {
  const input = req.body && typeof req.body === "object" ? req.body : {};
  for (const k of Object.keys(CFG)) {
    if (k === "ADMIN_TOKEN") continue;
    if (input[k] === undefined) continue;
    const safe = sanitizeConfigValue(k, input[k]);
    if (safe === null) return res.status(400).json({ ok: false, error: `Invalid value for ${k}` });
    CFG[k] = safe;
  }
  saveEnv();
  loadEnv();
  res.json({ ok: true });
});

app.post("/api/chatgpt/refresh-token", requireAdmin, (_req, res) => {
  const codexAuth = path.join(os.homedir(), ".codex", "auth.json");
  try {
    if (!fs.existsSync(codexAuth)) {
      return res.json({ ok: false, error: "~/.codex/auth.json not found", hint: "Install OpenAI Codex CLI and run 'codex' to authenticate." });
    }
    const auth = JSON.parse(fs.readFileSync(codexAuth, "utf-8"));
    const token = auth.access_token || auth.token;
    if (!token) return res.json({ ok: false, error: "No token found in auth.json" });
    let expiry = null;
    try {
      const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
      expiry = payload.exp ? new Date(payload.exp * 1000).toISOString() : null;
      if (payload.exp && Date.now() > payload.exp * 1000) {
        return res.json({ ok: false, error: "Token in auth.json is expired", expiry, hint: "Run 'codex' to re-authenticate, then refresh again." });
      }
    } catch {}
    CFG.CHATGPT_ACCESS_TOKEN = token;
    saveEnv();
    res.json({ ok: true, expiry, hint: "Token loaded from ~/.codex/auth.json" });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.post("/api/claude/validate-key", requireAdmin, async (req, res) => {
  const key = req.body?.key || CFG.CLAUDE_SESSION_KEY;
  if (!key) return res.json({ ok: false, error: "No session key provided" });
  try {
    const r = await apiFetch("https://claude.ai/api/organizations", {
      headers: {
        "Cookie": `sessionKey=${key}`,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      },
    });
    if (!r.ok) return res.json({ ok: false, error: `${r.status} ${r.error}`, hint: "Key is invalid or expired." });
    const orgs = Array.isArray(r.data) ? r.data : [r.data];
    const org = orgs.find(o => o.capabilities?.includes?.("chat") || o.capabilities?.includes?.("claude_pro")) || orgs[0];
    res.json({ ok: true, orgName: org?.name, plan: org?.capabilities });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.get("/api/ollama/usage", async (_req, res) => {
  if (!CFG.OLLAMA_API_KEY) return res.json({ configured: false });
  try {
    const [meR, scraped] = await Promise.all([
      apiFetch("https://ollama.com/api/me", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + CFG.OLLAMA_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      }),
      scrapeOllamaUsage(),
    ]);
    const usageData = loadOllamaUsage();
    const windows = computeOllamaWindows(usageData.entries || []);
    const c = ollamaCloud();
    let modelCount = 0;
    let cloudModelNames = [];
    try {
      const list = await c.list();
      const models = list.models || [];
      modelCount = models.length;
      cloudModelNames = models.map(m => m.name).slice(0, 30);
    } catch {}
    let local = { connected: false };
    try {
      const lc = ollamaLocal();
      const lList = await lc.list();
      let running = [];
      try { running = (await lc.ps()).models || []; } catch {}
      local = {
        connected: true, host: CFG.OLLAMA_LOCAL_HOST,
        modelCount: (lList.models || []).length,
        runningCount: running.length,
        running: running.map(m => ({ name: m.name, vram: m.size_vram })),
      };
    } catch {}
    const usage = { ...windows };
    if (scraped && scraped.scraped) {
      usage.real = {
        session_pct: scraped.session_pct,
        weekly_pct: scraped.weekly_pct,
        session_resets_at: scraped.session_resets_at,
        weekly_resets_at: scraped.weekly_resets_at,
        plan: scraped.plan,
      };
    } else if (scraped && scraped.error) {
      usage.scrapeError = scraped.error;
    }
    if (!meR.ok) {
      return res.json({
        configured: true,
        error: meR.error,
        cloudModels: modelCount,
        local,
        usage,
      });
    }
    const me = meR.data;
    res.json({
      configured: true,
      account: {
        name: me.Name || me.Email,
        email: me.Email,
        plan: scraped?.plan || me.Plan || "free",
        avatarUrl: me.AvatarURL,
        customerId: me.CustomerID?.String || null,
        subscriptionActive: !!me.SubscriptionID?.Valid && !!me.SubscriptionID?.String,
        subscriptionStart: me.SubscriptionPeriodStart?.Valid ? me.SubscriptionPeriodStart.Time : null,
        subscriptionEnd: me.SubscriptionPeriodEnd?.Valid ? me.SubscriptionPeriodEnd.Time : null,
      },
      cloudModels: modelCount,
      cloudModelNames,
      local,
      usage,
    });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});

function zaiHeaders() {
  return {
    "Authorization": CFG.ZAI_AUTH_TOKEN,
    "Accept-Language": "en-US,en",
    "Content-Type": "application/json",
  };
}

function zaiTimeWindow() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, now.getHours(), 0, 0, 0);
  const end = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), 59, 59, 999);
  const fmt = (d) => {
    const Y = d.getFullYear();
    const M = String(d.getMonth() + 1).padStart(2, "0");
    const D = String(d.getDate()).padStart(2, "0");
    const h = String(d.getHours()).padStart(2, "0");
    const m = String(d.getMinutes()).padStart(2, "0");
    const s = String(d.getSeconds()).padStart(2, "0");
    return `${Y}-${M}-${D} ${h}:${m}:${s}`;
  };
  return `?startTime=${encodeURIComponent(fmt(start))}&endTime=${encodeURIComponent(fmt(end))}`;
}

app.get("/api/zai/usage", async (_req, res) => {
  if (!CFG.ZAI_AUTH_TOKEN) return res.json({ configured: false });
  try {
    const base = "https://api.z.ai";
    const qp = zaiTimeWindow();
    const hdrs = zaiHeaders();
    const [quotaR, modelR, toolR] = await Promise.all([
      apiFetch(`${base}/api/monitor/usage/quota/limit`, { headers: hdrs }),
      apiFetch(`${base}/api/monitor/usage/model-usage${qp}`, { headers: hdrs }),
      apiFetch(`${base}/api/monitor/usage/tool-usage${qp}`, { headers: hdrs }),
    ]);
    if (!quotaR.ok && !modelR.ok && !toolR.ok) {
      return res.json({ configured: true, error: quotaR.error || modelR.error || toolR.error });
    }
    let tokenLimit = null;
    let mcpLimit = null;
    const limits = quotaR.ok && quotaR.data?.data?.limits ? quotaR.data.data.limits : [];
    for (const lim of limits) {
      if (lim.type === "TOKENS_LIMIT") {
        tokenLimit = { type: "Token Usage (5 Hour)", percentage: lim.percentage };
      } else if (lim.type === "TIME_LIMIT") {
        mcpLimit = {
          type: "MCP Usage (Monthly)",
          percentage: lim.percentage,
          currentUsage: lim.currentValue,
          total: lim.usage,
          usageDetails: lim.usageDetails,
        };
      }
    }
    const modelUsage = modelR.ok && modelR.data?.data ? modelR.data.data : null;
    const toolUsage = toolR.ok && toolR.data?.data ? toolR.data.data : null;
    res.json({
      configured: true,
      quota: { tokenLimit, mcpLimit },
      modelUsage,
      toolUsage,
    });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});

function claudeHeaders() {
  return {
    "Cookie": `sessionKey=${CFG.CLAUDE_SESSION_KEY}`,
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  };
}

app.get("/api/claude/usage", async (_req, res) => {
  if (!CFG.CLAUDE_SESSION_KEY) return res.json({ configured: false });
  try {
    const orgsR = await apiFetch("https://claude.ai/api/organizations", {
      headers: claudeHeaders(),
    });
    if (!orgsR.ok) return res.json({ configured: true, error: `Orgs: ${orgsR.error}`, hint: "Session key may be expired. Re-copy from browser." });
    const orgs = Array.isArray(orgsR.data) ? orgsR.data : [orgsR.data];
    const org = orgs.find(o => o.capabilities?.includes?.("chat") || o.capabilities?.includes?.("claude_pro")) || orgs[0];
    if (!org?.uuid) return res.json({ configured: true, error: "No org found" });
    const usageR = await apiFetch(`https://claude.ai/api/organizations/${org.uuid}/usage`, {
      headers: claudeHeaders(),
    });
    if (!usageR.ok) return res.json({ configured: true, error: `Usage: ${usageR.error}` });
    let overage = null;
    const overageR = await apiFetch(`https://claude.ai/api/organizations/${org.uuid}/overage_spend_limit`, {
      headers: claudeHeaders(),
    });
    if (overageR.ok) overage = overageR.data;
    res.json({
      configured: true,
      orgName: org.name || org.display_name,
      plan: org.active_subscription_plan || org.billing_plan || org.capabilities?.plan,
      usage: usageR.data,
      overage,
    });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});

app.get("/api/chatgpt/usage", async (_req, res) => {
  if (!CFG.CHATGPT_ACCESS_TOKEN) return res.json({ configured: false });
  try {
    const r = await apiFetch("https://chatgpt.com/backend-api/wham/usage", {
      headers: { "Authorization": `Bearer ${CFG.CHATGPT_ACCESS_TOKEN}` },
    });
    if (!r.ok) return res.json({ configured: true, error: r.error, hint: "Token may be expired. Get a fresh token from ~/.codex/auth.json or browser DevTools." });
    res.json({ configured: true, usage: r.data });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});

app.get("/api/copilot/usage", async (_req, res) => {
  if (!CFG.GITHUB_TOKEN) return res.json({ configured: false });
  try {
    const r = await apiFetch("https://api.github.com/copilot_internal/user", {
      headers: {
        "Authorization": `token ${CFG.GITHUB_TOKEN}`,
        "Accept": "application/json",
        "User-Agent": "AI-Command-Center/5.0",
        "X-GitHub-Api-Version": "2022-11-28",
        "Editor-Version": "vscode/1.96.0",
        "Editor-Plugin-Version": "copilot/1.250.0",
        "Copilot-Integration-Id": "vscode-chat",
      },
    });
    if (!r.ok) return res.json({ configured: true, error: r.error, hint: "PAT needs read:user scope. Create at github.com/settings/tokens" });
    const d = r.data;
    res.json({
      configured: true,
      plan: d.copilot_plan || d.access_type_sku,
      quotaReset: d.quota_reset_date,
      quotas: d.quota_snapshots || {},
      chatEnabled: d.chat_enabled,
      login: d.login,
    });
  } catch (e) { res.json({ configured: true, error: e.message }); }
});

app.get("/api/platforms", (_req, res) => {
  res.json([
    { id: "chatgpt", name: "ChatGPT", accent: "#10b981" },
    { id: "copilot", name: "Copilot", accent: "#58a6ff" },
    { id: "claude", name: "Claude", accent: "#e09145" },
    { id: "ollama", name: "Ollama", accent: "#a78bfa" },
    { id: "zai", name: "Z.AI", accent: "#4f8cff" },
  ]);
});

app.get("/api/yasb/summary", async (_req, res) => {
  try {
    const result = {
      chatgpt_session: null, chatgpt_weekly: null, chatgpt_session_reset: null, chatgpt_weekly_reset: null, chatgpt_ok: false,
      copilot_used: null, copilot_total: null, copilot_pct: null, copilot_reset: null, copilot_ok: false,
      claude_session: null, claude_weekly: null, claude_session_reset: null, claude_weekly_reset: null, claude_ok: false,
      ollama_session: null, ollama_weekly: null, ollama_session_reset: null, ollama_weekly_reset: null, ollama_ok: false,
      zai_token_pct: null, zai_mcp_pct: null, zai_ok: false,
    };

    const formatSeconds = (s) => {
      if (!s || s <= 0) return "--";
      if (s < 3600) return Math.floor(s / 60) + "m";
      return Math.floor(s / 3600) + "h";
    };

    const formatUntil = (iso) => {
      if (!iso) return "--";
      const ms = new Date(iso) - Date.now();
      if (ms <= 0) return "now";
      return formatSeconds(ms / 1000);
    };

    const [chatgptR, copilotR, claudeR, ollamaR, zaiR] = await Promise.allSettled([
      CFG.CHATGPT_ACCESS_TOKEN ? apiFetch("https://chatgpt.com/backend-api/wham/usage", {
        headers: { "Authorization": `Bearer ${CFG.CHATGPT_ACCESS_TOKEN}` },
      }) : Promise.resolve(null),
      CFG.GITHUB_TOKEN ? apiFetch("https://api.github.com/copilot_internal/user", {
        headers: {
          "Authorization": `token ${CFG.GITHUB_TOKEN}`,
          "Accept": "application/json",
          "User-Agent": "AI-Command-Center/5.0",
          "X-GitHub-Api-Version": "2022-11-28",
          "Editor-Version": "vscode/1.96.0",
          "Editor-Plugin-Version": "copilot/1.250.0",
          "Copilot-Integration-Id": "vscode-chat",
        },
      }) : Promise.resolve(null),
      CFG.CLAUDE_SESSION_KEY ? (async () => {
        const orgsR = await apiFetch("https://claude.ai/api/organizations", { headers: claudeHeaders() });
        if (!orgsR.ok) return null;
        const orgs = Array.isArray(orgsR.data) ? orgsR.data : [orgsR.data];
        const org = orgs.find(o => o.capabilities?.includes?.("chat") || o.capabilities?.includes?.("claude_pro")) || orgs[0];
        if (!org?.uuid) return null;
        return apiFetch(`https://claude.ai/api/organizations/${org.uuid}/usage`, { headers: claudeHeaders() });
      })() : Promise.resolve(null),
      (CFG.OLLAMA_API_KEY || CFG.OLLAMA_SESSION_COOKIE) ? scrapeOllamaUsage() : Promise.resolve(null),
      CFG.ZAI_AUTH_TOKEN ? apiFetch("https://api.z.ai/api/monitor/usage/quota/limit", {
        headers: zaiHeaders(),
      }) : Promise.resolve(null),
    ]);
    const chatgpt = chatgptR.status === "fulfilled" ? chatgptR.value : null;
    if (chatgpt?.ok && chatgpt.data?.rate_limit) {
      const rl = chatgpt.data.rate_limit;
      result.chatgpt_session = Math.round(rl.primary_window?.used_percent || 0);
      result.chatgpt_weekly = Math.round(rl.secondary_window?.used_percent || 0);
      result.chatgpt_session_reset = formatSeconds(rl.primary_window?.reset_after_seconds);
      result.chatgpt_weekly_reset = formatSeconds(rl.secondary_window?.reset_after_seconds);
      result.chatgpt_ok = true;
    }
    const copilot = copilotR.status === "fulfilled" ? copilotR.value : null;
    if (copilot?.ok && copilot.data?.quota_snapshots?.premium_interactions) {
      const prem = copilot.data.quota_snapshots.premium_interactions;
      result.copilot_used = prem.entitlement - (prem.remaining || 0);
      result.copilot_total = prem.entitlement;
      result.copilot_pct = prem.entitlement > 0 ? Math.round((result.copilot_used / prem.entitlement) * 100) : 0;
      if (copilot.data.quota_reset_date) {
        const resetDiff = new Date(copilot.data.quota_reset_date) - Date.now();
        result.copilot_reset = resetDiff > 0 ? Math.ceil(resetDiff / 86400000) + 'd' : '--';
      }
      result.copilot_ok = true;
    }
    const claude = claudeR.status === "fulfilled" ? claudeR.value : null;
    if (claude?.ok && claude.data) {
      const fh = claude.data.five_hour || {};
      const sd = claude.data.seven_day || {};
      result.claude_session = fh.utilization != null ? Math.round(fh.utilization) : null;
      result.claude_weekly = sd.utilization != null ? Math.round(sd.utilization) : null;
      result.claude_session_reset = formatUntil(fh.resets_at);
      result.claude_weekly_reset = formatUntil(sd.resets_at);
      result.claude_ok = true;
    }
    const ollama = ollamaR.status === "fulfilled" ? ollamaR.value : null;
    if (ollama?.scraped) {
      result.ollama_session = ollama.session_pct != null ? Math.round(ollama.session_pct) : null;
      result.ollama_weekly = ollama.weekly_pct != null ? Math.round(ollama.weekly_pct) : null;
      result.ollama_session_reset = formatUntil(ollama.session_resets_at);
      result.ollama_weekly_reset = formatUntil(ollama.weekly_resets_at);
      result.ollama_ok = true;
    }
    const zai = zaiR.status === "fulfilled" ? zaiR.value : null;
    if (zai?.ok && zai.data?.data?.limits) {
      for (const lim of zai.data.data.limits) {
        if (lim.type === "TOKENS_LIMIT" && lim.percentage != null) {
          result.zai_token_pct = Math.round(lim.percentage);
        } else if (lim.type === "TIME_LIMIT" && lim.percentage != null) {
          result.zai_mcp_pct = Math.round(lim.percentage);
        }
      }
      result.zai_ok = true;
    }
    res.json(result);
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = isValidPort(CFG.PORT) ? Number.parseInt(CFG.PORT, 10) : 3456;
const HOST = isValidHost(CFG.BIND_HOST) ? CFG.BIND_HOST : "127.0.0.1";
app.listen(PORT, HOST, () => {
  console.log(`\n  AI Usage Dashboard`);
  console.log(`  http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}\n`);
  console.log(`  ChatGPT   ${CFG.CHATGPT_ACCESS_TOKEN ? "OK" : "--"}`);
  console.log(`  Copilot   ${CFG.GITHUB_TOKEN ? "OK" : "--"}`);
  console.log(`  Claude    ${CFG.CLAUDE_SESSION_KEY ? "OK" : "--"}`);
  console.log(`  Ollama    ${CFG.OLLAMA_API_KEY ? "OK" : "--"}${CFG.OLLAMA_SESSION_COOKIE ? " (cookie)" : ""}`);
  console.log(`  Z.AI      ${CFG.ZAI_AUTH_TOKEN ? "OK" : "--"}`);
  console.log(`  Admin     ${CFG.ADMIN_TOKEN ? "OK" : "--"}\n`);
});
