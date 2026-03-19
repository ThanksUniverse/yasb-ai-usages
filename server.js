const express = require("express");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const { Ollama } = require("ollama");

// ── Encryption helpers (AES-256-GCM) ─────────────────────────────
const ENC_KEY_PATH = path.join(__dirname, "data", ".enc.key");
let _encKey = null;
function loadEncKey() {
  if (_encKey) return _encKey;
  try {
    if (fs.existsSync(ENC_KEY_PATH)) {
      const key = fs.readFileSync(ENC_KEY_PATH);
      if (key.length === 32) { _encKey = key; return _encKey; }
    }
  } catch {}
  return null;
}
function ensureEncKey() {
  const existing = loadEncKey();
  if (existing) return existing;
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(ENC_KEY_PATH), { recursive: true });
  fs.writeFileSync(ENC_KEY_PATH, key, { mode: 0o600 });
  _encKey = key;
  return _encKey;
}
function encryptValue(v) {
  const key = ensureEncKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(v, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `ENC:${iv.toString("base64")}:${tag.toString("base64")}:${enc.toString("base64")}`;
}
function decodeStoredValue(v) {
  if (!v || !v.startsWith("ENC:")) return { ok: true, value: v, encrypted: false };
  try {
    const key = loadEncKey();
    if (!key) return { ok: false, encrypted: true, error: `Missing encryption key at ${ENC_KEY_PATH}` };
    const parts = v.slice(4).split(":");
    if (parts.length !== 3) return { ok: false, encrypted: true, error: "Malformed encrypted value" };
    const [ivB64, tagB64, encB64] = parts;
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const enc = Buffer.from(encB64, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return {
      ok: true,
      value: Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8"),
      encrypted: true,
    };
  } catch (error) {
    return { ok: false, encrypted: true, error: error.message };
  }
}
const ENCRYPT_KEYS = new Set([
  "OLLAMA_API_KEY", "OLLAMA_SESSION_COOKIE",
  "CLAUDE_SESSION_KEY", "CHATGPT_ACCESS_TOKEN",
  "GITHUB_TOKEN", "ZAI_AUTH_TOKEN",
  "GEMINI_ACCESS_TOKEN",
]);

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
const DEFAULT_CFG = {
  OLLAMA_API_KEY: "",
  OLLAMA_LOCAL_HOST: "http://localhost:11434",
  OLLAMA_SESSION_COOKIE: "",
  CLAUDE_SESSION_KEY: "",
  CHATGPT_ACCESS_TOKEN: "",
  GITHUB_TOKEN: "",
  ZAI_AUTH_TOKEN: "",
  GEMINI_PROJECT_ID: "",
  GEMINI_ACCESS_TOKEN: "",
  ADMIN_TOKEN: "",
  BIND_HOST: "127.0.0.1",
  PORT: "3456",
};
const CFG = { ...DEFAULT_CFG };
const PERSISTED_CFG = { ...DEFAULT_CFG };
const RAW_PERSISTED_VALUES = new Map();
let CONFIG_LOAD_WARNINGS = [];

function resetConfig(target) {
  for (const [k, v] of Object.entries(DEFAULT_CFG)) target[k] = v;
}

function setPersistedConfigValue(key, value) {
  PERSISTED_CFG[key] = value;
  RAW_PERSISTED_VALUES.delete(key);
}

function saveConfigValue(key, value) {
  CFG[key] = value;
  setPersistedConfigValue(key, value);
}

function loadEnv() {
  const currentAdminToken = CFG.ADMIN_TOKEN;
  resetConfig(CFG);
  resetConfig(PERSISTED_CFG);
  CFG.ADMIN_TOKEN = currentAdminToken;
  RAW_PERSISTED_VALUES.clear();
  CONFIG_LOAD_WARNINGS = [];
  const plaintextSensitiveKeys = new Set();

  if (fs.existsSync(ENV_PATH)) {
    for (const line of fs.readFileSync(ENV_PATH, "utf-8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const k = t.slice(0, eq).trim();
      let v = t.slice(eq + 1).trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (!(k in CFG)) continue;
      const decoded = decodeStoredValue(v);
      if (decoded.ok) {
        CFG[k] = decoded.value;
        PERSISTED_CFG[k] = decoded.value;
        if (ENCRYPT_KEYS.has(k) && decoded.value && !decoded.encrypted) plaintextSensitiveKeys.add(k);
        continue;
      }
      RAW_PERSISTED_VALUES.set(k, v);
      CONFIG_LOAD_WARNINGS.push(`${k}: ${decoded.error}`);
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
  return { plaintextSensitiveKeys: [...plaintextSensitiveKeys] };
}
const envLoad = loadEnv();
if (!CFG.ADMIN_TOKEN) CFG.ADMIN_TOKEN = crypto.randomBytes(24).toString("hex");

// ── Gemini prefs (lightweight key-value store) ─────────────────
const PREFS_PATH = path.join(__dirname, "data", "prefs.json");
let _prefs = {};
function loadPrefs() {
  try { if (fs.existsSync(PREFS_PATH)) _prefs = JSON.parse(fs.readFileSync(PREFS_PATH, "utf-8")); } catch {}
}
function savePref(k, v) {
  _prefs[k] = v;
  try { fs.mkdirSync(path.dirname(PREFS_PATH), { recursive: true }); fs.writeFileSync(PREFS_PATH, JSON.stringify(_prefs, null, 2)); } catch {}
}
loadPrefs();
if (CONFIG_LOAD_WARNINGS.length) {
  for (const warning of CONFIG_LOAD_WARNINGS) {
    console.warn(`[config] Preserving stored value for ${warning}`);
  }
}
if (envLoad.plaintextSensitiveKeys.length && !CONFIG_LOAD_WARNINGS.length) {
  saveEnv();
  console.log(`[config] Encrypted ${envLoad.plaintextSensitiveKeys.length} plaintext secret(s) in .env`);
}

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
  for (const [k, v] of Object.entries(PERSISTED_CFG)) {
    if (k === "PORT" || k === "ADMIN_TOKEN" || k === "BIND_HOST") continue;
    const storedValue = RAW_PERSISTED_VALUES.has(k)
      ? RAW_PERSISTED_VALUES.get(k)
      : (ENCRYPT_KEYS.has(k) && v ? encryptValue(v) : v);
    lines.push(`${k}=${storedValue}`);
  }
  lines.push(`BIND_HOST=${PERSISTED_CFG.BIND_HOST}`);
  lines.push(`PORT=${PERSISTED_CFG.PORT}`, "");
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
      resets_at: fiveH.length ? new Date(fiveH.reduce((m, e) => Math.min(m, e.ts), Infinity) + 5 * 3600 * 1000).toISOString() : null,
    },
    seven_day: {
      requests: sevenD.length,
      prompt_tokens: sum(sevenD, "pt"),
      eval_tokens: sum(sevenD, "et"),
      total_tokens: sum(sevenD, "pt") + sum(sevenD, "et"),
      total_duration_ms: Math.round(sum(sevenD, "dur") / 1e6),
      resets_at: sevenD.length ? new Date(sevenD.reduce((m, e) => Math.min(m, e.ts), Infinity) + 7 * 24 * 3600 * 1000).toISOString() : null,
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

let _gcloudBinary = undefined;
let _detectedGeminiProjectId = undefined;
let _gcloudAccessTokenCache = { token: null, source: null, at: 0, errorAt: 0 };

function runCommand(command, args, timeout = 8000) {
  try {
    const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(String(command));
    const res = spawnSync(command, args, {
      encoding: "utf8",
      timeout,
      windowsHide: true,
      shell: needsShell,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (res.error || res.status !== 0) return null;
    return String(res.stdout || "").trim();
  } catch {
    return null;
  }
}

function findGcloudBinary() {
  if (_gcloudBinary !== undefined) return _gcloudBinary;
  const bins = process.platform === "win32" ? ["gcloud.cmd", "gcloud"] : ["gcloud"];
  for (const bin of bins) {
    const out = runCommand(bin, ["--version"], 4000);
    if (out) {
      _gcloudBinary = bin;
      return _gcloudBinary;
    }
  }
  _gcloudBinary = null;
  return null;
}

function getDetectedGeminiProjectId() {
  if (_detectedGeminiProjectId !== undefined) return _detectedGeminiProjectId;
  const bin = findGcloudBinary();
  if (!bin) return _detectedGeminiProjectId = null;
  const out = runCommand(bin, ["config", "get-value", "project"], 4000);
  if (!out) return _detectedGeminiProjectId = null;
  const trimmed = out.trim();
  if (!trimmed || trimmed === "(unset)" || trimmed === "unset") return _detectedGeminiProjectId = null;
  return _detectedGeminiProjectId = trimmed;
}

function getGeminiProjectId() {
  return String(CFG.GEMINI_PROJECT_ID || "").trim() || getDetectedGeminiProjectId();
}

function getGeminiAccessToken() {
  const envToken = String(CFG.GEMINI_ACCESS_TOKEN || "").trim();
  if (envToken) return { token: envToken, source: "env" };
  return getGcloudAccessToken();
}

function getGcloudAccessToken(forceRefresh = false) {
  const bin = findGcloudBinary();
  const now = Date.now();
  if (!forceRefresh && _gcloudAccessTokenCache.token && now - _gcloudAccessTokenCache.at < 45 * 60 * 1000) {
    return { token: _gcloudAccessTokenCache.token, source: "gcloud" };
  }
  if (bin) {
    const out = runCommand(bin, ["auth", "print-access-token"], 10000);
    if (out) {
      const token = out.trim();
      if (token && !token.startsWith("(")) {
        _gcloudAccessTokenCache = { token, source: "gcloud", at: now, errorAt: 0 };
        return { token, source: "gcloud" };
      }
    }
    _gcloudAccessTokenCache.errorAt = now;
  }
  return { token: null, source: null };
}

async function geminiFetchProject(projectId, token) {
  const r = await apiFetch(`https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(projectId)}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
    timeout: 15000,
  });
  if (!r.ok) return { ok: false, error: r.error || `HTTP ${r.status}`, status: r.status || null };
  return {
    ok: true,
    project: {
      id: r.data?.projectId || projectId,
      number: r.data?.projectNumber ? String(r.data.projectNumber) : null,
      name: r.data?.name || null,
    },
  };
}

function geminiDisplayName(model) {
  const raw = String(model || "").trim();
  if (!raw) return "Unknown";
  if (!raw.startsWith("gemini-")) return raw.replace(/_/g, " ");
  return "Gemini " + raw.slice(7).replace(/-/g, " ").replace(/\b([a-z])/g, s => s.toUpperCase());
}

function geminiCategoryForModel(model) {
  const m = String(model || "").toLowerCase();
  if (m.includes("image")) return "Image models";
  if (m.includes("audio") || m.includes("tts")) return "Audio models";
  if (m.includes("embed")) return "Embedding models";
  return "Text-out models";
}

function isGeminiModel(model) {
  return String(model || "").trim().toLowerCase().startsWith("gemini-");
}

function parseQuotaLimitValue(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return n < 0 ? null : n;
}

function extractQuotaBuckets(metrics, metricType) {
  const metric = (metrics || []).find(m => m.metric === metricType);
  if (!metric) return [];
  const out = [];
  for (const limit of (metric.consumerQuotaLimits || [])) {
    for (const bucket of (limit.quotaBuckets || [])) {
      out.push({
        unit: limit.unit || null,
        metric: limit.metric || metric.metric,
        dimensions: bucket.dimensions || {},
        effectiveLimit: parseQuotaLimitValue(bucket.effectiveLimit),
        defaultLimit: parseQuotaLimitValue(bucket.defaultLimit),
      });
    }
  }
  return out;
}

function pickModelBucket(buckets, model) {
  const specific = buckets.find(b => b.dimensions?.model === model);
  if (specific) return specific;
  return buckets.find(b => !b.dimensions || Object.keys(b.dimensions).length === 0) || null;
}

function buildGeminiUsageMap(timeSeries, allowedLimitNames = []) {
  const map = new Map();
  for (const ts of timeSeries || []) {
    const model = ts.metric?.labels?.model;
    const limitName = ts.metric?.labels?.limit_name || "";
    if (!model) continue;
    if (allowedLimitNames.length && !allowedLimitNames.includes(limitName)) continue;
    const series = parseTimeSeriesPoints([ts]);
    const current = map.get(model) || { points: [], peak: 0, sum: 0 };
    current.points.push(...series.points);
    current.peak = Math.max(current.peak, series.peak);
    current.sum += series.sum;
    current.points.sort((a, b) => String(a.ts || "").localeCompare(String(b.ts || "")));
    map.set(model, current);
  }
  return map;
}

function parseTimeSeriesPoints(timeSeries) {
  const points = [];
  let sum = 0;
  let peak = 0;
  for (const ts of timeSeries || []) {
    for (const point of (ts.points || [])) {
      const raw = point.value?.int64Value ?? point.value?.doubleValue ?? point.value?.stringValue;
      const value = raw === undefined || raw === null ? null : Number(raw);
      if (!Number.isFinite(value)) continue;
      const tsValue = point.interval?.endTime || point.interval?.startTime || null;
      points.push({ ts: tsValue, value });
      sum += value;
      if (value > peak) peak = value;
    }
  }
  points.sort((a, b) => String(a.ts || "").localeCompare(String(b.ts || "")));
  return { points, sum, peak };
}

async function geminiFetchQuotaMetrics(projectId, token) {
  const r = await apiFetch(`https://serviceusage.googleapis.com/v1beta1/projects/${encodeURIComponent(projectId)}/services/generativelanguage.googleapis.com/consumerQuotaMetrics?view=FULL`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
    timeout: 15000,
  });
  if (!r.ok) return { ok: false, error: r.error || `HTTP ${r.status}`, status: r.status || null };
  return { ok: true, metrics: Array.isArray(r.data?.metrics) ? r.data.metrics : [] };
}

async function geminiFetchUsageSeries(projectId, token, metricType) {
  const end = new Date();
  const start = new Date(end.getTime() - 24 * 3600 * 1000);
  const params = new URLSearchParams({
    filter: `metric.type = "${metricType}" AND resource.type = "generativelanguage.googleapis.com/Location" AND resource.labels.location = "global"`,
    "interval.startTime": start.toISOString(),
    "interval.endTime": end.toISOString(),
    view: "FULL",
    pageSize: "1000",
  });
  const r = await apiFetch(`https://monitoring.googleapis.com/v3/projects/${encodeURIComponent(projectId)}/timeSeries?${params.toString()}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
    timeout: 15000,
  });
  if (!r.ok) {
    const notFound = String(r.error || "").includes("Cannot find metric(s)") || Number(r.status) === 404;
    return { ok: false, notFound, error: r.error || `HTTP ${r.status}` };
  }
  return { ok: true, timeSeries: Array.isArray(r.data?.timeSeries) ? r.data.timeSeries : [] };
}

function geminiBuildModelRow(model, quota, usage) {
  const rpm = pickModelBucket(quota.rpmBuckets, model);
  const paidTpm = pickModelBucket(quota.paidTpmBuckets, model);
  const freeTpm = pickModelBucket(quota.freeTpmBuckets, model);
  const tpm = paidTpm || freeTpm;
  const rpd = pickModelBucket(quota.rpdBuckets, model);
  const rpmUsage = usage.rpm.get(model) || { points: [], peak: 0, sum: 0 };
  const tpmUsage = (paidTpm ? usage.tpmPaid : usage.tpmFree).get(model) || { points: [], peak: 0, sum: 0 };
  const rpdUsage = usage.rpd.get(model) || { points: [], peak: 0, sum: 0 };
  const rpmLimit = rpm?.effectiveLimit ?? rpm?.defaultLimit ?? null;
  const tpmLimit = tpm?.effectiveLimit ?? tpm?.defaultLimit ?? null;
  const rpdLimit = rpd?.effectiveLimit ?? rpd?.defaultLimit ?? null;
  const rpmUsed = rpmUsage.peak || 0;
  const tpmUsed = tpmUsage.peak || 0;
  // Use dedicated daily metric when available; fall back to summing today's RPM points (since midnight UTC)
  let rpdUsed = rpdUsage.sum || 0;
  if (rpdUsed === 0 && rpmUsage.points.length > 0) {
    const midnightUTC = new Date();
    midnightUTC.setUTCHours(0, 0, 0, 0);
    rpdUsed = rpmUsage.points
      .filter(p => p.ts && new Date(p.ts) >= midnightUTC)
      .reduce((acc, p) => acc + (p.value || 0), 0);
  }
  const maxPct = Math.max(
    rpmLimit > 0 ? (rpmUsed / rpmLimit) * 100 : 0,
    tpmLimit > 0 ? (tpmUsed / tpmLimit) * 100 : 0,
    rpdLimit > 0 ? (rpdUsed / rpdLimit) * 100 : 0
  );
  return {
    id: model,
    model,
    displayName: geminiDisplayName(model),
    name: geminiDisplayName(model),
    category: geminiCategoryForModel(model),
    maxPct,
    limits: {
      rpm: rpmLimit,
      tpm: tpmLimit,
      rpd: rpdLimit,
    },
    units: {
      rpm: rpm?.unit || null,
      tpm: tpm?.unit || null,
      rpd: rpd?.unit || null,
    },
    series: {
      rpm: {
        metric: "generativelanguage.googleapis.com/quota/generate_requests_per_model/usage",
        peak_24h: rpmUsage.peak || 0,
        sum_24h: rpmUsage.sum || 0,
        points: rpmUsage.points || [],
      },
      tpm: {
        metric: paidTpm
          ? "generativelanguage.googleapis.com/quota/generate_content_paid_tier_input_token_count/usage"
          : "generativelanguage.googleapis.com/quota/generate_content_free_tier_input_token_count/usage",
        peak_24h: tpmUsage.peak || 0,
        sum_24h: tpmUsage.sum || 0,
        points: tpmUsage.points || [],
      },
      rpd: {
        metric: "generativelanguage.googleapis.com/quota/generate_requests_per_model_per_day/usage",
        peak_24h: rpdUsage.peak || 0,
        sum_24h: rpdUsage.sum || 0,
        points: rpdUsage.points || [],
      },
    },
    rpm: {
      limit: rpmLimit,
      used: rpmUsed,
      peak: rpmUsed,
      series: rpmUsage.points || [],
      unit: rpm?.unit || null,
    },
    tpm: {
      limit: tpmLimit,
      used: tpmUsed,
      peak: tpmUsed,
      series: tpmUsage.points || [],
      unit: tpm?.unit || null,
    },
    rpd: {
      limit: rpdLimit,
      used: rpdUsed,
      peak: rpdUsage.peak || 0,
      series: rpdUsage.points || [],
      unit: rpd?.unit || null,
    },
    usage: {
      rpm_peak_24h: rpmUsed,
      rpm_used_24h: rpmUsed,
      tpm_peak_24h: tpmUsed,
      rpd_peak_24h: rpdUsage.peak || 0,
      rpd_used_24h: rpdUsed,
      window_hours: 24,
    },
  };
}

async function _doGeminiUsageFetch() {
  const projectId = getGeminiProjectId();
  if (!projectId) return { configured: false };
  const projectSource = String(CFG.GEMINI_PROJECT_ID || "").trim() ? "env" : "gcloud";
  let auth = getGeminiAccessToken();
  if (!auth.token) {
    return {
      configured: true,
      source: "none",
      hasGcloud: !!findGcloudBinary(),
      project: { id: projectId, source: projectSource, detected: projectSource === "gcloud" },
      projectId,
      auth: { source: "none", hasEnvToken: false, hasGcloud: !!findGcloudBinary() },
      tier: null,
      notes: ["No Google Cloud access token available"],
      models: [],
      summary: null,
      error: "No Gemini Google Cloud access token available",
      hint: "Install/authenticate gcloud or set GEMINI_ACCESS_TOKEN as an optional fallback.",
    };
  }

  let projectR = await geminiFetchProject(projectId, auth.token);

  // If the env token returned 401/403, automatically retry with a fresh gcloud token
  if (!projectR.ok && (projectR.status === 401 || projectR.status === 403) && auth.source === "env") {
    const gcloudAuth = getGcloudAccessToken();
    if (gcloudAuth.token) {
      auth = { ...gcloudAuth, fallback: true };
      projectR = await geminiFetchProject(projectId, auth.token);
    }
  }
  // If gcloud token also got 401, force-refresh (re-run gcloud auth print-access-token)
  if (!projectR.ok && (projectR.status === 401 || projectR.status === 403) && auth.source === "gcloud") {
    const freshAuth = getGcloudAccessToken(true);
    if (freshAuth.token && freshAuth.token !== auth.token) {
      auth = freshAuth;
      projectR = await geminiFetchProject(projectId, auth.token);
    }
  }

  if (!projectR.ok || !projectR.project?.number) {
    const isExpired = projectR.status === 401 || projectR.status === 403;
    return {
      configured: true,
      source: auth.source || "none",
      hasGcloud: !!findGcloudBinary(),
      project: { id: projectId, number: null, name: null, source: projectSource, detected: projectSource === "gcloud" },
      projectId,
      auth: { source: auth.source || "none", hasEnvToken: !!String(CFG.GEMINI_ACCESS_TOKEN || "").trim(), hasGcloud: !!findGcloudBinary() },
      tier: null,
      notes: ["Project metadata lookup failed"],
      models: [],
      summary: null,
      error: projectR.error || "Unable to resolve Gemini project metadata",
      hint: isExpired
        ? "Access token is expired. Clear the Access Token field in Settings and let gcloud manage tokens automatically."
        : "Grant the authenticated Google account project viewer access, or verify GEMINI_PROJECT_ID.",
    };
  }

  const project = { ...projectR.project, source: projectSource, detected: projectSource === "gcloud" };
  const projectRef = project.number;
  const [quotaR, rpmR, tpmPaidR, tpmFreeR, rpdR] = await Promise.all([
    geminiFetchQuotaMetrics(projectRef, auth.token),
    geminiFetchUsageSeries(projectRef, auth.token, "generativelanguage.googleapis.com/quota/generate_requests_per_model/usage"),
    geminiFetchUsageSeries(projectRef, auth.token, "generativelanguage.googleapis.com/quota/generate_content_paid_tier_input_token_count/usage"),
    geminiFetchUsageSeries(projectRef, auth.token, "generativelanguage.googleapis.com/quota/generate_content_free_tier_input_token_count/usage"),
    geminiFetchUsageSeries(projectRef, auth.token, "generativelanguage.googleapis.com/quota/generate_requests_per_model_per_day/usage"),
  ]);

  if (!quotaR.ok) {
    return {
      configured: true,
      source: auth.source || "none",
      hasGcloud: !!findGcloudBinary(),
      project,
      projectId,
      auth: { source: auth.source || "none", hasEnvToken: !!String(CFG.GEMINI_ACCESS_TOKEN || "").trim(), hasGcloud: !!findGcloudBinary() },
      tier: null,
      notes: ["Quota read failed", "Monitoring will not be queried if quota access is missing"],
      models: [],
      summary: null,
      error: quotaR.error || "Unable to read Gemini quotas",
      hint: "Grant the authenticated Google account serviceusage and monitoring read access for the project.",
    };
  }

  const quota = {
    rpmBuckets: extractQuotaBuckets(quotaR.metrics, "generativelanguage.googleapis.com/generate_requests_per_model"),
    paidTpmBuckets: extractQuotaBuckets(quotaR.metrics, "generativelanguage.googleapis.com/generate_content_paid_tier_input_token_count"),
    freeTpmBuckets: extractQuotaBuckets(quotaR.metrics, "generativelanguage.googleapis.com/generate_content_free_tier_input_token_count"),
    rpdBuckets: extractQuotaBuckets(quotaR.metrics, "generativelanguage.googleapis.com/generate_requests_per_model_per_day"),
  };
  const modelNames = new Set();
  for (const buckets of [quota.rpmBuckets, quota.paidTpmBuckets, quota.freeTpmBuckets, quota.rpdBuckets]) {
    for (const bucket of buckets) {
      if (bucket.dimensions?.model && isGeminiModel(bucket.dimensions.model)) modelNames.add(bucket.dimensions.model);
    }
  }

  const usage = {
    rpm: buildGeminiUsageMap(rpmR.ok ? rpmR.timeSeries : [], ["GenerateRequestsPerMinutePerProjectPerModel"]),
    tpmPaid: buildGeminiUsageMap(tpmPaidR.ok ? tpmPaidR.timeSeries : [], ["GenerateContentPaidTierInputTokensPerModelPerMinute"]),
    tpmFree: buildGeminiUsageMap(tpmFreeR.ok ? tpmFreeR.timeSeries : [], ["GenerateContentFreeTierInputTokensPerModelPerMinute"]),
    rpd: buildGeminiUsageMap(rpdR.ok ? rpdR.timeSeries : [], []),
  };

  const models = [...modelNames]
    .map(model => geminiBuildModelRow(model, quota, usage))
    .filter(model => model.limits.rpm != null || model.limits.tpm != null || model.limits.rpd != null)
    .sort((a, b) => (b.maxPct || 0) - (a.maxPct || 0) || a.displayName.localeCompare(b.displayName));
  const preferredModelId = String(_prefs.gemini_selected_model || "").trim();
  const selectedModel = (preferredModelId && models.find(m => m.model === preferredModelId))
    || models.slice().sort((a, b) => {
      const aScore = Math.max(a.maxPct || 0, a.usage.rpm_peak_24h || 0, a.usage.tpm_peak_24h || 0);
      const bScore = Math.max(b.maxPct || 0, b.usage.rpm_peak_24h || 0, b.usage.tpm_peak_24h || 0);
      if (bScore !== aScore) return bScore - aScore;
      return a.displayName.localeCompare(b.displayName);
    })[0] || null;

  return {
    configured: true,
    source: auth.source || "none",
    hasGcloud: !!findGcloudBinary(),
    preferredModelId: String(_prefs.gemini_selected_model || "").trim() || null,
    project,
    projectId,
    auth: {
      source: auth.source || "none",
      hasEnvToken: !!String(CFG.GEMINI_ACCESS_TOKEN || "").trim(),
      hasGcloud: !!findGcloudBinary(),
    },
    tier: null,
    notes: [
      "Quota values come from Service Usage consumerQuotaMetrics",
      "Usage peaks come from Monitoring timeSeries over the last 24h",
      "TPM falls back to the free-tier quota when the paid-tier bucket is missing",
      "RPD uses generate_requests_per_model_per_day/usage; falls back to today's UTC RPM sum if that metric is absent",
    ],
    seriesStatus: {
      rpm: rpmR.ok ? "ok" : (rpmR.notFound ? "missing" : "error"),
      tpm: (tpmPaidR.ok || tpmFreeR.ok) ? "ok" : ((tpmPaidR.notFound || tpmFreeR.notFound) ? "missing" : "error"),
      rpd: rpdR.ok ? "ok" : (rpdR.notFound ? "missing" : "error"),
    },
    models,
    selectedModel,
    summary: selectedModel ? {
      model: selectedModel.displayName,
      modelId: selectedModel.model,
      rpm: Math.round(selectedModel.usage.rpm_peak_24h || 0),
      tpm: Math.round(selectedModel.usage.tpm_peak_24h || 0),
      rpd: Math.round(selectedModel.usage.rpd_used_24h || 0),
      windowHours: 24,
    } : null,
    usage: selectedModel ? {
      rpm: Math.round(selectedModel.usage.rpm_peak_24h || 0),
      tpm: Math.round(selectedModel.usage.tpm_peak_24h || 0),
      rpd: Math.round(selectedModel.usage.rpd_used_24h || 0),
    } : { rpm: 0, tpm: 0, rpd: 0 },
  };
}

app.get("/api/config", (_req, res) => {
  const geminiProjectId = getGeminiProjectId();
  res.json({
    ollama: { configured: !!CFG.OLLAMA_API_KEY, local: CFG.OLLAMA_LOCAL_HOST, hasSessionCookie: !!CFG.OLLAMA_SESSION_COOKIE },
    claude: { configured: !!CFG.CLAUDE_SESSION_KEY },
    chatgpt: { configured: !!CFG.CHATGPT_ACCESS_TOKEN, source: CFG.CHATGPT_ACCESS_TOKEN ? "token" : "none" },
    copilot: { configured: !!CFG.GITHUB_TOKEN },
    zai: { configured: !!CFG.ZAI_AUTH_TOKEN },
    gemini: {
      configured: !!geminiProjectId,
      project: geminiProjectId ? { id: geminiProjectId } : null,
      projectId: geminiProjectId || "",
      hasAccessToken: !!String(CFG.GEMINI_ACCESS_TOKEN || "").trim(),
      hasGcloud: !!findGcloudBinary(),
      source: String(CFG.GEMINI_ACCESS_TOKEN || "").trim() ? "env" : (findGcloudBinary() ? "gcloud" : "none"),
    },
  });
});

app.post("/api/config", requireAdmin, (req, res) => {
  const input = req.body && typeof req.body === "object" ? req.body : {};
  for (const k of Object.keys(CFG)) {
    if (k === "ADMIN_TOKEN") continue;
    if (input[k] === undefined) continue;
    const safe = sanitizeConfigValue(k, input[k]);
    if (safe === null) return res.status(400).json({ ok: false, error: `Invalid value for ${k}` });
    saveConfigValue(k, safe);
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
    saveConfigValue("CHATGPT_ACCESS_TOKEN", token);
    saveEnv();
    res.json({ ok: true, expiry, hint: "Token loaded from ~/.codex/auth.json" });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.get("/api/gemini/usage", async (_req, res) => {
  try {
    res.json(await loadGeminiUsageSnapshot());
  } catch (e) {
    res.json({ configured: !!getGeminiProjectId(), error: e.message });
  }
});

app.post("/api/gemini/set-default", (req, res) => {
  const modelId = String(req.body?.modelId || "").trim();
  savePref("gemini_selected_model", modelId);
  _summaryCache = null;
  _summaryCacheTime = 0;
  _geminiCache = null;
  _geminiCacheTime = 0;
  res.json({ ok: true, modelId: modelId || null });
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
    { id: "gemini", name: "Gemini", accent: "#4285f4" },
  ]);
});

// ── Gemini usage cache (stale-while-revalidate) ────────────────────
let _geminiCache = null;
let _geminiCacheTime = 0;
let _geminiFetch = null;
const GEMINI_CACHE_TTL = 120_000; // 2 min — Google Cloud APIs are slow

async function loadGeminiUsageSnapshot() {
  if (_geminiCache && Date.now() - _geminiCacheTime < GEMINI_CACHE_TTL) return _geminiCache;
  if (_geminiFetch) return _geminiFetch; // deduplicate concurrent requests
  _geminiFetch = _doGeminiUsageFetch()
    .then(r => {
      if (r.configured && !r.error) {
        _geminiCache = r;
        _geminiCacheTime = Date.now();
      } else if (r.error && _geminiCache) {
        // Return stale data on transient API failures rather than going blank
        return { ..._geminiCache, stale: true, staleError: r.error };
      }
      return r;
    })
    .catch(err => {
      if (_geminiCache) return { ..._geminiCache, stale: true, staleError: err.message };
      return { configured: !!getGeminiProjectId(), error: err.message };
    })
    .finally(() => { _geminiFetch = null; });
  return _geminiFetch;
}

// ── YASB summary cache ─────────────────────────────────────────────
let _summaryCache = null;
let _summaryCacheTime = 0;
let _summaryFetch = null;
const SUMMARY_CACHE_TTL = 90_000; // 90 s — widgets poll every 120 s
let _healthCache = null;
let _healthCacheTime = 0;
const HEALTH_CACHE_TTL = 5_000; // match YASB poll interval so all monitors see identical snapshot

const formatSeconds = (s) => {
  if (!s || s <= 0) return "--";
  if (s < 3600) return Math.floor(s / 60) + "m";
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
};
const formatUntil = (iso) => {
  if (!iso) return "--";
  const ms = new Date(iso) - Date.now();
  if (ms <= 0) return "now";
  return formatSeconds(ms / 1000);
};

async function _fetchSummary() {
  const result = {
    chatgpt_session: null, chatgpt_weekly: null, chatgpt_session_reset: null, chatgpt_weekly_reset: null, chatgpt_ok: false,
    copilot_used: null, copilot_total: null, copilot_pct: null, copilot_reset: null, copilot_ok: false,
    claude_session: null, claude_weekly: null, claude_session_reset: null, claude_weekly_reset: null, claude_ok: false,
    ollama_session: null, ollama_weekly: null, ollama_session_reset: null, ollama_weekly_reset: null, ollama_ok: false,
    zai_token_pct: null, zai_mcp_pct: null, zai_ok: false,
    gemini_model: null,
    gemini_rpm_used: null, gemini_rpm_limit: null,
    gemini_tpm_used: null, gemini_tpm_limit: null,
    gemini_rpd_used: null, gemini_rpd_limit: null, gemini_rpd_pct: null, gemini_rpd_reset: null,
    gemini_ok: false,
  };

    const [chatgptR, copilotR, claudeR, ollamaR, zaiR, geminiR] = await Promise.allSettled([
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
      loadGeminiUsageSnapshot(),
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
    const gemini = geminiR.status === "fulfilled" ? geminiR.value : null;
    if (gemini?.configured && gemini?.selectedModel) {
      const sm = gemini.selectedModel;
      result.gemini_model = sm.displayName || sm.model || null;
      result.gemini_rpm_used = Math.round(sm.rpm?.used || 0);
      result.gemini_rpm_limit = sm.rpm?.limit ?? null;
      result.gemini_tpm_used = Math.round(sm.tpm?.used || 0);
      result.gemini_tpm_limit = sm.tpm?.limit ?? null;
      result.gemini_rpd_used = Math.round(sm.rpd?.used || 0);
      result.gemini_rpd_limit = sm.rpd?.limit ?? null;
      result.gemini_rpd_pct = (sm.rpd?.limit > 0) ? Math.round((sm.rpd.used / sm.rpd.limit) * 100) : 0;
      const now = new Date();
      const nextMidnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
      result.gemini_rpd_reset = formatSeconds((nextMidnight - now) / 1000);
      result.gemini_ok = true;
    }
  // Normalize nulls → "--" so YASB labels never render "None"
  for (const k of Object.keys(result)) {
    if (result[k] === null) result[k] = "--";
  }
  _summaryCache = result;
  _summaryCacheTime = Date.now();
  return result;
}

async function computeSummary() {
  if (_summaryCache && Date.now() - _summaryCacheTime < SUMMARY_CACHE_TTL) return _summaryCache;
  if (_summaryFetch) return _summaryFetch; // deduplicate concurrent requests
  _summaryFetch = _fetchSummary().finally(() => { _summaryFetch = null; });
  return _summaryFetch;
}

app.get("/api/yasb/summary", async (_req, res) => {
  try { res.json(await computeSummary()); } catch (e) { res.json({ error: e.message }); }
});

// Per-service endpoints — 204 when not configured (triggers YASB hide_empty)
for (const [svc, okKey] of [
  ["chatgpt", "chatgpt_ok"], ["copilot", "copilot_ok"],
  ["claude", "claude_ok"],   ["ollama",  "ollama_ok"],
  ["zai",    "zai_ok"],
  ["gemini", "gemini_ok"],
]) {
  app.get(`/api/yasb/${svc}`, async (_req, res) => {
    try {
      const data = await computeSummary();
      data[okKey] ? res.json(data) : res.status(204).end();
    } catch { res.status(204).end(); }
  });
}

// Force-refresh — clears all caches then returns fresh data
app.get("/api/yasb/refresh", async (_req, res) => {
  _summaryCache = null;
  _summaryCacheTime = 0;
  _geminiCache = null;
  _geminiCacheTime = 0;
  try { res.json(await computeSummary()); } catch (e) { res.json({ error: e.message }); }
});

app.get("/api/health", (_req, res) => {
  const now = Date.now();
  const updating = !!_summaryFetch;
  // Serve a cached snapshot so all monitors polling within the same 5 s window
  // receive the exact same object — eliminating per-monitor countdown skew.
  // Bust the cache immediately when an update is in flight (updating flag changed).
  if (_healthCache && !updating && !_healthCache.updating && now - _healthCacheTime < HEALTH_CACHE_TTL) {
    return res.json(_healthCache);
  }
  const nextSecs = _summaryCacheTime > 0
    ? Math.max(0, Math.round((SUMMARY_CACHE_TTL - (now - _summaryCacheTime)) / 1000))
    : 0;
  const nextLabel = updating ? "\u22EF" : (nextSecs > 0 ? `${nextSecs}s` : "--");
  _healthCache = { ok: 1, indicator: "\uF111", next_s: nextSecs, next_label: nextLabel, updating };
  _healthCacheTime = now;
  res.json(_healthCache);
});

// Catch unmatched /api/* before SPA fallback — return JSON 404 instead of HTML
app.all("/api/*", (_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = isValidPort(CFG.PORT) ? Number.parseInt(CFG.PORT, 10) : 3456;
const HOST = isValidHost(CFG.BIND_HOST) ? CFG.BIND_HOST : "127.0.0.1";
const server = app.listen(PORT, HOST, () => {
  console.log(`\n  AI Usage Dashboard`);
  console.log(`  http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}\n`);
  console.log(`  ChatGPT   ${CFG.CHATGPT_ACCESS_TOKEN ? "OK" : "--"}`);
  console.log(`  Copilot   ${CFG.GITHUB_TOKEN ? "OK" : "--"}`);
  console.log(`  Claude    ${CFG.CLAUDE_SESSION_KEY ? "OK" : "--"}`);
  console.log(`  Ollama    ${CFG.OLLAMA_API_KEY ? "OK" : "--"}${CFG.OLLAMA_SESSION_COOKIE ? " (cookie)" : ""}`);
  console.log(`  Z.AI      ${CFG.ZAI_AUTH_TOKEN ? "OK" : "--"}`);
  const geminiProject = getGeminiProjectId();
  const geminiAuthSource = String(CFG.GEMINI_ACCESS_TOKEN || "").trim() ? "env" : (findGcloudBinary() ? "gcloud" : "none");
  console.log(`  Gemini    ${geminiProject ? "OK" : "--"}${geminiProject ? ` (${geminiProject})` : ""}${geminiProject ? ` [${geminiAuthSource}]` : ""}`);
  console.log(`  Admin     ${CFG.ADMIN_TOKEN ? "OK" : "--"}\n`);
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`\n  ERROR: Port ${PORT} is already in use. Is the server already running?\n`);
  } else {
    console.error(`\n  ERROR: Server failed to start: ${err.message}\n`);
  }
  process.exit(1);
});

// ── Graceful shutdown ──────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n  [${signal}] Shutting down gracefully...`);
  server.close(() => {
    console.log("  HTTP server closed. Bye.");
    process.exit(0);
  });
  // Force-kill after 5 s to prevent zombie processes
  setTimeout(() => {
    console.error("  Forced exit after 5s timeout.");
    process.exit(1);
  }, 5000).unref();
}
process.on("SIGINT",  () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// ── 24/7 resilience ────────────────────────────────────────────────
process.on("uncaughtException", (err) => {
  console.error(`[fatal] Uncaught exception: ${err.message}`);
  // Don't exit — keep serving other requests
});
process.on("unhandledRejection", (reason) => {
  console.error(`[warn] Unhandled rejection: ${reason?.message || reason}`);
});

// Refresh gcloud project detection every hour so a changed `gcloud config set project`
// is picked up without restarting the server
setInterval(() => {
  _detectedGeminiProjectId = undefined;
}, 3_600_000).unref();
