import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import PDFDocumentImport from "pdfkit";
import { ensureUsersFile, readUsers, findUser, verifyPassword, createToken, setAuthCookie, clearAuthCookie, authMiddleware, requireAuth, requireAdmin } from "./auth.mjs";

const PDFDocument = PDFDocumentImport?.default || PDFDocumentImport;

// --- watsonx IAM token exchange + cache ---
// Watsonx.ai expects an IAM access token in the `Authorization: Bearer ...` header.
// Many users will (reasonably) configure an IBM Cloud API key instead. In that case,
// we exchange the API key for a short-lived IAM access token and cache it until expiry.
//
// If WATSONX_API_KEY already looks like a JWT (starts with "eyJ" and has 3 dot-separated parts),
// we treat it as an IAM token and use it as-is.
const _watsonxIamTokenCache = new Map();

function _looksLikeJwt(token) {
  const s = String(token || "").trim();
  // JWTs are base64url header.payload.signature; most start with "eyJ".
  return s.startsWith("eyJ") && s.split(".").length === 3;
}

async function getWatsonxBearerToken(apiKeyOrToken) {
  const raw = String(apiKeyOrToken || "").trim();
  if (!raw) throw new Error("Missing watsonx API key");
  if (_looksLikeJwt(raw)) return raw;

  const now = Date.now();
  const cached = _watsonxIamTokenCache.get(raw);
  // Refresh 60s before expiry.
  if (cached?.token && cached.expiresAtMs && (cached.expiresAtMs - 60_000) > now) {
    return cached.token;
  }

  const iamUrl = String(process.env.WATSONX_IAM_URL || "https://iam.cloud.ibm.com/identity/token").trim();
  const body = new URLSearchParams();
  body.set("grant_type", "urn:ibm:params:oauth:grant-type:apikey");
  body.set("apikey", raw);

  const r = await fetch(iamUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "accept": "application/json",
    },
    body: body.toString(),
  });

  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch { j = null; }
  if (!r.ok) {
    const msg = j?.error_description || j?.error || txt.slice(0, 600);
    throw new Error(`watsonx IAM token exchange failed: ${msg}`);
  }

  const token = j?.access_token;
  const expiresIn = Number(j?.expires_in || 0);
  if (!token) throw new Error("watsonx IAM token exchange failed: missing access_token");
  const expiresAtMs = now + (expiresIn > 0 ? (expiresIn * 1000) : (55 * 60 * 1000));
  _watsonxIamTokenCache.set(raw, { token, expiresAtMs });
  return token;
}



const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "base-uri": ["'self'"],
      "object-src": ["'none'"],
      // Allow remote images for avatars/favicons entered in the UI.
      "img-src": ["'self'", "data:", "https:", "http:"],
      "font-src": ["'self'", "data:"],
      "style-src": ["'self'"],
      "script-src": ["'self'"],
      "connect-src": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  referrerPolicy: { policy: "no-referrer" },
  crossOriginEmbedderPolicy: false
}));

app.use(morgan("combined"));
app.use(express.json({ limit: "5mb" }));


app.set("trust proxy", 1);

// --- Simple built-in authentication (cookie session) ---
const AUTH_SECRET = process.env.AUTH_SECRET || "change-me-in-prod";
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || "ReAtEt-wAInve-M0UsER";
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || process.env.MCP_URL || null;
const MCP_INTERNAL_TOKEN = process.env.MCP_INTERNAL_TOKEN || process.env.INTERNAL_TOKEN || "";

// If AUTH_SERVER_URL is set, credentials are verified against that server's /api/auth/verify endpoint.
// Otherwise, this app keeps its own local users.json (same format as MCP server).
const USERS_FILE = path.join(process.env.DATA_DIR || "/data", "users.json");
if (!AUTH_SERVER_URL) {
  ensureUsersFile(USERS_FILE, DEFAULT_ADMIN_PASSWORD);
}

app.use(authMiddleware(AUTH_SECRET));

// Protect all /api routes except auth + health
app.use((req, res, next) => {
  if (req.path.startsWith("/api") &&
      !req.path.startsWith("/api/auth") &&
      req.path !== "/api/health") {
    return requireAuth()(req, res, next);
  }
  return next();
});

// ---- Auth endpoints ----
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  try {
    let role = "user";
    let uname = String(username || "").trim();
    if (AUTH_SERVER_URL) {
      const r = await fetch(`${AUTH_SERVER_URL.replace(/\/$/, "")}/api/auth/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: uname, password })
      });
      if (!r.ok) return res.status(401).json({ error: "invalid_credentials" });
      const data = await r.json();
      role = data.role || role;
      uname = data.username || uname;
    } else {
      const users = readUsers(USERS_FILE);
      const u = findUser(users, uname);
      if (!u || !verifyPassword(password, u.salt, u.hash)) {
        return res.status(401).json({ error: "invalid_credentials" });
      }
      role = u.role || role;
      uname = u.username || uname;
    }

    const token = createToken(AUTH_SECRET, uname, role);
    const secure = String(process.env.COOKIE_SECURE || "").toLowerCase() === "true";
    setAuthCookie(res, token, secure);
    return res.json({ username: uname, role });
  } catch (e) {
    console.error("login error", e);
    return res.status(500).json({ error: "auth_error" });
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "unauthorized" });
  res.json(req.user);
});

app.post("/api/auth/logout", (req, res) => {
  const secure = String(process.env.COOKIE_SECURE || "").toLowerCase() === "true";
  clearAuthCookie(res, secure);
  res.json({ ok: true });
});

// Lightweight auth mode introspection for the UI.
// (kept under /api/auth so it remains reachable even when /api is protected)
app.get("/api/auth/info", (_req, res) => {
  res.json({
    mode: AUTH_SERVER_URL ? "remote" : "local",
    authServerUrl: AUTH_SERVER_URL ? String(AUTH_SERVER_URL) : null,
  });
});

// Help HTML is served by the backend so it also works in deployments where SPA routing
// or static asset paths are restricted. If MCP_URL is configured, we try to reuse the
// MCP Server help content; otherwise we fall back to a local built-in copy.
const LOCAL_HELP_HTML = `<!doctype html><html><body>
<h1>Maximo AI Agent Help &amp; UI Guide</h1>
<p>This page explains how the <strong>Maximo AI Agent</strong> works end-to-end and what you can do in the UI.</p>
<hr />
<h2>1. Architecture – How the AI Agent Works</h2>
<p>The AI Agent is the user-facing application that turns natural-language instructions into structured actions. It can operate in two main ways:</p>
<ul>
  <li><strong>Direct Maximo mode</strong> – the agent calls Maximo REST endpoints directly (when configured).</li>
  <li><strong>MCP mode</strong> – the agent delegates actions to the <strong>MCP Server</strong>, which exposes a governed toolset and handles Maximo REST translation.</li>
</ul>
<h2>2. UI Pages</h2>
<ul>
  <li><strong>Chat</strong> – primary interface for asking questions and requesting actions.</li>
  <li><strong>MCP Tool Orchestration</strong> – configure MCP URL and validate tool connectivity.</li>
  <li><strong>Settings</strong> – configure Maximo and AI provider/model.</li>
</ul>
<h2>3. Troubleshooting</h2>
<ul>
  <li>If tool calls fail, verify Maximo base URL / API key (direct mode) or MCP URL (MCP mode).</li>
  <li>For governance and auditing, prefer <strong>MCP mode</strong> so actions are visible in MCP logs/traces.</li>
</ul>
</body></html>`;

app.get("/api/help", async (_req, res) => {
  try {
    const mcpUrl = (process.env.MCP_URL || "").trim();
    if (mcpUrl) {
      const r = await fetch(`${mcpUrl.replace(/\/$/, "")}/api/help`, { method: "GET" });
      if (r.ok) {
        const html = await r.text();
        res.type("text/html").send(html);
        return;
      }
    }
  } catch (e) {
    console.warn("help proxy failed; using local help", e?.message || e);
  }
  res.type("text/html").send(LOCAL_HELP_HTML);
});


const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || "/data";
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");

function envSettings() {
  return {
    maximo_url: process.env.MAXIMO_URL,
    maximo_apikey: process.env.MAXIMO_APIKEY,
    maximo_user: process.env.MAXIMO_USER,
    maximo_password: process.env.MAXIMO_PASSWORD,
    default_siteid: process.env.DEFAULT_SITEID,
    maximo_tenant: process.env.MAXIMO_TENANT || "default",
    tenants: process.env.TENANTS_JSON ? JSON.parse(process.env.TENANTS_JSON) : undefined,
    enable_mcp_tools: process.env.ENABLE_MCP_TOOLS === "true" || process.env.ENABLE_MCP_TOOLS === "1",
    mcp_url: process.env.MCP_URL,
    openai_key: process.env.OPENAI_API_KEY,
    openai_base: process.env.OPENAI_BASE,
    anthropic_key: process.env.ANTHROPIC_API_KEY,
    anthropic_base: process.env.ANTHROPIC_BASE,
    gemini_key: process.env.GEMINI_API_KEY,
    gemini_base: process.env.GEMINI_BASE,
    mistral_key: process.env.MISTRAL_API_KEY,
    mistral_base: process.env.MISTRAL_BASE,
    deepseek_key: process.env.DEEPSEEK_API_KEY,
    deepseek_base: process.env.DEEPSEEK_BASE,
    watsonx_api_key: process.env.WATSONX_API_KEY,
    watsonx_region: process.env.WATSONX_REGION,
    watsonx_project: process.env.WATSONX_PROJECT,
    watsonx_base: process.env.WATSONX_BASE
  };
}


function readFileSettings() {
  try {
    if (!fs.existsSync(SETTINGS_FILE)) return {};
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function writeFileSettings(obj) {
  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(obj, null, 2), "utf-8");
}

function mergeDeep(base, override) {
  if (override === undefined) return base;
  if (override === null) return override;
  if (Array.isArray(base) || Array.isArray(override)) return Array.isArray(override) ? override : base;
  if (typeof base !== "object" || typeof override !== "object") return override;
  const out = { ...(base || {}) };
  for (const [k, v] of Object.entries(override || {})) {
    if (v && typeof v === "object" && !Array.isArray(v) && out[k] && typeof out[k] === "object" && !Array.isArray(out[k])) {
      out[k] = mergeDeep(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function redactSecrets(settings) {
  const s = mergeDeep({}, settings || {});
  // Nested Maximo secrets
  if (s.maximo) {
    delete s.maximo.apiKey;
    delete s.maximo.password;
  }
  // Nested AI provider secrets
  if (s.ai) {
    delete s.ai.apiKey;
    delete s.ai.openaiKey;
    delete s.ai.anthropicKey;
    delete s.ai.geminiKey;
    delete s.ai.mistralKey;
    delete s.ai.deepseekKey;
    delete s.ai.watsonxApiKey;
  }
  // Flat env-style keys (kept for backward compatibility in code)
  const flatKeys = [
    "maximo_apikey","maximo_password","openai_key","anthropic_key","gemini_key",
    "mistral_key","deepseek_key","watsonx_api_key"
  ];
  for (const k of flatKeys) delete s[k];
  return s;
}

function getEffectiveSettings(requestSettings) {
  // Global baseline = env vars + settings.json; requestSettings can override per-request fields.
  const base = normalizeServerSettings(mergeDeep(envSettings(), readFileSettings()));
  return normalizeServerSettings(mergeDeep(base, requestSettings || {}));
}

function normalizeServerSettings(input) {
  const s = mergeDeep({}, input || {});
  // Map flat env-style settings into nested objects so both env vars and JSON file work.
  s.maximo = s.maximo && typeof s.maximo === "object" ? s.maximo : {};
  if (!s.maximo.baseUrl && s.maximo_url) s.maximo.baseUrl = s.maximo_url;
  if (!s.maximo.apiKey && s.maximo_apikey) s.maximo.apiKey = s.maximo_apikey;
  if (!s.maximo.defaultSite && s.default_siteid) s.maximo.defaultSite = s.default_siteid;
  if (!s.maximo.defaultTenant && (s.maximo_tenant || s.maximoTenant)) s.maximo.defaultTenant = s.maximo_tenant || s.maximoTenant;

  s.mcp = s.mcp && typeof s.mcp === "object" ? s.mcp : {};
  if (!s.mcp.url && (s.mcp_url || s.mcpUrl)) s.mcp.url = s.mcp_url || s.mcpUrl;

  s.ai = s.ai && typeof s.ai === "object" ? s.ai : {};
  if (!s.ai.provider && s.ai_provider) s.ai.provider = s.ai_provider;
  if (!s.ai.model && s.ai_model) s.ai.model = s.ai_model;

  return s;
}



// --- Tool normalization for OpenAI-compatible tool calling ---
function safeJsonParse(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// Normalize an MCP Server URL so callers can paste either the base URL
// (e.g. https://host:3001) OR a path like /mcp, /mcp/call, /mcp/tools.
function normalizeMcpBaseUrl(input) {
  let s = String(input || "").trim();
  if (!s) return "";
  // Remove trailing slashes.
  s = s.replace(/\/+$/, "");
  // If a full MCP endpoint was pasted, strip it back to the base.
  s = s.replace(/\/mcp(?:\/(?:call|tools|tenants))?$/i, "");
  // Remove trailing slashes again after stripping.
  s = s.replace(/\/+$/, "");
  return s;
}

// --- Maximo Query Synonyms (server-side preprocessor) ---
// The UI can define per-Object-Structure synonym rules that expand common phrases
// (e.g., "not a task", "open", "last 30 days") into OSLC where fragments.
//
// Settings shape (stored in /data/settings.json via /api/settings):
// settings.maximo.querySynonyms = {
//   mxapiwo: [ { phrase:"not a task", where:"parent is null" }, { phrase:"last 30 days", macro:"DATE_RANGE_LAST_N", args:{ field:"changedate", days:30 } } ],
//   mxapisr: [ ... ],
//   mxapipm: [ ... ]
// }
//
// Applied rules are appended to the outgoing oslc.where for `maximo_queryOS`
// calls and logged in server output + attached to MCP call meta.

function _isoStartOfDayUtc(dateObj) {
  const d = new Date(dateObj);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}T00:00:00Z`;
}

function _expandSynonymMacro(rule) {
  const macro = String(rule?.macro || "").trim();
  const args = (rule?.args && typeof rule.args === "object") ? rule.args : {};
  const now = new Date();

  if (macro === "DATE_RANGE_LAST_N") {
    const field = String(args.field || "changedate").trim();
    const days = Number(args.days || 30);
    if (!field || !Number.isFinite(days)) return "";
    const start = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
    return `${field} >= "${_isoStartOfDayUtc(start)}"`;
  }

  if (macro === "BEFORE_TODAY") {
    const field = String(args.field || "nextdate").trim();
    if (!field) return "";
    return `${field} < "${_isoStartOfDayUtc(now)}"`;
  }

  return "";
}

function applyQuerySynonyms({ toolName, toolArgs, userText, settings }) {
  const name = String(toolName || "").trim();
  if (name !== "maximo_queryOS" && name !== "maximo.queryOS") return { args: toolArgs, applied: [] };
  const args = (toolArgs && typeof toolArgs === "object") ? { ...toolArgs } : {};

  const os = String(args.os || "").trim();
  if (!os) return { args, applied: [] };

  const dict = settings?.maximo?.querySynonyms;
  if (!dict || typeof dict !== "object") return { args, applied: [] };

  const rules = Array.isArray(dict?.[os]) ? dict[os] : [];
  if (!rules.length) return { args, applied: [] };

  const userLower = String(userText || "").toLowerCase();
  if (!userLower) return { args, applied: [] };

  const p = (args.params && typeof args.params === "object") ? { ...args.params } : {};
  const whereKey = (p["oslc.where"] != null) ? "params" : "args";
  let where0 = String(p["oslc.where"] || args.where || "").trim();

  const applied = [];

  for (const r of rules) {
    const phrase = String(r?.phrase || "").trim();
    if (!phrase) continue;
    if (!userLower.includes(phrase.toLowerCase())) continue;

    let clause = String(r?.where || "").trim();
    if (!clause && r?.macro) clause = _expandSynonymMacro(r);
    if (!clause) continue;

    // Avoid obvious duplicates.
    const whereLower = where0.toLowerCase();
    if (whereLower.includes(clause.toLowerCase())) continue;

    const needsParens = /\bor\b/i.test(clause);
    const toAppend = needsParens ? `(${clause})` : clause;
    where0 = where0 ? `${where0} and ${toAppend}` : toAppend;
    applied.push({ phrase, clause });
  }

  if (applied.length) {
    if (whereKey === "params") {
      p["oslc.where"] = where0;
      args.params = p;
    } else {
      args.where = where0;
      // Keep params in sync if caller uses both.
      if (Object.keys(p).length) args.params = p;
    }

    try {
      console.info("[synonyms] applied", { os, applied });
    } catch {}
  }

  return { args, applied };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}
function sanitizeToolName(name) {
  const s = String(name || "").trim();
  if (!s) return "";
  // Replace invalid characters with underscore, then collapse repeats.
  return s.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/_+/g, "_").replace(/^_+|_+$/g, "").slice(0, 64) || "tool";
}
function normalizeToolDef(t) {
  const fn = t?.function || t || {};
  const name = sanitizeToolName(fn.name || t?.name);
  const description = fn.description || t?.description || "";
  // Accept various schema fields from MCP servers
  const parameters = fn.parameters || t?.parameters || t?.inputSchema || t?.schema || { type: "object", properties: {}, additionalProperties: true };
  // Ensure JSON-schema object wrapper
  const params = (parameters && typeof parameters === "object") ? parameters : { type: "object", properties: {}, additionalProperties: true };
  if (!params.type) params.type = "object";
  if (!params.properties) params.properties = {};
  return { type: "function", function: { name, description, parameters: params } };
}

/**
 * NEW: infer an "Excel-like" table from common Maximo OSLC responses or generic arrays.
 * Keeps payload bounded: max 24 columns, max 200 rows.
 */
function inferTableFromResult(result) {
  if (!result) return null;

  // Pass-through if already shaped like a table
  if (result?.table && Array.isArray(result.table?.columns) && Array.isArray(result.table?.rows)) {
    return result.table;
  }

  const members =
    (Array.isArray(result?.member) && result.member) ||
    (Array.isArray(result?.["rdfs:member"]) && result["rdfs:member"]) ||
    (Array.isArray(result?.members) && result.members) ||
    (Array.isArray(result?.member) && result.member) ||
    (Array.isArray(result?.response?.member) && result.response.member) ||
    (Array.isArray(result?.response?.members) && result.response.members) ||
    null;

  const pickObjects = (arr) => (Array.isArray(arr) ? arr.filter(x => x && typeof x === "object") : []);

  if (members) {
    const arr = pickObjects(members);
    if (!arr.length) return null;

    const keys0 = Object.keys(arr[0] || {});
    const looksLikeOnlyLinks =
      keys0.length <= 2 &&
      (keys0.includes("href") || keys0.includes("_href") || keys0.includes("rdf:resource") || keys0.includes("rdf:about"));

    if (looksLikeOnlyLinks) return null;

    const allKeys = new Set();
    for (const row of arr.slice(0, 200)) {
      for (const k of Object.keys(row || {})) allKeys.add(k);
    }

    const columns = Array.from(allKeys)
      .filter((k) => !["href", "_href", "rdf:resource", "rdf:about"].includes(k))
      .slice(0, 24);

    const rows = arr.slice(0, 200).map((r) => {
      const o = {};
      for (const c of columns) o[c] = r?.[c];
      return o;
    });

    return { title: "Result", columns, rows };
  }

  if (Array.isArray(result) && result.length && typeof result[0] === "object") {
    const columns = Array.from(new Set(result.slice(0, 200).flatMap((r) => Object.keys(r || {})))).slice(0, 24);
    const rows = result.slice(0, 200).map((r) => {
      const o = {};
      for (const c of columns) o[c] = r?.[c];
      return o;
    });
    return { title: "Result", columns, rows };
  }

  
return null;
}

/**
 * NEW: If args.params["oslc.select"] is present, force the table columns to match that select list exactly
 * (in the same order), regardless of any extra properties returned by Maximo.
 */
function parseOslcSelect(selectStr) {
  if (!selectStr || typeof selectStr !== "string") return null;
  const cols = selectStr.split(",").map(s => s.trim()).filter(Boolean);
  return cols.length ? cols : null;
}

function pickRowByColumns(row, cols) {
  const out = {};
  if (!row || typeof row !== "object") {
    for (const c of cols) out[c] = "";
    return out;
  }
  // Dot-path + case-insensitive lookup (e.g. item.description, invbalances.curbal)
  const getByPath = (obj, pathStr) => {
    if (!obj || typeof obj !== "object") return "";
    const raw = String(pathStr || "").trim();
    if (!raw) return "";

    const parts = raw.split(".").map(p => p.trim()).filter(Boolean);
    if (!parts.length) return "";

    const step = (cur, idx) => {
      if (cur === null || cur === undefined) return undefined;
      if (idx >= parts.length) return cur;

      const key = parts[idx];

      if (Array.isArray(cur)) {
        const vals = cur
          .map(el => step(el, idx))
          .filter(v => v !== undefined && v !== null && String(v).trim() !== "");
        if (!vals.length) return undefined;
        if (vals.length === 1) return vals[0];
        return vals.map(String).join("|");
      }

      if (typeof cur !== "object") return undefined;
      const map = new Map(Object.keys(cur).map(k => [String(k).toLowerCase(), k]));
      const actual = map.get(String(key).toLowerCase());
      if (!actual) return undefined;
      return step(cur[actual], idx + 1);
    };

    const v = step(obj, 0);
    if (v === undefined || v === null) return "";
    if (typeof v === "object") {
      try { return JSON.stringify(v); } catch { return String(v); }
    }
    return v;
  };

  for (const c of cols) out[c] = getByPath(row, c);
  return out;
}

function unwrapMcpToolResult(mcpResult) {
  if (!mcpResult) return mcpResult;

  // Some MCP servers (or reverse proxies / logging wrappers) return the real payload as a JSON string
  // under `responseBody`.
  if (typeof mcpResult.responseBody === "string") {
    const rb = mcpResult.responseBody.trim();
    if (rb) {
      try { return JSON.parse(rb); } catch { /* ignore */ }
    }
  }

  // Some MCP servers return tool results in the standard MCP shape:
  // { content: [ { type: 'text', text: '...json...' } ] }
  if (Array.isArray(mcpResult.content) && mcpResult.content.length) {
    const c = mcpResult.content[0];
    if (c && typeof c === "object") {
      if (c.type === "json") {
        return c.json ?? c.data ?? mcpResult;
      }
      if (c.type === "text" && typeof c.text === "string") {
        const s = c.text.trim();
        // If the text contains JSON, parse it so we can render tables.
        if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
          try { return JSON.parse(s); } catch { /* ignore */ }
        }
      }
    }
  }

  // Some implementations wrap the actual response under `result` or `response`.
  if (mcpResult.result) return mcpResult.result;
  if (mcpResult.response) return mcpResult.response;

  return mcpResult;
}

function tableFromMembersAndSelect(result, cols) {
  if (!cols || !cols.length || !result) return null;

  const members =
    (Array.isArray(result?.member) && result.member) ||
    (Array.isArray(result?.["rdfs:member"]) && result["rdfs:member"]) ||
    (Array.isArray(result?.members) && result.members) ||
    (Array.isArray(result?.member) && result.member) ||
    (Array.isArray(result?.response?.member) && result.response.member) ||
    (Array.isArray(result?.response?.members) && result.response.members) ||
    null;

  if (!Array.isArray(members) || !members.length) return null;

  const arr = members.filter(x => x && typeof x === "object").slice(0, 200);
  if (!arr.length) return null;

  const rows = arr.map(r => pickRowByColumns(r, cols));
  return { title: "Result", columns: cols, rows };
}

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.get("/api/settings", (req, res) => {
  const merged = normalizeServerSettings(mergeDeep(envSettings(), readFileSettings()));
  const role = String(req.user?.role || "user").toLowerCase();
  if (role !== "admin") return res.json(redactSecrets(merged));
  return res.json(merged);
});

app.post("/api/settings", requireAdmin(), (req, res) => {
  const body = req.body || {};
  // Persisting is enabled here because your requirement explicitly asks for shared server-side storage.
  writeFileSettings(body);
  return res.json({ ok: true });
});

// Agent orchestration endpoint remains from prior versions for OpenAI-compatible tool calling

app.post("/api/agent/chat", async (req, res) => {
  // Minimal "streaming" keep-alive: send early bytes + periodic whitespace so upstream
  // proxies (ingress/LB) don't time out while we wait for the LLM/tool orchestration.
  // UI stays unchanged: the final response is still a single JSON document; leading
  // whitespace is valid JSON and won't break `response.json()`.
  const KEEPALIVE_MS = Number(process.env.AGENT_STREAM_KEEPALIVE_MS || 15000);
  let _kaTimer = null;

  const _stopKeepAlive = () => {
    if (_kaTimer) {
      clearInterval(_kaTimer);
      _kaTimer = null;
    }
  };

  const _startKeepAlive = () => {
    if (res.headersSent) return;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("X-Accel-Buffering", "no");
    if (typeof res.flushHeaders === "function") res.flushHeaders();
    try { res.write(" "); } catch {}

    _kaTimer = setInterval(() => {
      if (res.writableEnded) return _stopKeepAlive();
      try { res.write("\n "); } catch { _stopKeepAlive(); }
    }, KEEPALIVE_MS);

    res.on("close", _stopKeepAlive);
    res.on("finish", _stopKeepAlive);
  };

  // Finalize a JSON response safely after keep-alive writes.
  // IMPORTANT: Do not call _finalJson()/res.send() after res.write(), otherwise Content-Length can mismatch.
  const _finalJson = (obj) => {
    _stopKeepAlive();
    if (res.writableEnded) return;
    try {
      // Headers were already flushed; finish with a single JSON document.
      res.end(JSON.stringify(obj));
    } catch {
      try { res.end(); } catch {}
    }
  };


  try {
    _startKeepAlive();

    const provider = String(req.body?.provider || "openai").toLowerCase();
    const model = String(req.body?.model || "").trim();
    const system = String(req.body?.system || "").trim();
    const temperature = Number.isFinite(Number(req.body?.temperature)) ? Number(req.body.temperature) : 0.7;
    const text = String(req.body?.text || "").trim();
    const action = req.body?.action || null;
    const settings = getEffectiveSettings(req.body?.settings || {});
    const mcp = settings.mcp || {};
    const enableTools = !!mcp.enableTools;
    const mcpUrl = normalizeMcpBaseUrl(mcp.url);
    const tenant = (settings.maximo?.defaultTenant || settings.maximo_tenant || "default").toString();

    const secrets = settings.secrets || settings;

    const getKey = (k, envk, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || "").trim();
    const getBase = (k, envk, defv, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || defv || "").trim().replace(/\/$/,"");

    const messages = [];
    if (system) messages.push({ role: "system", content: system });
    messages.push({ role: "user", content: text });

    // When MCP tools are used, we attach the last tool JSON in the response
    // so the UI can offer "Analyze/Summarize last response".
    let lastToolResult = null;

    // ---- OpenAI-compatible chat (OpenAI/Mistral/DeepSeek) ----
    async function openaiCompatChat(base, apiKey, compatModel, tools) {
      const url = `${base}/v1/chat/completions`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: compatModel || model || "gpt-4o-mini",
          temperature,
          messages,
          tools: tools?.length ? tools : undefined,
          tool_choice: tools?.length ? "auto" : undefined
        })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j = null;
      if (ct.includes("application/json")) { try { j = JSON.parse(raw) } catch { j = null } }
      if (!r.ok) throw new Error(j?.error?.message || raw.slice(0,400));
      return j;
    }

    // ---- Anthropic messages API (minimal) ----
    async function anthropicChat(apiKey, anthropicModel) {
      const base = getBase("anthropic_base", "ANTHROPIC_BASE", "https://api.anthropic.com");
      const url = `${base}/v1/messages`;
      const r = await fetch(url, {
        method:"POST",
        headers: {
          "content-type":"application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify({
          model: anthropicModel || model || "claude-3-5-sonnet-latest",
          max_tokens: 1024,
          temperature,
          system: system || undefined,
          messages: [{ role:"user", content: text }]
        })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j = null;
      if (ct.includes("application/json")) { try { j = JSON.parse(raw) } catch { j = null } }
      if (!r.ok) throw new Error(j?.error?.message || raw.slice(0,400));
      const out = (j?.content || []).map(x => x?.text).filter(Boolean).join("\n");
      return { reply: out };
    }

    // ---- Gemini generateContent (minimal) ----
    async function geminiChat(apiKey, geminiModel) {
      const base = getBase("gemini_base", "GEMINI_BASE", "https://generativelanguage.googleapis.com");
      const m = geminiModel || model || "gemini-1.5-flash";
      const url = `${base}/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(apiKey)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json" },
        body: JSON.stringify({
          contents: [{ role:"user", parts: [{ text }] }],
          generationConfig: { temperature }
        })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null;
      if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch { j=null } }
      if (!r.ok) throw new Error((j && JSON.stringify(j).slice(0,400)) || raw.slice(0,400));
      const cand = j?.candidates?.[0]?.content?.parts?.map(p=>p.text).filter(Boolean).join("\n") || "";
      return { reply: cand };
    }

    // ---- watsonx text generation (best-effort; depends on instance) ----
    async function watsonxChat(apiKey, wxModel) {
      const base = getBase("watsonx_base", "WATSONX_BASE", "https://us-south.ml.cloud.ibm.com", "WATSONX_BASE_URL");
      const project = getKey("watsonx_project", "WATSONX_PROJECT", "WATSONX_PROJECT_ID");
      if (!project) throw new Error("Missing watsonx project id (watsonx_project)");
      const bearer = await getWatsonxBearerToken(apiKey);
      const wxv = String(process.env.WATSONX_TEXTGEN_VERSION || process.env.WATSONX_API_VERSION || process.env.WATSONX_VERSION || "2025-02-11").trim();
      const url = `${base}/ml/v1/text/generation?version=${encodeURIComponent(wxv)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${bearer}` },
        body: JSON.stringify({
          model_id: wxModel || model || "ibm/granite-13b-chat-v2",
          input: system ? `${system}

User: ${text}
Assistant:` : text,
          parameters: { temperature, max_new_tokens: 1024 },
          project_id: project
        })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null;
      if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch { j=null } }
      if (!r.ok) throw new Error(raw.slice(0,400));
      const out = j?.results?.[0]?.generated_text || "";
      return { reply: out };
    }

    
    // ---- Provider-agnostic single-shot completion (used for action summaries and tool-planning) ----
    async function callProviderOnce(promptText, tempOverride = temperature) {
      const p = String(provider || "openai").toLowerCase();
      if (openaiCompatProviders.has(p)) {
        const keyName = p === "openai" ? "openai_key" : (p === "mistral" ? "mistral_key" : "deepseek_key");
        const baseName = p === "openai" ? "openai_base" : (p === "mistral" ? "mistral_base" : "deepseek_base");
        const apiKey = getKey(keyName, p.toUpperCase() + "_API_KEY");
        const baseDefault = (p === "openai") ? "https://api.openai.com" : (p === "mistral" ? "https://api.mistral.ai" : "");
        const base = getBase(baseName, p.toUpperCase() + "_BASE", baseDefault) || (p === "mistral" ? String(process.env.MISTRAL_BASE_URL||"").trim().replace(/\/$/,"") : "");
        if (!apiKey) throw new Error(`Missing ${p} API key`);
        if (!base) throw new Error(`Missing ${p} base URL`);
        const url = `${base}/v1/chat/completions`;
        const r = await fetch(url, {
          method: "POST",
          headers: { "content-type":"application/json", "authorization": `Bearer ${apiKey}` },
          body: JSON.stringify({
            model: model || (p === "openai" ? "gpt-4o-mini" : undefined),
            temperature: tempOverride,
            messages: [
              ...(system ? [{ role: "system", content: system }] : []),
              { role: "user", content: String(promptText || "") }
            ],
          })
        });
        const raw = await r.text();
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
        if (!r.ok) throw new Error(j?.error?.message || raw.slice(0,600));
        return j?.choices?.[0]?.message?.content || "";
      }

      if (p === "anthropic") {
        const apiKey = getKey("anthropic_key","ANTHROPIC_API_KEY");
        if (!apiKey) throw new Error("Missing anthropic API key");
        const base = getBase("anthropic_base","ANTHROPIC_BASE","https://api.anthropic.com");
        const r = await fetch(`${base}/v1/messages`, {
          method:"POST",
          headers: { "content-type":"application/json", "x-api-key": apiKey, "anthropic-version":"2023-06-01" },
          body: JSON.stringify({
            model: model || "claude-3-5-sonnet-latest",
            max_tokens: 1024,
            temperature: tempOverride,
            ...(system ? { system } : {}),
            messages: [{ role:"user", content: String(promptText || "") }]
          })
        });
        const raw = await r.text();
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
        if (!r.ok) throw new Error(j?.error?.message || raw.slice(0,600));
        return (j?.content || []).map(x => x?.text).filter(Boolean).join("\n");
      }

      if (p === "gemini") {
        const apiKey = getKey("gemini_key","GEMINI_API_KEY");
        if (!apiKey) throw new Error("Missing gemini API key");
        const base = getBase("gemini_base","GEMINI_BASE","https://generativelanguage.googleapis.com");
        const m = model || "gemini-1.5-flash";
        const url = `${base}/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(apiKey)}`;
        const fullText = system ? `${system}\n\n${String(promptText || "")}` : String(promptText || "");
        const r = await fetch(url, {
          method:"POST",
          headers:{ "content-type":"application/json" },
          body: JSON.stringify({ contents: [{ role:"user", parts:[{ text: fullText }] }], generationConfig:{ temperature: tempOverride } })
        });
        const raw = await r.text();
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
        if (!r.ok) throw new Error((j && JSON.stringify(j).slice(0,600)) || raw.slice(0,600));
        return j?.candidates?.[0]?.content?.parts?.map(p=>p.text).filter(Boolean).join("\n") || "";
      }

      if (p === "watsonx") {
        const apiKey = getKey("watsonx_api_key","WATSONX_API_KEY");
        if (!apiKey) throw new Error("Missing watsonx API key");
        const base = getBase("watsonx_base","WATSONX_BASE","https://us-south.ml.cloud.ibm.com","WATSONX_BASE_URL");
        const project = getKey("watsonx_project","WATSONX_PROJECT","WATSONX_PROJECT_ID");
        if (!project) throw new Error("Missing watsonx project id (watsonx_project)");
        const bearer = await getWatsonxBearerToken(apiKey);
        const wxv = String(process.env.WATSONX_TEXTGEN_VERSION || process.env.WATSONX_API_VERSION || process.env.WATSONX_VERSION || "2025-02-11").trim();
      const url = `${base}/ml/v1/text/generation?version=${encodeURIComponent(wxv)}`;
        const fullText = system ? `${system}\n\nUser: ${String(promptText || "")}\nAssistant:` : String(promptText || "");
        const r = await fetch(url, {
          method:"POST",
          headers:{ "content-type":"application/json", "authorization": `Bearer ${bearer}` },
          body: JSON.stringify({
            model_id: model || "ibm/granite-13b-chat-v2",
            input: fullText,
            parameters: { temperature: tempOverride, max_new_tokens: 1024 },
            project_id: project
          })
        });
        const raw = await r.text();
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
        if (!r.ok) throw new Error(raw.slice(0,600));
        return j?.results?.[0]?.generated_text || "";
      }

      throw new Error(`Unsupported provider: ${p}`);
    }

    function extractJsonObject(text) {
      const s = String(text || "").trim();
      const direct = safeJsonParse(s);
      if (direct) return direct;
      const m = s.match(/\{[\s\S]*\}/);
      if (m) return safeJsonParse(m[0]);
      return null;
    }


// Tool orchestration supported for OpenAI-compatible providers only (OpenAI/Mistral/DeepSeek).
// For other providers (Gemini/Anthropic/Watsonx), we implement a fast "tool-first" fallback:
// infer a Maximo OS from the user's text, call MCP `maximo_queryOS`, and return the table/result.
const openaiCompatProviders = new Set(["openai","mistral","deepseek"]);


// ---- Action shortcuts from the UI (still routed through the AI provider for the final reply) ----
if (action && enableTools && mcpUrl) {
  try {
    const at = String(action?.type || "").toLowerCase();
    const maximo = settings?.maximo || {};
    const defaultTenant = String(maximo?.defaultTenant || settings?.maximo_tenant || "default");
    const actTenant = String(action?.tenant || tenant || defaultTenant || "default");

    let toolName = "";
    let toolArgs = null;

    if (at === "query_preset") {
      const presetId = String(action?.presetId || "").trim();
      const presets = Array.isArray(maximo?.queryPresets) ? maximo.queryPresets : [];
      const preset = presets.find(p => String(p?.id) === presetId);
      if (!preset) return _finalJson({ error: "preset_not_found", detail: `Preset not found: ${presetId}` });

      const defaultSite = String(maximo?.defaultSite || "").trim().toUpperCase();
      const where = String(preset?.where || "").replace(/\{siteid\}/g, defaultSite);
      const select = String(preset?.select || "").replace(/\{siteid\}/g, defaultSite);
      const orderBy = String(preset?.orderBy || "").trim();
      const pageSize = Number(preset?.pageSize || 50);

      toolName = "maximo_queryOS";
      toolArgs = {
        os: String(preset?.os || "").trim(),
        lean: true,
        ...(where ? { where } : {}),
        ...(select ? { params: { "oslc.select": select } } : {}),
        ...(orderBy ? { params: { ...(select ? { "oslc.select": select } : {}), "oslc.orderBy": orderBy } } : {}),
        ...(Number.isFinite(pageSize) ? { pageSize } : {})
      };

      // Merge params if both select+orderby provided
      if (select && orderBy) {
        toolArgs.params = { "oslc.select": select, "oslc.orderBy": orderBy };
      }
    } else if (at === "create_record") {
      const rt = String(action?.recordType || action?.record_type || "").toLowerCase();
      const site = String(action?.site || "").trim().toUpperCase();
      const assetnum = String(action?.assetnum || "").trim();
      const priority = action?.priority != null ? String(action.priority).trim() : "";
      const description = String(action?.description || "").trim();
      if (!site || !description) return _finalJson({ error: "missing_fields", detail: "site and description are required" });
      toolName = (rt === "sr") ? "maximo_createSR" : "maximo_createWO";
      toolArgs = { site, description, ...(assetnum ? { assetnum } : {}), ...(priority ? { priority } : {}) };
    } else if (at === "query_os") {
      toolName = "maximo_queryOS";
      toolArgs = action?.args || null;
    } else {
      return _finalJson({ error: "unknown_action", detail: `Unknown action: ${at}` });
    }

    if (!toolName || !toolArgs) return _finalJson({ error: "bad_action", detail: "Missing tool mapping for action." });

    const callResp = await fetchWithTimeout(`${mcpUrl}/mcp/call`, {
      method:"POST",
      headers:{
        "content-type":"application/json",
        "x-ai-provider": String(provider || ""),
        "x-ai-model": String(model || ""),
      },
      body: JSON.stringify({ name: toolName, args: toolArgs, userText: text, tenant: actTenant, meta: { aiProvider: provider, aiModel: model, action: at,  } })
    }, 30000);

    const callRaw = await callResp.text();
    const callJson = safeJsonParse(callRaw) || { error: "mcp_parse_failed", detail: callRaw.slice(0, 800), status: callResp.status };
    if (!callResp.ok) {
      // Preserve exact Maximo/MCP error so the UI can show it.
      return _finalJson({ error: "mcp_call_failed", detail: callJson?.error?.message || callJson?.message || callRaw.slice(0,800), status: callResp.status, lastToolResult: callJson });
    }

    const unwrapped = unwrapMcpToolResult(callJson);
    lastToolResult = unwrapped;

    const table =
      (unwrapped && typeof unwrapped === "object" && unwrapped.table && Array.isArray(unwrapped.table.columns) && Array.isArray(unwrapped.table.rows)
        ? { columns: unwrapped.table.columns, rows: unwrapped.table.rows }
        : null) ||
      inferTableFromResult(callJson) ||
      null;

    const jsonText = (() => { try { return JSON.stringify(unwrapped, null, 2); } catch { return String(unwrapped); } })();
    const clipped = jsonText.length > 120000 ? jsonText.slice(0, 120000) + "\n...[truncated]" : jsonText;

    let promptText = `You are the Maximo AI Agent. The user asked:\n\n${text}\n\n` +
      `A Maximo/MCP tool was executed:\n- tool: ${toolName}\n- args: ${JSON.stringify(toolArgs)}\n\n` +
      `Tool result (JSON):\n${clipped}\n\n` +
      `Write a friendly, concise response to the user. If this created a record, confirm the identifier. If this is a list, state how many rows and what it represents.`;

    let reply = "";
    try {
      reply = await callProviderOnce(promptText, temperature);
    } catch (e) {
      // If the provider is unavailable, still return tool output with a deterministic message.
      reply = `Action completed via ${toolName}. (AI provider unavailable: ${String(e?.message || e)})`;
    }

    return _finalJson({
      reply,
      table: table || undefined,
      trace: { action: at, tool: toolName, args: toolArgs, tenant: actTenant },
      lastToolResult
    });
  } catch (e) {
    return _finalJson({ error: "action_failed", detail: String(e?.message || e) });
  }
}


// ----- Agent-side defaults (Option B): keep inferred columns in sync with MCP OS_DEFAULTS -----
// These columns are sent as args.columns so the MCP server will translate them into oslc.select.
// (We keep them as arrays here for easier manipulation.)
const OS_DEFAULTS_AGENT = {
  mxapiasset: {
    columns: ["assetnum","description","status","siteid","orgid","location","assettype","serialnum","priority","changedate"],
    pageSize: 50,
  },
  mxapilocations: {
    columns: ["location","description","status","siteid","orgid","parent","loctype","type","changedate"],
    pageSize: 50,
  },
  mxapiwo: {
    columns: ["wonum","description","status","worktype","priority","siteid","orgid","assetnum","location","reportdate","targstartdate","targcompdate","changedate"],
    pageSize: 50,
  },
  mxapisr: {
    columns: ["ticketid","description","status","class","priority","siteid","orgid","assetnum","location","reportedby","reportdate","changedate"],
    pageSize: 50,
  },
  mxapipm: {
    columns: ["pmnum","description","status","siteid","orgid","location","assetnum","freq","frequency","worktype","nextdate","changedate"],
    pageSize: 50,
  },
  mxapijobplan: {
    columns: ["jpnum","description","status","siteid","orgid","pluscrevnum","changedate"],
    pageSize: 50,
  },
  mxapiinspectionres: {
    columns: ["inspectionresultid","inspectionformnum","status","siteid","orgid","assetnum","location","createdate","changedate"],
    pageSize: 50,
  },
  mxapipr: {
    columns: ["prnum","description","status","siteid","orgid","requestor","prdate","totalcost","changedate"],
    pageSize: 50,
  },
  mxapipo: {
    columns: ["ponum","description","status","siteid","orgid","vendor","orderdate","totalcost","changedate"],
    pageSize: 50,
  },
  mxapiinventory: {
    // NOTE: keep dot-paths — MCP server & agent both support dot-path projection.
    columns: ["itemnum","item.description","status","issueunit","location","invbalances.curbal","changedate"],
    pageSize: 25,
  },
};

const inferOsAndColumns = (userText) => {
  const t = String(userText || "").toLowerCase();

  // MAS Manage commonly exposes OS names prefixed with `mxapi*` (e.g. /api/os/mxapipm).
  // We'll prefer mxapi* names but still allow fallback to mx* if mxapi* isn't present.
  if (t.includes("preventive maintenance") || /\bpms?\b/.test(t) || /\bpm\b/.test(t)) {
    return { os: "mxapipm", fallbackOs: "mxpm", ...OS_DEFAULTS_AGENT.mxapipm };
  }
  if (t.includes("job plan") || t.includes("jobplan") || /\bjps?\b/.test(t) || /\bjp\b/.test(t)) {
    return { os: "mxapijobplan", fallbackOs: "mxjobplan", ...OS_DEFAULTS_AGENT.mxapijobplan };
  }
  if (t.includes("location") || /\bloc\b/.test(t)) {
    // FIX: OS name must match MCP defaults key: mxapilocations (plural)
    return { os: "mxapilocations", fallbackOs: "mxlocations", ...OS_DEFAULTS_AGENT.mxapilocations };
  }
  if (t.includes("service request") || /\bsr\b/.test(t)) {
    return { os: "mxapisr", fallbackOs: "mxsr", ...OS_DEFAULTS_AGENT.mxapisr };
  }
  // Work Orders
  // NOTE: we handle corrective/open filters elsewhere, but OS is still mxapiwo.
  if (t.includes("work order") || t.includes("workorder") || /\bwo\b/.test(t)) {
    return { os: "mxapiwo", fallbackOs: "mxwo", ...OS_DEFAULTS_AGENT.mxapiwo };
  }
  if (t.includes("inventory") || t.includes("item") || /\binv\b/.test(t)) {
    return { os: "mxapiinventory", fallbackOs: "mxinventory", ...OS_DEFAULTS_AGENT.mxapiinventory };
  }

  // Default to assets
  return { os: "mxapiasset", fallbackOs: "mxasset", ...OS_DEFAULTS_AGENT.mxapiasset };
};


if (enableTools && mcpUrl && !openaiCompatProviders.has(provider)) {
  try {
    // Provider-first tool planning (for providers without native OpenAI tool-calling).
    const toolsResp = await fetchWithTimeout(`${mcpUrl}/mcp/tools?tenant=${encodeURIComponent(tenant)}`, {
      headers: {
        accept: "application/json",
        "x-ai-provider": String(provider || ""),
        "x-ai-model": String(model || ""),
      },
    }, 15000);
    const toolsRawText = await toolsResp.text();
    const toolsJson = safeJsonParse(toolsRawText) || {};
    const rawTools = Array.isArray(toolsJson?.tools) ? toolsJson.tools : [];

    const allowedToolNames = new Set([
      "maximo_queryOS",
      "maximo_createWO",
      "maximo_createSR",
      "maximo_listAssets",
      "maximo_listSites",
      "maximo_listTenants",
    ]);
    const candidateTools = rawTools
      .map(normalizeToolDef)
      .filter(t => t?.function?.name && allowedToolNames.has(t.function.name))
      .slice(0, 16);

    const defaultSite = String(settings?.maximo?.defaultSite || "").trim().toUpperCase();

    const toolLines = candidateTools.map(t => {
      const name = t.function.name;
      const desc = (t.function.description || "").replace(/\s+/g, " ").trim();
      const keys = Object.keys(t.function.parameters?.properties || {}).slice(0, 20);
      return `- ${name}: ${desc}${keys.length ? ` (args: ${keys.join(", ")})` : ""}`;
    }).join("\n");

    const plannerPrompt =
`Return ONLY valid JSON.

If you need to use a tool to answer the user's request, respond with:
{"tool":"<toolName>","args":{...}}

If no tool is needed, respond with:
{"reply":"<your answer>"}

OSLC / Maximo guidance (important):
- Use tool maximo_queryOS for list/search questions against Maximo Object Structures.
- Pick the correct object structure in args.os (examples: mxapiasset, mxapiwo, mxapisr, mxapipm, mxapijobplan).
- args.where must be OSLC where syntax, e.g. status="DECOMMISSIONED" and siteid="BEDFORD".
- If the user says "decommissioned", use status="DECOMMISSIONED".
${defaultSite ? `- If the user didn't specify a site, include siteid="${defaultSite}" in args.where.\n` : ""}- If you set orderBy, use OSLC orderBy syntax with a leading + or -, e.g. +changedate or -reportdate.

Available tools:
${toolLines || "(none)"}

User request:
${text}`;

    const planText = await callProviderOnce(plannerPrompt, 0.2);
    const plan = extractJsonObject(planText) || {};
    if (plan.reply && !plan.tool) {
      return _finalJson({ reply: String(plan.reply) });
    }

    const toolName = String(plan.tool || plan.name || "").trim();
    let toolArgs = plan.args && typeof plan.args === "object" ? plan.args : null;
    if (!toolName || !toolArgs) {
      return _finalJson({ error: "tool_plan_failed", detail: `Could not parse tool plan JSON. Raw: ${String(planText).slice(0,600)}` });
    }

    // Guardrail: inject default site filter when absent and we can safely do so.
    try {
      if (defaultSite && toolName === "maximo_queryOS") {
        const where0 = String(toolArgs.where || toolArgs?.params?.["oslc.where"] || "").trim();
        if (!/\bsiteid\s*=\s*/i.test(where0)) {
          const where = where0 ? `${where0} and siteid="${defaultSite}"` : `siteid="${defaultSite}"`;
          toolArgs.where = where;
        }
      }
    } catch {}

    const callResp = await fetchWithTimeout(`${mcpUrl}/mcp/call`, {
      method:"POST",
      headers:{
        "content-type":"application/json",
        "x-ai-provider": String(provider || ""),
        "x-ai-model": String(model || ""),
      },
      body: JSON.stringify({ name: toolName, args: toolArgs, tenant, meta: { aiProvider: provider, aiModel: model,  } })
    }, 30000);

    const callRaw = await callResp.text();
    const callJson = safeJsonParse(callRaw) || { error: "mcp_parse_failed", detail: callRaw.slice(0, 800), status: callResp.status };
    if (!callResp.ok) {
      return _finalJson({ error: "mcp_call_failed", detail: callJson?.error?.message || callJson?.message || callRaw.slice(0,800), status: callResp.status, lastToolResult: callJson });
    }

    const unwrapped = unwrapMcpToolResult(callJson);
    lastToolResult = unwrapped;

    const table =
      (unwrapped && typeof unwrapped === "object" && unwrapped.table && Array.isArray(unwrapped.table.columns) && Array.isArray(unwrapped.table.rows)
        ? { columns: unwrapped.table.columns, rows: unwrapped.table.rows }
        : null) ||
      inferTableFromResult(callJson) ||
      null;

    const jsonText = (() => { try { return JSON.stringify(unwrapped, null, 2); } catch { return String(unwrapped); } })();
    const clipped = jsonText.length > 120000 ? jsonText.slice(0, 120000) + "\n...[truncated]" : jsonText;

    const answerPrompt =
`User request:
${text}

Tool executed: ${toolName}
Tool args: ${JSON.stringify(toolArgs)}

Tool result (JSON):
${clipped}

Write a helpful answer for the user. If there's a table/list, summarize what it contains and highlight anything important.`;

    const reply = await callProviderOnce(answerPrompt, temperature);

    return _finalJson({ reply, table: table || undefined, trace: { tool: toolName, args: toolArgs }, lastToolResult });
  } catch (e) {
    return _finalJson({ error:"agent_failed", detail:String(e?.message || e).slice(0,800) });
  }
}

if (openaiCompatProviders.has(provider)) {
      const keyName = provider === "openai" ? "openai_key" : (provider === "mistral" ? "mistral_key" : "deepseek_key");
      const baseName = provider === "openai" ? "openai_base" : (provider === "mistral" ? "mistral_base" : "deepseek_base");
      const apiKey = getKey(keyName, provider.toUpperCase() + "_API_KEY");
      const baseDefault = (provider === "openai") ? "https://api.openai.com" : (provider === "mistral" ? "https://api.mistral.ai" : "");
      const base = getBase(baseName, provider.toUpperCase() + "_BASE", baseDefault) || (provider==="mistral" ? String(process.env.MISTRAL_BASE_URL||"").trim().replace(/\/$/,"") : "");
      if (!apiKey) return _finalJson({ error:"missing_api_key", detail:`Missing ${provider} API key` });
      if (!base) return _finalJson({ error:"missing_base", detail:`Missing ${provider} base URL` });

      // no tools: plain chat
      if (!(enableTools && mcpUrl)) {
        const out = await openaiCompatChat(base, apiKey, model, []);
        const reply = out?.choices?.[0]?.message?.content || "";
        return _finalJson({ reply });
      }

      // tools: load from MCP and run tool-call loop
      const toolsResp = await fetchWithTimeout(`${mcpUrl}/mcp/tools?tenant=${encodeURIComponent(tenant)}`, {
        headers: {
          accept: "application/json",
          "x-ai-provider": String(provider || ""),
          "x-ai-model": String(model || ""),
        },
      }, 15000);
      const toolsRawText = await toolsResp.text();
      const toolsJson = safeJsonParse(toolsRawText) || {};
      const rawTools = Array.isArray(toolsJson?.tools) ? toolsJson.tools : [];
      // Convert MCP tool defs into OpenAI-compatible tool objects: { type:"function", function:{name,description,parameters} }
      const tools = rawTools.map(normalizeToolDef).filter(t => t?.type === "function" && t?.function?.name);

      let loopMessages = messages.slice();

      // NEW: track last inferred table from tool outputs
      let lastTable = null;

      for (let i = 0; i < 6; i++) {
        const out = await openaiCompatChat(base, apiKey, model, tools);
        const msg = out?.choices?.[0]?.message || {};
        const toolCalls = msg?.tool_calls || [];
        const content = msg?.content || "";

        // ✅ Return reply + table (if any)
        if (!toolCalls.length) return _finalJson({ reply: content, table: lastTable || undefined, lastToolResult });

        // append assistant with tool_calls
        loopMessages.push({ role:"assistant", content, tool_calls: toolCalls });

        for (const tc of toolCalls) {
          const name = tc?.function?.name;
          const argsStr = tc?.function?.arguments || "{}";
          let args = {};
          try { args = JSON.parse(argsStr) } catch { args = { raw: argsStr } }

          // Heuristic guardrails: if the user asked for corrective work orders, ensure WO queries
          // include worktype=CM (and siteid=defaultSite when available) unless the tool call
          // already provided those filters explicitly.
          try {
            const userLower = String(text || "").toLowerCase();
            const wantsCorrective = userLower.includes("corrective") || /\bcm\b/.test(userLower) || userLower.includes("corrective maintenance");
            const wantsDecommissioned = userLower.includes("decommissioned") || userLower.includes("de-commissioned") || userLower.includes("retired");
            const isQuery = String(name || "") === "maximo_queryOS" || String(name || "") === "maximo.queryOS";
            const osName = String(args?.os || "").toLowerCase();
            const isWoOs = osName.includes("wo") || osName.includes("workorder") || osName === "mxapiwo" || osName === "mxwo";

            const defaultSite = String(settings?.maximo?.defaultSite || "").trim().toUpperCase();

            if (wantsCorrective && isQuery && isWoOs) {
              const p = (args?.params && typeof args.params === "object") ? args.params : {};
              let where = String(p["oslc.where"] || args?.where || "").trim();

              // Default site filter if missing
              if (defaultSite && !/\bsiteid\s*=\s*/i.test(where)) {
                where = where ? `${where} and siteid="${defaultSite}"` : `siteid="${defaultSite}"`;
              }
              // Corrective worktype filter if missing
              if (!/\bworktype\s*=\s*/i.test(where)) {
                where = where ? `${where} and worktype="CM"` : `worktype="CM"`;
              }

              // Write back using the preferred arg field.
              if (p["oslc.where"] != null) {
                p["oslc.where"] = where;
                args.params = p;
              } else {
                args.where = where;
              }
            }
          } catch {}
            // Asset-status guardrail: if the user asks for decommissioned assets and the model calls queryOS,
            // ensure status="DECOMMISSIONED" is applied (unless a status filter already exists).
            try {
              const isQuery2 = String(name || "") === "maximo_queryOS" || String(name || "") === "maximo.queryOS";
              const osName2 = String(args?.os || "").toLowerCase();
              const isAssetOs = osName2.includes("asset") || osName2 === "mxapiasset" || osName2 === "mxasset";

              if (wantsDecommissioned && isQuery2 && isAssetOs) {
                const p2 = (args?.params && typeof args.params === "object") ? args.params : {};
                let where2 = String(p2["oslc.where"] || args?.where || "").trim();

                if (!/\bstatus\s*=\s*/i.test(where2)) {
                  where2 = where2 ? `${where2} and status="DECOMMISSIONED"` : `status="DECOMMISSIONED"`;
                }

                // Default site filter if missing
                const defaultSite2 = String(settings?.maximo?.defaultSite || "").trim().toUpperCase();
                if (defaultSite2 && !/\bsiteid\s*=\s*/i.test(where2)) {
                  where2 = where2 ? `${where2} and siteid="${defaultSite2}"` : `siteid="${defaultSite2}"`;
                }

                if (p2["oslc.where"] != null) {
                  p2["oslc.where"] = where2;
                  args.params = p2;
                } else {
                  args.where = where2;
                }
              }
            } catch {}

          const callResp = await fetchWithTimeout(`${mcpUrl}/mcp/call`, {
            method:"POST",
            headers:{
              "content-type":"application/json",
              "x-ai-provider": String(provider || ""),
              "x-ai-model": String(model || ""),
            },
            body: JSON.stringify({ name, args, userText: text, tenant, meta: { aiProvider: provider, aiModel: model,  } })
          }, 25000);
          const callRaw = await callResp.text();
          const callJson = safeJsonParse(callRaw) || { error: "mcp_parse_failed", detail: callRaw.slice(0, 600), status: callResp.status };
          // Keep last tool result for "Analyze last response".
          try { lastToolResult = unwrapMcpToolResult(callJson); } catch { lastToolResult = callJson; }

          // NEW: If oslc.select was used, force table columns to exactly that select list.
          const selectCols = parseOslcSelect(args?.params?.["oslc.select"]);
          const selectedTable = selectCols ? tableFromMembersAndSelect(callJson, selectCols) : null;

          // Fallback: infer an "Excel-like" table from tool JSON (e.g., OSLC member arrays)
          const maybeTable = selectedTable || inferTableFromResult(callJson);
          if (maybeTable) lastTable = maybeTable;

          loopMessages.push({ role:"tool", tool_call_id: tc.id, content: JSON.stringify(callJson) });
        }

        // update messages reference for next loop
        messages.length = 0;
        loopMessages.forEach(m => messages.push(m));
      }

      // ✅ Return reply + table (if any)
      return _finalJson({ reply: "Tool orchestration exceeded max iterations.", table: lastTable || undefined, lastToolResult });
    }

    if (provider === "anthropic") {
      const apiKey = getKey("anthropic_key","ANTHROPIC_API_KEY");
      if (!apiKey) return _finalJson({ error:"missing_api_key", detail:"Missing anthropic API key" });
      const out = await anthropicChat(apiKey, model);
      return _finalJson(out);
    }

    if (provider === "gemini") {
      const apiKey = getKey("gemini_key","GEMINI_API_KEY");
      if (!apiKey) return _finalJson({ error:"missing_api_key", detail:"Missing gemini API key" });
      const out = await geminiChat(apiKey, model);
      return _finalJson(out);
    }

    if (provider === "watsonx") {
      const apiKey = getKey("watsonx_api_key","WATSONX_API_KEY");
      if (!apiKey) return _finalJson({ error:"missing_api_key", detail:"Missing watsonx API key (bearer/IAM token)" });
      const out = await watsonxChat(apiKey, model);
      return _finalJson(out);
    }

    return _finalJson({ error:"unsupported_provider", detail:`Provider not supported: ${provider}` });
  } catch (e) {
    _stopKeepAlive();
    return _finalJson({ error:"agent_failed", detail:String(e?.message || e) });
  }
});

// Analyze/summarize the last MCP tool response (bypasses MCP orchestration; direct LLM call)
app.post("/api/agent/analyze-last", async (req, res) => {
  try {
    const provider = String(req.body?.provider || "openai").toLowerCase();
    const model = String(req.body?.model || "").trim();
    const system = String(req.body?.system || "").trim();
    const temperature = Number.isFinite(Number(req.body?.temperature)) ? Number(req.body.temperature) : 0.2;
    const lastToolResult = req.body?.lastToolResult;
    const settings = getEffectiveSettings(req.body?.settings || {});
    if (lastToolResult == null) return res.status(400).json({ error: "missing_lastToolResult" });

    const secrets = settings.secrets || settings;
    const getKey = (k, envk, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || "").trim();
    const getBase = (k, envk, defv, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || defv || "").trim().replace(/\/$/,"");

    const jsonText = (() => {
      try { return JSON.stringify(lastToolResult, null, 2); } catch { return String(lastToolResult); }
    })();
    const MAX = Number(process.env.ANALYZE_LAST_MAX_CHARS || 180000);
    const clipped = jsonText.length > MAX ? jsonText.slice(0, MAX) + "\n\n...[truncated]" : jsonText;

    const promptText =
`Analyze and summarize the following JSON response from an MCP/Maximo tool call.

Requirements:
- Give a short summary (2-5 bullets)
- Highlight key fields, anomalies, and next actions
- If it's a table-like result, describe the columns and notable rows
- Be concise but actionable

JSON:\n${clipped}`;

    const messages = [];
    if (system) messages.push({ role: "system", content: system });
    messages.push({ role: "user", content: promptText });

    const openaiCompatProviders = new Set(["openai","mistral","deepseek"]);
    if (openaiCompatProviders.has(provider)) {
      const keyName = provider === "openai" ? "openai_key" : (provider === "mistral" ? "mistral_key" : "deepseek_key");
      const baseName = provider === "openai" ? "openai_base" : (provider === "mistral" ? "mistral_base" : "deepseek_base");
      const apiKey = getKey(keyName, provider.toUpperCase() + "_API_KEY");
      const baseDefault = (provider === "openai") ? "https://api.openai.com" : (provider === "mistral" ? "https://api.mistral.ai" : "");
      const base = getBase(baseName, provider.toUpperCase() + "_BASE", baseDefault) || (provider === "mistral" ? String(process.env.MISTRAL_BASE_URL||"").trim().replace(/\/$/,"") : "");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:`Missing ${provider} API key` });
      if (!base) return res.status(400).json({ error:"missing_base", detail:`Missing ${provider} base URL` });

      const url = `${base}/v1/chat/completions`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${apiKey}` },
        body: JSON.stringify({ model: model || "gpt-4o-mini", temperature, messages })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: j?.error?.message || raw.slice(0,600) });
      const reply = j?.choices?.[0]?.message?.content || "";
      return res.json({ reply, truncated: jsonText.length > MAX });
    }

    if (provider === "anthropic") {
      const apiKey = getKey("anthropic_key","ANTHROPIC_API_KEY");
      const base = getBase("anthropic_base","ANTHROPIC_BASE","https://api.anthropic.com");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing anthropic API key" });

      const r = await fetch(`${base}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: model || "claude-3-5-sonnet-latest",
          max_tokens: 1024,
          temperature,
          // Anthropic uses a separate system field.
          ...(system ? { system } : {}),
          messages: [{ role: "user", content: promptText }],
        }),
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: j?.error?.message || raw.slice(0,600) });
      const reply = (j?.content || []).map(x => x?.text).filter(Boolean).join("\n");
      return res.json({ reply, truncated: jsonText.length > MAX });
    }

    if (provider === "gemini") {
      const apiKey = getKey("gemini_key","GEMINI_API_KEY");
      const base = getBase("gemini_base","GEMINI_BASE","https://generativelanguage.googleapis.com");
      const m = model || "gemini-1.5-flash";
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing gemini API key" });

      const url = `${base}/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(apiKey)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json" },
        body: JSON.stringify({
          contents: [{ role:"user", parts: [{ text: system ? `${system}\n\n${promptText}` : promptText }] }],
          generationConfig: { temperature }
        })
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: (j && JSON.stringify(j).slice(0,600)) || raw.slice(0,600) });
      const reply = j?.candidates?.[0]?.content?.parts?.map(p=>p.text).filter(Boolean).join("\n") || "";
      return res.json({ reply, truncated: jsonText.length > MAX });
    }

    if (provider === "watsonx") {
      const apiKey = getKey("watsonx_api_key","WATSONX_API_KEY");
      const base = getBase("watsonx_base","WATSONX_BASE","https://us-south.ml.cloud.ibm.com","WATSONX_BASE_URL");
      const project = getKey("watsonx_project","WATSONX_PROJECT","WATSONX_PROJECT_ID");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing watsonx API key" });
      if (!project) return res.status(400).json({ error:"missing_project", detail:"Missing watsonx project id (watsonx_project)" });

      // Accept either an IAM bearer token (JWT) or a long-lived IBM Cloud API key.
      // If it's an API key, exchange it for an IAM token and cache until expiry.
      const bearer = await getWatsonxBearerToken(apiKey);

      const wxv = String(process.env.WATSONX_TEXTGEN_VERSION || process.env.WATSONX_API_VERSION || process.env.WATSONX_VERSION || "2025-02-11").trim();
      const url = `${base}/ml/v1/text/generation?version=${encodeURIComponent(wxv)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${bearer}` },
        body: JSON.stringify({
          model_id: model || "ibm/granite-13b-chat-v2",
          input: system ? `${system}\n\nUser: ${promptText}\nAssistant:` : promptText,
          parameters: { temperature, max_new_tokens: 1024 },
          project_id: project
        })
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: raw.slice(0,600) });
      const reply = j?.results?.[0]?.generated_text || "";
      return res.json({ reply, truncated: jsonText.length > MAX });
    }

    return res.status(400).json({ error: "unsupported_provider", detail: "Analyze-last supports openai/mistral/deepseek/anthropic/gemini/watsonx." });
  } catch (e) {
    return res.status(500).json({ error: "analyze_failed", detail: String(e?.message || e) });
  }
});

// Follow-up on the last analysis text (bypasses MCP orchestration; direct LLM call)
app.post("/api/agent/followup", async (req, res) => {
  try {
    const provider = String(req.body?.provider || "openai").toLowerCase();
    const model = String(req.body?.model || "").trim();
    const system = String(req.body?.system || "").trim();
    const temperature = Number.isFinite(Number(req.body?.temperature)) ? Number(req.body.temperature) : 0.2;
    const context = String(req.body?.context || "").trim();
    const instruction = String(req.body?.instruction || "").trim();
    const settings = getEffectiveSettings(req.body?.settings || {});
    if (!context) return res.status(400).json({ error: "missing_context" });
    if (!instruction) return res.status(400).json({ error: "missing_instruction" });

    const secrets = settings.secrets || settings;
    const getKey = (k, envk, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || "").trim();
    const getBase = (k, envk, defv, envk2) => String(secrets?.[k] || process.env[envk] || (envk2 ? process.env[envk2] : "") || defv || "").trim().replace(/\/$/,"");

    const MAX = Number(process.env.FOLLOWUP_MAX_CHARS || 90000);
    const clippedContext = context.length > MAX ? context.slice(0, MAX) + "\n\n...[truncated]" : context;

    const promptText =
`You are continuing a conversation with a user. You have a prior analysis from the assistant.

Prior analysis (context):\n${clippedContext}

User follow-up instruction:\n${instruction}
`;

    const messages = [];
    if (system) messages.push({ role: "system", content: system });
    messages.push({ role: "user", content: promptText });

    const openaiCompatProviders = new Set(["openai","mistral","deepseek"]);
    if (openaiCompatProviders.has(provider)) {
      const keyName = provider === "openai" ? "openai_key" : (provider === "mistral" ? "mistral_key" : "deepseek_key");
      const baseName = provider === "openai" ? "openai_base" : (provider === "mistral" ? "mistral_base" : "deepseek_base");
      const apiKey = getKey(keyName, provider.toUpperCase() + "_API_KEY");
      const baseDefault = (provider === "openai") ? "https://api.openai.com" : (provider === "mistral" ? "https://api.mistral.ai" : "");
      const base = getBase(baseName, provider.toUpperCase() + "_BASE", baseDefault) || (provider === "mistral" ? String(process.env.MISTRAL_BASE_URL||"").trim().replace(/\/$/,"") : "");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:`Missing ${provider} API key` });
      if (!base) return res.status(400).json({ error:"missing_base", detail:`Missing ${provider} base URL` });

      const url = `${base}/v1/chat/completions`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${bearer}` },
        body: JSON.stringify({ model: model || "gpt-4o-mini", temperature, messages })
      });
      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: j?.error?.message || raw.slice(0,600) });
      const reply = j?.choices?.[0]?.message?.content || "";
      return res.json({ reply, truncated: context.length > MAX });
    }

    if (provider === "anthropic") {
      const apiKey = getKey("anthropic_key","ANTHROPIC_API_KEY");
      const base = getBase("anthropic_base","ANTHROPIC_BASE","https://api.anthropic.com");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing anthropic API key" });

      const r = await fetch(`${base}/v1/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: model || "claude-3-5-sonnet-latest",
          max_tokens: 1200,
          temperature,
          ...(system ? { system } : {}),
          messages: [{ role: "user", content: promptText }],
        }),
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: j?.error?.message || raw.slice(0,600) });
      const reply = (j?.content || []).map(x => x?.text).filter(Boolean).join("\n");
      return res.json({ reply, truncated: context.length > MAX });
    }

    if (provider === "gemini") {
      const apiKey = getKey("gemini_key","GEMINI_API_KEY");
      const base = getBase("gemini_base","GEMINI_BASE","https://generativelanguage.googleapis.com");
      const m = model || "gemini-1.5-flash";
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing gemini API key" });

      const url = `${base}/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(apiKey)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json" },
        body: JSON.stringify({
          contents: [{ role:"user", parts: [{ text: system ? `${system}\n\n${promptText}` : promptText }] }],
          generationConfig: { temperature }
        })
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: (j && JSON.stringify(j).slice(0,600)) || raw.slice(0,600) });
      const reply = j?.candidates?.[0]?.content?.parts?.map(p=>p.text).filter(Boolean).join("\n") || "";
      return res.json({ reply, truncated: context.length > MAX });
    }

    if (provider === "watsonx") {
      const apiKey = getKey("watsonx_api_key","WATSONX_API_KEY");
      const base = getBase("watsonx_base","WATSONX_BASE","https://us-south.ml.cloud.ibm.com","WATSONX_BASE_URL");
      const project = getKey("watsonx_project","WATSONX_PROJECT","WATSONX_PROJECT_ID");
      if (!apiKey) return res.status(400).json({ error:"missing_api_key", detail:"Missing watsonx API key (bearer/IAM token)" });
      if (!project) return res.status(400).json({ error:"missing_project", detail:"Missing watsonx project id (watsonx_project)" });

      const bearer = await getWatsonxBearerToken(apiKey);
      const wxv = String(process.env.WATSONX_TEXTGEN_VERSION || process.env.WATSONX_API_VERSION || process.env.WATSONX_VERSION || "2025-02-11").trim();
      const url = `${base}/ml/v1/text/generation?version=${encodeURIComponent(wxv)}`;
      const r = await fetch(url, {
        method:"POST",
        headers: { "content-type":"application/json", "authorization": `Bearer ${bearer}` },
        body: JSON.stringify({
          model_id: model || "ibm/granite-13b-chat-v2",
          input: system ? `${system}\n\nUser: ${promptText}\nAssistant:` : promptText,
          parameters: { temperature, max_new_tokens: 1200 },
          project_id: project
        })
      });

      const raw = await r.text();
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let j=null; if (ct.includes("application/json")) { try { j=JSON.parse(raw) } catch {} }
      if (!r.ok) return res.status(r.status).json({ error:"llm_error", detail: raw.slice(0,600) });
      const reply = j?.results?.[0]?.generated_text || "";
      return res.json({ reply, truncated: context.length > MAX });
    }

    return res.status(400).json({ error: "unsupported_provider", detail: "Followup supports openai/mistral/deepseek/anthropic/gemini/watsonx." });
  } catch (e) {
    return res.status(500).json({ error: "followup_failed", detail: String(e?.message || e) });
  }
});

function safePdfFilename(name) {
  const s = String(name || "").trim() || "ai-report";
  return s.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/_+/g,"_").slice(0, 80);
}

// Render plain text into a downloadable PDF
app.post("/api/pdf", async (req, res) => {
  try {
    const title = String(req.body?.title || "AI Agent Result").trim() || "AI Agent Result";
    const content = String(req.body?.content || "");
    const filename = safePdfFilename(req.body?.filename || title);

    res.status(200);
    res.setHeader("content-type", "application/pdf");
    res.setHeader("content-disposition", `attachment; filename=\"${filename}.pdf\"`);

    const doc = new PDFDocument({ size: "A4", margin: 48 });
    doc.info.Title = title;
    doc.pipe(res);
    doc.fontSize(18).text(title, { align: "left" });
    doc.moveDown();
    doc.fontSize(11).text(content, { align: "left", lineGap: 2 });
    doc.end();
  } catch (e) {
    try {
      return res.status(500).json({ error: "pdf_failed", detail: String(e?.message || e) });
    } catch {
      // If headers/body already started, just end.
      return res.end();
    }
  }
});

// Value-list: tenants (IDs only). Used by guided modal and other UIs.
app.post("/api/agent/value-list/tenants", async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });

    const r = await fetchWithTimeout(`${mcpBase}/mcp/tenants`, { method: "GET" }, 10000);
    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    return res.status(r.status).json(j);
  } catch (e) {
    return res.status(500).json({ error: "value_list_failed", detail: String(e?.message || e) });
  }
});


// Tenant catalog (no secrets): used by Settings to pick a tenant and auto-fill baseUrl/defaultSite.
app.post("/api/agent/tenants-info", async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });

    const r = await fetchWithTimeout(`${mcpBase}/mcp/tenants-info`, { method: "GET" }, 10000);
    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    return res.status(r.status).json(j);
  } catch (e) {
    return res.status(500).json({ error: "tenants_info_failed", detail: String(e?.message || e) });
  }
});

// Tenant catalog (secrets): admin-only. Requires MCP server internal token (or admin cookie on same domain).
app.post("/api/agent/tenants-raw", requireAdmin(), async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });

    const headers = { "accept": "application/json" };
    if (MCP_INTERNAL_TOKEN) headers["x-internal-token"] = MCP_INTERNAL_TOKEN;

    const r = await fetchWithTimeout(`${mcpBase}/mcp/tenants-raw`, { method: "GET", headers }, 10000);
    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    if (!r.ok) {
      if (!MCP_INTERNAL_TOKEN && r.status === 403) {
        return res.status(400).json({
          error: "missing_internal_token",
          detail: "MCP server denied /mcp/tenants-raw. Set MCP_INTERNAL_TOKEN on the AI Agent and INTERNAL_TOKEN (or MCP_INTERNAL_TOKEN) on the MCP Server to enable tenant secret sync.",
        });
      }
      return res.status(r.status).json(j);
    }

    return res.json(j);
  } catch (e) {
    return res.status(500).json({ error: "tenants_raw_failed", detail: String(e?.message || e) });
  }
});

// Value-list: assets for a tenant+site (used by guided modal)
app.post("/api/agent/value-list/assets", async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const tenant = String(req.body?.tenant || settings.maximo?.defaultTenant || "default");
    const site = String(req.body?.site || "").trim();
    const search = String(req.body?.search || "").trim();
    const pageSize = Number(req.body?.pageSize || 100);
    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });
    if (!site) return res.status(400).json({ error: "missing_site" });

    const r = await fetchWithTimeout(`${mcpBase}/mcp/call`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "maximo_listAssets", args: { site, search, pageSize }, tenant })
    }, 20000);
    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    return res.status(r.status).json(j);
  } catch (e) {
    return res.status(500).json({ error: "value_list_failed", detail: String(e?.message || e) });
  }
});

// Create a Work Order or Service Request from structured fields (guided modal)
app.post("/api/agent/create-record", async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const type = String(req.body?.type || "").toLowerCase();
    const tenant = String(req.body?.tenant || settings.maximo?.defaultTenant || "default");
    const site = String(req.body?.site || "").trim();
    const assetnum = String(req.body?.assetnum || "").trim();
    const priority = req.body?.priority != null ? String(req.body.priority) : "";
    const description = String(req.body?.description || "").trim();
    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });
    if (!site || !description) return res.status(400).json({ error: "missing_fields", detail: "site and description are required" });
    if (type !== "wo" && type !== "sr") return res.status(400).json({ error: "bad_type", detail: "type must be 'wo' or 'sr'" });

    const tool = type === "wo" ? "maximo_createWO" : "maximo_createSR";
    const r = await fetchWithTimeout(`${mcpBase}/mcp/call`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: tool, args: { site, assetnum: assetnum || undefined, priority: priority || undefined, description }, tenant })
    }, 20000);
    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    if (!r.ok) return res.status(r.status).json(j);

    const id = String(j?.id || j?.wonum || j?.ticketid || "");
    return res.json({ ok: true, type, id, response: j });
  } catch (e) {
    return res.status(500).json({ error: "create_failed", detail: String(e?.message || e) });
  }
});

// Direct queryOS via MCP (bypasses the LLM). Used by dynamic Object Structure presets.
app.post("/api/agent/query-os", async (req, res) => {
  try {
    const settings = getEffectiveSettings(req.body?.settings || {});
    const tenant = String(req.body?.tenant || settings.maximo?.defaultTenant || "default");
    const argsIn = req.body?.args || {};
    const args = {
      ...argsIn,
      ...(settings?.debug?.nlq ? { debugNlq: 1 } : {}),
    };

    const mcpBase = normalizeMcpBaseUrl(settings?.mcp?.url);
    if (!mcpBase) return res.status(400).json({ error: "missing_mcp_url" });
    if (!args || !String(args?.os || "").trim()) return res.status(400).json({ error: "missing_os", detail: "args.os is required" });

    const r = await fetchWithTimeout(`${mcpBase}/mcp/call`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "maximo_queryOS", args, tenant }),
    }, 25000);

    const txt = await r.text();
    const j = safeJsonParse(txt);
    if (!j) {
      return res.status(r.ok ? 502 : r.status).json({
        error: "mcp_parse_failed",
        detail: txt.slice(0, 600),
        status: r.status,
      });
    }
    return res.status(r.status).json(j);
  } catch (e) {
    return res.status(500).json({ error: "query_os_failed", detail: String(e?.message || e) });
  }
});


// Generic proxy: used for Maximo REST calls and non-orchestrated provider calls
app.post("/proxy", async (req, res) => {
  const { method, url, headers, payload } = req.body || {};
  if (!method || !url) return res.status(400).json({ error: "method and url are required" });

  try {
    const resp = await fetch(url, {
      method,
      headers: headers || {},
      body: ["GET", "HEAD"].includes(String(method).toUpperCase()) ? undefined : JSON.stringify(payload ?? {}),
    });

    const contentType = resp.headers.get("content-type") || "";
    const text = await resp.text();

    res.status(resp.status);
    if (contentType.includes("application/json")) {
      try { return res.json(JSON.parse(text)); } catch { return res.type("application/json").send(text); }
    }
    return res.type(contentType || "text/plain").send(text);
  } catch (e) {
    return res.status(502).json({ error: "proxy_failed", detail: String(e) });
  }
});

const publicDir = path.join(process.cwd(), "public");
app.use(express.static(publicDir, {
  setHeaders: (res, filePath) => {
    // Prevent stale UI bundles after redeploys (especially across clusters / routes).
    res.setHeader("Cache-Control", "no-store");
  }
}));

app.get("*", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(publicDir, "index.html"));
});



// ---- AI model listing (best-effort) ----
app.post("/api/models", async (req, res) => {
  try {
    const provider = String(req.query.provider || req.body?.provider || "openai").toLowerCase();
    const settings = getEffectiveSettings(req.body?.settings || {});
    const ai = settings.ai || {};

    // allow keys/bases to come from settings or env
    const get = (k) => (ai && ai[k]) || (settings && settings[k]) || "";
    const openaiKey = get("openai_key") || process.env.OPENAI_API_KEY || settings?.openai_key || "";
    const openaiBase = (get("openai_base") || process.env.OPENAI_BASE || "https://api.openai.com").replace(/\/$/,"");

    const mistralKey = get("mistral_key") || process.env.MISTRAL_API_KEY || "";
    const mistralBase =
      (get("mistral_base") || process.env.MISTRAL_BASE || process.env.MISTRAL_BASE_URL || "https://api.mistral.ai").replace(/\/$/,"");

    const anthropicKey = get("anthropic_key") || process.env.ANTHROPIC_API_KEY || "";
    const anthropicBase = (get("anthropic_base") || process.env.ANTHROPIC_BASE || "https://api.anthropic.com").replace(/\/$/,"");

    const geminiKey = get("gemini_key") || process.env.GEMINI_API_KEY || "";
    const geminiBase = (get("gemini_base") || process.env.GEMINI_BASE || "https://generativelanguage.googleapis.com").replace(/\/$/,"");

    const watsonxKey = get("watsonx_api_key") || process.env.WATSONX_API_KEY || "";
    const watsonxBase =
      (get("watsonx_base") || (process.env.WATSONX_BASE || process.env.WATSONX_BASE_URL || "https://us-south.ml.cloud.ibm.com")).replace(/\/$/,"");
    // Version dates are required by the watsonx.ai REST API; allow override via env.
    const watsonxVersion = String(process.env.WATSONX_API_VERSION || process.env.WATSONX_VERSION || "2024-05-31").trim();

    // Curated fallback lists (keeps UI usable even if provider blocks model listing)
    const curated = {
      openai: ["gpt-4o-mini","gpt-4.1-mini","gpt-4o","gpt-4.1"],
      mistral: ["mistral-large-latest","mistral-small-latest","open-mistral-nemo"],
      deepseek: ["deepseek-chat","deepseek-reasoner"],
      anthropic: ["claude-3-5-sonnet-latest","claude-3-5-haiku-latest"],
      gemini: ["gemini-2.0-flash","gemini-1.5-flash"],
      watsonx: ["ibm/granite-3-8b-instruct","ibm/granite-13b-chat-v2"]
    };


    // ---- watsonx.ai (foundation models) ----
    // List models via /ml/v1/foundation_model_specs (preferred) and fall back to curated list if unavailable.
    // IBM docs: GET {watsonx_ai_url}/ml/v1/foundation_model_specs?version=YYYY-MM-DD
    if (provider === "watsonx") {
      if (!watsonxKey) return res.json({ models: curated.watsonx, warning: "Missing watsonx API key" });

      try {
        const bearer = await getWatsonxBearerToken(watsonxKey);
        const url = `${watsonxBase}/ml/v1/foundation_model_specs?version=${encodeURIComponent(watsonxVersion)}`;
        const r = await fetch(url, {
          method: "GET",
          headers: { "authorization": `Bearer ${bearer}`, "accept": "application/json" }
        });
        const raw = await r.text();
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        let j = null;
        if (ct.includes("application/json")) { try { j = JSON.parse(raw) } catch { j = null } }
        if (!r.ok || !j) {
          return res.json({ models: curated.watsonx, warning: `watsonx foundation_model_specs failed (${r.status})`, detail: raw.slice(0, 200) });
        }

        // Extract model ids robustly (response shape can vary between environments).
        const ids = new Set();
        const maybeAdd = (v) => { if (typeof v === "string" && v.trim()) ids.add(v.trim()); };

        const supportsTextGeneration = (obj) => {
          // Best-effort: look for common task fields in the spec
          const taskKeys = ["task_ids", "tasks", "supported_tasks", "task_id", "task"];
          for (const k of taskKeys) {
            const v = obj?.[k];
            if (typeof v === "string" && /text[_-]?generation|generation/i.test(v)) return true;
            if (Array.isArray(v) && v.some(x => typeof x === "string" && /text[_-]?generation|generation/i.test(x))) return true;
          }
          return false; // unknown
        };

        const walk = (node) => {
          if (!node) return;
          if (Array.isArray(node)) { node.forEach(walk); return; }
          if (typeof node !== "object") return;

          // Common top-level: { resources: [ { model_id, ... } ] }
          if (Array.isArray(node.resources)) node.resources.forEach(walk);

          // If object has model_id, decide whether to include it
          if (typeof node.model_id === "string") {
            // If task info exists and suggests non-text-generation, skip; otherwise include.
            const hasTaskInfo = ["task_ids","tasks","supported_tasks","task_id","task"].some(k => node[k] != null);
            if (!hasTaskInfo || supportsTextGeneration(node)) maybeAdd(node.model_id);
          }

          // Recurse through all fields
          for (const v of Object.values(node)) walk(v);
        };

        walk(j);

        const out = Array.from(ids).filter(id => /\//.test(id) || /granite|llama|mistral|mixtral|gemma|flan|starcoder|codellama/i.test(id));
        out.sort();

        return res.json({ models: out.length ? out : curated.watsonx, ...(out.length ? {} : { warning: "No watsonx text-generation models found; using curated fallback" }) });
      } catch (e) {
        return res.json({ models: curated.watsonx, warning: "watsonx model listing failed; using curated fallback", detail: String(e).slice(0, 200) });
      }
    }

    // ---- OpenAI (and OpenAI-base compatible endpoints that support /v1/models) ----
    if (provider === "openai" && openaiKey) {
      const r = await fetch(`${openaiBase}/v1/models`, {
        headers: { "authorization": `Bearer ${openaiKey}` }
      });
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const raw = await r.text();
      if (!r.ok) {
        return res.json({ models: curated.openai, warning: `OpenAI /v1/models failed (${r.status})`, detail: raw.slice(0,200) });
      }
      if (ct.includes("application/json")) {
        const j = JSON.parse(raw);
        const ids = (j?.data || []).map(x => x.id).filter(Boolean);
        const filtered = ids.filter(id => /gpt|o\d|chat/i.test(id)).slice(0,200);
        return res.json({ models: filtered.length ? filtered : curated.openai });
      }
      return res.json({ models: curated.openai, warning: "OpenAI returned non-JSON model list" });
    }

    // ---- Mistral ----
    if (provider === "mistral") {
      if (!mistralKey) return res.json({ models: curated.mistral, warning: "Missing Mistral API key" });

      // Mistral's API base is https://api.mistral.ai (the /v1 is added per endpoint)
      const r = await fetch(`${mistralBase}/v1/models`, {
        headers: { "authorization": `Bearer ${mistralKey}`, "accept": "application/json" }
      });
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const raw = await r.text();
      if (!r.ok) {
        return res.json({ models: curated.mistral, warning: `Mistral /v1/models failed (${r.status})`, detail: raw.slice(0,200) });
      }
      if (!ct.includes("application/json")) {
        return res.json({ models: curated.mistral, warning: "Mistral returned non-JSON model list" });
      }
      const j = JSON.parse(raw);
      const ids = (j?.data || []).map(x => x.id).filter(Boolean);

      // Best-effort filter for chat-capable models; avoid embeddings, rerankers, etc.
      const filtered = ids
        .filter(id => /(mistral|codestral|magistral|open-)/i.test(id))
        .filter(id => !/(embed|embedding|rerank|moderation)/i.test(id))
        .slice(0,200);

      return res.json({ models: filtered.length ? filtered : curated.mistral });
    }

    // ---- Anthropic ----
    if (provider === "anthropic") {
      if (!anthropicKey) return res.json({ models: curated.anthropic, warning: "Missing Anthropic API key" });

      const r = await fetch(`${anthropicBase}/v1/models`, {
        headers: {
          "x-api-key": anthropicKey,
          "anthropic-version": "2023-06-01",
          "accept": "application/json"
        }
      });
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const raw = await r.text();
      if (!r.ok) {
        return res.json({ models: curated.anthropic, warning: `Anthropic /v1/models failed (${r.status})`, detail: raw.slice(0,200) });
      }
      if (!ct.includes("application/json")) {
        return res.json({ models: curated.anthropic, warning: "Anthropic returned non-JSON model list" });
      }
      const j = JSON.parse(raw);
      const ids = (j?.data || []).map(x => x.id).filter(Boolean);
      const filtered = ids.filter(id => /^claude/i.test(id)).slice(0,200);
      return res.json({ models: filtered.length ? filtered : curated.anthropic });
    }

    // ---- Gemini (Generative Language API) ----
    if (provider === "gemini") {
      if (!geminiKey) return res.json({ models: curated.gemini, warning: "Missing Gemini API key" });

      // models.list: filters to models that support generateContent
      const r = await fetch(`${geminiBase}/v1beta/models?key=${encodeURIComponent(geminiKey)}`, {
        headers: { "accept": "application/json" }
      });
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const raw = await r.text();
      if (!r.ok) {
        return res.json({ models: curated.gemini, warning: `Gemini models.list failed (${r.status})`, detail: raw.slice(0,200) });
      }
      if (!ct.includes("application/json")) {
        return res.json({ models: curated.gemini, warning: "Gemini returned non-JSON model list" });
      }
      const j = JSON.parse(raw);
      const models = (j?.models || []).filter(Boolean);

      // Keep only models that support generateContent and normalize names ("models/gemini-..." -> "gemini-...")
      const ids = models
        .filter(m => (m?.supportedGenerationMethods || []).includes("generateContent"))
        .map(m => String(m?.name || "").replace(/^models\//, ""))
        .filter(Boolean);

      // Filter out non-chat models (embeddings etc.) best-effort
      const filtered = ids
        .filter(id => /gemini/i.test(id))
        .filter(id => !/(embed|embedding)/i.test(id))
        .slice(0,200);

      return res.json({ models: filtered.length ? filtered : curated.gemini });
    }

    // Other providers: fall back to curated list (keeps UI usable)
    return res.json({ models: curated[provider] || curated.openai });
  } catch (e) {
    return res.json({ models: ["gpt-4o-mini"], warning: String(e?.message || e) });
  }
});

// ---- Maximo helpers ----
function normMaximoBase(url) {
  let u = String(url || "").trim();
  if (!u) return "";
  u = u.replace(/\/$/,"");
  if (!/\/maximo$/.test(u)) u = u + "/maximo";
  return u;
}
function maximoApiBase(base) {
  const b = normMaximoBase(base);
  if (!b) return "";
  return b.replace(/\/maximo$/,"/maximo/api");
}
function quoteWhereValue(v) {
  // OSLC where values should be quoted when strings.
  const s = String(v ?? "").trim();
  if (!s) return "";
  if (/^\d+(\.\d+)?$/.test(s)) return s;
  // escape double quotes
  return `"${s.replace(/"/g,'\\"')}"`;
}
function extractRows(maximoJson) {
  // Maximo OSLC commonly uses "member" array; sometimes "rdfs:member"
  const arr = maximoJson?.member || maximoJson?.["rdfs:member"] || maximoJson?.response?.member;
  return Array.isArray(arr) ? arr : [];
}

app.post("/api/maximo/query", async (req, res) => {
  try {
    const text = String(req.body?.text || "").trim();
    const intentIn = String(req.body?.intent || "").trim();
    const settings = getEffectiveSettings(req.body?.settings || {});
    const maximo = settings.maximo || {};
    const baseUrl = maximo.baseUrl || settings.maximo_url || process.env.MAXIMO_URL;
    const apiKey = maximo.apiKey || settings.maximo_apikey || process.env.MAXIMO_APIKEY;
    const siteid = (maximo.defaultSite || settings.default_siteid || process.env.DEFAULT_SITEID || "")
      .toString()
      .trim()
      .toUpperCase();

    if (!baseUrl || !apiKey) {
      return res.status(400).json({
        error: "missing_maximo_settings",
        detail: "Configure Maximo Base URL and API Key in Settings.",
      });
    }
    if (!siteid) {
      return res.status(400).json({
        error: "missing_siteid",
        detail: "Configure a Default Site in Settings (used for siteid filter).",
      });
    }

    // Convert 'field desc/asc' to OSLC sort sign syntax (+field / -field)
    const normalizeOrderBy = (orderBy) => {
      const s = String(orderBy || "").trim();
      if (!s) return "";
      const m = s.match(/^([a-zA-Z0-9_:\-]+)\s+(asc|desc)$/i);
      if (m) return (m[2].toLowerCase() === "desc" ? "-" : "+") + m[1];
      if (/^[+-]/.test(s)) return s;
      return s;
    };

    // Infer intent from text if not provided
    const t = text.toLowerCase();
    let intent = intentIn;
    if (!intent) {
      if (t.includes("location")) intent = "locations";
      else if (t.includes("inventory")) intent = "inventory";
      else if (t.includes("service request") || /\bsr\b/.test(t)) intent = "srs";
      else if (t.includes("corrective")) intent = "cm_wos";
      else if ((t.includes("work order") || t.includes("workorder") || /\bwo\b/.test(t)) && t.includes("open"))
        intent = "open_wos";
      else if (t.includes("work order") || t.includes("workorder") || /\bwo\b/.test(t))
        intent = "open_wos";
            else if (t.includes("preventive maintenance") || /\bpms?\b/.test(t) || t.includes("pm ")) intent = "pms";
      else if (t.includes("job plan") || t.includes("jobplan") || /\bjps?\b/.test(t)) intent = "jobplans";
else if (t.includes("asset")) intent = "assets";
      else intent = "assets";
    }

    // Default OS per intent (ignores saved objectStructure for these intents)
    const osByIntent = {
      locations: "mxapilocations",
      assets: "mxapiasset",
      open_wos: "mxapiwo",
      cm_wos: "mxapiwo",
      srs: "mxapisr",
      inventory: "mxapiinventory",
      pms: "mxapipm",
      jobplans: "mxapijobplan",
    };

    const os = osByIntent[intent] || String(maximo.objectStructure || settings.maximo_os || "mxapiasset").trim();

    // Predictable columns per intent. Adjust if your OS differs.
    const selects = {
      locations: "location,description,status,siteid,orgid,parent,loctype,type,changedate",
      assets: "assetnum,description,status,siteid,orgid,location,assettype,serialnum,priority,changedate",
      open_wos: "wonum,description,status,worktype,priority,siteid,orgid,assetnum,location,reportdate,targstartdate,targcompdate,changedate",
      cm_wos: "wonum,description,status,worktype,priority,siteid,orgid,assetnum,location,reportdate,targstartdate,targcompdate,changedate",
      srs: "ticketid,description,status,class,priority,siteid,orgid,assetnum,location,reportedby,reportdate,changedate",
      inventory: "itemnum,item.description,status,issueunit,location,invbalances.curbal,changedate",
      pms: "pmnum,description,status,frequency,frequencyunit,nextdate,lastdate,siteid,orgid,assetnum,location",
      jobplans: "jpnum,description,status,jobplanid,revisionnum,siteid,orgid",
    };

    let where = `siteid=${quoteWhereValue(siteid)}`;

    if (intent === "cm_wos") {
      where += ` and worktype=${quoteWhereValue("CM")}`;
    } else if (intent === "open_wos") {
      // "Open" = not closed/completed
      where += ` and status!=${quoteWhereValue("CLOSE")} and status!=${quoteWhereValue("COMP")}`;
    }

    const select = selects[intent] || selects.assets;
    const orderBy = normalizeOrderBy("-changedate");
    const pageSize = "200";

    const api = maximoApiBase(baseUrl);
    const url = `${api}/os/${encodeURIComponent(os)}?oslc.where=${encodeURIComponent(where)}&oslc.select=${encodeURIComponent(select)}&oslc.pageSize=${encodeURIComponent(pageSize)}&oslc.orderBy=${encodeURIComponent(orderBy)}`;

    let resp = await fetch(url, {
      method: "GET",
      headers: { "accept":"application/json", "apikey": apiKey }
    });

    const contentType = resp.headers.get("content-type") || "";
    const raw = await resp.text();
    let j=null;
    if (contentType.includes("application/json")) { try { j=JSON.parse(raw) } catch { j=null } }
    // Some OSLC resources don't expose changedate in their resource definition; in that case,
    // Maximo returns BMXAA9105E for the orderBy. Retry once without oslc.orderBy.
    if (!resp.ok && resp.status === 400 && /BMXAA9105E|Invalid\s+OSLC\s+order\s+by\s+identifier/i.test(raw)) {
      const url2 = `${api}/os/${encodeURIComponent(os)}?oslc.where=${encodeURIComponent(where)}&oslc.select=${encodeURIComponent(select)}&oslc.pageSize=${encodeURIComponent(pageSize)}`;
      resp = await fetch(url2, {
        method: "GET",
        headers: { "accept":"application/json", "apikey": apiKey }
      });
      const raw2 = await resp.text();
      const ct2 = resp.headers.get("content-type") || "";
      let j2 = null;
      if (ct2.includes("application/json")) { try { j2 = JSON.parse(raw2) } catch { j2 = null } }
      if (!resp.ok) return res.status(resp.status).json({ error:"maximo_failed", detail: raw2.slice(0,400) });

      const rows2 = extractRows(j2 || {});
      return res.json({
        summary: `I found ${rows2.length} record(s) in Maximo (${os}).`,
        table: { title: os.toUpperCase(), columns: select.split(","), rows: rows2 },
        trace: { url: url2, where, select, pageSize, orderBy: "" }
      });
    }

    if (!resp.ok) return res.status(resp.status).json({ error:"maximo_failed", detail: raw.slice(0,400) });

    const rows = extractRows(j || {});
    return res.json({
      summary: `I found ${rows.length} record(s) in Maximo (${os}).`,
      table: {
        title: os.toUpperCase(),
        columns: select.split(","),
        rows
      },
      trace: { url, where, select, pageSize, orderBy }
    });
  } catch (e) {
    return res.status(500).json({ error:"maximo_query_failed", detail:String(e?.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`app listening on :${PORT}`);
});
