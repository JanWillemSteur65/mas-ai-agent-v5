// mcp-server/server.mjs
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import fetch from "node-fetch";

// ✅ NEW: redaction policy engine (best-effort, safe by default)
import { applyRedactionPolicy } from "./redaction.js";
import { ensureUsersFile, readUsers, writeUsers, findUser, verifyPassword, hashPassword, createToken, setAuthCookie, clearAuthCookie, authMiddleware, requireAuth, requireAdmin } from "./auth.mjs";

const app = express();

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
  })
);
app.use(morgan("combined"));
app.use(express.json({ limit: "10mb" }));


app.set("trust proxy", 1);

// --- Simple built-in authentication (cookie session) ---
const AUTH_SECRET = process.env.AUTH_SECRET || "change-me-in-prod";
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || "ReAtEt-wAInve-M0UsER";
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || process.env.MCP_INTERNAL_TOKEN || "";
const DATA_DIR = process.env.DATA_DIR || "/data";
const USERS_FILE = path.join(DATA_DIR, "users.json");
// Tenants persistence
// - Primary (requested): /data/tenant.json
// - Legacy (backward compatible): /data/tenants.json
const TENANTS_FILE_PRIMARY = path.join(DATA_DIR, "tenant.json");
const TENANTS_FILE_LEGACY = path.join(DATA_DIR, "tenants.json");

ensureUsersFile(USERS_FILE, DEFAULT_ADMIN_PASSWORD);

// Populate req.user if session cookie is present
app.use(authMiddleware(AUTH_SECRET));


function requireInternalOrAdmin() {
  return function(req, res, next) {
    const hdr = String(req.headers["x-internal-token"] || "").trim();
    if (INTERNAL_TOKEN && hdr && hdr === INTERNAL_TOKEN) return next();
    if (req.user && req.user.role === "admin") return next();
    return res.status(403).json({ error: "forbidden" });
  };
}

// Protect all /api routes except auth + health
app.use((req, res, next) => {
  if (req.path.startsWith("/api") &&
      !req.path.startsWith("/api/auth") &&
      req.path !== "/api/health" &&
      req.path !== "/api/help") {
    return requireAuth()(req, res, next);
  }
  return next();
});

// Help HTML is served by the MCP server itself so other UIs can reuse it.
// This endpoint is intentionally unauthenticated (docs only).
const HELP_HTML = `<!doctype html><html><body>
<h1>MCP Server Help &amp; Architecture Guide</h1>
<p>This page describes how the <strong>MCP Server</strong> works, how it communicates with the <strong>AI Agent</strong> and <strong>IBM Maximo</strong>, and how to use the <strong>MCP Server Observability UI</strong>.</p>
<hr />
<h2>Key endpoints</h2>
<ul>
  <li><code>GET /mcp/tools</code> — discover tools</li>
  <li><code>POST /mcp/call</code> — execute a tool</li>
  <li><code>POST /api/auth/login</code> — login (UI)</li>
  <li><code>POST /api/auth/verify</code> — verify credentials (for AI Agent)</li>
</ul>
<h2>Where users live</h2>
<p>Users are stored in <code>/data/users.json</code>. The AI Agent can be configured to validate against this store by setting <code>AUTH_SERVER_URL</code> (or <code>MCP_URL</code>) to this MCP server.</p>
<hr />
<p><em>Tip:</em> For full details, see the Help section in the MCP Server UI.</p>
</body></html>`;

app.get("/api/help", (_req, res) => {
  res.type("text/html").send(HELP_HTML);
});

// ---- Auth endpoints ----
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  try {
    const users = readUsers(USERS_FILE);
    const u = findUser(users, username);
    if (!u || !verifyPassword(password, u.salt, u.hash)) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    const token = createToken(AUTH_SECRET, u.username, u.role);
    const secure = String(process.env.COOKIE_SECURE || "").toLowerCase() === "true";
    setAuthCookie(res, token, secure);
    return res.json({ username: u.username, role: u.role });
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

// For the AI Agent to validate credentials against the MCP's user store
app.post("/api/auth/verify", (req, res) => {
  const { username, password } = req.body || {};
  try {
    const users = readUsers(USERS_FILE);
    const u = findUser(users, username);
    if (!u || !verifyPassword(password, u.salt, u.hash)) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    return res.json({ ok: true, username: u.username, role: u.role });
  } catch (e) {
    console.error("verify error", e);
    return res.status(500).json({ error: "auth_error" });
  }
});

// --- Help (served by backend; no external file dependency) ---
// Note: kept unprotected so the AI Agent can reuse it without needing MCP cookies.
const MCP_HELP_HTML = `<!doctype html><html><body>
<h1>MCP-Server Help &amp; Architecture Guide</h1>
<p>This document describes how the <strong>MCP Server</strong> works and how it communicates with the <strong>AI Agent</strong> and <strong>IBM Maximo</strong>.</p>
<hr />
<h2>1. Key Endpoints</h2>
<ul>
  <li><code>GET /mcp/tools</code> – discover available tools</li>
  <li><code>POST /mcp/call</code> – execute a tool</li>
  <li><code>/api/*</code> – UI + settings + logs endpoints (most require login)</li>
</ul>
<h2>2. Authentication</h2>
<p>The MCP Server uses a cookie session (<code>session</code>) after successful login via <code>POST /api/auth/login</code>. Users are stored in <code>/data/users.json</code>.</p>
<h2>3. Observability</h2>
<p>The MCP UI shows logs, tool calls, and (optional) HTTP trace. Enable tracing via the server settings if required.</p>
</body></html>`;

app.get("/api/help", (_req, res) => {
  res.type("text/html").send(MCP_HELP_HTML);
});

// ---- User management (admin only) ----
app.get("/api/users", requireAdmin(), (req, res) => {
  try {
    const users = readUsers(USERS_FILE).map(u => ({ username: u.username, role: u.role, createdAt: u.createdAt }));
    res.json({ users });
  } catch (e) {
    console.error("list users error", e);
    res.status(500).json({ error: "users_error" });
  }
});

// ---- Users summary (all authenticated users) ----
// Returns only aggregate counts (no credentials, no usernames). This is safe to show to USER role on dashboards.
app.get("/api/users/summary", (req, res) => {
  try {
    const users = readUsers(USERS_FILE);
    const byRole = {};
    for (const u of users) {
      const r = String(u?.role || "user").toLowerCase();
      byRole[r] = (byRole[r] || 0) + 1;
    }
    res.json({ total: users.length, byRole });
  } catch (e) {
    console.error("users summary error", e);
    res.status(500).json({ error: "users_summary_error" });
  }
});

app.post("/api/users", requireAdmin(), (req, res) => {
  const { username, password, role } = req.body || {};
  const uname = String(username || "").trim();
  if (!uname || !password) return res.status(400).json({ error: "missing_fields" });
  if (uname.toLowerCase() === "admin") return res.status(400).json({ error: "reserved_username" });
  const r = String(role || "user");
  try {
    const users = readUsers(USERS_FILE);
    if (findUser(users, uname)) return res.status(409).json({ error: "user_exists" });
    const { salt, hash } = hashPassword(password);
    users.push({ username: uname, role: r, salt, hash, createdAt: new Date().toISOString() });
    writeUsers(USERS_FILE, users);
    res.json({ ok: true });
  } catch (e) {
    console.error("add user error", e);
    res.status(500).json({ error: "users_error" });
  }
});

app.put("/api/users/:username", requireAdmin(), (req, res) => {
  const target = String(req.params.username || "").trim();
  const { password, role } = req.body || {};
  try {
    const users = readUsers(USERS_FILE);
    const u = findUser(users, target);
    if (!u) return res.status(404).json({ error: "not_found" });
    if (password) {
      const { salt, hash } = hashPassword(password);
      u.salt = salt; u.hash = hash;
    }
    if (role) u.role = String(role);
    writeUsers(USERS_FILE, users);
    res.json({ ok: true });
  } catch (e) {
    console.error("update user error", e);
    res.status(500).json({ error: "users_error" });
  }
});

app.delete("/api/users/:username", requireAdmin(), (req, res) => {
  const target = String(req.params.username || "").trim();
  if (target.toLowerCase() === "admin") return res.status(400).json({ error: "cannot_delete_admin" });
  try {
    const users = readUsers(USERS_FILE);
    const next = users.filter(u => String(u.username).toLowerCase() !== target.toLowerCase());
    if (next.length === users.length) return res.status(404).json({ error: "not_found" });
    writeUsers(USERS_FILE, next);
    res.json({ ok: true });
  } catch (e) {
    console.error("delete user error", e);
    res.status(500).json({ error: "users_error" });
  }
});

// ---- Tenant management (admin only; persisted to /data/tenants.json) ----
app.get("/api/tenants", requireAdmin(), (_req, res) => {
  try {
    refreshTenants();
    const list = Object.entries(TENANTS).map(([id, t]) => redactTenantForUi(id, t));
    return res.json({ tenants: list });
  } catch (e) {
    console.error("list tenants error", e);
    return res.status(500).json({ error: "tenants_error" });
  }
});

app.post("/api/tenants", requireAdmin(), (req, res) => {
  const id = String(req.body?.id || "").trim();
  const tenant = req.body?.tenant || {};
  if (!id) return res.status(400).json({ error: "missing_id" });
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) return res.status(400).json({ error: "bad_id", detail: "Use only letters, digits, _ or -" });
  try {
    refreshTenants();
    if (TENANTS[id]) return res.status(409).json({ error: "tenant_exists" });
    const next = { ...TENANTS, [id]: {
      baseUrl: String(tenant.baseUrl || "").trim(),
      apiKey: String(tenant.apiKey || "").trim(),
      user: String(tenant.user || "").trim(),
      password: String(tenant.password || "").trim(),
      defaultSite: String(tenant.defaultSite || "").trim(),
    }};
    writeTenantsFile(next);
    TENANTS = next;
    return res.json({ ok: true });
  } catch (e) {
    console.error("create tenant error", e);
    return res.status(500).json({ error: "tenants_error" });
  }
});

app.put("/api/tenants/:id", requireAdmin(), (req, res) => {
  const id = String(req.params.id || "").trim();
  const patch = req.body?.tenant || {};
  try {
    refreshTenants();
    const cur = TENANTS[id];
    if (!cur) return res.status(404).json({ error: "not_found" });
    // For secrets, empty string means "keep existing".
    const apiKey = String(patch.apiKey ?? "").trim();
    const password = String(patch.password ?? "").trim();
    const nextTenant = {
      ...cur,
      ...(patch.baseUrl !== undefined ? { baseUrl: String(patch.baseUrl || "").trim() } : {}),
      ...(patch.user !== undefined ? { user: String(patch.user || "").trim() } : {}),
      ...(patch.defaultSite !== undefined ? { defaultSite: String(patch.defaultSite || "").trim() } : {}),
      ...(apiKey ? { apiKey } : {}),
      ...(password ? { password } : {}),
    };
    const next = { ...TENANTS, [id]: nextTenant };
    writeTenantsFile(next);
    TENANTS = next;
    return res.json({ ok: true });
  } catch (e) {
    console.error("update tenant error", e);
    return res.status(500).json({ error: "tenants_error" });
  }
});

app.delete("/api/tenants/:id", requireAdmin(), (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id || id === "default") return res.status(400).json({ error: "cannot_delete_default" });
  try {
    refreshTenants();
    if (!TENANTS[id]) return res.status(404).json({ error: "not_found" });
    const next = { ...TENANTS };
    delete next[id];
    writeTenantsFile(next);
    TENANTS = next;
    return res.json({ ok: true });
  } catch (e) {
    console.error("delete tenant error", e);
    return res.status(500).json({ error: "tenants_error" });
  }
});


// -------------------- inbound request logging (into in-memory LOGS for the UI) --------------------
// Note: morgan logs to stdout; this middleware records /api/*, /mcp/* and /healthz in the UI log buffer.
app.use((req, res, next) => {
  const start = Date.now();
  let resBytes = 0;

  const origWrite = res.write.bind(res);
  const origEnd = res.end.bind(res);

  res.write = (chunk, encoding, cb) => {
    try {
      if (chunk) resBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), encoding || "utf-8");
    } catch {}
    return origWrite(chunk, encoding, cb);
  };
  res.end = (chunk, encoding, cb) => {
    try {
      if (chunk) resBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), encoding || "utf-8");
    } catch {}
    return origEnd(chunk, encoding, cb);
  };

  res.on("finish", () => {
    try {
      const url = req.originalUrl || req.url || "";
      if (!(url.startsWith("/api/") || url.startsWith("/mcp/") || url === "/healthz")) return;

      const pathOnly = String(url).split("?")[0];
      const routeKey = `${req.method} ${pathOnly}`;
      const ms = Date.now() - start;

      const tenant =
        (req.query && req.query.tenant) ||
        (req.body && (req.body.tenantId || req.body.tenant)) ||
        req.headers["x-tenant"] ||
        "default";

      let reqBody = "";
      if (HTTP_TRACE_ENABLED && req.body && Object.keys(req.body).length) {
        reqBody = clip(redactSecrets(req.body));
      }
      const reqBytes = reqBody ? Buffer.byteLength(reqBody) : 0;

      pushLog({
        kind: "http_in",
        title: `${res.statusCode} ${routeKey}`,
        tenant: String(tenant),
        status: res.statusCode,
        url,
        routeKey,
        ms,
        requestBytes: reqBytes,
        responseBytes: resBytes,
        reqTokensApprox: reqBytes ? Math.round(reqBytes / 4) : 0,
        resTokensApprox: resBytes ? Math.round(resBytes / 4) : 0,
        requestBody: reqBody,
      });
    } catch {}
  });

  next();
});


const PORT = process.env.PORT || 8081;
const LOG_LIMIT = Number(process.env.LOG_LIMIT || 2000);

// -------------------- SETTINGS (NEW) --------------------
const SETTINGS_PATH = path.join(DATA_DIR, "mcp_settings.json");

function readMcpSettings() {
  try {
    if (!fs.existsSync(SETTINGS_PATH)) return {};
    return JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf-8"));
  } catch {
    return {};
  }
}
function writeMcpSettings(obj) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(obj, null, 2), "utf-8");
  } catch {
    // best-effort persistence
  }
}

// -------------------- SAVED TOOLS (NEW) --------------------
// Admin-defined Maximo OS query presets, persisted per-tenant.
// Stored under DATA_DIR as: mcp_tools_<tenant>.json

function toolsPathForTenant(tenantId) {
  const safe = String(tenantId || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(DATA_DIR, `mcp_tools_${safe}.json`);
}

function readSavedTools(tenantId) {
  try {
    const p = toolsPathForTenant(tenantId);
    if (!fs.existsSync(p)) return [];
    const j = JSON.parse(fs.readFileSync(p, "utf-8"));
    return Array.isArray(j?.tools) ? j.tools : Array.isArray(j) ? j : [];
  } catch {
    return [];
  }
}

function writeSavedTools(tenantId, tools) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const p = toolsPathForTenant(tenantId);
    fs.writeFileSync(p, JSON.stringify({ tools: tools || [] }, null, 2), "utf-8");
  } catch {
    // best-effort
  }
}

function normalizeSavedTool(tool) {
  const t = tool || {};
  const name = String(t.name || "").trim();
  if (!name) throw new Error("tool.name required");
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error("tool.name must match [a-zA-Z0-9._-]+");

  const os = String(t.os || "").trim();
  if (!os) throw new Error("tool.os required");

  const select = String(t.select || "").trim();
  const where = String(t.where || "").trim();
  const orderBy = String(t.orderBy || "").trim();
  const pageSize = t.pageSize === undefined || t.pageSize === null ? "" : String(t.pageSize);
  const lean = typeof t.lean === "boolean" ? t.lean : (String(t.lean || "").toLowerCase() === "true" ? true : (String(t.lean || "").toLowerCase() === "false" ? false : undefined));
  const enabled = typeof t.enabled === "boolean" ? t.enabled : true;

  return {
    name,
    title: String(t.title || "").trim() || name,
    description: String(t.description || "").trim() || `Saved Maximo query preset (${os}).`,
    enabled,
    os,
    select,
    where,
    orderBy,
    pageSize,
    lean,
  };
}

function upsertSavedTool(tenantId, tool) {
  const nt = normalizeSavedTool(tool);
  const all = readSavedTools(tenantId);
  const idx = all.findIndex((x) => String(x?.name || "") === nt.name);
  if (idx >= 0) all[idx] = { ...all[idx], ...nt };
  else all.push(nt);
  writeSavedTools(tenantId, all);
  return nt;
}

function deleteSavedTool(tenantId, name) {
  const all = readSavedTools(tenantId);
  const next = all.filter((x) => String(x?.name || "") !== String(name || ""));
  writeSavedTools(tenantId, next);
  return all.length !== next.length;
}

// Default ON (as you requested). Can be overridden by env or persisted settings.
const persisted = readMcpSettings();
let HTTP_TRACE_ENABLED =
  (process.env.HTTP_TRACE_ENABLED === "0" || process.env.HTTP_TRACE_ENABLED === "false")
    ? false
    : (process.env.HTTP_TRACE_ENABLED === "1" || process.env.HTTP_TRACE_ENABLED === "true")
      ? true
      : (typeof persisted.httpTraceEnabled === "boolean")
        ? persisted.httpTraceEnabled
        : true;

// ✅ NEW: Redaction policy (safe default: disabled)
// Stored in mcp_settings.json under { redaction: { enabled, mode, fields, regexes } }
function getRedactionPolicy() {
  const s = readMcpSettings();
  const p = s?.redaction || {};
  return {
    enabled: typeof p.enabled === "boolean" ? p.enabled : false,
    mode: (p.mode === "full" || p.mode === "logs-only") ? p.mode : "logs-only",
    fields: Array.isArray(p.fields) ? p.fields.map(String) : [],
    regexes: Array.isArray(p.regexes) ? p.regexes : [],
  };
}

// ---------- helpers ----------
function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}
function nowIso() { return new Date().toISOString(); }
function clip(val, max = 12000) {
  const s = typeof val === "string" ? val : JSON.stringify(val);
  if (s.length <= max) return s;
  return s.slice(0, max) + `…(clipped ${s.length - max} chars)`;
}
function redactSecrets(obj) {
  try {
    const s = typeof obj === "string" ? obj : JSON.stringify(obj);
    // very small, best-effort redaction for common secrets
    return s
      .replace(/("apikey"\s*:\s*")[^"]+(")/gi, '$1***$2')
      .replace(/("authorization"\s*:\s*")[^"]+(")/gi, '$1***$2')
      .replace(/("password"\s*:\s*")[^"]+(")/gi, '$1***$2')
      .replace(/("token"\s*:\s*")[^"]+(")/gi, '$1***$2');
  } catch {
    return "";
  }
}

function uuid() { return crypto.randomBytes(12).toString("hex"); }
function normalizeBaseUrl(u) {
  let s = String(u || "").trim();
  if (!s) return "";
  s = s.replace(/\/+$/, "");
  return s;
}
function normalizeOrderBy(orderBy) {
  // MAS Manage OSLC expects each sort key to start with + or -
  // Examples: "+assetnum", "-changedate,+assetnum", "assetnum asc".
  const s = String(orderBy || "").trim();
  if (!s) return "";

  return s
    .split(",")
    .map((tok) => String(tok || "").trim())
    .filter(Boolean)
    .map((tok) => {
      const m = tok.match(/^([a-zA-Z0-9_:\-]+)\s+(asc|desc)$/i);
      if (m) return (m[2].toLowerCase() === "desc" ? "-" : "+") + m[1];
      if (/^[+-]/.test(tok)) return tok;
      // Default to ascending if no explicit sign is provided
      return "+" + tok;
    })
    .join(",");
}


/**
 * Parse an OSLC select string (comma-separated) into a list of column selectors.
 * Keeps order, removes empties, and strips common OSLC nested syntax (e.g. asset{assetnum} -> asset).
 *
 * IMPORTANT: Do NOT strip dot-paths (e.g. item.description, invbalances.curbal).
 * Those are valid selectors in MAS Manage OSLC and must survive end-to-end so we can
 * project them into tabular rows.
 */
function parseSelectColumns(selectStr) {
  const s = String(selectStr || "").trim();
  if (!s) return [];
  return s
    .split(",")
    .map((x) => String(x || "").trim())
    .filter(Boolean)
    .map((col) => {
      // strip nested selection: something{...}
      const beforeBrace = col.split("{")[0].trim();
      return beforeBrace;
    })
    .filter(Boolean);
}

/**
 * Safe dot-path getter for OSLC/Maximo responses.
 * - Supports case-insensitive matching of object keys at each segment.
 * - Supports arrays: if an intermediate value is an array, we read the remaining
 *   path from each element and join multiple values with "|".
 */
function getByPath(obj, pathStr) {
  if (!obj || typeof obj !== "object") return "";
  const raw = String(pathStr || "").trim();
  if (!raw) return "";

  const parts = raw.split(".").map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return "";

  const step = (cur, idx) => {
    if (cur === null || cur === undefined) return undefined;
    if (idx >= parts.length) return cur;

    const key = parts[idx];

    if (Array.isArray(cur)) {
      const vals = cur
        .map((el) => step(el, idx))
        .filter((v) => v !== undefined && v !== null && String(v).trim() !== "");
      if (!vals.length) return undefined;
      if (vals.length === 1) return vals[0];
      return vals.map(String).join("|");
    }

    if (typeof cur !== "object") return undefined;

    // Case-insensitive key lookup
    const map = new Map(Object.keys(cur).map((k) => [String(k).toLowerCase(), k]));
    const actual = map.get(String(key).toLowerCase());
    if (!actual) return undefined;
    return step(cur[actual], idx + 1);
  };

  const v = step(obj, 0);
  if (v === undefined || v === null) return "";
  // Keep primitives as-is; stringify objects/arrays defensively.
  if (typeof v === "object") {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return v;
}

/**
 * Project a Maximo OSLC JSON response down to only the selected columns.
 * Returns a stable, LLM-friendly tabular payload: { os, columns, rows, totalCount? }.
 */
function projectOslcResponseToTable(os, body, columns, opts = {}) {
  const cols = Array.isArray(columns) ? columns.filter(Boolean) : [];
  const members = Array.isArray(body?.member)
    ? body.member
    : Array.isArray(body?.["rdfs:member"])
      ? body["rdfs:member"]
      : [];

  // If members are rdf:resource-only, we can't project; return a lightweight list of hrefs.
  const isRdfResourceList =
    members.length > 0 &&
    typeof members[0] === "object" &&
    members[0] !== null &&
    !Array.isArray(members[0]) &&
    Object.keys(members[0]).length === 1 &&
    (members[0]["rdf:resource"] || members[0].href);

  if (isRdfResourceList) {
    const hrefs = members
      .map((m) => m["rdf:resource"] || m.href)
      .filter(Boolean);
    const returnedCount = hrefs.length;
    const pageSize = typeof opts.pageSize === "number" && Number.isFinite(opts.pageSize) && opts.pageSize > 0 ? opts.pageSize : returnedCount;
    const page = typeof opts.page === "number" && Number.isFinite(opts.page) && opts.page > 0 ? opts.page : 1;
    const hasMore = returnedCount === pageSize;
    const nextPage = hasMore ? page + 1 : null;

    return {
      os,
      renderHint: "grid",
      table: { columns: ["href"], rows: hrefs.map((h) => ({ href: h })) },
      columns: ["href"],
      rows: hrefs.map((h) => ({ href: h })),
      returnedCount,
      pageSize,
      page,
      hasMore,
      nextPage,
      totalCount: hrefs.length,
    };
  }

  const rows = members.map((m) => {
    const row = {};
    for (const c of cols) {
      // include key even if missing for stable tabular rendering
      row[c] = getByPath(m, c);
    }
    return row;
  });

  // Try to infer totalCount if present
  const totalCount =
    body?.["oslc:responseInfo"]?.["oslc:totalCount"] ??
    body?.responseInfo?.totalCount ??
    body?.totalCount ??
    (Array.isArray(members) ? members.length : undefined);

  const returnedCount = rows.length;
  const pageSize = typeof opts.pageSize === "number" && Number.isFinite(opts.pageSize) && opts.pageSize > 0 ? opts.pageSize : returnedCount;
  const page = typeof opts.page === "number" && Number.isFinite(opts.page) && opts.page > 0 ? opts.page : 1;
  const hasMore = typeof totalCount !== "undefined" ? (page * pageSize < Number(totalCount)) : (returnedCount === pageSize);
  const nextPage = hasMore ? page + 1 : null;

  return {
    os,
    renderHint: "grid",
    table: { columns: cols, rows },
    columns: cols,
    rows,
    returnedCount,
    pageSize,
    page,
    hasMore,
    nextPage,
    ...(typeof totalCount !== "undefined" ? { totalCount } : {}),
  };
}

// ---------- OSLC helpers (paging / parsing) ----------
function getOslcMembers(body) {
  if (!body || typeof body !== "object") return [];
  if (Array.isArray(body.member)) return body.member;
  if (Array.isArray(body["rdfs:member"])) return body["rdfs:member"];
  return [];
}

function setOslcMembers(body, members) {
  if (!body || typeof body !== "object") return body;
  const out = { ...body };
  if (Array.isArray(body.member)) out.member = members;
  if (Array.isArray(body["rdfs:member"])) out["rdfs:member"] = members;
  // If neither was present, default to `member`.
  if (!Array.isArray(body.member) && !Array.isArray(body["rdfs:member"])) out.member = members;
  return out;
}

function getOslcTotalCount(body) {
  if (!body || typeof body !== "object") return undefined;
  return (
    body?.["oslc:responseInfo"]?.["oslc:totalCount"] ??
    body?.responseInfo?.totalCount ??
    body?.totalCount
  );
}

function getOslcNextPageHref(body) {
  if (!body || typeof body !== "object") return "";
  const np = body?.["oslc:responseInfo"]?.["oslc:nextPage"] ?? body?.responseInfo?.nextPage ?? body?.nextPage;
  if (!np) return "";
  if (typeof np === "string") return np;
  if (typeof np === "object") return np["rdf:resource"] || np.href || "";
  return "";
}

// ---------- in-memory logs ----------
const LOGS = [];
function pushLog(evt) {
  // NEW: When trace OFF, keep meta logs but avoid large bodies/headers
  const sanitized = { ...evt };

  if (!HTTP_TRACE_ENABLED) {
    delete sanitized.requestHeaders;
    delete sanitized.responseHeaders;
    delete sanitized.requestBody;
    delete sanitized.responseBody;
    // keep a short marker if desired
    if (evt?.requestBody) sanitized.requestBody = "[httpTrace disabled]";
    if (evt?.responseBody) sanitized.responseBody = "[httpTrace disabled]";
  }

  const e = {
    id: uuid(),
    ts: Date.now(),
    iso: nowIso(),
    ...sanitized,
  };

  LOGS.push(e);
  if (LOGS.length > LOG_LIMIT) LOGS.splice(0, LOGS.length - LOG_LIMIT);
  return e.id;
}

// ---------- tenant config (persistent) ----------
function parseTenantsFromEnv() {
  try {
    if (process.env.TENANTS_JSON) return JSON.parse(process.env.TENANTS_JSON);
  } catch {}
  const baseUrl = process.env.MAXIMO_URL;
  const apiKey = process.env.MAXIMO_APIKEY;
  return {
    default: { baseUrl, apiKey, user: process.env.MAXIMO_USER, password: process.env.MAXIMO_PASSWORD, defaultSite: process.env.MAXIMO_SITE || process.env.DEFAULT_SITE || "" },
  };
}

function readTenantsFile() {
  // Prefer the requested filename (tenant.json), but keep backward compatibility
  // with older deployments that used tenants.json.
  const candidates = [TENANTS_FILE_PRIMARY, TENANTS_FILE_LEGACY];

  for (const p of candidates) {
    try {
      if (!fs.existsSync(p)) continue;
      const j = JSON.parse(fs.readFileSync(p, "utf-8"));
      // Allow either { tenants: {...} } or a direct map.
      if (j && typeof j === "object" && j.tenants && typeof j.tenants === "object") return j.tenants;
      if (j && typeof j === "object") return j;
    } catch {
      // Try next candidate
    }
  }
  return null;
}

function writeTenantsFile(tenants) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    // Primary write location (requested)
    fs.writeFileSync(TENANTS_FILE_PRIMARY, JSON.stringify({ tenants }, null, 2), "utf-8");

    // Best-effort: also keep the legacy filename in sync so older docs/scripts
    // (or previously deployed versions) keep working.
    try {
      fs.writeFileSync(TENANTS_FILE_LEGACY, JSON.stringify({ tenants }, null, 2), "utf-8");
    } catch {
      // ignore
    }

    return true;
  } catch {
    return false;
  }
}

function maskSecret(v) {
  const s = String(v || "");
  if (!s) return "";
  if (s.length <= 6) return "••••";
  return `${s.slice(0, 2)}••••${s.slice(-2)}`;
}

function redactTenantForUi(id, t) {
  const baseUrl = String(t?.baseUrl || "");
  return {
    id,
    baseUrl,
    defaultSite: String(t?.defaultSite || ""),
    apiKey: t?.apiKey ? maskSecret(t.apiKey) : "",
    user: String(t?.user || ""),
    password: t?.password ? "••••" : "",
    hasApiKey: !!t?.apiKey,
    hasPassword: !!t?.password,
  };
}

function loadTenants() {
  const env = parseTenantsFromEnv() || {};
  const file = readTenantsFile() || {};
  // File tenants override env (so UI edits persist).
  return { ...env, ...file };
}

let TENANTS = loadTenants();

function refreshTenants() {
  TENANTS = loadTenants();
  return TENANTS;
}

function tenantOrThrow(tenantId) {
  const id = String(tenantId || "default");
  const t = TENANTS[id];
  if (!t) throw new Error(`Tenant is not configured: ${id}`);
  const baseUrl = normalizeBaseUrl(t.baseUrl);
  if (!baseUrl) throw new Error(`Tenant ${id} is missing baseUrl`);
  return { tenantId: id, ...t, baseUrl };
}

function authHeaders(t) {
  const headers = { accept: "application/json" };
  if (t.apiKey) headers["apikey"] = t.apiKey;
  return headers;
}

// Best-effort extraction of a readable Maximo error message.
// Maximo error envelopes vary by version / config.
function extractMaximoErrorMessage(bodyRaw, fallbackText = "") {
  try {
    if (!bodyRaw || typeof bodyRaw !== "object") return String(fallbackText || "").trim();

    // Common patterns we've seen in Maximo REST API:
    // 1) { Error: { message, statusCode, ... } }
    // 2) { error: { message, ... } }
    // 3) { message: "..." }
    const cand =
      bodyRaw?.Error?.message ||
      bodyRaw?.Error?.Message ||
      bodyRaw?.error?.message ||
      bodyRaw?.error_description ||
      bodyRaw?.message ||
      bodyRaw?.detail ||
      bodyRaw?.error;

    if (cand == null) return String(fallbackText || "").trim();
    if (typeof cand === "string") return cand.trim();
    try {
      return JSON.stringify(cand);
    } catch {
      return String(fallbackText || "").trim();
    }
  } catch {
    return String(fallbackText || "").trim();
  }
}

function isLikelyOsNotFound(status, respText) {
  if (status === 404) return true;
  if (status !== 400) return false;
  const s = String(respText || "");
  // Maximo often returns 400 with an error message when an OS isn't defined.
  // Examples include BMXAA errors, "object structure ... is not defined", etc.
  return /(object\s+structure|os\s+name|mxapi|mxasset|BMXAA)/i.test(s) &&
         /(not\s+found|not\s+defined|does\s+not\s+exist|is\s+not\s+defined|unknown)/i.test(s);
}

function isLikelyWhereClauseError(status, respText) {
  if (status !== 400) return false;
  const s = String(respText || "");
  return /(oslc\.where|where\s+clause|query\s+syntax|invalid\s+query|BMXAA)/i.test(s) &&
         /(invalid|syntax|parse|cannot|unable)/i.test(s);
}

function isLikelyInvalidOrderBy(status, respText) {
  if (status !== 400) return false;
  const s = String(respText || "");
  // Example: BMXAA9105E - Invalid OSLC order by identifier changedate specified...
  return /(Invalid\s+OSLC\s+order\s+by\s+identifier|BMXAA9105E)/i.test(s);
}

function maximoApiBase(t) {
  const b = normalizeBaseUrl(t.baseUrl);
  const base = b.endsWith("/maximo") ? b : b + "/maximo";
  return base + "/api";
}

// ---------- allowlist storage ----------
function allowlistPath(tenantId) {
  return path.join(DATA_DIR, `os_allowlist_${tenantId}.json`);
}
function readAllowlist(tenantId) {
  try {
    const p = allowlistPath(tenantId);
    if (!fs.existsSync(p)) return null;
    const j = JSON.parse(fs.readFileSync(p, "utf-8"));
    if (Array.isArray(j)) return j.map(String);
    if (Array.isArray(j?.allowed)) return j.allowed.map(String);
    return null;
  } catch {
    return null;
  }
}
function writeAllowlist(tenantId, allowed) {
  const arr = Array.from(
    new Set((Array.isArray(allowed) ? allowed : []).map((x) => String(x).trim()).filter(Boolean))
  ).sort();
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(allowlistPath(tenantId), JSON.stringify({ allowed: arr }, null, 2), "utf-8");
  } catch {}
  return arr;
}
function isAllowedOs(tenantId, os, allowlist) {
  const list = allowlist ?? readAllowlist(tenantId);
  if (!list || !list.length) return true;
  return list.includes(os);
}


// ---------- enabled tools (per-tenant tool allowlist/denylist) ----------
function enabledToolsPath(tenantId) {
  return path.join(DATA_DIR, `enabled_tools_${tenantId}.json`);
}
function readEnabledTools(tenantId) {
  try {
    const p = enabledToolsPath(tenantId);
    if (!fs.existsSync(p)) return null;
    const j = JSON.parse(fs.readFileSync(p, "utf-8"));
    if (Array.isArray(j)) return j.map(String);
    if (Array.isArray(j?.enabledTools)) return j.enabledTools.map(String);
    if (Array.isArray(j?.enabled)) return j.enabled.map(String);
    return null;
  } catch {
    return null;
  }
}
function writeEnabledTools(tenantId, enabledTools) {
  const arr = Array.from(
    new Set((Array.isArray(enabledTools) ? enabledTools : []).map((x) => String(x).trim()).filter(Boolean))
  ).sort();
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(enabledToolsPath(tenantId), JSON.stringify({ enabledTools: arr }, null, 2), "utf-8");
  } catch {}
  return arr;
}
function isToolEnabled(tenantId, toolName, enabledTools) {
  const list = enabledTools ?? readEnabledTools(tenantId);
  if (!list || !list.length) return true; // default: everything enabled
  return list.includes(String(toolName || ""));
}


// ---------- OS discovery (best-effort) ----------
async function fetchOsListBestEffort(t) {
  const maximoBase = normalizeBaseUrl(t.baseUrl);
  const candidates = [
    `${maximoBase}/oslc/apimeta?lean=1`,
    `${maximoBase}/api/oslc/apimeta?lean=1`,
    `${maximoBase}/oslc/apimeta`,
    `${maximoBase}/api/oslc/apimeta`,
  ];
  const headers = { ...authHeaders(t), accept: "application/json" };

  let lastErr = null;
  for (const url of candidates) {
    try {
      const r = await fetch(url, { headers, redirect: "follow" });
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const bodyText = await r.text();

      if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}: ${bodyText.slice(0, 240)}`);
      if (ct.includes("text/html") || bodyText.trim().startsWith("<!DOCTYPE html"))
        throw new Error(`Returned HTML (likely login/UI). URL=${url}`);

      const j = safeJson(bodyText);
      if (!j) throw new Error(`Returned non-JSON. URL=${url} ct=${ct || "unknown"}`);

      const members = j.member || j["rdfs:member"] || j?.response?.member || j?.osList || [];
      const names = (Array.isArray(members) ? members : [])
        .map((m) => m?.name || m?.objectStructure || m?.osName || m?.os || m?.oslc_shortTitle)
        .filter(Boolean)
        .map((s) => String(s).trim())
        .filter(Boolean);

      return { names: Array.from(new Set(names)), raw: j };
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  throw lastErr || new Error("OS discovery failed");
}

// ---------- outgoing Maximo request wrapper ----------
async function maximoFetch(t, { method, url, headers, body, kind, title, meta }) {
  const start = Date.now();
  const redaction = getRedactionPolicy();

  // If mode=full, redact before the request goes out. Default is logs-only (safe).
  let outgoingBody = body;
  if (redaction.enabled && redaction.mode === "full" && body) {
    const parsed = safeJson(String(body));
    const { payload } = applyRedactionPolicy(parsed ?? String(body), redaction);
    outgoingBody = typeof payload === "string" ? payload : JSON.stringify(payload);
  }

  const reqBytes = outgoingBody ? Buffer.byteLength(String(outgoingBody)) : 0;

  const txId = pushLog({
    kind: kind || "tx_maximo",
    title: title || "→ Maximo",
    method,
    url,
    tenant: t.tenantId,
    requestHeaders: HTTP_TRACE_ENABLED
      ? (headers ? { ...headers, apikey: headers.apikey ? "***" : undefined } : undefined)
      : undefined,
    requestBody: HTTP_TRACE_ENABLED
      ? (() => {
          if (!outgoingBody) return "";
          // logs-only redaction applies even when request is not redacted
          const src = safeJson(String(outgoingBody)) ?? String(outgoingBody);
          const { payload } = applyRedactionPolicy(src, redaction);
          return clip(typeof payload === "string" ? payload : JSON.stringify(payload));
        })()
      : "",
    requestBytes: reqBytes,
    reqTokensApprox: reqBytes ? Math.round(reqBytes / 4) : 0,
    meta,
  });

  let r;
  let respText = "";
  try {
    r = await fetch(url, { method, headers, body: outgoingBody });
    respText = await r.text();
  } catch (e) {
    const ms = Date.now() - start;
    pushLog({
      kind: "rx_maximo",
      title: "← Maximo (network error)",
      tenant: t.tenantId,
      status: 0,
      url,
      relatedId: txId,
      ms,
      responseBytes: 0,
      resTokensApprox: 0,
      responseHeaders: {},
      responseBody: HTTP_TRACE_ENABLED ? clip(String(e?.message || e)) : "",
      meta: { ...(meta || {}), error: String(e?.message || e) },
    });
    throw e;
  }

  const ms = Date.now() - start;
  const resBytes = respText ? Buffer.byteLength(respText) : 0;

  // logs-only redaction for response bodies
  const redRes = (() => {
    if (!respText) return "";
    const src = safeJson(respText) ?? respText;
    const { payload } = applyRedactionPolicy(src, redaction);
    return typeof payload === "string" ? payload : JSON.stringify(payload);
  })();

  pushLog({
    kind: "rx_maximo",
    title: "← Maximo",
    tenant: t.tenantId,
    status: r.status,
    url,
    relatedId: txId,
    ms,
    responseBytes: resBytes,
    resTokensApprox: resBytes ? Math.round(resBytes / 4) : 0,
    responseHeaders: HTTP_TRACE_ENABLED ? { "content-type": r.headers.get("content-type") || "" } : undefined,
    responseBody: HTTP_TRACE_ENABLED ? clip(redRes) : "",
    meta,
  });

  return { r, respText, ms, reqBytes, resBytes };
}

// ---------- health ----------
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// ---------- logs api ----------
app.get("/api/logs", (req, res) => {
  const limit = Math.min(Number(req.query.limit || 200), 5000);
  res.json({ logs: LOGS.slice(Math.max(0, LOGS.length - limit)) });
});
app.get("/api/logs/:id", (req, res) => {
  const id = String(req.params.id || "");
  const hit = LOGS.find((x) => x.id === id);
  if (!hit) return res.status(404).json({ error: "not_found" });
  return res.json(hit);
});
// Clearing logs is an admin-only action.
app.post("/api/logs/clear", requireAdmin(), (_req, res) => {
  LOGS.splice(0, LOGS.length);
  return res.json({ ok: true });
});

// ---------- settings api (UPDATED) ----------
app.get("/api/settings", (_req, res) => {
  refreshTenants();
  res.json({
    port: PORT,
    logLimit: LOG_LIMIT,
    dataDir: DATA_DIR,
    tenants: Object.keys(TENANTS),
    allowlistPersistence: "best-effort (/data)",
    osDiscovery: "best-effort (apimeta; may be disabled by Maximo)",
    httpTraceEnabled: HTTP_TRACE_ENABLED, // ✅ NEW
    traceHttp: HTTP_TRACE_ENABLED, // ✅ legacy for unchanged UI
  });
});

// ✅ NEW: toggle http trace (admin-only)
app.put("/api/settings", requireAdmin(), (req, res) => {
  const v = req.body?.httpTraceEnabled;
  const legacy = req.body?.traceHttp;
  const enabled = req.body?.enabled;

  const next =
    typeof v === "boolean" ? v :
    typeof legacy === "boolean" ? legacy :
    typeof enabled === "boolean" ? enabled :
    null;

  if (typeof next !== "boolean") {
    return res.status(400).json({
      error: "bad_request",
      detail: "Body must include boolean httpTraceEnabled (or legacy traceHttp / enabled)",
    });
  }

  HTTP_TRACE_ENABLED = next;
  writeMcpSettings({ ...(readMcpSettings() || {}), httpTraceEnabled: next });

  return res.json({
    ok: true,
    httpTraceEnabled: HTTP_TRACE_ENABLED,
    traceHttp: HTTP_TRACE_ENABLED,
    enabled: HTTP_TRACE_ENABLED,
  });
});

// -------------------- saved tools admin api (NEW) --------------------
app.get("/api/tools", (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  const tools = readSavedTools(tenantId);
  res.json({ tenant: tenantId, tools });
});

// Create/update/delete tools are admin-only. USER role gets a read-only Tools page.
app.post("/api/tools", requireAdmin(), (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const tool = req.body?.tool;
  try {
    const saved = upsertSavedTool(tenantId, tool);
    res.json({ ok: true, tenant: tenantId, tool: saved });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.put("/api/tools/:name", requireAdmin(), (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const name = String(req.params.name || "");
  const tool = { ...(req.body?.tool || {}), name };
  try {
    const saved = upsertSavedTool(tenantId, tool);
    res.json({ ok: true, tenant: tenantId, tool: saved });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

app.delete("/api/tools/:name", requireAdmin(), (req, res) => {
  const tenantId = String(req.query?.tenant || req.body?.tenant || "default");
  const name = String(req.params.name || "");
  const ok = deleteSavedTool(tenantId, name);
  res.json({ ok, tenant: tenantId, name });
});


// -------------------- enabled tools admin api (NEW) --------------------
app.get("/api/enabled-tools", (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  const enabledTools = readEnabledTools(tenantId);
  res.json({ tenant: tenantId, enabledTools });
});

// Toggle a tool enabled/disabled for this tenant (applies to built-ins + saved tools)
app.put("/api/enabled-tools/:name", requireAdmin(), (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const name = String(req.params.name || "");
  const enabled = typeof req.body?.enabled === "boolean" ? req.body.enabled : null;
  if (!name) return res.status(400).json({ ok: false, error: "missing_name" });
  if (enabled === null) return res.status(400).json({ ok: false, error: "missing_enabled_boolean" });

  // If allowlist doesn't exist yet, initialize it to "everything currently known is enabled"
  const current = readEnabledTools(tenantId);
  const knownNames = mcpToolsForTenant(tenantId, { all: true }).map((t) => String(t?.name || "")).filter(Boolean);
  const baseline = current && Array.isArray(current) ? current : knownNames;

  let next = baseline.slice();
  if (enabled) {
    if (!next.includes(name)) next.push(name);
  } else {
    next = next.filter((x) => x !== name);
  }

  next = writeEnabledTools(tenantId, next);
  res.json({ ok: true, tenant: tenantId, name, enabled, enabledTools: next });
});


// Backward compat: UI may POST instead of PUT (admin-only)
app.post("/api/settings", requireAdmin(), (req, res) => {
  const v = req.body?.httpTraceEnabled;
  const legacy = req.body?.traceHttp;
  const enabled = req.body?.enabled;

  const next =
    typeof v === "boolean" ? v :
    typeof legacy === "boolean" ? legacy :
    typeof enabled === "boolean" ? enabled :
    null;

  if (typeof next !== "boolean") {
    return res.status(400).json({
      error: "bad_request",
      detail: "Body must include boolean httpTraceEnabled (or legacy traceHttp / enabled)",
    });
  }

  HTTP_TRACE_ENABLED = next;
  writeMcpSettings({ ...(readMcpSettings() || {}), httpTraceEnabled: next });

  return res.json({
    ok: true,
    httpTraceEnabled: HTTP_TRACE_ENABLED,
    traceHttp: HTTP_TRACE_ENABLED,
    enabled: HTTP_TRACE_ENABLED,
  });
});


// -------------------- BACKWARD COMPAT: /api/trace --------------------
// The UI expects /api/trace. Keep it stable even if we also support /api/settings.

app.get("/api/trace", (req, res) => {
  const limit = Math.min(Number(req.query.limit || 2000), 5000);

  // Combine Maximo responses + inbound HTTP responses for a single "payload/token trace" view.
  // Tokens≈ bytes ÷ 4 (rough heuristic).
  const events = LOGS.filter((e) => e.kind === "rx_maximo" || e.kind === "http_in").slice(-limit);

  // Recent: latest events first
  const recent = events
    .slice(-200)
    .map((e) => ({
      id: e.id,
      ts: e.ts,
      title: e.title || "",
      status: e.status,
      routeKey: e.routeKey || undefined,
      ms: e.ms,
      reqTokensApprox: e.reqTokensApprox,
      resTokensApprox: e.resTokensApprox,
      requestBytes: e.requestBytes,
      responseBytes: e.responseBytes,
      kind: e.kind,
    }))
    .reverse();

  // Aggregates: group by routeKey (for http_in) or by URL path (for rx_maximo)
  const byKey = new Map();
  for (const e of events) {
    const key =
      e.kind === "http_in"
        ? String(e.routeKey || e.title || "unknown")
        : String((e.url || "").split("?")[0] || e.title || "unknown");

    const cur = byKey.get(key) || {
      key,
      count: 0,
      sumResBytes: 0,
      sumResTokens: 0,
      maxResTokens: 0,
      sumMs: 0,
    };

    const resBytes = Number(e.responseBytes || 0);
    const resTokens = Number(e.resTokensApprox || 0);
    const ms = Number(e.ms || 0);

    cur.count += 1;
    cur.sumResBytes += resBytes;
    cur.sumResTokens += resTokens;
    cur.maxResTokens = Math.max(cur.maxResTokens, resTokens);
    cur.sumMs += ms;

    byKey.set(key, cur);
  }

  const aggregates = Array.from(byKey.values())
    .map((a) => ({
      key: a.key,
      count: a.count,
      avgResBytes: a.count ? Math.round(a.sumResBytes / a.count) : 0,
      avgResTokensApprox: a.count ? Math.round(a.sumResTokens / a.count) : 0,
      maxResTokensApprox: a.maxResTokens,
      avgMs: a.count ? Math.round(a.sumMs / a.count) : 0,
    }))
    .sort((a, b) => (b.avgResBytes || 0) - (a.avgResBytes || 0))
    .slice(0, 50);

  return res.json({
    httpTraceEnabled: HTTP_TRACE_ENABLED,
    traceHttp: HTTP_TRACE_ENABLED,
    enabled: HTTP_TRACE_ENABLED,
    tokensHeuristic: "Tokens≈ bytes ÷ 4",
    aggregates,
    recent,
  });
});

// Enabling/disabling trace is an admin-only action.
app.put("/api/trace", requireAdmin(), (req, res) => {
  const v = req.body?.httpTraceEnabled;
  const legacy = req.body?.enabled;

  const next =
    typeof v === "boolean" ? v :
    typeof legacy === "boolean" ? legacy :
    null;

  if (typeof next !== "boolean") {
    return res.status(400).json({
      error: "bad_request",
      detail: "Body must include boolean httpTraceEnabled (or legacy boolean enabled)",
    });
  }

  HTTP_TRACE_ENABLED = next;
  writeMcpSettings({ ...(readMcpSettings() || {}), httpTraceEnabled: next });

  return res.json({
    ok: true,
    httpTraceEnabled: HTTP_TRACE_ENABLED,
    enabled: HTTP_TRACE_ENABLED,
  });
});


// ---------- OS allowlist admin api ----------
// This endpoint is used by the admin Settings UI to manage an OS allowlist.
// USER role should not be able to change allowlists.
app.get("/api/os", requireAdmin(), async (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  try {
    const t = tenantOrThrow(tenantId);

    const allowlist = readAllowlist(tenantId);

    let names = [];
    let discoverySupported = true;
    let warning = null;

    try {
      const out = await fetchOsListBestEffort(t);
      names = out.names || [];
    } catch (e) {
      discoverySupported = false;
      warning = String(e?.message || e);
      names = Array.isArray(allowlist) ? allowlist : [];
    }

    const baseList = Array.from(new Set([...(names || []), ...((allowlist || []) ?? [])])).sort();

    const entries = baseList.map((name) => ({
      name,
      allowed: allowlist ? allowlist.includes(name) : true,
    }));

    return res.json({
      tenant: tenantId,
      discoverySupported,
      warning,
      allowlist: allowlist || [],
      entries,
    });
  } catch (e) {
    return res.status(500).json({ error: "os_list_failed", detail: String(e?.message || e) });
  }
});

app.put("/api/os/allowlist", requireAdmin(), (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  try {
    const allowed = Array.isArray(req.body?.allowed) ? req.body.allowed : [];
    const saved = writeAllowlist(tenantId, allowed);
    return res.json({ ok: true, tenant: tenantId, allowed: saved });
  } catch (e) {
    return res.status(500).json({ error: "allowlist_save_failed", detail: String(e?.message || e) });
  }
});


// ---------- NLQ (Option A + E Phase 2) ----------
// This adds deterministic natural-language query expansion for Maximo queryOS.
// Inputs: req.body.userText (string) and args.os/args.where (optional)
// Outputs: args.os, args.where (and debug meta when requested).

function nlqDataDir() {
  return path.join(process.env.DATA_DIR || "/data", "nlq");
}

function nlqMetadataDir(tenantId) {
  return path.join(nlqDataDir(), "metadata", String(tenantId || "default"));
}

function nlqRulesPaths(tenantId) {
  const dir = nlqDataDir();
  return {
    base: path.join(dir, "rules.default.json"),
    tenant: path.join(dir, `rules.tenant.${String(tenantId || "default")}.json`),
  };
}

function ensureNlqDefaults() {
  const dir = nlqDataDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const { base } = nlqRulesPaths("default");
  if (!fs.existsSync(base)) {
    const defaults = {
      version: 1,
      objects: [
        { phrase: "assets", os: "mxapiasset", object: "ASSET" },
        { phrase: "asset", os: "mxapiasset", object: "ASSET" },
        { phrase: "work orders", os: "mxapiwo", object: "WORKORDER" },
        { phrase: "work order", os: "mxapiwo", object: "WORKORDER" },
        { phrase: "wo", os: "mxapiwo", object: "WORKORDER" },
        { phrase: "service requests", os: "mxapisr", object: "SR" },
        { phrase: "service request", os: "mxapisr", object: "SR" },
        { phrase: "sr", os: "mxapisr", object: "SR" }
      ],
      filters: {
        mxapiasset: [
          { phrase: "not ready", filter: { field: "status", op: "=", value: "NOT READY" } },
          { phrase: "not-ready", filter: { field: "status", op: "=", value: "NOT READY" } },
          { phrase: "notready", filter: { field: "status", op: "=", value: "NOT READY" } }
        ]
      }
    };
    fs.writeFileSync(base, JSON.stringify(defaults, null, 2));
  }
}

function readNlqRules(tenantId) {
  ensureNlqDefaults();
  const { base, tenant } = nlqRulesPaths(tenantId);
  let b = {};
  let t = {};
  try { b = JSON.parse(fs.readFileSync(base, "utf-8")); } catch { b = {}; }
  try { if (fs.existsSync(tenant)) t = JSON.parse(fs.readFileSync(tenant, "utf-8")); } catch { t = {}; }
  const merged = { ...(b || {}), ...(t || {}) };
  merged.objects = Array.isArray(t?.objects) ? t.objects : (Array.isArray(b?.objects) ? b.objects : []);
  merged.filters = { ...(b?.filters || {}), ...(t?.filters || {}) };
  return merged;
}

function writeNlqRules(tenantId, rulesObj) {
  ensureNlqDefaults();
  const { tenant } = nlqRulesPaths(tenantId);
  fs.writeFileSync(tenant, JSON.stringify(rulesObj ?? {}, null, 2));
  return true;
}

function normalizeKey(s) {
  return String(s || "").trim().toLowerCase().replace(/[_\-\s]+/g, "");
}

function textIncludesPhrase(text, phrase) {
  const t = String(text || "").toLowerCase();
  const p = String(phrase || "").toLowerCase();
  if (!t || !p) return false;
  return t.includes(p);
}

function resolveOsFromText(text, rules) {
  const objects = Array.isArray(rules?.objects) ? rules.objects : [];
  for (const o of objects) {
    if (o?.phrase && o?.os && textIncludesPhrase(text, o.phrase)) return String(o.os).trim().toLowerCase();
  }
  return "";
}

function resolveFiltersFromText(osKey, text, rules) {
  const list = (rules?.filters && rules.filters[osKey]) ? rules.filters[osKey] : [];
  const applied = [];
  const filters = [];
  for (const r of (Array.isArray(list) ? list : [])) {
    if (r?.phrase && r?.filter && textIncludesPhrase(text, r.phrase)) {
      applied.push({ phrase: r.phrase, filter: r.filter });
      filters.push(r.filter);
    }
  }
  return { filters, applied };
}

function compileFiltersToWhere(filters) {
  const parts = [];
  for (const f of (Array.isArray(filters) ? filters : [])) {
    const field = String(f?.field || "").trim();
    const op = String(f?.op || "").trim();
    const value = String(f?.value || "");
    if (!field || !op) continue;
    const safeVal = value.replace(/"/g, '\\"');
    parts.push(`${field}${op}"${safeVal}"`);
  }
  return parts.join(" and ");
}

async function loadAssetStatusValues(t, tenantId, rxId, aiMeta) {
  const dir = nlqMetadataDir(tenantId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, "mxapiassetstatus.values.json");

  const ttlMs = Number(process.env.NLQ_METADATA_TTL_MS || (24 * 60 * 60 * 1000));
  try {
    const st = fs.statSync(p);
    if ((Date.now() - st.mtimeMs) < ttlMs) {
      const j = JSON.parse(fs.readFileSync(p, "utf-8"));
      if (Array.isArray(j?.values)) return j.values;
    }
  } catch {}

  const api = maximoApiBase(t);
  const qs = new URLSearchParams();
  qs.set("lean", "1");
  qs.set("oslc.pageSize", "200");
  qs.set("oslc.select", "status,description,value,maxvalue");
  const url = `${api}/os/${encodeURIComponent("MXAPIASSETSTATUS")}?${qs.toString()}`;
  const headers = authHeaders(t);

  try {
    const out = await maximoFetch(t, {
      method: "GET",
      url,
      headers,
      kind: "tx_maximo",
      title: `→ Maximo OS MXAPIASSETSTATUS (metadata)`,
      meta: { tool: "nlq_metadata", relatedId: rxId, ...(aiMeta || {}) },
    });
    const ct = (out.r.headers.get("content-type") || "").toLowerCase();
    let values = [];
    if (out.r.ok && ct.includes("application/json")) {
      const body = safeJson(out.respText);
      const members = getOslcMembers(body);
      const set = new Set();
      for (const m of members) {
        const cand = [m?.status, m?.value, m?.maxvalue, m?.domainvalue, m?.alnvalue, m?.synonymvalue, m?.internalvalue]
          .filter((x) => typeof x === "string" && x.trim());
        for (const c of cand) set.add(String(c).trim());
      }
      values = Array.from(set);
    }
    if (!values.length) values = ["NOT READY"];
    fs.writeFileSync(p, JSON.stringify({ fetchedAt: new Date().toISOString(), values }, null, 2));
    return values;
  } catch (e) {
    const values = ["NOT READY"];
    try { fs.writeFileSync(p, JSON.stringify({ fetchedAt: new Date().toISOString(), values, error: String(e?.message || e) }, null, 2)); } catch {}
    return values;
  }
}

// Phase 2: schema grounding via MXOBJECTCFG + synonym normalization via MXAPISYNONYMDOMAIN.
async function loadObjectCfgForObject(t, tenantId, rxId, aiMeta, objectName) {
  const dir = nlqMetadataDir(tenantId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const key = String(objectName || "").trim().toUpperCase();
  const p = path.join(dir, `mxobjectcfg.${key}.json`);

  const ttlMs = Number(process.env.NLQ_METADATA_TTL_MS || (24 * 60 * 60 * 1000));
  try {
    const st = fs.statSync(p);
    if ((Date.now() - st.mtimeMs) < ttlMs) {
      const j = JSON.parse(fs.readFileSync(p, "utf-8"));
      if (j && typeof j === "object") return j;
    }
  } catch {}

  const api = maximoApiBase(t);
  const qs = new URLSearchParams();
  qs.set("lean", "1");
  qs.set("oslc.pageSize", "2000");
  qs.set("oslc.select", "objectname,attributename,domainid,maxtype,remarks");
  qs.set("oslc.where", `objectname="${key}"`);
  const url = `${api}/os/${encodeURIComponent("MXOBJECTCFG")}?${qs.toString()}`;

  const out = await maximoFetch(t, {
    method: "GET",
    url,
    headers: authHeaders(t),
    kind: "tx_maximo",
    title: `→ Maximo OS MXOBJECTCFG (${key})`,
    meta: { tool: "nlq_metadata", relatedId: rxId, ...(aiMeta || {}) },
  });

  let schema = { object: key, fields: [], domains: {} };
  const ct = (out.r.headers.get("content-type") || "").toLowerCase();
  if (out.r.ok && ct.includes("application/json")) {
    const body = safeJson(out.respText);
    const members = getOslcMembers(body);
    const fields = new Set();
    const domains = {};
    for (const m of members) {
      const attr = String(m?.attributename || "").trim();
      if (!attr) continue;
      fields.add(attr.toLowerCase());
      const dom = String(m?.domainid || "").trim();
      if (dom) domains[attr.toLowerCase()] = dom;
    }
    schema = { object: key, fields: Array.from(fields).sort(), domains };
  }
  fs.writeFileSync(p, JSON.stringify({ fetchedAt: new Date().toISOString(), ...schema }, null, 2));
  return schema;
}

async function loadSynonymDomainMap(t, tenantId, rxId, aiMeta, domainId) {
  const dir = nlqMetadataDir(tenantId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const key = String(domainId || "").trim().toUpperCase();
  const p = path.join(dir, `mxapisynonymdomain.${key}.json`);

  const ttlMs = Number(process.env.NLQ_METADATA_TTL_MS || (24 * 60 * 60 * 1000));
  try {
    const st = fs.statSync(p);
    if ((Date.now() - st.mtimeMs) < ttlMs) {
      const j = JSON.parse(fs.readFileSync(p, "utf-8"));
      if (j && typeof j === "object" && j.map) return j.map;
    }
  } catch {}

  const api = maximoApiBase(t);
  const qs = new URLSearchParams();
  qs.set("lean", "1");
  qs.set("oslc.pageSize", "2000");
  qs.set("oslc.select", "domainid,value,description,maxvalue,defaults,internalvalue,synonymvalue");
  qs.set("oslc.where", `domainid="${key}"`);
  const url = `${api}/os/${encodeURIComponent("MXAPISYNONYMDOMAIN")}?${qs.toString()}`;

  const out = await maximoFetch(t, {
    method: "GET",
    url,
    headers: authHeaders(t),
    kind: "tx_maximo",
    title: `→ Maximo OS MXAPISYNONYMDOMAIN (${key})`,
    meta: { tool: "nlq_metadata", relatedId: rxId, ...(aiMeta || {}) },
  });

  const map = {};
  const ct = (out.r.headers.get("content-type") || "").toLowerCase();
  if (out.r.ok && ct.includes("application/json")) {
    const body = safeJson(out.respText);
    const members = getOslcMembers(body);
    for (const m of members) {
      const canonical = String(m?.value || m?.maxvalue || m?.internalvalue || "").trim();
      if (!canonical) continue;
      const keys = [
        m?.value, m?.maxvalue, m?.internalvalue, m?.synonymvalue, m?.description
      ].filter((x) => typeof x === "string" && x.trim()).map((x) => normalizeKey(x));
      for (const k of keys) {
        if (k && !map[k]) map[k] = canonical;
      }
    }
  }
  fs.writeFileSync(p, JSON.stringify({ fetchedAt: new Date().toISOString(), domain: key, map }, null, 2));
  return map;
}

async function loadAlnDomainMap(t, tenantId, rxId, aiMeta, domainId) {
  const dir = nlqMetadataDir(tenantId);
  if (!dir) return {};
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const key = String(domainId || "").trim().toUpperCase();
  const p = path.join(dir, `mxapialndomain.${key}.json`);

  const ttlMs = Number(process.env.NLQ_METADATA_TTL_MS || (24 * 60 * 60 * 1000));
  try {
    const st = fs.statSync(p);
    if ((Date.now() - st.mtimeMs) < ttlMs) {
      const j = JSON.parse(fs.readFileSync(p, "utf-8"));
      if (j && typeof j === "object" && j.map) return j.map;
    }
  } catch {}

  const api = maximoApiBase(t);
  const qs = new URLSearchParams();
  qs.set("lean", "1");
  qs.set("oslc.pageSize", "2000");
  qs.set("oslc.select", "domainid,value,alnvalue,description");
  qs.set("oslc.where", `domainid="${key}"`);
  const url = `${api}/os/${encodeURIComponent("MXAPIALNDOMAIN")}?${qs.toString()}`;

  const out = await maximoFetch(t, {
    method: "GET",
    url,
    headers: authHeaders(t),
    kind: "tx_maximo",
    title: `→ Maximo OS MXAPIALNDOMAIN (${key})`,
    meta: { tool: "nlq_metadata", relatedId: rxId, ...(aiMeta || {}) },
  });

  const map = {};
  const ct = (out.r.headers.get("content-type") || "").toLowerCase();
  if (out.r.ok && ct.includes("application/json")) {
    const body = safeJson(out.respText);
    const members = getOslcMembers(body);
    for (const m of members) {
      const val = String(m?.value || m?.alnvalue || "").trim();
      if (!val) continue;
      map[normalizeKey(val)] = val;
    }
  }
  fs.writeFileSync(p, JSON.stringify({ fetchedAt: new Date().toISOString(), domainId: key, map }, null, 2));
  return map;
}


function objectInfoForOs(osKey, rules) {
  const objects = Array.isArray(rules?.objects) ? rules.objects : [];
  for (const o of objects) {
    if (String(o?.os || "").trim().toLowerCase() === String(osKey || "").trim().toLowerCase()) {
      return { os: String(o.os).trim().toLowerCase(), object: String(o?.object || "").trim().toUpperCase() };
    }
  }
  return { os: String(osKey || "").trim().toLowerCase(), object: "" };
}


async function normalizeFilterValues(osKey, filters, t, tenantId, rxId, aiMeta, rules) {
  // Phase 2 grounding:
  // - validate fields via MXOBJECTCFG (when object name known)
  // - normalize status values via MXAPISYNONYMDOMAIN (domain derived from MXOBJECTCFG or fallback ASSETSTATUS)
  const info = objectInfoForOs(osKey, rules);
  let schema = null;
  try {
    if (info.object) schema = await loadObjectCfgForObject(t, tenantId, rxId, aiMeta, info.object);
  } catch {}

  const normalized = [];
  const dropped = [];
  let statusMap = null;
  try {
    const dom = schema?.domains?.["status"] || schema?.domains?.["status".toLowerCase()];
    const domainId = dom || (osKey === "mxapiasset" ? "ASSETSTATUS" : "");
    if (domainId) statusMap = await loadSynonymDomainMap(t, tenantId, rxId, aiMeta, domainId);
  } catch {}

  const out = (Array.isArray(filters) ? filters : []).filter(Boolean).map((f) => {
    const field = String(f?.field || "").trim().toLowerCase();
    if (schema?.fields?.length && field && !schema.fields.includes(field)) {
      dropped.push({ reason: "unknown_field", field, filter: f });
      return null;
    }
    if (field === "status" && typeof f?.value === "string") {
      const nk = normalizeKey(f.value);
      const canonical = (statusMap && statusMap[nk]) ? statusMap[nk] : f.value;
      if (canonical !== f.value) normalized.push({ field: "status", from: f.value, to: canonical });
      return { ...f, field, value: canonical };
    }
    return { ...f, field };
  }).filter(Boolean);

  return { filters: out, normalized, dropped, schemaObject: info.object || "" };
}

async function expandNlqToArgs({ tenantId, t, rxId, aiMeta, userText, args }) {
  const rules = readNlqRules(tenantId);
  const text = String(userText || "");
  const outArgs = { ...(args || {}) };

  const osKey = String(outArgs?.os || "").trim().toLowerCase();
  let resolvedOs = osKey;
  if (!resolvedOs) {
    resolvedOs = resolveOsFromText(text, rules);
    if (resolvedOs) outArgs.os = resolvedOs;
  }

  const applied = [];
  let normalized = [];
  const hasWhere = !!(outArgs?.where || (outArgs?.params && outArgs.params["oslc.where"]));
  if (resolvedOs && !hasWhere) {
    const r = resolveFiltersFromText(resolvedOs, text, rules);
    applied.push(...(r.applied || []));
    const norm = await normalizeFilterValues(resolvedOs, r.filters, t, tenantId, rxId, aiMeta, rules);
    normalized = norm.normalized || [];
        var dropped = norm.dropped || [];
        var schemaObject = norm.schemaObject || "";
    const where = compileFiltersToWhere(norm.filters);
    if (where) outArgs.where = where;
  }

  return { args: outArgs, debug: { resolvedOs: resolvedOs || "", applied, normalized, dropped: (typeof dropped !== 'undefined' ? dropped : []), schemaObject: (typeof schemaObject !== 'undefined' ? schemaObject : "") } };
}

// ---------- MCP tools ----------
function mcpToolsForTenant(tenantId, opts = {}) {
  const all = opts?.all === true;

  const enabledTools = readEnabledTools(tenantId); // null => everything enabled
  const isEnabledByAllowlist = (name) => isToolEnabled(tenantId, name, enabledTools);

  const builtins = [
    {
      name: "maximo_queryOS",
      description:
        "Query a Maximo Object Structure (OS). Returns a table by default. Args: { os, columns|select, where, orderBy, pageSize, page, lean, rawResponse, params }.",
      isBuiltin: true,
      enabled: isEnabledByAllowlist("maximo_queryOS"),
      inputSchema: {
        type: "object",
        properties: {
          os: { type: "string" },

          // Preferred (LLM-friendly)
          columns: { type: "array", items: { type: "string" }, description: "Preferred. List of columns to select, e.g. [\"assetnum\",\"description\",\"status\"]." },
          select: { type: "string", description: "Comma-separated OSLC select list, e.g. 'assetnum,description,status'." },
          where: { type: "string", description: "OSLC where clause, e.g. siteid=\"BEDFORD\"." },
          orderBy: { type: "string", description: "OSLC orderBy, e.g. '-changedate,assetnum'." },
          pageSize: { type: ["string", "number"], description: "OSLC page size (oslc.pageSize)." },
          page: { type: ["string", "number"], description: "Page number for paging (maps to Maximo pageno). Default 1." },
          lean: { type: ["boolean", "string"], description: "If true, adds lean=1 to reduce response envelope." },
          rawResponse: { type: "boolean", description: "If true, return the raw Maximo JSON instead of projecting to columns/rows." },

          // Backward compatible: arbitrary query params (including oslc.*)
          params: { type: "object", additionalProperties: { type: "string" } },
        },
        required: ["os"],
      },
    },
    {
      name: "maximo_raw",
      description: "Raw Maximo request wrapper. Args: { method, path, query, body }. Path is under /maximo/api.",
      isBuiltin: true,
      enabled: isEnabledByAllowlist("maximo_raw"),
      inputSchema: {
        type: "object",
        properties: {
          method: { type: "string" },
          path: { type: "string" },
          query: { type: "object", additionalProperties: { type: "string" } },
          body: {},
        },
        required: ["method", "path"],
      },
    },
    {
      name: "maximo_listAssets",
      description: "List assets for a site (value list). Args: { site, search?, pageSize? }. Returns { items, table }.",
      isBuiltin: true,
      enabled: isEnabledByAllowlist("maximo_listAssets"),
      inputSchema: {
        type: "object",
        properties: {
          site: { type: "string", description: "Maximo siteid (required)." },
          search: { type: "string", description: "Optional filter text applied to assetnum/description." },
          pageSize: { type: ["string", "number"], description: "Max results (default 100)." },
        },
        required: ["site"],
      },
    },
    {
      name: "maximo_createWO",
      description: "Create a Work Order. Args: { site, assetnum?, priority?, description, fields? }. Returns created identifiers.",
      isBuiltin: true,
      enabled: isEnabledByAllowlist("maximo_createWO"),
      inputSchema: {
        type: "object",
        properties: {
          site: { type: "string" },
          assetnum: { type: "string" },
          priority: { type: ["string", "number"] },
          description: { type: "string" },
          fields: { type: "object", additionalProperties: true, description: "Optional additional fields for the record body." },
        },
        required: ["site", "description"],
      },
    },
    {
      name: "maximo_createSR",
      description: "Create a Service Request. Args: { site, assetnum?, priority?, description, fields? }. Returns created identifiers.",
      isBuiltin: true,
      enabled: isEnabledByAllowlist("maximo_createSR"),
      inputSchema: {
        type: "object",
        properties: {
          site: { type: "string" },
          assetnum: { type: "string" },
          priority: { type: ["string", "number"] },
          description: { type: "string" },
          fields: { type: "object", additionalProperties: true, description: "Optional additional fields for the record body." },
        },
        required: ["site", "description"],
      },
    },
  ];

  const savedAll = readSavedTools(tenantId).map((t) => ({
    name: String(t?.name || ""),
    description: String(t?.description || (t?.os ? `Saved Maximo query preset (${t.os}).` : "Saved Maximo query preset.")),
    isBuiltin: false,
    enabled: (t?.enabled !== false) && isEnabledByAllowlist(String(t?.name || "")),
    // UI/management fields
    os: t?.os,
    select: t?.select,
    where: t?.where,
    orderBy: t?.orderBy,
    pageSize: t?.pageSize,
    lean: t?.lean,
    inputSchema: {
      type: "object",
      properties: {
        where: { type: "string", description: "Override oslc.where" },
        select: { type: "string", description: "Override oslc.select" },
        columns: { type: "array", items: { type: "string" }, description: "Override columns -> oslc.select" },
        orderBy: { type: "string", description: "Override oslc.orderBy" },
        pageSize: { type: ["string", "number"], description: "Override oslc.pageSize" },
        page: { type: ["string", "number"], description: "Override pageno (1-based)" },
        lean: { type: ["boolean", "string"], description: "Override lean=1" },
        rawResponse: { type: "boolean", description: "If true, return raw Maximo JSON" },
      },
    },
  }));

  // What we expose to agents: only callable tools.
  // What we expose to the UI Tools page: pass all=1 to include disabled tools as well.
  const saved = all ? savedAll : savedAll.filter((t) => t.enabled === true);

  const combined = [...builtins, ...saved];
  return all ? combined : combined.filter((t) => t?.enabled === true);
}


app.get("/mcp/tools", (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  const aiProvider = String(req.headers["x-ai-provider"] || "").trim();
  const aiModel = String(req.headers["x-ai-model"] || "").trim();
  const aiMeta = (aiProvider || aiModel) ? { aiProvider: aiProvider || undefined, aiModel: aiModel || undefined } : undefined;
  pushLog({
    kind: "rx_agent",
    title: "GET /mcp/tools",
    method: "GET",
    path: "/mcp/tools",
    tenant: tenantId,
    query: req.query,
    ...aiMeta,
  });
  const all = String(req.query.all || "").trim() === "1" || String(req.query.all || "").toLowerCase() === "true";
  const tools = mcpToolsForTenant(tenantId, { all });
  pushLog({
    kind: "tx_agent",
    title: "200 /mcp/tools",
    tenant: tenantId,
    status: 200,
    responseBody: clip({ tools }),
    ...aiMeta,
  });
  res.json({ tools });
});

// List available tenant IDs (no secrets). Useful for UIs and the AI Agent.
app.get("/mcp/tenants", (_req, res) => {
  refreshTenants();
  res.json({ tenants: Object.keys(TENANTS).sort() });
});

// Tenant info for UI selection (no secrets). Includes baseUrl + defaultSite.
app.get("/mcp/tenants-info", (_req, res) => {
  refreshTenants();
  const tenants = Object.entries(TENANTS).map(([id, t]) => ({
    id,
    baseUrl: String(t?.baseUrl || ""),
    defaultSite: String(t?.defaultSite || ""),
  })).sort((a,b) => a.id.localeCompare(b.id));
  res.json({ tenants });
});



// ---------- NLQ admin endpoints (Phase 1) ----------
app.get("/mcp/nlq/rules", requireAdmin(), (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  try {
    const rules = readNlqRules(tenantId);
    res.json({ tenant: tenantId, rules });
  } catch (e) {
    res.status(500).json({ error: "nlq_rules_read_failed", detail: String(e?.message || e) });
  }
});

app.put("/mcp/nlq/rules", requireAdmin(), (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  try {
    writeNlqRules(tenantId, req.body || {});
    const rules = readNlqRules(tenantId);
    res.json({ ok: true, tenant: tenantId, rules });
  } catch (e) {
    res.status(500).json({ error: "nlq_rules_write_failed", detail: String(e?.message || e) });
  }
});

app.post("/mcp/nlq/test", requireAuth(), async (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const userText = String(req.body?.userText || "");
  const argsIn = req.body?.args || {};
  try {
    const t = tenantOrThrow(tenantId);
    const rxId = pushLog({ kind: "rx_agent", title: "POST /mcp/nlq/test", method: "POST", path: "/mcp/nlq/test", tenant: tenantId, args: clip({ userText, args: argsIn }) });
    const out = await expandNlqToArgs({ tenantId, t, rxId, userText, args: argsIn });
    res.json({ tenant: tenantId, input: { userText, args: argsIn }, output: out });
  } catch (e) {
    res.status(500).json({ error: "nlq_test_failed", detail: String(e?.message || e) });
  }
});


app.get("/mcp/nlq/metadata", requireAdmin(), (req, res) => {
  const tenantId = String(req.query.tenant || "default");
  const which = String(req.query.which || "").toLowerCase();
  const key = String(req.query.key || "").trim();
  try {
    const dir = nlqMetadataDir(tenantId);
    if (!fs.existsSync(dir)) {
      res.json({ tenant: tenantId, which, key, data: null });
      return;
    }
    if (!which) {
      const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
      res.json({ tenant: tenantId, files });
      return;
    }
    let filename = "";
    if (which === "mxapiassetstatus") filename = "mxapiassetstatus.values.json";
    if (which === "mxobjectcfg") filename = `mxobjectcfg.${String(key || "ASSET").toUpperCase()}.json`;
    if (which === "mxapisynonymdomain") filename = `mxapisynonymdomain.${String(key || "ASSETSTATUS").toUpperCase()}.json`;
    if (which === "mxapialndomain") filename = `mxapialndomain.${String(key || "").toUpperCase()}.json`;
    if (!filename) {
      res.status(400).json({ error: "bad_request", detail: `Unknown metadata type: ${which}` });
      return;
    }
    const fp = path.join(dir, filename);
    if (!fs.existsSync(fp)) {
      res.json({ tenant: tenantId, which, key, data: null });
      return;
    }
    const data = JSON.parse(fs.readFileSync(fp, "utf-8"));
    res.json({ tenant: tenantId, which, key, data });
  } catch (e) {
    res.status(500).json({ error: "nlq_metadata_read_failed", detail: String(e?.message || e) });
  }
});

app.post("/mcp/nlq/metadata/refresh", requireAdmin(), async (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const which = String(req.body?.which || req.query?.which || "mxapiassetstatus").toLowerCase();
  const objectName = String(req.body?.object || req.query?.object || "").trim();
  const domainId = String(req.body?.domain || req.query?.domain || "").trim();
  try {
    const t = tenantOrThrow(tenantId);
    const rxId = pushLog({ kind: "rx_agent", title: "POST /mcp/nlq/metadata/refresh", method: "POST", path: "/mcp/nlq/metadata/refresh", tenant: tenantId, args: clip({ which, object: objectName, domain: domainId }) });

    if (which === "mxapiassetstatus") {
      const values = await loadAssetStatusValues(t, tenantId, rxId);
      res.json({ ok: true, tenant: tenantId, which, valuesCount: values.length, values });
      return;
    }

    if (which === "mxobjectcfg") {
      const obj = objectName || "ASSET";
      const schema = await loadObjectCfgForObject(t, tenantId, rxId, undefined, obj);
      res.json({ ok: true, tenant: tenantId, which, object: obj, schema });
      return;
    }

    if (which === "mxapisynonymdomain") {
      const dom = domainId || "ASSETSTATUS";
      const map = await loadSynonymDomainMap(t, tenantId, rxId, undefined, dom);
      res.json({ ok: true, tenant: tenantId, which, domain: dom, entries: Object.keys(map || {}).length });
      return;
    }

    if (which === "mxapialndomain") {
      if (!domainId) {
        res.status(400).json({ error: "bad_request", detail: "domain is required for mxapialndomain" });
        return;
      }
      const map = await loadAlnDomainMap(t, tenantId, rxId, undefined, domainId);
      res.json({ ok: true, tenant: tenantId, which, domain: domainId, entries: Object.keys(map || {}).length });
      return;
    }

    res.status(400).json({ error: "bad_request", detail: `Unknown metadata type: ${which}` });
  } catch (e) {
    res.status(500).json({ error: "nlq_metadata_refresh_failed", detail: String(e?.message || e) });
  }
});

app.get("/mcp/tenants-raw", requireInternalOrAdmin(), (_req, res) => {
  refreshTenants();
  const tenants = Object.entries(TENANTS).map(([id, t]) => ({
    id,
    baseUrl: String(t?.baseUrl || ""),
    apiKey: String(t?.apiKey || ""),
    user: String(t?.user || ""),
    password: String(t?.password || ""),
    defaultSite: String(t?.defaultSite || ""),
  })).sort((a,b) => a.id.localeCompare(b.id));
  res.json({ tenants });
});

app.post("/mcp/call", async (req, res) => {
  const tenantId = String(req.body?.tenant || req.query?.tenant || "default");
  const name = String(req.body?.name || req.body?.tool || "");
  let args = req.body?.args || {};

  const userText = String(req.body?.userText || req.body?.meta?.userText || req.headers["x-user-text"] || "");

  // Optional: AI provider/model metadata (for UI + observability)
  const aiProvider = String(req.body?.meta?.aiProvider || req.body?.meta?.provider || req.headers["x-ai-provider"] || "").trim();
  const aiModel = String(req.body?.meta?.aiModel || req.body?.meta?.model || req.headers["x-ai-model"] || "").trim();
  const aiMeta = (aiProvider || aiModel) ? { aiProvider: aiProvider || undefined, aiModel: aiModel || undefined } : undefined;

  const rxId = pushLog({
    kind: "rx_agent",
    title: "POST /mcp/call",
    method: "POST",
    path: "/mcp/call",
    tenant: tenantId,
    tool: name,
    args: clip(args),
    ...aiMeta,
  });

  try {
    const t = tenantOrThrow(tenantId);

    // Optional per-tenant tool allowlist: if set, only tools in enabled_tools_<tenant>.json may be called.
    const enabledTools = readEnabledTools(tenantId);
    if (Array.isArray(enabledTools) && enabledTools.length && !enabledTools.includes(name)) {
      pushLog({ kind: "tx_agent", title: "403 /mcp/call", tenant: tenantId, status: 403, relatedId: rxId, ...aiMeta, responseBody: clip({ error: "tool_disabled", name }) });
      return res.status(403).json({ error: "tool_disabled", name });
    }
    const allowlist = readAllowlist(tenantId);

    // ✅ NEW: resolve saved tool presets (dynamic OS query tools)
    const preset = readSavedTools(tenantId).find((x) => x && x.enabled !== false && String(x.name) === name);
    if (preset) {
      args = {
        // preset defaults
        os: preset.os,
        ...(preset.select ? { select: preset.select } : {}),
        ...(preset.where ? { where: preset.where } : {}),
        ...(preset.orderBy ? { orderBy: preset.orderBy } : {}),
        ...(preset.pageSize ? { pageSize: preset.pageSize } : {}),
        ...(preset.lean !== undefined ? { lean: preset.lean } : {}),
        // caller overrides
        ...(args || {}),
      };
    }

    if (preset || name === "maximo.queryOS" || name === "maximo_queryOS") {
      const osIn = String(args?.os || "").trim();

      // Generic OS aliasing: prefer MXAPI* object structures when callers send MX*.
      // Examples: MXASSET -> mxapiasset, MXLOCATIONS -> mxapilocations, MXWO -> mxapiwo
      // Disable by setting DISABLE_OS_ALIASES=true.
      const DISABLE_OS_ALIASES = String(process.env.DISABLE_OS_ALIASES || "").toLowerCase() === "true";
      const osNorm = String(osIn).trim().toLowerCase();
      // Friendly aliases -> canonical MXAPI object structures
      // This forces common short names (asset, locations, wo, sr, etc.) to their mxapi* OS names.
      // Disable by setting DISABLE_OS_FRIENDLY_ALIASES=true.
      const DISABLE_OS_FRIENDLY_ALIASES = String(process.env.DISABLE_OS_FRIENDLY_ALIASES || "").toLowerCase() === "true";
      const FRIENDLY_OS_ALIASES = {
        "asset": "mxapiasset",
        "assets": "mxapiasset",
        "location": "mxapilocations",
        "locations": "mxapilocations",
        "wo": "mxapiwo",
        "workorder": "mxapiwo",
        "workorders": "mxapiwo",
        "sr": "mxapisr",
        "servicerequest": "mxapisr",
        "servicerequests": "mxapisr",
        "jobplan": "mxapijobplan",
        "jobplans": "mxapijobplan",
        "inspectionres": "mxapiinspectionres",
        "inspectionresults": "mxapiinspectionres",
        "pr": "mxapipr",
        "po": "mxapipo",
        "inventory": "mxapiinventory",
        "inv": "mxapiinventory",
        "pm": "mxapipm",
        "pms": "mxapipm"
      };

      let os = osIn;
      // Apply friendly aliases first (asset -> mxapiasset, etc.)
      if (!DISABLE_OS_FRIENDLY_ALIASES) {
        const friendly = FRIENDLY_OS_ALIASES[osNorm];
        if (friendly) {
          os = friendly;
        }
      }


      if (!DISABLE_OS_ALIASES && osNorm.startsWith("mx") && !osNorm.startsWith("mxapi")) {
        const candidate = "mxapi" + osNorm.slice(2);

        // Only apply the alias if it's allowlisted (so we don't accidentally break custom OS usage).
        if (isAllowedOs(tenantId, candidate, allowlist)) {
          os = candidate;
          pushLog({
            kind: "info",
            title: "OS alias applied",
            tenant: tenantId,
            relatedId: rxId,
            meta: { from: osIn, to: os },
          });
        }
      }
      if (!os) return res.status(400).json({ error: "bad_request", detail: "args.os is required" });

      if (osIn && osIn !== os) {
        pushLog({ kind: "info", title: "OS alias applied", tenant: tenantId, relatedId: rxId, meta: { from: osIn, to: os } });
      }

      if (!isAllowedOs(tenantId, os, allowlist)) {
        const msg = `OS not allowed by allowlist: ${os}`;
        pushLog({ kind: "tx_agent", title: "403 /mcp/call", tenant: tenantId, status: 403, relatedId: rxId, responseBody: msg, ...aiMeta });
        return res.status(403).json({ error: "os_not_allowed", detail: msg });
      }

      const api = maximoApiBase(t);
      const params = { ...(args?.params || {}) };
      // ----- LLM-friendly args -> query params (backward compatible with args.params) -----
      // If callers provide select/where/orderBy/pageSize/lean at the top-level, translate to OSLC query parameters.
      // Prefer columns[] over select string when both are provided.
      if (Array.isArray(args?.columns) && args.columns.length && !params["oslc.select"]) {
        const cols = args.columns
          .map((c) => String(c || "").trim())
          .filter((c) => c);
        if (cols.length) params["oslc.select"] = cols.join(",");
      }
      if (args?.select && !params["oslc.select"]) params["oslc.select"] = String(args.select);
      if (args?.where && !params["oslc.where"]) params["oslc.where"] = String(args.where);
      if (args?.orderBy && !params["oslc.orderBy"]) params["oslc.orderBy"] = String(args.orderBy);
      // If caller supplies a top-level pageSize, it should win (even if params already had oslc.pageSize).
      if (typeof args?.pageSize !== "undefined" && args?.pageSize !== null)
        params["oslc.pageSize"] = String(args.pageSize);
      if (typeof args?.page !== "undefined" && args?.page !== null && !params["pageno"]) params["pageno"] = String(args.page);
      if (typeof args?.lean !== "undefined" && args?.lean !== null && !params["lean"])
        params["lean"] = args.lean === true ? "1" : String(args.lean);

      // ----- Default query params per Object Structure (ensures tabular responses) -----
      // These defaults apply only when the caller did not specify an explicit oslc.select / oslc.pageSize / lean.
      const OS_DEFAULTS = {
        mxapiasset: {
          select: "assetnum,description,status,siteid,orgid,location,assettype,serialnum,priority,changedate",
          pageSize: "50",
        },
        mxapilocations: {
          select: "location,description,status,siteid,orgid,parent,loctype,type,changedate",
          pageSize: "50",
        },
        mxapiwo: {
          select: "wonum,description,status,worktype,priority,siteid,orgid,assetnum,location,reportdate,targstartdate,targcompdate,changedate",
          pageSize: "50",
        },
        mxapisr: {
          select: "ticketid,description,status,class,priority,siteid,orgid,assetnum,location,reportedby,reportdate,changedate",
          pageSize: "50",
        },
        mxapipm: {
          select: "pmnum,description,status,siteid,orgid,location,assetnum,freq,frequency,worktype,nextdate,changedate",
          pageSize: "50",
        },
        mxapijobplan: {
          select: "jpnum,description,status,siteid,orgid,pluscrevnum,changedate",
          pageSize: "50",
        },
        mxapiinspectionres: {
          select: "inspectionresultid,inspectionformnum,status,siteid,orgid,assetnum,location,createdate,changedate",
          pageSize: "50",
        },
        mxapipr: {
          select: "prnum,description,status,siteid,orgid,requestor,prdate,totalcost,changedate",
          pageSize: "50",
        },
        mxapipo: {
          select: "ponum,description,status,siteid,orgid,vendor,orderdate,totalcost,changedate",
          pageSize: "50",
        },
        mxapiinventory: {
          select: "itemnum,item.description,status,issueunit,location,invbalances.curbal,changedate",
          pageSize: "25",
        },
      };

      const osKey = String(os).trim().toLowerCase();
      const def = OS_DEFAULTS[osKey];
      if (def) {
        if (!params["oslc.select"] || !String(params["oslc.select"]).trim()) params["oslc.select"] = def.select;
        if (!params["oslc.pageSize"] || !String(params["oslc.pageSize"]).trim()) params["oslc.pageSize"] = def.pageSize;
      }
      if (!params["lean"] || !String(params["lean"]).trim()) params["lean"] = "1";

      // Enforce a sane max page size to avoid timeouts / huge payloads
      const MAX_PAGE_SIZE = Number(process.env.MAX_PAGE_SIZE || 200);
      if (params["oslc.pageSize"]) {
        const n = Number(params["oslc.pageSize"]);
        if (!Number.isFinite(n) || n <= 0) {
          delete params["oslc.pageSize"];
        } else if (n > MAX_PAGE_SIZE) {
          params["oslc.pageSize"] = String(MAX_PAGE_SIZE);
        }
      }

      // Normalize orderBy after all sources of params have been applied.
      if (params["oslc.orderBy"]) params["oslc.orderBy"] = normalizeOrderBy(params["oslc.orderBy"]);


      // Normalize oslc.where: Maximo OSLC does not accept backslash-escaped quotes (e.g. \' or \"), which some LLM/tool layers may emit.
      if (params["oslc.where"]) {
        params["oslc.where"] = String(params["oslc.where"])
          .replace(/\'/g, "'")
          .replace(/\"/g, '"');
      }

      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || String(v).trim() === "") continue;
        qs.set(k, String(v));
      }

      const url = `${api}/os/${encodeURIComponent(os)}${qs.toString() ? `?${qs.toString()}` : ""}`;
      const headers = authHeaders(t);

      let { r, respText } = await maximoFetch(t, {
        method: "GET",
        url,
        headers,
        kind: "tx_maximo",
        title: `→ Maximo OS ${os}`,
        meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
      });

      // Some environments reject certain orderBy identifiers (e.g. changedate) depending on OSLC resource definition.
      // If that happens, retry once without oslc.orderBy so the query still succeeds.
      if (!r.ok && params["oslc.orderBy"] && isLikelyInvalidOrderBy(r.status, respText)) {
        const params2 = { ...params };
        delete params2["oslc.orderBy"];

        const qs2 = new URLSearchParams();
        for (const [k, v] of Object.entries(params2)) {
          if (v === undefined || v === null || String(v).trim() === "") continue;
          qs2.set(k, String(v));
        }
        const url2 = `${api}/os/${encodeURIComponent(os)}${qs2.toString() ? `?${qs2.toString()}` : ""}`;

        const retry = await maximoFetch(t, {
          method: "GET",
          url: url2,
          headers,
          kind: "tx_maximo",
          title: `→ Maximo OS ${os} (retry without orderBy)`,
          meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
        });
        r = retry.r;
        respText = retry.respText;
        // Keep params in sync for downstream projection/logging
        delete params["oslc.orderBy"];
      }

      const ct = (r.headers.get("content-type") || "").toLowerCase();
      let bodyOutRaw = ct.includes("application/json") ? (safeJson(respText) ?? { raw: respText }) : { raw: respText };

      // If the caller requested a larger pageSize than the server returns per request (often capped at 50),
      // opportunistically fetch additional pages (OSLC startIndex) and stitch members together up to oslc.pageSize.
      // This keeps the UX intuitive: pageSize=200 returns up to 200 rows.
      if (r.status >= 200 && r.status < 300 && ct.includes("application/json")) {
        const requestedMax = Number(params["oslc.pageSize"] || 0);
        const pageNo = Number(params["pageno"] || 1);
        if (Number.isFinite(requestedMax) && requestedMax > 0) {
          const firstBody = safeJson(respText);
          if (firstBody && typeof firstBody === "object") {
            const firstMembers = getOslcMembers(firstBody);
            const totalCount = getOslcTotalCount(firstBody);
            const nextHref = getOslcNextPageHref(firstBody);

            const tcNum = Number(totalCount);
            const hasTotal = Number.isFinite(tcNum) && tcNum > 0;

            // If totalCount is known and larger, we definitely have more.
            // If nextPage is present, we likely have more.
            // If requestedMax > 50 and we got 50, many Manage environments are capped per request.
            const shouldPage =
              requestedMax > firstMembers.length &&
              (
                (hasTotal && tcNum > firstMembers.length) ||
                !!nextHref ||
                (requestedMax > 50 && firstMembers.length >= 50)
              );

            if (shouldPage && firstMembers.length > 0) {
              const combined = [...firstMembers];

              let startIndex = Number(params["oslc.startIndex"] || 0);
              if (!Number.isFinite(startIndex) || startIndex < 1) {
                startIndex = ((Number.isFinite(pageNo) && pageNo > 1) ? ((pageNo - 1) * requestedMax + 1) : 1);
              }
              let nextStart = startIndex + firstMembers.length;

              // Guard against runaway paging. Default at most 20 extra pages.
              const maxPages = Math.min(20, Math.ceil(Math.max(0, requestedMax - combined.length) / 25) + 3);
              for (let i = 0; i < maxPages && combined.length < requestedMax; i++) {
                const paramsN = { ...params, "oslc.startIndex": String(nextStart) };

                const qsN = new URLSearchParams();
                for (const [k, v] of Object.entries(paramsN)) {
                  if (v === undefined || v === null || String(v).trim() === "") continue;
                  qsN.set(k, String(v));
                }

                const urlN = `${api}/os/${encodeURIComponent(os)}${qsN.toString() ? `?${qsN.toString()}` : ""}`;
                const next = await maximoFetch(t, {
                  method: "GET",
                  url: urlN,
                  headers,
                  kind: "tx_maximo",
                  title: `→ Maximo OS ${os} (page ${i + 2})`,
                  meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
                });

                if (!next.r.ok) break;
                const ctN = (next.r.headers.get("content-type") || "").toLowerCase();
                if (!ctN.includes("application/json")) break;
                const bodyN = safeJson(next.respText);
                if (!bodyN || typeof bodyN !== "object") break;

                const memN = getOslcMembers(bodyN);
                if (!memN.length) break;

                combined.push(...memN);
                nextStart += memN.length;

                // If the server returns less than the first page size, we likely hit the end.
                // (We don't know the server cap, but this is a safe early-exit.)
                if (memN.length < firstMembers.length) {
                  // If totalCount indicates more, keep going; otherwise stop.
                  if (!(hasTotal && tcNum > combined.length)) break;
                }
              }

              const sliced = combined.slice(0, requestedMax);
              bodyOutRaw = setOslcMembers(firstBody, sliced);
            }
          }
        }
      }

      // By default, return only the requested oslc.select columns (no *_collectionref / href / _rowstamp noise).
      // Set args.rawResponse=true to return the raw Maximo response instead.
      let bodyOut = bodyOutRaw;
      if (!(args?.rawResponse === true) && r.status >= 200 && r.status < 300 && ct.includes("application/json")) {
        const cols = parseSelectColumns(params["oslc.select"] || "");
        if (cols.length) bodyOut = projectOslcResponseToTable(os, bodyOutRaw, cols, { pageSize: Number(params["oslc.pageSize"] || 0), page: Number(params["pageno"] || 1) });
      }

      pushLog({
        kind: "tx_agent",
        title: `${r.status} /mcp/call`,
        tenant: tenantId,
        status: r.status,
        relatedId: rxId,
        responseBody: clip(bodyOut),
        ...aiMeta,
      });

      if (req._nlqDebug) {
        // Attach NLQ debug under _nlq when requested (debugNlq=1)
        if (bodyOut && typeof bodyOut === "object") bodyOut._nlq = req._nlqDebug;
      }
      return res.status(r.status).json(bodyOut);
    }

    if (name === "maximo_listAssets") {
      const site = String(args?.site || "").trim().toUpperCase();
      const search = String(args?.search || "").trim().toLowerCase();
      const pageSize = Number(args?.pageSize || 100);
      if (!site) return res.status(400).json({ error: "bad_request", detail: "args.site is required" });

      // Reuse the queryOS path for a safe value list.
      const qArgs = {
        // Prefer mxapiasset but support environments that expose older mxasset OS names.
        os: "mxapiasset",
        columns: ["assetnum", "description", "status", "siteid"],
        where: `siteid=\"${site}\"`,
        // OSLC requires + / - sort sign. Default ascending.
        orderBy: "+assetnum",
        pageSize: String(Math.max(1, Math.min(500, pageSize))),
        lean: true,
      };

      // Call our own query handler by issuing an internal HTTP request is overkill.
      // Instead, share the same code path by reconstructing the OSLC request here.
      const api = maximoApiBase(t);

      // Some environments are picky about quoting in oslc.where.
      // We'll try a double-quote variant first, then single-quote if we see a where-clause parse error.
      const whereVariants = [
        `siteid=\"${site}\"`,
        `siteid='${site}'`,
        "", // Fallback: some environments reject where clauses; we'll filter client-side.
      ];
      // Try mxapiasset first; fall back to mxasset if the OS isn't present.
      const candidatesAll = ["mxapiasset", "mxasset"];
      const candidates = (allowlist && allowlist.length)
        ? candidatesAll.filter((osName) => isAllowedOs(tenantId, osName, allowlist))
        : candidatesAll;
      if (!candidates.length) {
        const msg = `OS not allowed by allowlist: ${candidatesAll.join(", ")}`;
        pushLog({ kind: "tx_agent", title: "403 /mcp/call", tenant: tenantId, status: 403, relatedId: rxId, responseBody: msg, ...aiMeta });
        return res.status(403).json({ error: "os_not_allowed", detail: msg });
      }

      let usedOs = candidates[0];
      let usedWhere = whereVariants[0];
      let r = null;
      let respText = "";
      outer: for (const osName of candidates) {
        usedOs = osName;
        // Try both where variants if needed.
        for (let wi = 0; wi < whereVariants.length; wi++) {
          usedWhere = whereVariants[wi];
          const params = {
            "oslc.select": qArgs.columns.join(","),
            ...(usedWhere ? { "oslc.where": usedWhere } : {}),
            "oslc.orderBy": normalizeOrderBy(qArgs.orderBy),
            "oslc.pageSize": qArgs.pageSize,
            "lean": "1",
          };
          const qs = new URLSearchParams();
          for (const [k, v] of Object.entries(params)) {
            if (v === undefined || v === null || String(v).trim() === "") continue;
            qs.set(k, String(v));
          }

          const url = `${api}/os/${encodeURIComponent(osName)}?${qs.toString()}`;
          const out = await maximoFetch(t, {
            method: "GET",
            url,
            headers: { ...authHeaders(t), accept: "application/json" },
            kind: "tx_maximo",
            title: `→ Maximo LIST assets (${site})`,
            meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
          });
          r = out.r;
          respText = out.respText;

          if (r.ok) break outer;

          // If the OS name isn't present, Maximo often returns 404 or a 400 containing a "not defined" style error.
          if (isLikelyOsNotFound(r.status, respText)) {
            // Try next OS candidate.
            break;
          }

          // If where-clause looks invalid, try the next where variant (if available).
          if (isLikelyWhereClauseError(r.status, respText) && wi < whereVariants.length - 1) {
            continue;
          }

          // Other errors: stop trying.
          break outer;
        }
      }

      if (!r) {
        return res.status(500).json({ error: "maximo_failed", detail: "Asset list request failed." });
      }

      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const bodyRaw = ct.includes("application/json") ? (safeJson(respText) ?? { raw: respText }) : { raw: respText };

      // If Maximo returns an error status, do NOT project to table — surface the real error message.
      if (!r.ok) {
        const msg = extractMaximoErrorMessage(bodyRaw, respText) || String(respText || "").slice(0, 600);
        const outErr = {
          error: "maximo_error",
          status: r.status,
          os: String(usedOs),
          where: String(usedWhere || ""),
          detail: msg,
        };
        pushLog({
          kind: "tx_agent",
          title: `${r.status} /mcp/call`,
          tenant: tenantId,
          status: r.status,
          relatedId: rxId,
          responseBody: clip(outErr),
          ...aiMeta,
        });
        return res.status(r.status).json(outErr);
      }

      const projected = ct.includes("application/json")
        ? projectOslcResponseToTable(String(usedOs), bodyRaw, qArgs.columns, { pageSize: Number(qArgs.pageSize), page: 1 })
        : bodyRaw;

      let rows = Array.isArray(projected?.rows) ? projected.rows : [];

      // If we couldn't apply a where-clause (usedWhere=""), filter by site client-side when possible.
      if (!usedWhere) {
        rows = rows.filter((x) => {
          const s = String(x?.siteid || "").trim().toUpperCase();
          // Keep rows with matching siteid; if siteid is absent, keep it (can't reliably filter).
          return !s || s === site;
        });
      }

      const filtered = search
        ? rows.filter((x) => {
            const a = String(x?.assetnum || "").toLowerCase();
            const d = String(x?.description || "").toLowerCase();
            return a.includes(search) || d.includes(search);
          })
        : rows;
      const items = filtered.slice(0, 200).map((x) => ({
        id: String(x?.assetnum || ""),
        assetnum: String(x?.assetnum || ""),
        description: String(x?.description || ""),
        status: String(x?.status || ""),
        siteid: String(x?.siteid || site),
        label: `${String(x?.assetnum || "")} — ${String(x?.description || "")}`.trim(),
      })).filter((it) => it.id);

      const out = { items, table: { columns: projected?.columns || qArgs.columns, rows: filtered.slice(0, 200) } };

      pushLog({
        kind: "tx_agent",
        title: `${r.status} /mcp/call`,
        tenant: tenantId,
        status: r.status,
        relatedId: rxId,
        responseBody: clip({ items: items.slice(0, 20), count: items.length }),
        ...aiMeta,
      });
      return res.status(r.status).json(out);
    }

    if (name === "maximo_createWO" || name === "maximo_createSR") {
      const site = String(args?.site || "").trim().toUpperCase();
      const assetnum = String(args?.assetnum || "").trim();
      const priority = args?.priority != null ? String(args.priority) : "";
      const description = String(args?.description || "").trim();
      const fields = (args?.fields && typeof args.fields === "object") ? args.fields : {};
      if (!site || !description) return res.status(400).json({ error: "bad_request", detail: "args.site and args.description are required" });

      // Prefer mxapi* OS names, but support environments that expose legacy mxwo/mxsr.
      const osCandidatesAll = name === "maximo_createWO" ? ["mxapiwo", "mxwo"] : ["mxapisr", "mxsr"];
      const osCandidates = (allowlist && allowlist.length)
        ? osCandidatesAll.filter((osName) => isAllowedOs(tenantId, osName, allowlist))
        : osCandidatesAll;
      if (!osCandidates.length) {
        const msg = `OS not allowed by allowlist: ${osCandidatesAll.join(", ")}`;
        pushLog({ kind: "tx_agent", title: "403 /mcp/call", tenant: tenantId, status: 403, relatedId: rxId, responseBody: msg, ...aiMeta });
        return res.status(403).json({ error: "os_not_allowed", detail: msg });
      }

      const api = maximoApiBase(t);
      const body = {
        siteid: site,
        description,
        ...(assetnum ? { assetnum } : {}),
        ...(priority ? { priority } : {}),
        ...(fields || {}),
      };

      let usedOs = osCandidates[0];
      let r = null;
      let respText = "";
      for (const osName of osCandidates) {
        usedOs = osName;
        const url = `${api}/os/${encodeURIComponent(osName)}?lean=1`;
        const out = await maximoFetch(t, {
          method: "POST",
          url,
          headers: { ...authHeaders(t), "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body),
          kind: "tx_maximo",
          title: `→ Maximo CREATE ${osName} (${site})`,
          meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
        });
        r = out.r;
        respText = out.respText;
        if (r.ok) break;
        const notFound = r.status === 404 || (r.status === 400 && /not\s+found/i.test(respText));
        if (!notFound) break;
      }

      if (!r) return res.status(500).json({ error: "maximo_failed", detail: "Create request failed." });

      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const bodyOut = ct.includes("application/json") ? (safeJson(respText) ?? { raw: respText }) : { raw: respText };

      // Best-effort id extraction
      const id = bodyOut?.wonum || bodyOut?.ticketid || bodyOut?.srnum || bodyOut?.workorderid || "";
      const out = { ok: r.ok, os: usedOs, id: String(id || ""), response: bodyOut };

      pushLog({
        kind: "tx_agent",
        title: `${r.status} /mcp/call`,
        tenant: tenantId,
        status: r.status,
        relatedId: rxId,
        responseBody: clip(out),
        ...aiMeta,
      });
      return res.status(r.status).json(out);
    }

    if (name === "maximo.raw" || name === "maximo_raw") {
      const method = String(args?.method || "GET").toUpperCase();
      const p = String(args?.path || "").trim();
      const query = args?.query && typeof args.query === "object" ? args.query : {};
      const body = args?.body;

      const api = maximoApiBase(t);
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v === undefined || v === null || String(v).trim() === "") continue;
        qs.set(k, String(v));
      }

      const url = `${api}${p.startsWith("/") ? "" : "/"}${p}${qs.toString() ? `?${qs.toString()}` : ""}`;
      const headers = { ...authHeaders(t), "content-type": "application/json" };
      const bodyStr = ["GET", "HEAD"].includes(method) ? undefined : JSON.stringify(body ?? {});

      const { r, respText } = await maximoFetch(t, {
        method,
        url,
        headers,
        body: bodyStr,
        kind: "tx_maximo",
        title: `→ Maximo RAW ${method} ${p}`,
        meta: { tool: name, relatedId: rxId, ...(aiMeta || {}) },
      });

      const ct = (r.headers.get("content-type") || "").toLowerCase();
      const bodyOut = ct.includes("application/json") ? (safeJson(respText) ?? { raw: respText }) : { raw: respText };

      pushLog({
        kind: "tx_agent",
        title: `${r.status} /mcp/call`,
        tenant: tenantId,
        status: r.status,
        relatedId: rxId,
        responseBody: clip(bodyOut),
        ...aiMeta,
      });

      if (req._nlqDebug) {
        // Attach NLQ debug under _nlq when requested (debugNlq=1)
        if (bodyOut && typeof bodyOut === "object") bodyOut._nlq = req._nlqDebug;
      }
      return res.status(r.status).json(bodyOut);
    }

    const msg = `Unknown tool: ${name}`;
    pushLog({ kind: "tx_agent", title: "400 /mcp/call", tenant: tenantId, status: 400, relatedId: rxId, responseBody: msg, ...aiMeta });
    return res.status(400).json({ error: "unknown_tool", detail: msg });
  } catch (e) {
    const msg = String(e?.message || e);
    pushLog({ kind: "tx_agent", title: "500 /mcp/call", tenant: tenantId, status: 500, relatedId: rxId, responseBody: msg, ...aiMeta });
    return res.status(500).json({ error: "mcp_failed", detail: msg });
  }
});

// ---------- static UI + SPA fallback ----------
const publicDir = path.join(process.cwd(), "public");
app.use(express.static(publicDir, {
  setHeaders: (res, filePath) => {
    // Prevent stale UI bundles after redeploys (especially across clusters / routes).
    res.setHeader("Cache-Control", "no-store");
  }
}));
app.get(/^\/(?!api\/|mcp\/|healthz).*/, (req, res, next) => {
  const indexFile = path.join(publicDir, "index.html");
  try {
    if (fs.existsSync(indexFile)) { res.setHeader("Cache-Control", "no-store"); return res.sendFile(indexFile); }
  } catch {}
  return next();
});

app.listen(PORT, () => {
  console.log(`mcp-server listening on :${PORT}`);
});
