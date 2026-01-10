import React, { useEffect, useMemo, useState } from "react";

import {
  Theme,
  Header,
  HeaderName,
  HeaderGlobalBar,
  HeaderGlobalAction,
  SideNav,
  SideNavItems,
  SideNavLink,
  Content,
  Grid,
  Column,
  Stack,
  TextInput,
  Dropdown,
  Tile,
  InlineNotification,
  InlineLoading,
  Tag,
  Button,
  DataTable,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  TableContainer,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Pagination,
  CodeSnippet,
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  Modal,
  TextArea,
  Toggle,
} from "@carbon/react";

import { Renew, TrashCan, Settings, List, Analytics, Chat, Information, UserMultiple, Logout, Add, Edit } from "@carbon/icons-react";

// ✅ NEW: Tools page (saved OS tools/presets)
import ToolsPage from "./components/ToolsPage.jsx";
import NlqRulesPage from "./components/NlqRulesPage.jsx";
import NlqMetadataPage from "./components/NlqMetadataPage.jsx";

const PAGES = {
  DASH: "dash",
  TENANTS: "tenants",
  TOOLS: "tools",
  MESSAGES: "messages",
  LOGS: "logs",
  TRACE: "trace",
SETTINGS: "settings",
  USERS: "users",
};

function kindToTagType(kind) {
  if (!kind) return "gray";
  const k = String(kind);
  if (k.includes("rx_")) return "blue";
  if (k.includes("tx_")) return "teal";
  if (k.includes("maximo")) return "purple";
  if (k.includes("trace")) return "cool-gray";
  return "gray";
}

function fmtBytes(n) {
  const v = Number(n || 0);
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(1)} MB`;
}

function isMessageKind(kind) {
  const k = String(kind || "");
  return k === "rx_agent" || k === "tx_agent" || k === "rx_maximo" || k === "tx_maximo";
}

function fmtAiInfo(e) {
  if (!e) return "";
  const p = e.aiProvider || e?.meta?.aiProvider || e?.meta?.provider || "";
  const m = e.aiModel || e?.meta?.aiModel || e?.meta?.model || "";
  const left = String(p).trim();
  const right = String(m).trim();
  if (!left && !right) return "";
  return right ? `${left || "AI"} · ${right}` : left;
}

// ---------------------------------------------------------------------------
// Minimal, dependency-free charts (bar list + sparkline + donut)
// ---------------------------------------------------------------------------

// Carbon-ish palette (works in both light/dark themes)
const CHART_COLORS = [
  "#0f62fe", // blue
  "#42be65", // green
  "#ff832b", // orange
  "#be95ff", // purple
  "#ee5396", // magenta
  "#007d79", // teal
  "#fa4d56", // red
  "#8a3ffc", // violet
  "#4589ff", // light blue
  "#a56eff", // lavender
];

function colorForIndex(i) {
  return CHART_COLORS[Math.abs(Number(i) || 0) % CHART_COLORS.length];
}

function topNWithOther(data, n = 7) {
  const items = Array.isArray(data) ? data.filter(Boolean) : [];
  const sorted = items.slice().sort((a, b) => Number(b?.value || 0) - Number(a?.value || 0));
  if (sorted.length <= n) return sorted;
  const head = sorted.slice(0, n);
  const tail = sorted.slice(n);
  const other = tail.reduce((acc, x) => acc + Number(x?.value || 0), 0);
  return other > 0 ? [...head, { label: "Other", value: other }] : head;
}

function BarList({ data = [], valueFormatter = (v) => String(v), maxItems = 8 }) {
  const items = Array.isArray(data) ? data.slice(0, maxItems) : [];
  const max = Math.max(1, ...items.map((d) => Number(d?.value || 0)));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.map((d, idx) => {
        const label = String(d?.label ?? "");
        const value = Number(d?.value || 0);
        const pct = Math.max(0, Math.min(100, Math.round((value / max) * 100)));
        const c = colorForIndex(idx);
        return (
          <div key={label} style={{ display: "grid", gridTemplateColumns: "160px 1fr 70px", gap: 8, alignItems: "center" }}>
            <div style={{ fontSize: 12, opacity: 0.85, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={label}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 10, height: 10, borderRadius: 999, background: c, display: "inline-block" }} />
                <span>{label || "—"}</span>
              </span>
            </div>
            <div style={{ height: 10, background: "rgba(0,0,0,0.08)", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${pct}%`, background: c, opacity: 0.9 }} />
            </div>
            <div style={{ fontVariantNumeric: "tabular-nums", textAlign: "right", fontSize: 12, opacity: 0.9 }}>
              {valueFormatter(value)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DonutChart({ data = [], size = 180, thickness = 26, maxItems = 7 }) {
  const items = topNWithOther(data, maxItems).filter((d) => Number(d?.value || 0) > 0);
  const total = items.reduce((acc, d) => acc + Number(d?.value || 0), 0) || 1;
  const rOuter = size / 2;
  const rInner = Math.max(8, rOuter - thickness);

  // SVG arc helper
  const arcPath = (startAngle, endAngle) => {
    const cx = rOuter;
    const cy = rOuter;
    const a0 = startAngle - Math.PI / 2;
    const a1 = endAngle - Math.PI / 2;
    const x0 = cx + rOuter * Math.cos(a0);
    const y0 = cy + rOuter * Math.sin(a0);
    const x1 = cx + rOuter * Math.cos(a1);
    const y1 = cy + rOuter * Math.sin(a1);
    const x2 = cx + rInner * Math.cos(a1);
    const y2 = cy + rInner * Math.sin(a1);
    const x3 = cx + rInner * Math.cos(a0);
    const y3 = cy + rInner * Math.sin(a0);
    const large = endAngle - startAngle > Math.PI ? 1 : 0;
    return `M ${x0} ${y0} A ${rOuter} ${rOuter} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${rInner} ${rInner} 0 ${large} 0 ${x3} ${y3} Z`;
  };

  let acc = 0;
  const segs = items.map((d, idx) => {
    const v = Number(d?.value || 0);
    const start = acc;
    const end = acc + (v / total) * Math.PI * 2;
    acc = end;
    return {
      label: String(d?.label ?? ""),
      value: v,
      pct: Math.round((v / total) * 100),
      color: colorForIndex(idx),
      d: arcPath(start, end),
    };
  });

  return (
    <div style={{ display: "grid", gridTemplateColumns: `${size}px 1fr`, gap: 16, alignItems: "center" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: "block" }}>
        <circle cx={rOuter} cy={rOuter} r={rInner} fill="transparent" />
        {segs.map((s) => (
          <path key={s.label} d={s.d} fill={s.color} opacity="0.9" />
        ))}
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {segs.map((s) => (
          <div key={s.label} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12, opacity: 0.9 }}>
            <span style={{ width: 10, height: 10, borderRadius: 999, background: s.color, display: "inline-block" }} />
            <div style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.label}>
              {s.label || "—"}
            </div>
            <div style={{ fontVariantNumeric: "tabular-nums", opacity: 0.85 }}>{s.pct}%</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Sparkline({ values = [], height = 44 }) {
  const vals = Array.isArray(values) ? values.filter((v) => Number.isFinite(v)) : [];
  if (vals.length < 2) return <div style={{ opacity: 0.7, fontSize: 12 }}>Not enough data</div>;
  const w = 240;
  const h = Math.max(24, Number(height || 44));
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const range = max - min || 1;
  const pts = vals
    .map((v, i) => {
      const x = (i / (vals.length - 1)) * w;
      const y = h - ((v - min) / range) * h;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" style={{ display: "block" }}>
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="2" opacity="0.9" />
    </svg>
  );
}

function UsersPage({ users, usersError, onRefresh, onAddUser, onEditUser, onDeleteUser }) {
  return (
    <Grid condensed>
      <Column sm={4} md={8} lg={16}>
        <Stack gap={5}>
          <Stack orientation="horizontal" gap={3} style={{ alignItems: "center", justifyContent: "space-between" }}>
            <h3 style={{ margin: 0 }}>Users</h3>
            <div style={{ display: "flex", gap: 8 }}>
              <Button kind="secondary" onClick={onRefresh}>Refresh</Button>
              <Button onClick={onAddUser}>Add user</Button>
            </div>
          </Stack>

          <p style={{ margin: 0, opacity: 0.8 }}>
            Manage logins here (admin only). These credentials can be shared with the AI Agent by setting its AUTH_SERVER_URL (or MCP_URL) to this MCP Server URL.
          </p>

          {usersError && (
            <InlineNotification kind="error" lowContrast title={usersError} />
          )}

          <DataTable
            rows={(users || []).map((u) => ({ id: u.username, ...u }))}
            headers={[
              { key: "username", header: "Username" },
              { key: "role", header: "Role" },
              { key: "createdAt", header: "Created" },
              { key: "actions", header: "Actions" },
            ]}
            isSortable
          >
            {({ rows, headers, getHeaderProps, getRowProps }) => (
              <TableContainer title="">
                <Table size="lg">
                  <TableHead>
                    <TableRow>
                      {headers.map((header) => (
                        <TableHeader key={header.key} {...getHeaderProps({ header })}>
                          {header.header}
                        </TableHeader>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((row) => (
                      <TableRow key={row.id} {...getRowProps({ row })}>
                        {row.cells.map((cell) => {
                          if (cell.info.header === "actions") {
                            return (
                              <TableCell key={cell.id}>
                                <div style={{ display: "flex", gap: 8 }}>
                                  <Button size="sm" kind="ghost" renderIcon={Edit} onClick={() => onEditUser?.(row.id)}>Edit</Button>
                                  <Button size="sm" kind="danger--ghost" renderIcon={TrashCan} disabled={row.id === "admin"} onClick={() => onDeleteUser?.(row.id)}>Delete</Button>
                                </div>
                              </TableCell>
                            );
                          }
                          return <TableCell key={cell.id}>{cell.value}</TableCell>;
                        })}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </DataTable>
        </Stack>
      </Column>
    </Grid>
  );
}

function HelpModal({ open, onClose }) {
  const [html, setHtml] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    (async () => {
      try {
        setError("");
        const res = await fetch("/help.html", { cache: "no-cache" });
        if (!res.ok) throw new Error(`Unable to load help content (HTTP ${res.status})`);
        const t = await res.text();
        if (!cancelled) setHtml(t);
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open]);

  return (
    <Modal
      open={open}
      modalHeading="Help"
      primaryButtonText="Close"
      onRequestClose={onClose}
      onRequestSubmit={onClose}
      size="lg"
    >
      {error ? (
        <InlineNotification kind="error" lowContrast title="Help unavailable" subtitle={error} hideCloseButton />
      ) : (
        <div className="mx-help-content" dangerouslySetInnerHTML={{ __html: html }} />
      )}
    </Modal>
  );
}

export default function AppCore() {
  const [page, setPage] = useState(PAGES.DASH);

  // Theme toggle (kept local to UI; does not touch server settings)
  // Carbon themes: g10 (light), g100 (dark)
  const [uiTheme, setUiTheme] = useState("g10");

  // Current user (role-based UI)
  const [me, setMe] = useState(null);
  const isAdmin = String(me?.role || "").toLowerCase() === "admin";

  const [settings, setSettings] = useState(null);
  const [logs, setLogs] = useState([]);
  const [trace, setTrace] = useState(null);
  const [error, setError] = useState(null);

  // Users summary (safe aggregates used by the dashboard)
  const [usersSummary, setUsersSummary] = useState(null);

  // Users management
  const [users, setUsers] = useState([]);
  const [usersError, setUsersError] = useState(null);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [userEditing, setUserEditing] = useState(null); // username or null
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "user" });

  // Tenants management (admin only)
  const [tenants, setTenants] = useState([]);
  const [tenantsError, setTenantsError] = useState(null);
  const [tenantModalOpen, setTenantModalOpen] = useState(false);
  const [tenantEditingId, setTenantEditingId] = useState(null);
  const [tenantDraft, setTenantDraft] = useState({ id: "", baseUrl: "", apiKey: "", user: "", password: "", defaultSite: "" });

  // Role-based navigation guard: USER role should not access admin-only pages.
  useEffect(() => {
    if (isAdmin) return;
    const forbidden = new Set([PAGES.TENANTS, PAGES.LOGS, PAGES.SETTINGS, PAGES.USERS]);
    if (forbidden.has(page)) setPage(PAGES.DASH);
  }, [isAdmin, page]);


async function refreshUsers() {
  setUsersError(null);
  try {
    const r = await fetch("/api/users");
    if (!r.ok) throw new Error();
    const data = await r.json();
    setUsers(data.users || []);
  } catch {
    setUsersError("Failed to load users (admin only).");
  }
}

const openAddUser = () => {
  setUserEditing(null);
  setNewUser({ username: "", password: "", role: "user" });
  setUserModalOpen(true);
};

const openEditUser = (username) => {
  const u = users.find((x) => x.username === username);
  if (!u) return;
  setUserEditing(username);
  setNewUser({ username, password: "", role: u.role || "user" });
  setUserModalOpen(true);
};

const saveUser = async () => {
  try {
    setUsersError(null);
    const payload = { username: newUser.username, password: newUser.password, role: newUser.role };
    let r;
    if (userEditing) {
      // Update: password is optional; blank means "keep".
      r = await fetch(`/api/users/${encodeURIComponent(userEditing)}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
    } else {
      r = await fetch("/api/users", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
    }
    if (!r.ok) {
      const t = await r.text();
      throw new Error(t.slice(0, 240) || `HTTP ${r.status}`);
    }
    setUserModalOpen(false);
    setNewUser({ username: "", password: "", role: "user" });
    setUserEditing(null);
    await refreshUsers();
  } catch (e) {
    setUsersError(String(e?.message || e));
  }
};

const deleteUser = async (username) => {
  if (!username || username === "admin") return;
  try {
    setUsersError(null);
    const r = await fetch(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    if (!r.ok) {
      const t = await r.text();
      throw new Error(t.slice(0, 240) || `HTTP ${r.status}`);
    }
    await refreshUsers();
  } catch (e) {
    setUsersError(String(e?.message || e));
  }
};

async function refreshTenants() {
  setTenantsError(null);
  try {
    const r = await fetch("/api/tenants");
    if (!r.ok) throw new Error();
    const data = await r.json();
    setTenants(Array.isArray(data.tenants) ? data.tenants : []);
  } catch {
    setTenantsError("Failed to load tenants (admin only).");
  }
}

const openCreateTenant = () => {
  setTenantEditingId(null);
  setTenantDraft({ id: "mytenant", baseUrl: "", apiKey: "", user: "", password: "", defaultSite: "" });
  setTenantModalOpen(true);
};

const openEditTenant = (id) => {
  const t = tenants.find((x) => x.id === id);
  if (!t) return;
  setTenantEditingId(id);
  // Secrets are intentionally blank on edit; enter to update.
  setTenantDraft({ id, baseUrl: t.baseUrl || "", apiKey: "", user: t.user || "", password: "", defaultSite: t.defaultSite || "" });
  setTenantModalOpen(true);
};

const saveTenant = async () => {
  try {
    setTenantsError(null);
    if (!tenantDraft.id) throw new Error("Missing id");
    const payload = { id: tenantDraft.id, tenant: { baseUrl: tenantDraft.baseUrl, apiKey: tenantDraft.apiKey, user: tenantDraft.user, password: tenantDraft.password, defaultSite: tenantDraft.defaultSite } };
    const url = tenantEditingId ? `/api/tenants/${encodeURIComponent(tenantEditingId)}` : "/api/tenants";
    const method = tenantEditingId ? "PUT" : "POST";
    const r = await fetch(url, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error(txt.slice(0, 240) || `HTTP ${r.status}`);
    }
    setTenantModalOpen(false);
    await refreshTenants();
    await loadSettings();
  } catch (e) {
    setTenantsError(String(e?.message || e));
  }
};

const deleteTenant = async (id) => {
  if (!id) return;
  try {
    setTenantsError(null);
    const r = await fetch(`/api/tenants/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!r.ok) {
      const txt = await r.text();
      throw new Error(txt.slice(0, 240) || `HTTP ${r.status}`);
    }
    await refreshTenants();
    await loadSettings();
  } catch (e) {
    setTenantsError(String(e?.message || e));
  }
};


  // Logs UI state
  const [logSearch, setLogSearch] = useState("");
  const [logPage, setLogPage] = useState(1);
  const [logPageSize, setLogPageSize] = useState(20);

  // Messages UI state (separate; does not affect Logs page)
  const [msgSearch, setMsgSearch] = useState("");
  const [msgPage, setMsgPage] = useState(1);
  const [msgPageSize, setMsgPageSize] = useState(20);

  // Details modal
  const [selectedLog, setSelectedLog] = useState(null);
  const [logModalOpen, setLogModalOpen] = useState(false);

  // Settings modal (header icon)
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  // Settings editor
  const [settingsText, setSettingsText] = useState("{}");
  const [settingsSaving, setSettingsSaving] = useState(false);

  // -----------------------------
  // Fetch functions
  // -----------------------------
  async function loadMe() {
    try {
      const r = await fetch("/api/auth/me", { credentials: "include" });
      if (!r.ok) throw new Error(`GET /api/auth/me ${r.status}`);
      const j = await r.json();
      setMe(j);
    } catch {
      // AuthGate will handle redirect; keep best-effort local state.
      setMe(null);
    }
  }

  async function loadUsersSummary() {
    try {
      const r = await fetch("/api/users/summary", { credentials: "include" });
      if (!r.ok) throw new Error(`GET /api/users/summary ${r.status}`);
      const j = await r.json();
      setUsersSummary(j);
    } catch {
      setUsersSummary(null);
    }
  }

  async function loadSettings() {
    const r = await fetch("/api/settings");
    if (!r.ok) throw new Error(`GET /api/settings ${r.status}`);
    const j = await r.json();
    setSettings(j);
    setSettingsText(JSON.stringify(j, null, 2));
  }

  async function loadLogs(limit = 800) {
    const r = await fetch(`/api/logs?limit=${limit}`);
    if (!r.ok) throw new Error(`GET /api/logs ${r.status}`);
    const j = await r.json();
    setLogs(Array.isArray(j?.logs) ? j.logs : []);
  }

  async function loadTrace(limit = 200) {
    const r = await fetch(`/api/trace?limit=${limit}`);
    if (!r.ok) throw new Error(`GET /api/trace ${r.status}`);
    const j = await r.json();
    setTrace(j);
  }

  async function refreshAll() {
    try {
      setError(null);
      await Promise.all([loadMe(), loadUsersSummary(), loadSettings(), loadLogs(800), loadTrace(200)]);
    } catch (e) {
      setError(String(e?.message || e));
    }
  }

  async function clearLogs() {
    try {
      setError(null);
      const r = await fetch("/api/logs/clear", { method: "POST" });
      if (!r.ok) throw new Error(`POST /api/logs/clear ${r.status}`);
      await Promise.all([loadLogs(200), loadTrace(200)]);
    } catch (e) {
      setError(String(e?.message || e));
    }
  }

  async function saveSettings() {
    setSettingsSaving(true);
    try {
      setError(null);
      let parsed;
      try {
        parsed = JSON.parse(settingsText || "{}");
      } catch {
        throw new Error("Settings JSON is invalid.");
      }
      const r = await fetch("/api/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(parsed),
      });
      if (!r.ok) throw new Error(`POST /api/settings ${r.status}`);
      await loadSettings();
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setSettingsSaving(false);
    }
  }

  // -----------------------------
  // Initial load + polling
  // -----------------------------
  // Load users when opening Users page

useEffect(() => {
  if (page !== PAGES.USERS) return;
  refreshUsers();
}, [page]);

useEffect(() => {
  if (page !== PAGES.USERS) return;
  (async () => {
    setUsersError(null);
    try {
      const r = await fetch("/api/users");
      if (!r.ok) {
        const t = await r.text();
        throw new Error(t || `HTTP ${r.status}`);
      }
      const data = await r.json();
      setUsers(data.users || []);
    } catch (e) {
      setUsersError("Failed to load users (admin only).");
    }
  })();
}, [page]);

// Load tenants when opening Tenants page
useEffect(() => {
  if (page !== PAGES.TENANTS) return;
  refreshTenants();
}, [page]);

useEffect(() => {
    refreshAll();
    const t = setInterval(async () => {
      try {
        await Promise.all([loadLogs(800), loadTrace(200)]);
      } catch {
        // ignore polling errors
      }
    }, 2000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -----------------------------
  // Derived: map id->log (fixes Carbon DataTable dropping custom props)
  // -----------------------------
  const logById = useMemo(() => {
    const m = new Map();
    for (const e of logs) m.set(e.id, e);
    return m;
  }, [logs]);

  // Latest activity for dashboard: use real logs array (not DataTable rows)
  const latest = useMemo(() => logs.slice(-12).reverse(), [logs]);

  // -----------------------------------------------------------------
  // Dashboard chart data
  // -----------------------------------------------------------------
  const kindCounts = useMemo(() => {
    const m = new Map();
    for (const e of logs) {
      const k = String(e?.kind || "unknown");
      m.set(k, (m.get(k) || 0) + 1);
    }
    return Array.from(m.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }, [logs]);

  const tenantCounts = useMemo(() => {
    const m = new Map();
    for (const e of logs) {
      const t = String(e?.tenant || "default");
      m.set(t, (m.get(t) || 0) + 1);
    }
    return Array.from(m.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value);
  }, [logs]);

  const requestsPerMin = useMemo(() => {
    const buckets = new Map();
    const now = Date.now();
    // Look back ~15 minutes (best-effort; based on the logs we have in memory)
    const start = now - 15 * 60 * 1000;
    for (const e of logs) {
      const ts = Number(new Date(e?.ts).getTime() || 0);
      if (!ts || ts < start) continue;
      const key = Math.floor(ts / 60000);
      buckets.set(key, (buckets.get(key) || 0) + 1);
    }
    // Emit a dense series for the last 15 minutes
    const endKey = Math.floor(now / 60000);
    const out = [];
    for (let k = endKey - 14; k <= endKey; k++) {
      out.push(buckets.get(k) || 0);
    }
    return out;
  }, [logs]);

  const topTraceRoutes = useMemo(() => {
    const agg = Array.isArray(trace?.aggregates) ? trace.aggregates : [];
    return agg
      .slice()
      .sort((a, b) => Number(b.avgResTokensApprox || 0) - Number(a.avgResTokensApprox || 0))
      .slice(0, 8)
      .map((a) => ({
        label: String(a?.key || ""),
        value: Number(a?.avgResTokensApprox || 0),
      }));
  }, [trace]);

  // -----------------------------
  // Derived: Logs filtering + paging (existing Logs page)
  // -----------------------------
  const filteredLogs = useMemo(() => {
    const q = logSearch.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter((e) => {
      const hay = `${e.kind || ""} ${e.title || ""} ${e.tenant || ""} ${e.status || ""} ${
        e.tool || ""
      } ${e.url || ""} ${e.responseBody || ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [logs, logSearch]);

  const pagedLogs = useMemo(() => {
    const start = (logPage - 1) * logPageSize;
    const end = start + logPageSize;
    return filteredLogs.slice(start, end);
  }, [filteredLogs, logPage, logPageSize]);

  useEffect(() => setLogPage(1), [logSearch]);

  // -----------------------------
  // Derived: Messages filtering + paging (NEW Messages page)
  // -----------------------------
  const filteredMessages = useMemo(() => {
    const base = logs.filter((e) => isMessageKind(e.kind));
    const q = msgSearch.trim().toLowerCase();
    if (!q) return base;
    return base.filter((e) => {
      const hay = `${e.kind || ""} ${e.title || ""} ${e.tenant || ""} ${e.status || ""} ${
        e.tool || ""
      } ${e.url || ""} ${e.responseBody || ""}`.toLowerCase();
      return hay.includes(q);
    });
  }, [logs, msgSearch]);

  const pagedMessages = useMemo(() => {
    const start = (msgPage - 1) * msgPageSize;
    const end = start + msgPageSize;
    return filteredMessages.slice(start, end);
  }, [filteredMessages, msgPage, msgPageSize]);

  useEffect(() => setMsgPage(1), [msgSearch]);

  // -----------------------------
  // Table headers
  // -----------------------------
  const logsHeaders = useMemo(
    () => [
      { key: "time", header: "Time" },
      { key: "kind", header: "Kind" },
      { key: "ai", header: "AI" },
      { key: "title", header: "Title" },
      { key: "tenant", header: "Tenant" },
      { key: "status", header: "Status" },
      { key: "sizes", header: "Sizes" },
      { key: "actions", header: "" },
    ],
    []
  );

  const traceAggHeaders = useMemo(
    () => [
      { key: "key", header: "Route" },
      { key: "count", header: "Count" },
      { key: "avgResBytes", header: "Avg Res Bytes" },
      { key: "avgResTokensApprox", header: "Avg Res Tokens≈" },
      { key: "maxResTokensApprox", header: "Max Res Tokens≈" },
      { key: "avgMs", header: "Avg ms" },
    ],
    []
  );

  const traceRecentHeaders = useMemo(
    () => [
      { key: "time", header: "Time" },
      { key: "title", header: "Route" },
      { key: "status", header: "Status" },
      { key: "reqTokensApprox", header: "Req Tokens≈" },
      { key: "resTokensApprox", header: "Res Tokens≈" },
      { key: "ms", header: "ms" },
    ],
    []
  );

  // -----------------------------
  // DataTable rows (no custom props; Carbon may drop them)
  // -----------------------------
  const logsRows = useMemo(() => {
    return pagedLogs.map((e) => {
      const reqB = e.requestBytes ?? e.reqBytes ?? 0;
      const resB = e.responseBytes ?? e.resBytes ?? 0;
      return {
        id: e.id,
        time: new Date(e.ts).toLocaleTimeString(),
        kind: e.kind || "",
        ai: fmtAiInfo(e),
        title: e.title || "",
        tenant: e.tenant || "",
        status: e.status != null ? String(e.status) : "",
        sizes: reqB || resB ? `req ${fmtBytes(reqB)} / res ${fmtBytes(resB)}` : "",
      };
    });
  }, [pagedLogs]);

  const msgRows = useMemo(() => {
    return pagedMessages.map((e) => {
      const reqB = e.requestBytes ?? e.reqBytes ?? 0;
      const resB = e.responseBytes ?? e.resBytes ?? 0;
      return {
        id: e.id,
        time: new Date(e.ts).toLocaleTimeString(),
        kind: e.kind || "",
        ai: fmtAiInfo(e),
        title: e.title || "",
        tenant: e.tenant || "",
        status: e.status != null ? String(e.status) : "",
        sizes: reqB || resB ? `req ${fmtBytes(reqB)} / res ${fmtBytes(resB)}` : "",
      };
    });
  }, [pagedMessages]);

  const traceAggRows = useMemo(() => {
    const arr = trace?.aggregates || [];
    return arr.map((a, idx) => ({ id: `${a.key}-${idx}`, ...a }));
  }, [trace]);

  const traceRecentRows = useMemo(() => {
    const arr = trace?.recent || [];
    return arr.map((e) => ({
      id: e.id,
      time: new Date(e.ts).toLocaleTimeString(),
      title: e.title,
      status: String(e.status),
      reqTokensApprox: String(e.reqTokensApprox ?? ""),
      resTokensApprox: String(e.resTokensApprox ?? ""),
      ms: String(e.ms ?? ""),
    }));
  }, [trace]);

  // -----------------------------
  // Pages
  // -----------------------------
  function Dashboard() {
    const tenantsCount = settings?.tenants?.length ?? 0;
    const traceEnabled = !!(settings?.httpTraceEnabled ?? settings?.traceHttp);
    const traceOn = traceEnabled ? "ON" : "OFF";

    const usersTotal = Number(usersSummary?.total || 0);
    const usersByRole = usersSummary?.byRole || {};
    const usersRoleData = Object.entries(usersByRole)
      .map(([k, v]) => ({ label: k, value: Number(v || 0) }))
      .sort((a, b) => b.value - a.value);

    const logsCount = logs.length;

    return (
      <Grid fullWidth>
        <Column lg={16} md={8} sm={4}>
          <Stack gap={6}>
            <Grid fullWidth>
              <Column lg={4} md={4} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 8 }}>Tenants</h4>
                  <Tag type="blue">{tenantsCount}</Tag>
                </Tile>
              </Column>
              <Column lg={4} md={4} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 8 }}>Users</h4>
                  <Tag type="cool-gray">{usersTotal}</Tag>
                </Tile>
              </Column>
              <Column lg={4} md={4} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 8 }}>Logs (buffer)</h4>
                  <Tag type="teal">{logsCount}</Tag>
                </Tile>
              </Column>
              <Column lg={4} md={4} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 8 }}>HTTP Trace</h4>
                  <Tag type={traceOn === "ON" ? "green" : "red"}>{traceOn}</Tag>
                </Tile>
              </Column>
            </Grid>

            <Grid fullWidth>
              <Column lg={8} md={8} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 10 }}>Activity by kind</h4>
                  <div style={{ opacity: 0.75, marginBottom: 10, fontSize: 12 }}>
                    Counts from the in-memory log buffer (latest {logsCount} events).
                  </div>
                  <DonutChart data={kindCounts} />
                </Tile>
              </Column>
              <Column lg={8} md={8} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 10 }}>Activity by tenant</h4>
                  <div style={{ opacity: 0.75, marginBottom: 10, fontSize: 12 }}>
                    Includes tool calls, Maximo traffic, and UI/API events.
                  </div>
                  <DonutChart data={tenantCounts} />
                </Tile>
              </Column>
            </Grid>

            <Grid fullWidth>
              <Column lg={8} md={8} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 10 }}>Requests per minute (last ~15m)</h4>
                  <div style={{ opacity: 0.75, marginBottom: 10, fontSize: 12 }}>
                    Derived from timestamps in the log buffer.
                  </div>
                  <div style={{ color: colorForIndex(5) }}>
                    <Sparkline values={requestsPerMin} />
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6, opacity: 0.75, fontSize: 12 }}>
                    <span>{requestsPerMin?.[0] ?? 0}…</span>
                    <span>…{requestsPerMin?.[requestsPerMin.length - 1] ?? 0}</span>
                  </div>
                </Tile>
              </Column>
              <Column lg={8} md={8} sm={4}>
                <Tile>
                  <h4 style={{ marginBottom: 10 }}>Trace: biggest responses (tokens≈)</h4>
                  <div style={{ opacity: 0.75, marginBottom: 10, fontSize: 12 }}>
                    Tokens≈ are estimated as bytes ÷ 4. Enable HTTP Trace on the server to capture payload sizes.
                  </div>
                  {traceEnabled && topTraceRoutes.length ? (
                    <BarList data={topTraceRoutes} valueFormatter={(v) => `${Math.round(v)} ≈tok`} />
                  ) : (
                    <div style={{ opacity: 0.8, fontSize: 12 }}>
                      No trace data yet (trace is {traceOn}).
                    </div>
                  )}
                </Tile>
              </Column>
            </Grid>

            <Tile>
              <h4 style={{ marginBottom: 10 }}>Users by role</h4>
              {usersRoleData.length ? (
                <DonutChart data={usersRoleData} maxItems={8} />
              ) : (
                <div style={{ opacity: 0.8, fontSize: 12 }}>
                  Unable to load user summary.
                </div>
              )}
            </Tile>
          </Stack>
        </Column>
      </Grid>
    );
  }

  function TenantsPage() {
    return (
      <Grid condensed>
        <Column sm={4} md={8} lg={16}>
          <Stack gap={5}>
            <Stack orientation="horizontal" gap={3} style={{ alignItems: "center", justifyContent: "space-between" }}>
              <h3 style={{ margin: 0 }}>Tenants</h3>
              <div style={{ display: "flex", gap: 8 }}>
                <Button kind="secondary" onClick={refreshTenants}>Refresh</Button>
                <Button renderIcon={Add} onClick={openCreateTenant}>Add tenant</Button>
              </div>
            </Stack>

            <p style={{ margin: 0, opacity: 0.8 }}>
              Manage IBM Maximo Manage tenant connections (admin only). Stored in <code>/data/tenant.json</code> (legacy: <code>/data/tenants.json</code>).
            </p>

            {tenantsError && <InlineNotification kind="error" lowContrast title={tenantsError} />}

            <DataTable
              rows={(tenants || []).map((t) => ({ id: t.id, ...t }))}
              headers={[
                { key: "id", header: "Tenant" },
                { key: "baseUrl", header: "Base URL" },
                { key: "user", header: "User" },
                { key: "defaultSite", header: "Default Site" },
                { key: "hasApiKey", header: "API Key" },
                { key: "hasPassword", header: "Password" },
                { key: "actions", header: "Actions" },
              ]}
              isSortable
            >
              {({ rows, headers, getHeaderProps, getRowProps }) => (
                <TableContainer title="">
                  <Table size="lg">
                    <TableHead>
                      <TableRow>
                        {headers.map((header) => (
                          <TableHeader key={header.key} {...getHeaderProps({ header })}>
                            {header.header}
                          </TableHeader>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {rows.map((row) => (
                        <TableRow key={row.id} {...getRowProps({ row })}>
                          {row.cells.map((cell) => {
                            if (cell.info.header === "actions") {
                              return (
                                <TableCell key={cell.id}>
                                  <div style={{ display: "flex", gap: 8 }}>
                                    <Button size="sm" kind="ghost" renderIcon={Edit} onClick={() => openEditTenant(row.id)}>
                                      Edit
                                    </Button>
                                    <Button size="sm" kind="danger--ghost" renderIcon={TrashCan} disabled={row.id === "default"} onClick={() => deleteTenant(row.id)}>
                                      Delete
                                    </Button>
                                  </div>
                                </TableCell>
                              );
                            }
                            if (cell.info.header === "hasApiKey" || cell.info.header === "hasPassword") {
                              return <TableCell key={cell.id}>{String(cell.value) === "true" ? "Yes" : "No"}</TableCell>;
                            }
                            return <TableCell key={cell.id}>{cell.value}</TableCell>;
                          })}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </DataTable>
          </Stack>
        </Column>
      </Grid>
    );
  }

  function Logs() {
    return (
      <Grid fullWidth>
        <Column lg={16} md={8} sm={4}>
          <Stack gap={5}>
            <Tile>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                <div>
                  <h2 style={{ marginBottom: 6 }}>Logs</h2>
                  <p style={{ margin: 0, opacity: 0.85 }}>All log events (search + details).</p>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <Button kind="secondary" size="sm" onClick={() => loadLogs(800)}>
                    Refresh
                  </Button>
                  <Button kind="danger--tertiary" size="sm" renderIcon={TrashCan} onClick={clearLogs}>
                    Clear
                  </Button>
                </div>
              </div>

              <div style={{ marginTop: 12 }}>
                <DataTable rows={logsRows} headers={logsHeaders} useZebraStyles>
                  {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
                    <TableContainer title="Events" description="Search and inspect any event in detail">
                      <TableToolbar>
                        <TableToolbarContent>
                          <TableToolbarSearch
                            persistent
                            value={logSearch}
                            onChange={(e) => setLogSearch(e?.target?.value ?? "")}
                            placeholder="Search kind/title/status/tenant/url…"
                          />
                          <Button kind="ghost" size="sm" onClick={() => loadLogs(800)}>
                            Refresh
                          </Button>
                        </TableToolbarContent>
                      </TableToolbar>

                      <Table {...getTableProps()}>
                        <TableHead>
                          <TableRow>
                            {headers.map((h) => (
                              <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                                {h.header}
                              </TableHeader>
                            ))}
                          </TableRow>
                        </TableHead>

                        <TableBody>
                          {rows.map((row) => {
                            const raw = logById.get(row.id);
                            return (
                              <TableRow key={row.id} {...getRowProps({ row })}>
                                {row.cells.map((cell) => {
                                  if (cell.info.header === "kind") {
                                    return (
                                      <TableCell key={cell.id}>
                                        <Tag type={kindToTagType(cell.value)}>{cell.value}</Tag>
                                      </TableCell>
                                    );
                                  }

                                  if (cell.info.header === "actions") {
                                    return (
                                      <TableCell key={cell.id}>
                                        <Button
                                          size="sm"
                                          kind="ghost"
                                          disabled={!raw}
                                          onClick={() => {
                                            setSelectedLog(raw || null);
                                            setLogModalOpen(true);
                                          }}
                                        >
                                          Details
                                        </Button>
                                      </TableCell>
                                    );
                                  }

                                  return <TableCell key={cell.id}>{cell.value}</TableCell>;
                                })}
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>

                      <div style={{ marginTop: 8 }}>
                        <Pagination
                          page={logPage}
                          pageSize={logPageSize}
                          pageSizes={[10, 20, 50, 100]}
                          totalItems={filteredLogs.length}
                          onChange={({ page, pageSize }) => {
                            setLogPage(page);
                            setLogPageSize(pageSize);
                          }}
                          backwardText="Previous page"
                          forwardText="Next page"
                        />
                      </div>
                    </TableContainer>
                  )}
                </DataTable>
              </div>
            </Tile>
          </Stack>
        </Column>
      </Grid>
    );
  }

  // NEW: Messages page (rx/tx agent + maximo only)
  function Messages() {
    return (
      <Grid fullWidth>
        <Column lg={16} md={8} sm={4}>
          <Stack gap={5}>
            <Tile>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                <div>
                  <h2 style={{ marginBottom: 6 }}>Messages</h2>
                  <p style={{ margin: 0, opacity: 0.85 }}>
                    Filtered view: <strong>rx_agent (received from AI Agent)</strong>, <strong>tx_agent (sent to AI Agent)</strong>, <strong>rx_maximo (received from Maximo)</strong>,{" "}
                    <strong>tx_maximo (sent to AI Maximo)</strong>.
                  </p>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <Button kind="secondary" size="sm" onClick={() => loadLogs(800)}>
                    Refresh
                  </Button>
                </div>
              </div>

              <div style={{ marginTop: 12 }}>
                <DataTable rows={msgRows} headers={logsHeaders} useZebraStyles>
                  {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
                    <TableContainer title="Message events" description="Only the message flow events (with details)">
                      <TableToolbar>
                        <TableToolbarContent>
                          <TableToolbarSearch
                            persistent
                            value={msgSearch}
                            onChange={(e) => setMsgSearch(e?.target?.value ?? "")}
                            placeholder="Search message events…"
                          />
                        </TableToolbarContent>
                      </TableToolbar>

                      <Table {...getTableProps()}>
                        <TableHead>
                          <TableRow>
                            {headers.map((h) => (
                              <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                                {h.header}
                              </TableHeader>
                            ))}
                          </TableRow>
                        </TableHead>

                        <TableBody>
                          {rows.map((row) => {
                            const raw = logById.get(row.id);
                            return (
                              <TableRow key={row.id} {...getRowProps({ row })}>
                                {row.cells.map((cell) => {
                                  if (cell.info.header === "kind") {
                                    return (
                                      <TableCell key={cell.id}>
                                        <Tag type={kindToTagType(cell.value)}>{cell.value}</Tag>
                                      </TableCell>
                                    );
                                  }

                                  if (cell.info.header === "actions") {
                                    return (
                                      <TableCell key={cell.id}>
                                        <Button
                                          size="sm"
                                          kind="ghost"
                                          disabled={!raw}
                                          onClick={() => {
                                            setSelectedLog(raw || null);
                                            setLogModalOpen(true);
                                          }}
                                        >
                                          Details
                                        </Button>
                                      </TableCell>
                                    );
                                  }

                                  return <TableCell key={cell.id}>{cell.value}</TableCell>;
                                })}
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>

                      <div style={{ marginTop: 8 }}>
                        <Pagination
                          page={msgPage}
                          pageSize={msgPageSize}
                          pageSizes={[10, 20, 50, 100]}
                          totalItems={filteredMessages.length}
                          onChange={({ page, pageSize }) => {
                            setMsgPage(page);
                            setMsgPageSize(pageSize);
                          }}
                          backwardText="Previous page"
                          forwardText="Next page"
                        />
                      </div>
                    </TableContainer>
                  )}
                </DataTable>
              </div>
            </Tile>
          </Stack>
        </Column>
      </Grid>
    );
  }

  function Trace() {
    return (
      <Grid fullWidth>
        <Column lg={16} md={8} sm={4}>
          <Stack gap={5}>
            <Tile>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                <div>
                  <h2 style={{ marginBottom: 6 }}>Payload / Token Trace</h2>
                  <p style={{ margin: 0, opacity: 0.85 }}>Tokens≈ bytes ÷ 4. Use this to spot huge payloads.</p>
                </div>
                <Button kind="secondary" size="sm" onClick={() => loadTrace(200)}>
                  Refresh
                </Button>
              </div>

              <Tabs>
                <TabList aria-label="Trace tabs">
                  <Tab>Top offenders</Tab>
                  <Tab>Recent</Tab>
                </TabList>
                <TabPanels>
                  <TabPanel>
                    <div style={{ marginTop: 12 }}>
                      <DataTable rows={traceAggRows} headers={traceAggHeaders}>
                        {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
                          <TableContainer title="Top offenders" description="Largest avg responses">
                            <Table {...getTableProps()}>
                              <TableHead>
                                <TableRow>
                                  {headers.map((h) => (
                                    <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                                      {h.header}
                                    </TableHeader>
                                  ))}
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {rows.map((row) => (
                                  <TableRow key={row.id} {...getRowProps({ row })}>
                                    {row.cells.map((cell) => (
                                      <TableCell key={cell.id}>{cell.value}</TableCell>
                                    ))}
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </DataTable>
                    </div>
                  </TabPanel>

                  <TabPanel>
                    <div style={{ marginTop: 12 }}>
                      <DataTable rows={traceRecentRows} headers={traceRecentHeaders} useZebraStyles>
                        {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
                          <TableContainer title="Recent requests" description="Rolling view">
                            <Table {...getTableProps()}>
                              <TableHead>
                                <TableRow>
                                  {headers.map((h) => (
                                    <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                                      {h.header}
                                    </TableHeader>
                                  ))}
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {rows.map((row) => (
                                  <TableRow key={row.id} {...getRowProps({ row })}>
                                    {row.cells.map((cell) => (
                                      <TableCell key={cell.id}>{cell.value}</TableCell>
                                    ))}
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </DataTable>
                    </div>
                  </TabPanel>
                </TabPanels>
              </Tabs>

              {trace?.note && <div style={{ marginTop: 10, opacity: 0.8 }}>{trace.note}</div>}
            </Tile>
          </Stack>
        </Column>
      </Grid>
    );
  }

  function SettingsPage() {
    const isDark = uiTheme === "g100";

    return (
      <Grid fullWidth>
        <Column lg={16} md={8} sm={4}>
          <Stack gap={5}>
            <Tile>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                <div>
                  <h2 style={{ marginBottom: 6 }}>Settings</h2>
                  <p style={{ margin: 0, opacity: 0.85 }}>Edit JSON and save via /api/settings</p>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <Button kind="secondary" size="sm" onClick={loadSettings}>
                    Reload
                  </Button>
                  <Button size="sm" onClick={saveSettings} disabled={settingsSaving}>
                    {settingsSaving ? "Saving…" : "Save"}
                  </Button>
                </div>
              </div>

              {/* NEW: Light/Dark toggle (UI-only, does not change backend) */}
              <div style={{ marginTop: 16, marginBottom: 8 }}>
                <Toggle
                  id="theme-toggle"
                  labelText="Appearance"
                  labelA="Light"
                  labelB="Dark"
                  toggled={isDark}
                  onToggle={(t) => setUiTheme(t ? "g100" : "g10")}
                />
              </div>

              <div style={{ marginTop: 12 }}>
                <TextArea
                  labelText="Settings JSON"
                  value={settingsText}
                  onChange={(e) => setSettingsText(e?.target?.value ?? "")}
                  rows={16}
                />
              </div>
            </Tile>
          </Stack>
        </Column>
      </Grid>
    );
  }

  return (
    <Theme theme={uiTheme}>
      <Header aria-label="Maximo MCP Server" style={{ backgroundColor: "#000", color: "#fff" }}>
        <HeaderName prefix="">Maximo MCP Server</HeaderName>
        <HeaderGlobalBar>
          <HeaderGlobalAction aria-label="Refresh" onClick={refreshAll} tooltipAlignment="end">
            <Renew />
          </HeaderGlobalAction>
          {isAdmin ? (
            <HeaderGlobalAction aria-label="Clear logs" onClick={clearLogs} tooltipAlignment="end">
              <TrashCan />
            </HeaderGlobalAction>
          ) : null}
          {isAdmin ? (
            <HeaderGlobalAction aria-label="Settings" onClick={() => setSettingsModalOpen(true)} tooltipAlignment="end">
              <Settings />
            </HeaderGlobalAction>
          ) : null}
          <HeaderGlobalAction aria-label="Help" onClick={() => setHelpOpen(true)} tooltipAlignment="end">
            <Information />
          </HeaderGlobalAction>
          <HeaderGlobalAction
            aria-label="Logout"
            tooltipAlignment="end"
            onClick={async () => {
              try {
                await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
              } finally {
                window.location.reload();
              }
            }}
          >
            <Logout />
          </HeaderGlobalAction>
        </HeaderGlobalBar>
      </Header>

      <HelpModal open={helpOpen} onClose={() => setHelpOpen(false)} />

      <SideNav aria-label="Side navigation" expanded isFixedNav>
        <SideNavItems>
          <SideNavLink
            renderIcon={Analytics}
            isActive={page === PAGES.DASH}
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setPage(PAGES.DASH);
            }}
          >
            Dashboard
          </SideNavLink>

          <SideNavLink
            renderIcon={List}
            isActive={page === PAGES.TOOLS}
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setPage(PAGES.TOOLS);
            }}
          >
            Tools
          </SideNavLink>

          {isAdmin ? (
            <>
              <SideNavLink
                renderIcon={List}
                isActive={page === PAGES.NLQ_RULES}
                href="#"
                onClick={(e) => { e.preventDefault(); setPage(PAGES.NLQ_RULES); }}
              >
                NLQ Rules
              </SideNavLink>
              <SideNavLink
                renderIcon={List}
                isActive={page === PAGES.NLQ_METADATA}
                href="#"
                onClick={(e) => { e.preventDefault(); setPage(PAGES.NLQ_METADATA); }}
              >
                NLQ Metadata
              </SideNavLink>
            </>
          ) : null}

          {isAdmin ? (
            <SideNavLink
              renderIcon={List}
              isActive={page === PAGES.TENANTS}
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setPage(PAGES.TENANTS);
              }}
            >
              Tenants
            </SideNavLink>
          ) : null}

          {isAdmin ? (
            <SideNavLink
              renderIcon={List}
              isActive={page === PAGES.LOGS}
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setPage(PAGES.LOGS);
              }}
            >
              Logs
            </SideNavLink>
          ) : null}

          {/* NEW menu item */}
          <SideNavLink
            renderIcon={Chat}
            isActive={page === PAGES.MESSAGES}
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setPage(PAGES.MESSAGES);
            }}
          >
            Messages
          </SideNavLink>

          <SideNavLink
            renderIcon={Analytics}
            isActive={page === PAGES.TRACE}
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setPage(PAGES.TRACE);
            }}
          >
            Trace
          </SideNavLink>

          {isAdmin ? (
            <SideNavLink
              renderIcon={Settings}
              isActive={page === PAGES.SETTINGS}
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setPage(PAGES.SETTINGS);
              }}
            >
              Settings
            </SideNavLink>
          ) : null}

          {isAdmin ? (
            <SideNavLink
              renderIcon={UserMultiple}
              isActive={page === PAGES.USERS}
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setPage(PAGES.USERS);
              }}
            >
              Users
            </SideNavLink>
          ) : null}
        </SideNavItems>
      </SideNav>

      <Content>
        <div style={{ paddingTop: 16 }}>
          {error && (
            <InlineNotification
              kind="error"
              title="Error"
              subtitle={error}
              lowContrast
              onClose={() => setError(null)}
            />
          )}

          {page === PAGES.DASH && <Dashboard />}
          {isAdmin && page === PAGES.TENANTS && <TenantsPage />}
          {page === PAGES.TOOLS && <ToolsPage tenant="default" readOnly={!isAdmin} />}
          {isAdmin && page === PAGES.NLQ_RULES && <NlqRulesPage />}
          {isAdmin && page === PAGES.NLQ_METADATA && <NlqMetadataPage />}
          {isAdmin && page === PAGES.LOGS && <Logs />}
          {page === PAGES.MESSAGES && <Messages />}
          {page === PAGES.TRACE && <Trace />}
          {isAdmin && page === PAGES.SETTINGS && <SettingsPage />}
          {isAdmin && page === PAGES.USERS && (
            <UsersPage
              users={users}
              usersError={usersError}
              onRefresh={refreshUsers}
              onAddUser={openAddUser}
              onEditUser={openEditUser}
              onDeleteUser={deleteUser}
            />
          )}
        </div>
      </Content>

      <Modal
        open={logModalOpen}
        modalHeading="Log entry details"
        primaryButtonText="Close"
        onRequestClose={() => setLogModalOpen(false)}
        onRequestSubmit={() => setLogModalOpen(false)}
      >
        {selectedLog ? (
          <CodeSnippet type="multi" wrapText>
            {JSON.stringify(selectedLog, null, 2)}
          </CodeSnippet>
        ) : (
          <div style={{ opacity: 0.8 }}>No entry selected.</div>
        )}
      </Modal>

      {isAdmin ? (
        <Modal
          open={settingsModalOpen}
          modalHeading=""
          primaryButtonText="Close"
          onRequestClose={() => setSettingsModalOpen(false)}
          onRequestSubmit={() => setSettingsModalOpen(false)}
          size="lg"
        >
          <SettingsPage />
        </Modal>
      ) : null}

      {isAdmin ? (
        <Modal
          open={userModalOpen}
          modalHeading={userEditing ? `Edit user: ${userEditing}` : "Add user"}
          primaryButtonText={userEditing ? "Save" : "Create"}
          secondaryButtonText="Cancel"
          onRequestClose={() => {
            setUserModalOpen(false);
            setUserEditing(null);
          }}
          onRequestSubmit={saveUser}
        >
          <Stack gap={5}>
            <TextInput
              id="new-username"
              labelText="Username"
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              disabled={!!userEditing}
            />
            <TextInput
              id="new-password"
              labelText={userEditing ? "New password (leave blank to keep)" : "Password"}
              type="password"
              value={newUser.password}
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            />
            <Dropdown
              id="new-role"
              titleText="Role"
              label="Role"
              items={["user", "admin"]}
              selectedItem={newUser.role}
              onChange={({ selectedItem }) => setNewUser({ ...newUser, role: selectedItem })}
            />
          </Stack>
        </Modal>
      ) : null}

      {isAdmin ? (
        <Modal
          open={tenantModalOpen}
          modalHeading={tenantEditingId ? `Edit tenant: ${tenantEditingId}` : "Add tenant"}
          primaryButtonText={tenantEditingId ? "Save" : "Create"}
          secondaryButtonText="Cancel"
          onRequestClose={() => {
            setTenantModalOpen(false);
            setTenantEditingId(null);
          }}
          onRequestSubmit={saveTenant}
          size="lg"
        >
          <Stack gap={5}>
            <TextInput
              id="tenant-id"
              labelText="Tenant ID"
              helperText="Letters, digits, _ or -."
              value={tenantDraft.id}
              disabled={!!tenantEditingId}
              onChange={(e) => setTenantDraft({ ...tenantDraft, id: e.target.value })}
            />
            <TextInput
              id="tenant-baseurl"
              labelText="Base URL"
              placeholder="https://..."
              value={tenantDraft.baseUrl}
              onChange={(e) => setTenantDraft({ ...tenantDraft, baseUrl: e.target.value })}
            />
            <TextInput
              id="tenant-defaultsite"
              labelText="Default Site (optional)"
              placeholder="e.g. BEDFORD"
              value={tenantDraft.defaultSite}
              onChange={(e) => setTenantDraft({ ...tenantDraft, defaultSite: e.target.value })}
            />
            <TextInput
              id="tenant-user"
              labelText="User (optional)"
              value={tenantDraft.user}
              onChange={(e) => setTenantDraft({ ...tenantDraft, user: e.target.value })}
            />
            <TextInput
              id="tenant-apikey"
              labelText={tenantEditingId ? "API key (leave blank to keep)" : "API key"}
              value={tenantDraft.apiKey}
              onChange={(e) => setTenantDraft({ ...tenantDraft, apiKey: e.target.value })}
            />
            <TextInput
              id="tenant-password"
              labelText={tenantEditingId ? "Password (leave blank to keep)" : "Password"}
              type="password"
              value={tenantDraft.password}
              onChange={(e) => setTenantDraft({ ...tenantDraft, password: e.target.value })}
            />
          </Stack>
        </Modal>
      ) : null}

</Theme>
  );
}



