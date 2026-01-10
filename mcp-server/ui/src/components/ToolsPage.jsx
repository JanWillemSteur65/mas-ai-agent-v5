import React, { useEffect, useMemo, useState } from "react";
import {
  Stack,
  Tile,
  Button,
  InlineNotification,
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
  Toggle,
  Tag,
} from "@carbon/react";

import { Add, Edit, TrashCan, Renew } from "@carbon/icons-react";
import JsonModal from "./JsonModal.jsx";

function clip(s, n = 80) {
  const t = String(s ?? "");
  if (t.length <= n) return t;
  return t.slice(0, n) + "…";
}

export default function ToolsPage({ tenant = "default", readOnly = false }) {
  const [tools, setTools] = useState([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalTitle, setModalTitle] = useState("Edit tool");
  const [modalValue, setModalValue] = useState({});
  const [editingName, setEditingName] = useState(null);

  const canEdit = !readOnly;

  async function load() {
    const r = await fetch(`/mcp/tools?tenant=${encodeURIComponent(tenant)}&all=1`);
    if (!r.ok) throw new Error(`GET /api/tools ${r.status}`);
    const j = await r.json();
    setTools(Array.isArray(j?.tools) ? j.tools : []);
  }

  useEffect(() => {
    (async () => {
      try {
        setError(null);
        await load();
      } catch (e) {
        setError(String(e?.message || e));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenant]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return tools;
    return tools.filter((t) => {
      const blob = JSON.stringify(t || {}).toLowerCase();
      return blob.includes(q);
    });
  }, [tools, search]);

  const rows = useMemo(() => {
    return filtered.map((t) => ({
      id: t.name,
      name: t.name,
      enabled: String(t.enabled === true),
      type: t.isBuiltin ? "Built-in" : "Saved",
      os: t.os,
      select: clip(t.select),
      where: clip(t.where),
      orderBy: clip(t.orderBy),
      pageSize: String(t.pageSize ?? ""),
      lean: t.lean === true ? "true" : t.lean === false ? "false" : "",
    }));
  }, [filtered]);

  const headers = [
    { key: "enabled", header: "Enabled" },
    { key: "type", header: "Type" },
    { key: "name", header: "Name" },
    { key: "os", header: "OS" },
    { key: "select", header: "Select" },
    { key: "where", header: "Where" },
    { key: "orderBy", header: "OrderBy" },
    { key: "pageSize", header: "PageSize" },
    { key: "lean", header: "Lean" },
  ];

  const openCreate = () => {
    if (!canEdit) return;
    setEditingName(null);
    setModalTitle("Create tool");
    setModalValue({
      name: "my_tool_name",
      enabled: true,
      os: "mxapiasset",
      select: "assetnum,description,status,siteid",
      where: "",
      orderBy: "-changedate",
      pageSize: "50",
      lean: true,
      description: "",
    });
    setModalOpen(true);
  };

  const openEdit = (name) => {
    if (!canEdit) return;
    const bt = tools.find((x) => x?.name === name);
    if (bt?.isBuiltin) return;

    const t = tools.find((x) => x?.name === name);
    setEditingName(name);
    setModalTitle(`Edit tool: ${name}`);
    setModalValue(t || {});
    setModalOpen(true);
  };

  const saveTool = async (tool) => {
    if (!canEdit) return;
    setBusy(true);
    try {
      setError(null);
      const method = editingName ? "PUT" : "POST";
      const url = editingName ? `/api/tools/${encodeURIComponent(editingName)}?tenant=${encodeURIComponent(tenant)}` : `/api/tools?tenant=${encodeURIComponent(tenant)}`;
      const r = await fetch(url, {
        method,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tenant, tool }),
      });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(`${method} ${url} ${r.status}: ${t.slice(0, 240)}`);
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const deleteTool = async (name) => {
    if (!canEdit) return;
    const bt = tools.find((x) => x?.name === name);
    if (bt?.isBuiltin) return;

    if (!name) return;
    setBusy(true);
    try {
      setError(null);
      const r = await fetch(`/api/tools/${encodeURIComponent(name)}?tenant=${encodeURIComponent(tenant)}`, {
        method: "DELETE",
      });
      if (!r.ok) throw new Error(`DELETE /api/tools/${name} ${r.status}`);
      await load();
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const toggleEnabled = async (name, enabled) => {
    if (!canEdit) return;
    const t = tools.find((x) => x?.name === name);
    if (!t) return;

    // Built-ins are toggled via /api/enabled-tools allowlist.
    if (t.isBuiltin) {
      setBusy(true);
      try {
        setError(null);
        const r = await fetch(`/api/enabled-tools/${encodeURIComponent(name)}?tenant=${encodeURIComponent(tenant)}`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tenant, enabled }),
        });
        if (!r.ok) {
          const tt = await r.text();
          throw new Error(`PUT /api/enabled-tools/${name} ${r.status}: ${tt.slice(0, 240)}`);
        }
        await load();
      } catch (e) {
        setError(String(e?.message || e));
      } finally {
        setBusy(false);
      }
      return;
    }

    // Saved tools keep their own enabled flag persisted in the tools store.
    await saveTool({ ...t, enabled });
  };

  return (
    <Stack gap={4}>
      {error ? <InlineNotification kind="error" title="Error" subtitle={error} lowContrast /> : null}

      <Tile>
        <Stack gap={3}>
          <Stack orientation="horizontal" gap={3} style={{ alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ fontWeight: 600 }}>
              Tools {readOnly ? <Tag size="sm" type="cool-gray">Read-only</Tag> : null}
            </div>
            <Stack orientation="horizontal" gap={2}>
              <Button kind="secondary" size="sm" renderIcon={Renew} disabled={busy} onClick={() => load()}>
                Refresh
              </Button>
              {canEdit ? (
                <Button kind="primary" size="sm" renderIcon={Add} disabled={busy} onClick={openCreate}>
                  Create
                </Button>
              ) : null}
            </Stack>
          </Stack>

          <DataTable rows={rows} headers={headers} isSortable>
            {({ rows, headers, getHeaderProps, getRowProps }) => (
              <TableContainer>
                <TableToolbar>
                  <TableToolbarContent>
                    <TableToolbarSearch onChange={(e) => setSearch(e.target.value)} />
                  </TableToolbarContent>
                </TableToolbar>
                <Table size="sm" useZebraStyles>
                  <TableHead>
                    <TableRow>
                      {headers.map((header) => (
                        <TableHeader {...getHeaderProps({ header })} key={header.key}>
                          {header.header}
                        </TableHeader>
                      ))}
                      <TableHeader key="actions">Actions</TableHeader>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((row) => {
                      const name = row.id;
                      const tool = tools.find((t) => t?.name === name);
                      return (
                        <TableRow {...getRowProps({ row })} key={row.id}>
                          {row.cells.map((cell) => {
                            if (cell.info.header === "enabled") {
                              const on = tool?.enabled !== false;
                              return (
                                <TableCell key={cell.id}>
                                  <Toggle
                                    id={`toggle-${name}`}
                                    size="sm"
                                    toggled={on}
                                    labelText=""
                                    hideLabel
                                    disabled={busy || !canEdit}
                                    onToggle={(v) => toggleEnabled(name, v)}
                                  />
                                </TableCell>
                              );
                            }
                            if (cell.info.header === "type") {
                              return (
                                <TableCell key={cell.id}>
                                  {tool?.isBuiltin ? <Tag size="sm" type="cool-gray">Built-in 🔒</Tag> : <Tag size="sm" type="green">Saved</Tag>}
                                </TableCell>
                              );
                            }
                            return <TableCell key={cell.id}>{cell.value}</TableCell>;
                          })}
                          <TableCell key={`${row.id}-actions`}>
                            <Stack orientation="horizontal" gap={2}>
                              <Button kind="ghost" size="sm" renderIcon={Edit} disabled={busy || tool?.isBuiltin || !canEdit}
                                onClick={() => openEdit(name)}>
                                Edit
                              </Button>
                              <Button kind="danger--ghost" size="sm" renderIcon={TrashCan} disabled={busy || tool?.isBuiltin || !canEdit}
                                onClick={() => deleteTool(name)}>
                                Delete
                              </Button>
                            </Stack>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </DataTable>
        </Stack>
      </Tile>

      <JsonModal
        open={modalOpen}
        title={modalTitle}
        initialValue={modalValue}
        primaryButtonText={busy ? "Saving…" : "Save"}
        onClose={() => setModalOpen(false)}
        onSave={saveTool}
      />
    </Stack>
  );
}
