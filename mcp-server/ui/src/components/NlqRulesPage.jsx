import React, { useEffect, useMemo, useState } from "react";
import {
  Grid,
  Column,
  Stack,
  Button,
  InlineNotification,
  InlineLoading,
  Dropdown,
  TextInput,
  Modal,
  DataTable,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  CodeSnippet,
  Tile,
} from "@carbon/react";

async function fetchJson(url, opts = {}) {
  const r = await fetch(url, { credentials: "include", ...opts });
  const txt = await r.text();
  let data;
  try {
    data = txt ? JSON.parse(txt) : null;
  } catch {
    data = { _raw: txt };
  }
  if (!r.ok) {
    const msg =
      (data && (data.error || data.detail || data.message))
        ? (data.error || data.detail || data.message)
        : `${r.status} ${r.statusText}`;
    throw new Error(msg);
  }
  return data;
}

const CURATED_OS = [
  "MXAPIADDRESS","MXAPIALNDOMAIN","MXAPIAMCREW","MXAPIAMCREWT","MXAPIASSET","MXAPIASSETMETER","MXAPIASSETSPARE","MXAPIASSETSTATUS",
  "MXAPICONTRACT","MXAPICRAFT","MXAPIFAILURELIST","MXAPIGROUP","MXAPIINVENTORY","MXAPIJOBPLAN","MXAPILOCATIONMETER","MXAPILOCATIONS",
  "MXAPILOCSYS","MXAPIMETERDATA","MXAPINUMERICDOMAIN","MXAPIPM","MXAPIPO","MXAPIPR","MXAPIPROBLEM","MXAPIRECEIPT","MXAPIROUTES",
  "MXAPIRSSTRATEGY","MXAPISR","MXAPISRVAD","MXAPISTORELOC","MXAPISYNONYMDOMAIN","MXAPITKCLASS","MXAPIVENDOR","MXAPIWO","MXAPIWODETAIL",
  "MXAPIWORKLOG","MXOBJECTCFG",
];

function normalizeOs(os) {
  return String(os || "").trim().toUpperCase();
}

function uid() {
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function rulesToRows(tenantId, rules) {
  const rows = [];
  const byOs = rules?.filters || {};
  const osList = Object.keys(byOs || {});
  for (const os of osList) {
    const entries = Array.isArray(byOs[os]) ? byOs[os] : [];
    for (const entry of entries) {
      const f = entry?.filter || {};
      rows.push({
        id: uid(),
        tenant: tenantId,
        os: normalizeOs(os),
        object: String(entry?.object || "").trim(),
        phrase: String(entry?.phrase || "").trim(),
        field: String(f?.field || "").trim(),
        op: String(f?.op || f?.operand || "=").trim(),
        value: f?.value != null ? String(f.value) : "",
      });
    }
  }
  return rows;
}

function rowsToRules(rows, existingRules = {}) {
  const out = {
    ...(existingRules || {}),
    filters: {},
  };

  const grouped = new Map();
  for (const r of rows) {
    const os = normalizeOs(r.os);
    if (!os) continue;
    if (!grouped.has(os)) grouped.set(os, []);
    grouped.get(os).push(r);
  }

  for (const [os, list] of grouped.entries()) {
    out.filters[os] = list
      .filter((r) => r.phrase && r.field && r.op)
      .map((r) => ({
        phrase: String(r.phrase).trim(),
        ...(r.object ? { object: String(r.object).trim() } : {}),
        filter: {
          field: String(r.field).trim(),
          op: String(r.op).trim(),
          value: String(r.value ?? ""),
        },
      }));
  }
  return out;
}

export default function NlqRulesPage() {
  const [tenants, setTenants] = useState([{ id: "default" }]);
  const [tenant, setTenant] = useState("default");

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [saveOk, setSaveOk] = useState(false);

  const [rawRules, setRawRules] = useState(null);
  const [ruleRows, setRuleRows] = useState([]);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState("add"); // add|edit
  const [editRow, setEditRow] = useState(null);

  const [testPrompt, setTestPrompt] = useState("assets not ready");
  const [testBusy, setTestBusy] = useState(false);
  const [testErr, setTestErr] = useState("");
  const [testOut, setTestOut] = useState(null);

  const osItems = useMemo(() => {
    const discovered = new Set();
    try {
      for (const k of Object.keys(rawRules?.filters || {})) discovered.add(normalizeOs(k));
    } catch {}
    for (const k of CURATED_OS) discovered.add(normalizeOs(k));
    return Array.from(discovered).filter(Boolean).sort();
  }, [rawRules]);

  const loadTenants = async () => {
    try {
      const info = await fetchJson(`/mcp/tenants-info`);
      const list = Array.isArray(info?.tenants) ? info.tenants : [];
      const ids = list.map((t) => ({ id: String(t?.id || "").trim() })).filter((t) => t.id);
      setTenants(ids.length ? ids : [{ id: "default" }]);
    } catch {
      setTenants([{ id: "default" }]);
    }
  };

  const loadRules = async (tenantId) => {
    setBusy(true);
    setErr("");
    setSaveOk(false);
    try {
      const out = await fetchJson(`/mcp/nlq/rules?tenant=${encodeURIComponent(tenantId)}`);
      const r = out?.rules || out?.data || out; // tolerate older shapes
      setRawRules(r || {});
      setRuleRows(rulesToRows(tenantId, r || {}));
    } catch (e) {
      setErr(String(e?.message || e));
      setRawRules(null);
      setRuleRows([]);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    loadTenants();
    loadRules("default");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async () => {
    setBusy(true);
    setErr("");
    setSaveOk(false);
    try {
      const payload = rowsToRules(ruleRows, rawRules || {});
      await fetchJson(`/mcp/nlq/rules?tenant=${encodeURIComponent(tenant)}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      setSaveOk(true);
      await loadRules(tenant);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const openAdd = () => {
    setModalMode("add");
    setEditRow({ id: uid(), tenant, os: "MXAPIASSET", object: "ASSET", phrase: "not ready", field: "status", op: "=", value: "NOT READY" });
    setModalOpen(true);
  };

  const openEdit = (r) => {
    if (!r) return;
    setModalMode("edit");
    setEditRow({ ...r });
    setModalOpen(true);
  };

  const applyModal = () => {
    if (!editRow) return;
    const cleaned = {
      ...editRow,
      tenant,
      os: normalizeOs(editRow.os),
      phrase: String(editRow.phrase || "").trim(),
      field: String(editRow.field || "").trim(),
      op: String(editRow.op || "=").trim(),
      value: String(editRow.value ?? ""),
      object: String(editRow.object || "").trim(),
    };
    setRuleRows((prev) => {
      if (modalMode === "edit") return prev.map((x) => (x.id === cleaned.id ? cleaned : x));
      return [...prev, cleaned];
    });
    setModalOpen(false);
  };

  const delRow = (id) => setRuleRows((prev) => prev.filter((r) => r.id !== id));

  const runTest = async () => {
    setTestBusy(true);
    setTestErr("");
    setTestOut(null);
    try {
      const out = await fetchJson(`/mcp/nlq/test`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tenant, userText: testPrompt, args: {} }),
      });
      setTestOut(out);
    } catch (e) {
      setTestErr(String(e?.message || e));
    } finally {
      setTestBusy(false);
    }
  };

  const headers = [
    { key: "tenant", header: "Tenant" },
    { key: "os", header: "OS" },
    { key: "object", header: "Object" },
    { key: "phrase", header: "Filter (phrase)" },
    { key: "field", header: "Field" },
    { key: "op", header: "Operand" },
    { key: "value", header: "Value" },
    { key: "actions", header: "Actions" },
  ];

  return (
    <Grid fullWidth>
      <Column sm={4} md={8} lg={16}>
        <Stack gap={5}>
          <div>
            <h2 style={{ margin: 0 }}>NLQ Rules</h2>
            <div style={{ opacity: 0.75, marginTop: 6 }}>
              Manage phrase rules as rows. One row maps a phrase to a deterministic filter for a specific Object Structure.
            </div>
          </div>

          {err ? <InlineNotification kind="error" lowContrast title="Error" subtitle={err} /> : null}
          {saveOk ? <InlineNotification kind="success" lowContrast title="Saved" subtitle="Rules updated." /> : null}

          <Tile>
            <Stack gap={3}>
              <Dropdown
                id="nlq-tenant"
                titleText="Tenant"
                label=""
                items={tenants}
                itemToString={(it) => (it ? it.id : "")}
                selectedItem={tenants.find((t) => t.id === tenant) || tenants[0]}
                onChange={({ selectedItem }) => {
                  const id = selectedItem?.id || "default";
                  setTenant(id);
                  loadRules(id);
                }}
              />
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <Button size="sm" kind="secondary" onClick={() => loadRules(tenant)} disabled={busy}>Reload</Button>
                <Button size="sm" kind="secondary" onClick={openAdd} disabled={busy}>Add rule</Button>
                <Button size="sm" onClick={save} disabled={busy}>Save</Button>
                {busy ? <InlineLoading status="active" description="" /> : null}
              </div>
            </Stack>
          </Tile>

          <Tile>
            <DataTable rows={ruleRows} headers={headers}>
              {({ rows, headers, getHeaderProps, getRowProps }) => (
                <Table size="sm" useZebraStyles>
                  <TableHead>
                    <TableRow>
                      {headers.map((h) => (
                        <TableHeader key={h.key} {...getHeaderProps({ header: h })}>{h.header}</TableHeader>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((r) => (
                      <TableRow key={r.id} {...getRowProps({ row: r })}>
                        <TableCell>{r.cells.find((c)=>c.info.header==="tenant")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="os")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="object")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="phrase")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="field")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="op")?.value}</TableCell>
                        <TableCell>{r.cells.find((c)=>c.info.header==="value")?.value}</TableCell>
                        <TableCell>
                          <div style={{ display: "flex", gap: 6 }}>
                            <Button size="sm" kind="ghost" onClick={() => openEdit(ruleRows.find((x)=>x.id===r.id))} disabled={busy}>Edit</Button>
                            <Button size="sm" kind="danger--ghost" onClick={() => delRow(r.id)} disabled={busy}>Delete</Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </DataTable>
          </Tile>

          <Tile>
            <Stack gap={3}>
              <h3 style={{ margin: 0 }}>Test prompt</h3>
              {testErr ? <InlineNotification kind="error" lowContrast title="Test failed" subtitle={testErr} /> : null}
              <TextInput id="nlq-test" labelText="Prompt" value={testPrompt} onChange={(e) => setTestPrompt(e.target.value)} />
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <Button size="sm" onClick={runTest} disabled={testBusy}>Run test</Button>
                {testBusy ? <InlineLoading status="active" description="" /> : null}
              </div>
              {testOut ? (
                <div>
                  <div style={{ opacity: 0.75, marginBottom: 6 }}>Result</div>
                  <CodeSnippet type="multi" wrapText>{JSON.stringify(testOut, null, 2)}</CodeSnippet>
                </div>
              ) : null}
            </Stack>
          </Tile>
        </Stack>
      </Column>

      <Modal
        open={modalOpen}
        modalHeading={modalMode === "add" ? "Add NLQ rule" : "Edit NLQ rule"}
        primaryButtonText={modalMode === "add" ? "Add" : "Apply"}
        secondaryButtonText="Cancel"
        onRequestClose={() => setModalOpen(false)}
        onRequestSubmit={applyModal}
      >
        <Stack gap={3}>
          <Dropdown
            id="nlq-edit-os"
            titleText="OS"
            label=""
            items={osItems}
            itemToString={(it) => String(it || "")}
            selectedItem={normalizeOs(editRow?.os) || ""}
            onChange={({ selectedItem }) => setEditRow((p) => ({ ...(p||{}), os: String(selectedItem || "") }))}
          />
          <TextInput id="nlq-edit-object" labelText="Object" value={editRow?.object || ""} onChange={(e) => setEditRow((p)=>({...(p||{}), object: e.target.value}))} placeholder="ASSET" />
          <TextInput id="nlq-edit-phrase" labelText="Filter (phrase)" value={editRow?.phrase || ""} onChange={(e) => setEditRow((p)=>({...(p||{}), phrase: e.target.value}))} placeholder="not ready" />
          <TextInput id="nlq-edit-field" labelText="Field" value={editRow?.field || ""} onChange={(e) => setEditRow((p)=>({...(p||{}), field: e.target.value}))} placeholder="status" />
          <TextInput id="nlq-edit-op" labelText="Operand" value={editRow?.op || ""} onChange={(e) => setEditRow((p)=>({...(p||{}), op: e.target.value}))} placeholder="=" />
          <TextInput id="nlq-edit-value" labelText="Value" value={editRow?.value || ""} onChange={(e) => setEditRow((p)=>({...(p||{}), value: e.target.value}))} placeholder="NOT READY" />
        </Stack>
      </Modal>
    </Grid>
  );
}
