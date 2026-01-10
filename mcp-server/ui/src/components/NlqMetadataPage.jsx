import React, { useEffect, useState } from "react";
import {
  Grid,
  Column,
  Stack,
  TextInput,
  Dropdown,
  Button,
  InlineNotification,
  InlineLoading,
  CodeSnippet,
  DataTable,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Tile,
} from "@carbon/react";

async function fetchJson(url, opts = {}) {
  const r = await fetch(url, { credentials: "include", ...opts });
  const txt = await r.text();
  let data;
  try { data = txt ? JSON.parse(txt) : null; } catch { data = { _raw: txt }; }
  if (!r.ok) {
    const msg = (data && (data.error || data.detail || data.message)) ? (data.error || data.detail || data.message) : `${r.status} ${r.statusText}`;
    throw new Error(msg);
  }
  return data;
}

const WHICH_ITEMS = [
  { id: "mxapiassetstatus", label: "MXAPIASSETSTATUS (asset statuses)" },
  { id: "mxobjectcfg", label: "MXOBJECTCFG (schema)" },
  { id: "mxapisynonymdomain", label: "MXAPISYNONYMDOMAIN (domain synonyms)" },
  { id: "mxapialndomain", label: "MXAPIALNDOMAIN (aln domains)" },
];

export default function NlqMetadataPage() {
  const [tenant, setTenant] = useState("default");
  const [which, setWhich] = useState(WHICH_ITEMS[0]);
  const [key, setKey] = useState("");

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [data, setData] = useState(null);
  const [files, setFiles] = useState([]);

  const fileRows = (files || []).map((f, idx) => ({ id: String(idx), name: String(f || '') }));
  const fileHeaders = [{ key: 'name', header: 'Cached file' }];

  const loadList = async () => {
    setBusy(true);
    setErr("");
    try {
      const out = await fetchJson(`/mcp/nlq/metadata?tenant=${encodeURIComponent(tenant)}`);
      setFiles(Array.isArray(out?.files) ? out.files : []);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const load = async () => {
    setBusy(true);
    setErr("");
    setData(null);
    try {
      const out = await fetchJson(`/mcp/nlq/metadata?tenant=${encodeURIComponent(tenant)}&which=${encodeURIComponent(which.id)}&key=${encodeURIComponent(key)}`);
      setData(out);
    } catch (e) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  const refresh = async () => {
    setBusy(true);
    setErr("");
    try {
      const payload = { tenant, which: which.id };
      if (which.id === "mxobjectcfg") payload.object = key || "ASSET";
      if (which.id === "mxapisynonymdomain") payload.domain = key || "ASSETSTATUS";
      if (which.id === "mxapialndomain") payload.domain = key;

      await fetchJson(`/mcp/nlq/metadata/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      await load();
      await loadList();
    } catch (e) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    loadList();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Grid fullWidth>
      <Column sm={4} md={8} lg={16}>
        <Stack gap={5}>
          <div>
            <h2 style={{ margin: 0 }}>NLQ Metadata</h2>
            <div style={{ opacity: 0.75, marginTop: 6 }}>
              Refresh and inspect cached schema/domain metadata used for NLQ grounding.
            </div>
          </div>

          {err ? <InlineNotification kind="error" lowContrast title="Error" subtitle={err} /> : null}

          <Tile>
            <Stack gap={3}>
              <TextInput id="nlq-meta-tenant" labelText="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} />
              <Dropdown
                id="nlq-meta-which"
                titleText="Metadata source"
                label=""
                items={WHICH_ITEMS}
                itemToString={(it) => (it ? it.label : "")}
                selectedItem={which}
                onChange={({ selectedItem }) => setWhich(selectedItem || WHICH_ITEMS[0])}
              />
              <TextInput
                id="nlq-meta-key"
                labelText={which.id === "mxobjectcfg" ? "Object (e.g. ASSET)" : (which.id.includes("domain") ? "Domain (e.g. ASSETSTATUS)" : "Key")}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={which.id === "mxobjectcfg" ? "ASSET" : (which.id.includes("domain") ? "ASSETSTATUS" : "")}
              />

              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <Button size="sm" kind="secondary" onClick={loadList} disabled={busy}>List cache</Button>
                <Button size="sm" kind="secondary" onClick={load} disabled={busy}>Load</Button>
                <Button size="sm" onClick={refresh} disabled={busy}>Refresh</Button>
                {busy ? <InlineLoading status="active" description="" /> : null}
              </div>
            </Stack>
          </Tile>

          <Tile>
            <Stack gap={3}>
              <h3 style={{ margin: 0 }}>Cached files</h3>
              <DataTable rows={fileRows} headers={fileHeaders}>
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
                          <TableCell>{r.cells[0]?.value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </DataTable>
            </Stack>
          </Tile>

          <Tile>
            <Stack gap={3}>
              <h3 style={{ margin: 0 }}>Selected metadata</h3>
              <CodeSnippet type="multi" wrapText>{JSON.stringify(data, null, 2)}</CodeSnippet>
            </Stack>
          </Tile>
        </Stack>
      </Column>
    </Grid>
  );
}
