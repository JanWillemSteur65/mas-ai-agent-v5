import React, { useEffect, useMemo, useRef, useState } from 'react'
import {
  Header, HeaderName, HeaderGlobalBar, HeaderGlobalAction,
  Content, Theme,
  Button, TextArea, Dropdown, ComboBox, Modal, Tabs, Tab, Tile, Tag, Stack,
  DataTable, TableContainer, Table, TableHead, TableRow, TableHeader, TableBody, TableCell,
  InlineNotification, InlineLoading, TextInput, Toggle, CodeSnippet,
  SideNav, SideNavItems, SideNavLink
} from '@carbon/react'
import { Chat, Settings, Menu, Information, Logout } from '@carbon/icons-react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import './overrides.css'

// Optional (client-side) Excel export
import * as XLSX from 'xlsx'

const SETTINGS_KEY = 'mx_settings_v5'
const CHAT_STORAGE_KEY = 'mx_chat_v1'
const LAST_TOOL_RESULT_KEY = 'mx_last_tool_result'
const LAST_ANALYSIS_TEXT_KEY = 'mx_last_analysis_text_v1'
const PROMPT_HISTORY_KEY = 'mx_prompt_history_v1'
const NAV_EXPANDED_W = 256
const NAV_COLLAPSED_W = 56

function isLikelyImageUrl(u) {
  const s = String(u || '').trim().toLowerCase()
  if (!s) return false
  if (s.startsWith('data:image/')) return true
  if (s.startsWith('blob:')) return true
  // Common image extensions (keep this simple)
  return /\.(png|jpe?g|gif|webp|svg)(\?.*)?$/.test(s)
}

// If the user pastes a normal website URL, show a best-effort site icon (favicon).
function resolveAvatarSrc(input) {
  const v = String(input || '').trim()
  if (!v) return ''
  if (v.startsWith('data:') || v.startsWith('blob:')) return v
  if (isLikelyImageUrl(v)) return v
  try {
    const u = new URL(v)
    const origin = u.origin
    // Google favicon service (simple + reliable; requires CSP img-src to allow https)
    return `https://www.google.com/s2/favicons?domain_url=${encodeURIComponent(origin)}&sz=128`
  } catch {
    return v
  }
}

// Small helper used across the UI when endpoints return JSON as a string.
// (e.g., some MCP responses wrap tool output in content[0].text)
function safeJsonParse(text) {
  if (text == null) return null
  const s0 = String(text).trim()
  if (!s0) return null
  // 1) plain JSON
  try { return JSON.parse(s0) } catch {}

  // 2) JSON wrapped in markdown code fences
  const unfenced = s0.replace(/^```[a-zA-Z0-9_-]*\s*/,'').replace(/\s*```$/,'').trim()
  if (unfenced && unfenced !== s0) {
    try { return JSON.parse(unfenced) } catch {}
  }

  // 3) best-effort extraction of first JSON object/array substring
  const firstObj = s0.indexOf('{')
  const lastObj = s0.lastIndexOf('}')
  if (firstObj >= 0 && lastObj > firstObj) {
    const sub = s0.slice(firstObj, lastObj + 1)
    try { return JSON.parse(sub) } catch {}
  }
  const firstArr = s0.indexOf('[')
  const lastArr = s0.lastIndexOf(']')
  if (firstArr >= 0 && lastArr > firstArr) {
    const sub = s0.slice(firstArr, lastArr + 1)
    try { return JSON.parse(sub) } catch {}
  }
  return null
}

// ---------- Prompt history (local, cleared on logout) ----------
function readPromptHistory() {
  try {
    const raw = localStorage.getItem(PROMPT_HISTORY_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch { return [] }
}

function writePromptHistory(items) {
  try { localStorage.setItem(PROMPT_HISTORY_KEY, JSON.stringify(items)) } catch {}
}

function appendPromptHistory(text) {
  const t = String(text || '').trim()
  if (!t) return
  const items = readPromptHistory()
  const next = [{ ts: Date.now(), text: t }, ...items]
  // Drop consecutive duplicates (common when users re-send)
  if (next.length >= 2 && next[0].text === next[1].text) next.splice(1, 1)
  // Cap size
  if (next.length > 200) next.splice(200)
  writePromptHistory(next)
}

const PROVIDERS = [
  { id:'openai', label:'OpenAI' },
  { id:'anthropic', label:'Anthropic' },
  { id:'gemini', label:'Gemini' },
  { id:'watsonx', label:'IBM watsonx' },
  { id:'mistral', label:'Mistral' },
  { id:'deepseek', label:'DeepSeek' },
]

// Default Object-Structure query presets used for the dynamic "queryOS" chips.
// These are best-effort defaults and can be edited/deleted in Settings.
const DEFAULT_QUERY_PRESETS = [
  {
    id: 'locations',
    label: 'Locations',
    os: 'mxapilocations',
    select: 'location,description,status,siteid,orgid,parent,loctype,type,changedate',
    where: 'siteid="{siteid}"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'assets',
    label: 'Assets',
    os: 'mxapiasset',
    select: 'assetnum,description,status,siteid,orgid,location,assettype,serialnum,priority,changedate',
    where: 'siteid="{siteid}"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'open_wos',
    label: 'Open WOs',
    os: 'mxapiwo',
    select: 'wonum,description,status,worktype,priority,siteid,orgid,assetnum,location,reportdate,targstartdate,targcompdate,changedate',
    where: 'siteid="{siteid}" and status!="CLOSE" and status!="COMP"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'cm_wos',
    label: 'Corrective WOs',
    os: 'mxapiwo',
    select: 'wonum,description,status,worktype,priority,siteid,orgid,assetnum,location,reportdate,targstartdate,targcompdate,changedate',
    where: 'siteid="{siteid}" and worktype="CM"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'srs',
    label: 'Service Requests',
    os: 'mxapisr',
    select: 'ticketid,description,status,class,priority,siteid,orgid,assetnum,location,reportedby,reportdate,changedate',
    where: 'siteid="{siteid}"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'pms',
    label: 'Preventive Maintenance',
    os: 'mxapipm',
    select: 'pmnum,description,status,siteid,orgid,location,assetnum,frequency,frequencyunit,worktype,nextdate,changedate',
    where: 'siteid="{siteid}"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
  {
    id: 'jobplans',
    label: 'Job Plans',
    os: 'mxapijobplan',
    select: 'jpnum,description,status,siteid,orgid,pluscrevnum,changedate',
    where: 'siteid="{siteid}"',
    orderBy: '-changedate',
    pageSize: 200,
    lean: true,
    showAsChip: true,
  },
]

// Query synonym rules are managed in the MCP Server UI (NLQ Rules).
const DEFAULT_QUERY_SYNONYMS = {};

const DEFAULT_SETTINGS = {
  mode: 'maximo',
  maximo: {
    baseUrl: '',
    apiKey: '',
    defaultSite: '',
    defaultTenant: 'default',
    queryPresets: DEFAULT_QUERY_PRESETS,
    querySynonyms: {},
  },
  ai: { provider: 'openai', model: 'gpt-4o-mini', system: '', temperature: 0.7 },
  mcp: { enableTools: false, url: '' },
  results: {
    showReport: true,
    enableExcelDownload: true,
    enableOpenInMaximo: true,
  },
  maximoUi: {
    // Per-OS overrides. Template supports: {baseUrl} {os} {id} {field}
    // Example: "{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=wotrack"
    recordLinkTemplates: {},
  },
  avatars: { default: '', user: '', openai: '', anthropic: '', gemini: '', watsonx: '', mistral: '', deepseek: '' },
}

const ACTION_PROMPTS = [
  { id: 'create_wo', label: 'Create WO', action: 'create_wo', kind: 'danger' },
  { id: 'create_sr', label: 'Create SR', action: 'create_sr', kind: 'danger' },
  { id: 'analyze_last', label: 'Analyze / Summarize last response', action: 'analyze_last', kind: 'danger' },
  {
    id: 'followup_reasoning',
    label: 'Reasoning + Evidence + Confidence',
    action: 'followup_reasoning',
    kind: 'success',
    requiresAnalysis: true,
    downloadsPdf: true,
  },
  {
    id: 'followup_eli5',
    label: "Explain like I'm new to Maximo",
    action: 'followup_eli5',
    kind: 'success',
    requiresAnalysis: true,
    downloadsPdf: true,
  },
]

// Fallback prompt list (used when MCP isn't configured). These route through
// the legacy Maximo-mode intent mapper.
const FALLBACK_TEXT_PROMPTS = [
  { id: 'locations', label: 'Locations', prompt: 'Show me all locations' },
  { id: 'assets', label: 'Assets', prompt: 'Show me all assets' },
  { id: 'open_wos', label: 'Open WOs', prompt: 'Show me open work orders' },
  { id: 'cm_wos', label: 'Corrective WOs', prompt: 'Show me corrective work orders' },
  { id: 'srs', label: 'Service Requests', prompt: 'Show me service requests' },
  { id: 'pms', label: 'Preventive Maintenance', prompt: 'Show me preventive maintenance records' },
  { id: 'jobplans', label: 'Job Plans', prompt: 'Show me job plans' },
]

function buildPromptList(settings) {
  const mcpConfigured = !!String(settings?.mcp?.url || '').trim()
  if (!mcpConfigured) return [...FALLBACK_TEXT_PROMPTS, ...ACTION_PROMPTS]

  const presets = Array.isArray(settings?.maximo?.queryPresets) ? settings.maximo.queryPresets : []
  const presetPrompts = presets
    .filter((p) => p && p.id && p.showAsChip !== false)
    .map((p) => ({
      id: `qp_${p.id}`,
      label: p.label || p.id,
      action: 'query_preset',
      presetId: p.id,
    }))
  return [...presetPrompts, ...ACTION_PROMPTS]
}

function normalizeSettings(s) {
  const src = s || {}
  return {
    ...DEFAULT_SETTINGS,
    ...src,
    maximo: {
      ...DEFAULT_SETTINGS.maximo,
      ...(src.maximo || {}),
      queryPresets: Array.isArray(src?.maximo?.queryPresets) ? src.maximo.queryPresets : DEFAULT_SETTINGS.maximo.queryPresets,
      querySynonyms: (src?.maximo?.querySynonyms && typeof src.maximo.querySynonyms === 'object') ? src.maximo.querySynonyms : DEFAULT_SETTINGS.maximo.querySynonyms,
    },
    ai: { ...DEFAULT_SETTINGS.ai, ...(src.ai || {}) },
    mcp: { ...DEFAULT_SETTINGS.mcp, ...(src.mcp || {}) },
    results: { ...DEFAULT_SETTINGS.results, ...(src.results || {}) },
    maximoUi: { ...DEFAULT_SETTINGS.maximoUi, ...(src.maximoUi || {}) },
    avatars: { ...DEFAULT_SETTINGS.avatars, ...(src.avatars || {}) },
  }
}

function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY)
    if (!raw) return null
    const s = JSON.parse(raw) || {}
    return normalizeSettings(s)
  } catch {
    return null
  }
}
function persistSettings(v) { try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(v)) } catch {} }


async function apiAgentChat(payload) {
  const r = await fetch('/api/agent/chat', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiAnalyzeLast(payload) {
  const r = await fetch('/api/agent/analyze-last', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiFollowup(payload) {
  const r = await fetch('/api/agent/followup', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) {
    const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
    const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
    const name = (j && j.name) ? ` (${j.name})` : ''
    throw new Error(`HTTP ${r.status}: ${msg}${name}`)
  }
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

function safePdfFilename(name) {
  const s = String(name || '').trim() || 'ai-report'
  return s.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/_+/g,'_').slice(0, 80)
}

async function downloadPdfFromApi({ title, content, filename }) {
  const r = await fetch('/api/pdf', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title, content, filename })
  })
  if (!r.ok) {
    const t = await r.text()
    throw new Error(t || `HTTP ${r.status}`)
  }
  const blob = await r.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = safePdfFilename(filename || title || 'ai-report') + '.pdf'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1500)
}

async function apiGetSettings() {
  const r = await fetch('/api/settings', { method:'GET', credentials:'include', cache:'no-store' })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) {
    const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
    const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
    throw new Error(`HTTP ${r.status}: ${msg}`)
  }
  return j || {}
}

async function apiSaveSettings(settings) {
  const r = await fetch('/api/settings', {
    method:'POST',
    headers:{'content-type':'application/json'},
    credentials:'include',
    body: JSON.stringify(settings || {})
  })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) {
    const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
    const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
    throw new Error(`HTTP ${r.status}: ${msg}`)
  }
  return j || { ok:true }
}


async function apiValueListTenants(payload) {
  const r = await fetch('/api/agent/value-list/tenants', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}


async function apiTenantsInfo(payload) {
  const r = await fetch('/api/agent/tenants-info', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) {
    const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
    const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
    throw new Error(`HTTP ${r.status}: ${msg}`)
  }
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiTenantsRaw(payload) {
  const r = await fetch('/api/agent/tenants-raw', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) {
    const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
    const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
    throw new Error(`HTTP ${r.status}: ${msg}`)
  }
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiValueListAssets(payload) {
  const r = await fetch('/api/agent/value-list/assets', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiCreateRecord(payload) {
  const r = await fetch('/api/agent/create-record', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

async function apiAgentQueryOS(payload) {
  const r = await fetch('/api/agent/query-os', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
	if(!r.ok) {
	  const detail = (j && (j.detail || j.error)) ? (j.detail || j.error) : (raw || `HTTP ${r.status}`)
	  const msg = typeof detail === 'string' ? detail : JSON.stringify(detail)
	  const name = (j && j.name) ? ` (${j.name})` : ''
	  throw new Error(`HTTP ${r.status}: ${msg}${name}`)
	}
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}
async function apiMaximoQuery(payload) {
  const r = await fetch('/api/maximo/query', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const raw = await r.text()
  let j=null; try{ j=JSON.parse(raw) }catch{}
  if(!r.ok) throw new Error((j && (j.detail||j.error)) ? (j.detail||j.error) : (raw||`HTTP ${r.status}`))
  if(!j) throw new Error(`Unexpected response (not JSON): ${raw.slice(0,200)}`)
  return j
}

function usePrefersDark() {
  const [pref, setPref] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)')
    if (!mq) return
    const on = () => setPref(!!mq.matches)
    on()
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [])
  return pref
}

function normalizeTable(table) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const headers = columns.map((c) => ({ key: c.toLowerCase(), header: c.toUpperCase(), raw: c }))

  const toVal = (r, c) => {
    if (!r) return ''
    const direct = r[c] ?? r[c.toLowerCase()] ?? r[c.toUpperCase()]
    if (direct !== undefined) return direct
    const lc = c.toLowerCase()
    for (const k of Object.keys(r)) {
      if (String(k).toLowerCase().endsWith(lc)) return r[k]
    }
    return ''
  }

  const outRows = rows.map((r, i) => {
    const o = { id: String(i) }
    for (const c of columns) o[c.toLowerCase()] = toVal(r, c)
    return o
  })

  return { headers, rows: outRows }
}

function nowStamp() {
  const d = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`
}

function guessOsFromTitle(table) {
  const t = String(table?.title || '').trim()
  const m = t.match(/\b(mxapi[a-z0-9_]+)\b/i)
  return m ? m[1].toLowerCase() : ''
}

function guessOsFromRows(table) {
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const r = rows && rows.length ? rows[0] : null
  if (!r || typeof r !== 'object') return ''
  const has = (k) => Object.prototype.hasOwnProperty.call(r, k)
  if (has('wonum')) return 'mxapiwo'
  if (has('ticketid')) return 'mxapisr'
  if (has('assetnum')) return 'mxapiasset'
  if (has('location')) return 'mxapilocations'
  if (has('pmnum')) return 'mxapipm'
  if (has('jpnum')) return 'mxapijobplan'
  if (has('ponum')) return 'mxapipo'
  if (has('prnum')) return 'mxapipr'
  return ''
}

function toBaseUrl(settings) {
  const base = String(settings?.maximo?.baseUrl || '').trim().replace(/\/+$/, '')
  return base
}

function getDefaultRecordLinkTemplate(os) {
  // These are best-effort defaults. Many Maximo deployments support loadapp deep-links like this.
  // Users can override per OS in Settings.
  const map = {
    mxapiwo: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=wotrack',
    mxapisr: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=sr',
    mxapiasset: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=asset',
    mxapilocations: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=locations',
    mxapipo: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=po',
    mxapipr: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=pr',
    mxapipm: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=pm',
    mxapijobplan: '{baseUrl}/maximo/ui/?event=loadapp&value={id}&app=jobplan',
  }
  return map[String(os || '').toLowerCase()] || ''
}

function getDefaultRecordIdField(os) {
  const map = {
    mxapiwo: 'wonum',
    mxapisr: 'ticketid',
    mxapiasset: 'assetnum',
    mxapilocations: 'location',
    mxapipo: 'ponum',
    mxapipr: 'prnum',
    mxapipm: 'pmnum',
    mxapijobplan: 'jpnum',
  }
  return map[String(os || '').toLowerCase()] || ''
}

function buildRecordUrl({ os, row, settings }) {
  const baseUrl = toBaseUrl(settings)
  if (!baseUrl) return ''

  const idField = getDefaultRecordIdField(os)
  const id = (row && (row[idField] ?? row[idField?.toLowerCase()] ?? row[idField?.toUpperCase()]))
  if (!id) return ''

  const overrides = settings?.maximoUi?.recordLinkTemplates || {}
  const tpl = String(overrides[os] || getDefaultRecordLinkTemplate(os) || '').trim()
  if (!tpl) return ''
  const rendered = tpl
    .replaceAll('{baseUrl}', baseUrl)
    .replaceAll('{os}', String(os || ''))
    .replaceAll('{field}', String(idField || ''))
    .replaceAll('{id}', encodeURIComponent(String(id)))

  // Also support templates that reference any returned column, e.g. {wonum}, {assetnum}, {location},
  // including dot-path keys like {item.description}.
  return rendered.replace(/\{([a-zA-Z0-9_.-]+)\}/g, (_m, key) => {
    if (!row) return ''
    const k = String(key)
    const v = (row[k] ?? row[k.toLowerCase()] ?? row[k.toUpperCase()])
    if (v === undefined || v === null) return ''
    try {
      return encodeURIComponent(typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v))
    } catch {
      return encodeURIComponent(String(v))
    }
  })
}

function computeReport(table) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const n = rows.length
  const report = {
    rowCount: n,
    columnCount: columns.length,
    missingByColumn: [],
    topByColumn: {},
    dateRanges: {},
  }
  if (!n || !columns.length) return report

  const pickTop = (col, k=5) => {
    const counts = new Map()
    for (const r of rows) {
      const v = r?.[col]
      const s = v === null || v === undefined ? '' : String(v).trim()
      if (!s) continue
      counts.set(s, (counts.get(s) || 0) + 1)
    }
    const arr = [...counts.entries()].sort((a,b) => b[1]-a[1]).slice(0,k)
    return arr.map(([value,count]) => ({ value, count }))
  }

  for (const c of columns) {
    let missing = 0
    let maybeDate = 0
    let minDate = null
    let maxDate = null
    for (const r of rows) {
      const v = r?.[c]
      if (v === null || v === undefined || String(v).trim() === '') missing++
      // date heuristics
      const s = (v === null || v === undefined) ? '' : String(v)
      const d = new Date(s)
      if (s && !Number.isNaN(d.getTime()) && /date/i.test(c)) {
        maybeDate++
        if (!minDate || d < minDate) minDate = d
        if (!maxDate || d > maxDate) maxDate = d
      }
    }
    report.missingByColumn.push({ column: c, missing, pct: n ? Math.round((missing/n)*100) : 0 })
    if (['status','siteid','orgid','priority','worktype','class','assettype','loctype','type'].includes(c.toLowerCase())) {
      report.topByColumn[c] = pickTop(c, 8)
    }
    if (maybeDate && minDate && maxDate) {
      report.dateRanges[c] = { min: minDate.toISOString(), max: maxDate.toISOString() }
    }
  }
  report.missingByColumn.sort((a,b) => b.missing - a.missing)
  return report
}

function downloadExcel({ table, message, settings }) {
  const columns = Array.isArray(table?.columns) ? table.columns.map(String) : []
  const rows = Array.isArray(table?.rows) ? table.rows : []
  const os = guessOsFromTitle(table)
  const provider = String(message?.provider || settings?.ai?.provider || 'unknown')
  const model = String(message?.model || settings?.ai?.model || '').replace(/[^a-z0-9._-]+/gi, '-')
  const stamp = nowStamp()
  const safeOs = (os || 'results').replace(/[^a-z0-9._-]+/gi, '-')
  const fileName = `${safeOs}__${provider}${model ? '_' + model : ''}__${stamp}.xlsx`

  const data = rows.map((r) => {
    const o = {}
    for (const c of columns) o[c] = r?.[c]
    return o
  })

  const wb = XLSX.utils.book_new()
  const ws = XLSX.utils.json_to_sheet(data)
  XLSX.utils.book_append_sheet(wb, ws, 'Results')

  const report = computeReport(table)
  const meta = [
    { key: 'title', value: String(table?.title || '') },
    { key: 'os', value: os },
    { key: 'provider', value: provider },
    { key: 'model', value: String(message?.model || settings?.ai?.model || '') },
    { key: 'generatedAt', value: new Date().toISOString() },
    { key: 'rows', value: report.rowCount },
    { key: 'columns', value: report.columnCount },
  ]
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(meta), 'Query')
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet([
    { section: 'missingByColumn', json: JSON.stringify(report.missingByColumn, null, 2) },
    { section: 'topByColumn', json: JSON.stringify(report.topByColumn, null, 2) },
    { section: 'dateRanges', json: JSON.stringify(report.dateRanges, null, 2) },
  ]), 'Report')

  XLSX.writeFile(wb, fileName)
}

function FilterableTable({ table, settings, message }) {
  const nt = useMemo(() => normalizeTable(table), [table])
  const [filters, setFilters] = useState({})
  useEffect(() => setFilters({}), [table?.title])

  const os = useMemo(() => guessOsFromTitle(table) || guessOsFromRows(table), [table?.title, table?.rows])
  const canExcel = !!settings?.results?.enableExcelDownload
  const canOpen = !!settings?.results?.enableOpenInMaximo
  const showReport = !!settings?.results?.showReport
  const report = useMemo(() => (showReport ? computeReport(table) : null), [table, showReport])

  const filteredRows = useMemo(() => {
    const entries = Object.entries(filters).filter(([,v]) => String(v||'').trim() !== '')
    if (!entries.length) return nt.rows
    return nt.rows.filter((r) => {
      for (const [k, v] of entries) {
        const needle = String(v).toLowerCase()
        const hay = String(r?.[k] ?? '').toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [nt.rows, filters])

  return (
    <div className="mx-table-wrap">
      <div className="mx-table-actions">
        {canExcel ? (
          <Button size="sm" kind="secondary" onClick={() => downloadExcel({ table, message, settings })}>
            Download Excel
          </Button>
        ) : null}
        {os ? <Tag type="cool-gray">{os}</Tag> : null}
        {message?.provider ? <Tag type="warm-gray">{String(message.provider)}{message?.model ? ` · ${String(message.model)}` : ''}</Tag> : null}
        {report ? <Tag type="green">Report</Tag> : null}
      </div>
      <DataTable rows={filteredRows} headers={nt.headers} isSortable>
        {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
          <TableContainer title={table?.title || 'Results'} description="">
            <Table {...getTableProps()} size="sm" useZebraStyles>
              <TableHead>
                <TableRow>
                  {headers.map((h) => (
                    <TableHeader key={h.key} {...getHeaderProps({ header: h })}>
                      <div className="mx-th">
                        <div className="mx-th-title">{h.header}</div>
                        <TextInput
                          id={`flt-${h.key}`}
                          labelText=""
                          hideLabel
                          placeholder="filter…"
                          value={filters[h.key] || ''}
                          onChange={(e) => setFilters((p) => ({ ...p, [h.key]: e.target.value }))}
                          size="sm"
                        />
                      </div>
                    </TableHeader>
                  ))}
                  {canOpen ? <TableHeader key="__open" className="mx-th-open">OPEN</TableHeader> : null}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.id} {...getRowProps({ row })}>
                    {row.cells.map((cell) => (
                      <TableCell key={cell.id} className="mx-td">
                        {cell.value}
                      </TableCell>
                    ))}
                    {canOpen ? (
                      <TableCell className="mx-td">
                        {(() => {
                          const rawRow = Array.isArray(table?.rows) ? table.rows[Number(row.id)] : null
                          const url = buildRecordUrl({ os, row: rawRow, settings })
                          return url ? (
                            <a href={url} target="_blank" rel="noreferrer">↗</a>
                          ) : (
                            <span className="mx-muted">—</span>
                          )
                        })()}
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DataTable>

      {report ? (
        <div className="mx-report">
          <div className="mx-report-head">Summary report</div>
          <div className="mx-report-grid">
            <Tile>
              <div className="mx-report-k">Rows</div>
              <div className="mx-report-v">{report.rowCount}</div>
              <div className="mx-report-k">Columns</div>
              <div className="mx-report-v">{report.columnCount}</div>
            </Tile>
            <Tile>
              <div className="mx-report-k">Most missing columns</div>
              <div className="mx-report-small">
                {report.missingByColumn.slice(0, 5).map((x) => (
                  <div key={x.column} className="mx-report-row">
                    <span>{x.column}</span>
                    <span>{x.pct}% empty</span>
                  </div>
                ))}
              </div>
            </Tile>
          </div>

          {Object.keys(report.topByColumn || {}).length ? (
            <div className="mx-report-top">
              {Object.entries(report.topByColumn).map(([col, items]) => (
                <Tile key={col} className="mx-report-tile">
                  <div className="mx-report-k">Top {col}</div>
                  <div className="mx-report-small">
                    {(items || []).slice(0, 8).map((it) => (
                      <div key={it.value} className="mx-report-row">
                        <span>{it.value}</span>
                        <span>{it.count}</span>
                      </div>
                    ))}
                  </div>
                </Tile>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}


function getAvatarForMessage(m, settings) {
  const avatars = settings?.avatars || {}
  const fallback = String(avatars.default || '').trim()
  if (m?.role === 'user') return String(avatars.user || fallback || '').trim()
  if (m?.role === 'assistant' && m?.source === 'ai') {
    const prov = String(m?.provider || settings?.ai?.provider || '').trim()
    return String((prov && avatars[prov]) || fallback || '').trim()
  }
  return ''
}

function avatarFallbackText(m) {
  if (m?.role === 'user') return 'Y'
  if (m?.source === 'maximo') return 'M'
  const p = String(m?.provider || '').trim()
  return (p ? p[0] : 'A').toUpperCase()
}

function ChatPane({ messages, settings, onOpenTrace, onDownloadPdf }) {
  const bottomRef = useRef(null)
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }) }, [messages.length])

  return (
    <div className="mx-chat-scroll">
      {messages.map((m, idx) => (
        <div key={idx} className={`mx-msg ${m.role === 'user' ? 'mx-msg-user' : 'mx-msg-assistant'}`}>
          <div className="mx-msg-head">
            {m.role !== 'user' ? (() => {
              const url = getAvatarForMessage(m, settings)
              if (url && isLikelyImageUrl(url)) {
                return <img className="mx-msg-avatar" src={url} alt="" />
              }
              return <div className="mx-msg-avatar mx-msg-avatar-fallback">{avatarFallbackText(m)}</div>
            })() : null}

            <Tag type={m.source === 'maximo' ? 'green' : (m.role === 'assistant' ? 'cool-gray' : 'blue')}>
              {m.source === 'maximo' ? 'Maximo' : (m.role === 'assistant' ? 'AI Agent' : 'You')}
            </Tag>
            {m.intent ? <Tag type="warm-gray">{m.intent}</Tag> : null}
            {m.trace ? <Button size="sm" kind="ghost" onClick={() => onOpenTrace(m.trace)}>Trace</Button> : null}
            {m.pdf ? <Button size="sm" kind="ghost" onClick={() => onDownloadPdf?.(m.pdf)}>Download PDF</Button> : null}
            {m.role === 'user' ? (() => {
              const url = getAvatarForMessage(m, settings)
              if (url && isLikelyImageUrl(url)) {
                return <img className="mx-msg-avatar" src={url} alt="" />
              }
              return <div className="mx-msg-avatar mx-msg-avatar-fallback">{avatarFallbackText(m)}</div>
            })() : null}
          </div>
          {/* Show assistant text only when there is no table. Keep user text always. */}
          {!(m.role === 'assistant' && m.table) ? (
            <div className="mx-msg-body">{m.text}</div>
          ) : null}
          {m.table ? <FilterableTable table={m.table} settings={settings} message={m} /> : null}

          {settings?.debug?.nlq && m?.trace?.nlq ? (
            <div style={{ marginTop: 8 }}>
              <details className="mx-debug">
                <summary style={{ cursor: 'pointer', opacity: 0.85 }}>Debug: NLQ expansion</summary>
                <CodeSnippet type="multi" wrapText>
                  {JSON.stringify(m.trace.nlq, null, 2)}
                </CodeSnippet>
              </details>
            </div>
          ) : null}
        </div>
      ))}
      <div ref={bottomRef} />
    </div>
  )
}

function PromptBar({ input, setInput, busy, onSend, onClear, onHistory }) {
  return (
    <div className="mx-promptbar">
      <TextArea
        labelText=""
        hideLabel
        placeholder="Type a message…"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend() } }}
        className="mx-prompt"
      />
      <div className="mx-prompt-actions">
        <div className="mx-send-wrap">
          {busy ? <InlineLoading className="mx-sending" status="active" description="" /> : null}
          <Button onClick={onSend} disabled={busy || !input.trim()}>Send</Button>
        </div>
        <Button kind="tertiary" onClick={onHistory} disabled={busy}>History</Button>
        <Button kind="danger--tertiary" onClick={onClear} disabled={busy}>Clear</Button>
      </div>
    </div>
  )
}

function PromptChips({ onPick, prompts, hasAnalysis }) {
  return (
    <div className="mx-chips">
      <div className="mx-chips-title">Predefined prompts</div>
      <div className="mx-chips-row">
	      {(prompts || []).map((p) => (
          <Button
            key={p.id}
            size="sm"
            kind={p.kind === "danger" ? "danger--tertiary" : "tertiary"}
            className={`mx-chip ${p.kind === 'success' ? 'mx-chip-success' : ''}`}
            disabled={!!p.requiresAnalysis && !hasAnalysis}
            onClick={() => onPick(p)}
          >
            {p.label}
          </Button>
        ))}
      </div>
    </div>
  )
}

function SettingsBody({ local, setLocal, onSave, darkMode, setDarkMode, showSaveButton=true, role }) {
  const isUserRole = String(role || "user").toLowerCase() === "user";
  const isAdmin = String(role || "user").toLowerCase() === "admin";
  const mcpUrl = String(local?.mcp?.url || "").trim();
  const debugNlq = !!local?.debug?.nlq;
  // Model dropdown helpers (dynamic best-effort listing via /api/models)
  const providerId = String(local?.ai?.provider || 'openai').toLowerCase()

  // Curated fallbacks (keeps UI usable when provider listing fails)
  const BUILTIN_MODELS = {
    openai: [
      { id: '', label: '(default)' },
      { id: 'gpt-4o-mini', label: 'gpt-4o-mini' },
      { id: 'gpt-4o', label: 'gpt-4o' },
      { id: 'o1-mini', label: 'o1-mini' },
    ],
    anthropic: [
      { id: '', label: '(default)' },
      { id: 'claude-3-5-sonnet-latest', label: 'claude-3-5-sonnet-latest' },
      { id: 'claude-3-5-haiku-latest', label: 'claude-3-5-haiku-latest' },
    ],
    gemini: [
      { id: '', label: '(default)' },
      { id: 'gemini-2.0-flash', label: 'gemini-2.0-flash' },
      { id: 'gemini-1.5-flash', label: 'gemini-1.5-flash' },
    ],
    watsonx: [
      { id: '', label: '(default)' },
      { id: 'ibm/granite-3-8b-instruct', label: 'ibm/granite-3-8b-instruct' },
      { id: 'ibm/granite-13b-chat-v2', label: 'ibm/granite-13b-chat-v2' },
    ],
    mistral: [
      { id: '', label: '(default)' },
      { id: 'mistral-large-latest', label: 'mistral-large-latest' },
      { id: 'mistral-small-latest', label: 'mistral-small-latest' },
      { id: 'open-mistral-nemo', label: 'open-mistral-nemo' },
    ],
    deepseek: [
      { id: '', label: '(default)' },
      { id: 'deepseek-chat', label: 'deepseek-chat' },
      { id: 'deepseek-reasoner', label: 'deepseek-reasoner' },
    ],
  }

  const [remoteModelsByProvider, setRemoteModelsByProvider] = useState({})
  const [modelsBusy, setModelsBusy] = useState(false)
  const [modelsWarning, setModelsWarning] = useState('')
  const [modelsError, setModelsError] = useState('')

  // Only re-fetch model list when relevant settings change (prevents noisy fetch loops)
  const modelSig = (() => {
    const ai = local?.ai || {}
    if (providerId === 'openai') return [ai.openai_base, ai.openai_key, ai.openai_org].filter(Boolean).join('|')
    if (providerId === 'anthropic') return [ai.anthropic_key].filter(Boolean).join('|')
    if (providerId === 'gemini') return [ai.gemini_key].filter(Boolean).join('|')
    if (providerId === 'mistral') return [ai.mistral_base, ai.mistral_key].filter(Boolean).join('|')
    if (providerId === 'deepseek') return [ai.deepseek_base, ai.deepseek_key].filter(Boolean).join('|')
    if (providerId === 'watsonx') return [ai.watsonx_url, ai.watsonx_version, ai.watsonx_api_key].filter(Boolean).join('|')
    return ''
  })()

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      try {
        setModelsBusy(true)
        setModelsError('')
        setModelsWarning('')
        const r = await fetch(`/api/models?provider=${encodeURIComponent(providerId)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ settings: local || {} })
        })
        const j = await r.json().catch(() => ({}))
        if (cancelled) return
        const models = Array.isArray(j?.models) ? j.models.filter(Boolean) : []
        setRemoteModelsByProvider((p) => ({ ...p, [providerId]: models }))
        if (j?.warning) setModelsWarning(String(j.warning))
      } catch (e) {
        if (!cancelled) {
          setModelsError(String(e?.message || e))
          setModelsWarning('Model listing failed; using fallback list')
        }
      } finally {
        if (!cancelled) setModelsBusy(false)
      }
    }
    // Always best-effort refresh when provider changes (or its keys/bases change)
    run()
    return () => { cancelled = true }
  }, [providerId, modelSig])

  const savedModelId = String(local?.ai?.model || '')
  const remoteIds = remoteModelsByProvider?.[providerId] || []
  const baseModelItems = (
    remoteIds.length
      ? [{ id: '', label: '(default)' }, ...remoteIds.map((id) => ({ id, label: id }))]
      : (BUILTIN_MODELS[providerId] || [{ id: '', label: '(default)' }])
  ).slice()

  if (savedModelId && !baseModelItems.some((m) => m.id === savedModelId)) {
    baseModelItems.push({ id: savedModelId, label: savedModelId })
  }

  const modelItems = baseModelItems
  const selectedModelItem =
    modelItems.find((m) => m.id === savedModelId) || modelItems[0] || { id: savedModelId, label: savedModelId }


  const [tenantCatalog, setTenantCatalog] = useState([])
const [tenantCatalogRaw, setTenantCatalogRaw] = useState([])
const [tenantCatalogBusy, setTenantCatalogBusy] = useState(false)
const [tenantCatalogError, setTenantCatalogError] = useState('')
const [tenantCatalogRawError, setTenantCatalogRawError] = useState('')

  // Tenant UI helpers
  const tenantItems = (tenantCatalog || []).map((t) => {
    const id = String(t?.id || t?.tenant || t?.tenantId || t?.name || '').trim()
    const label = String(t?.label || t?.displayName || id).trim()
    return { ...t, id, label }
  }).filter((t) => t.id)

  const selectedTenantId = String(local?.maximo?.defaultTenant || 'default').trim()
  const selectedTenantItem =
    tenantItems.find((t) => t.id === selectedTenantId) ||
    (selectedTenantId ? { id: selectedTenantId, label: selectedTenantId } : null)

  const applyTenantSelection = (tenantId) => {
    const tid = String(tenantId || '').trim()
    if (!tid) return
    setLocal((p) => ({ ...p, maximo: { ...(p.maximo || {}), defaultTenant: tid } }))
  }

	// Fetch tenant catalog from MCP via the Agent backend.
	// NOTE: This is intentionally defined *before* JSX uses it to avoid ReferenceErrors in production builds.
	const refreshTenantCatalog = async () => {
	  if (!mcpUrl) return
	  setTenantCatalogBusy(true)
	  setTenantCatalogError('')
	  setTenantCatalogRawError('')
	  try {
	    const info = await apiTenantsInfo({ settings: local })
	    // Normalized list is expected at info.tenants; fall back to info itself if the server returns an array.
	    const tenants = Array.isArray(info?.tenants) ? info.tenants : (Array.isArray(info) ? info : [])
	    setTenantCatalog(tenants)
	  } catch (e) {
	    setTenantCatalog([])
	    setTenantCatalogError(String(e?.message || e))
	  }

	  // Raw (secrets) is admin-only; failure should not break the Settings page.
	  if (isAdmin) {
	    try {
	      const raw = await apiTenantsRaw({ settings: local })
	      const tenantsRaw = Array.isArray(raw?.tenants) ? raw.tenants : (Array.isArray(raw) ? raw : [])
	      setTenantCatalogRaw(tenantsRaw)
	    } catch (e) {
	      setTenantCatalogRaw([])
	      setTenantCatalogRawError(String(e?.message || e))
	    }
	  } else {
	    setTenantCatalogRaw([])
	  }
	  setTenantCatalogBusy(false)
	}

	// Auto-load tenant catalog when MCP URL becomes available.
	useEffect(() => {
	  if (!mcpUrl) return
	  // Avoid spamming refreshes; only run when empty.
	  if ((tenantCatalog || []).length) return
	  refreshTenantCatalog()
	  // eslint-disable-next-line react-hooks/exhaustive-deps
	}, [mcpUrl])


  const [linkTplText, setLinkTplText] = useState('')
  const [linkTplWarning, setLinkTplWarning] = useState('')
	const [qpEditorOpen, setQpEditorOpen] = useState(false)
	const [qpEditingIndex, setQpEditingIndex] = useState(null)
	const [qpDraft, setQpDraft] = useState({ id:'', label:'', os:'', select:'', where:'', orderBy:'', pageSize:200, lean:true, showAsChip:true })
	const [qpFormError, setQpFormError] = useState('')

  // Query synonyms are managed in the MCP Server UI (NLQ Rules).

	const queryPresets = Array.isArray(local?.maximo?.queryPresets) ? local.maximo.queryPresets : []

	const openAddQueryPreset = () => {
	  setQpFormError('')
	  setQpEditingIndex(null)
	  setQpDraft({ id:'', label:'', os:'', select:'', where:'siteid="{siteid}"', orderBy:'-changedate', pageSize:200, lean:true, showAsChip:true })
	  setQpEditorOpen(true)
	}

	const openEditQueryPreset = (idx) => {
	  const p = queryPresets[idx]
	  if (!p) return
	  setQpFormError('')
	  setQpEditingIndex(idx)
	  setQpDraft({
	    id: String(p.id || ''),
	    label: String(p.label || ''),
	    os: String(p.os || ''),
	    select: String(p.select || ''),
	    where: String(p.where || ''),
	    orderBy: String(p.orderBy || ''),
	    pageSize: Number(p.pageSize || 100),
	    lean: p.lean !== false,
	    showAsChip: p.showAsChip !== false,
	  })
	  setQpEditorOpen(true)
	}

	const deleteQueryPreset = (id) => {
	  const key = String(id || '')
	  if (!key) return
	  if (!window.confirm(`Delete query preset "${key}"?`)) return
	  setLocal((prev) => ({
	    ...prev,
	    maximo: {
	      ...(prev.maximo || {}),
	      queryPresets: (Array.isArray(prev?.maximo?.queryPresets) ? prev.maximo.queryPresets : []).filter((p) => String(p?.id) !== key)
	    }
	  }))
	}

	const saveQueryPreset = () => {
	  const id = String(qpDraft?.id || '').trim()
	  const label = String(qpDraft?.label || '').trim()
	  const os = String(qpDraft?.os || '').trim()
	  const pageSize = Number(qpDraft?.pageSize || 100)
	  if (!id) { setQpFormError('Preset id is required.'); return }
	  if (!label) { setQpFormError('Label is required.'); return }
	  if (!os) { setQpFormError('Object Structure (os) is required.'); return }
	  if (!Number.isFinite(pageSize) || pageSize <= 0) { setQpFormError('Page Size must be a positive number.'); return }
	  const existingIdx = queryPresets.findIndex((p) => String(p?.id) === id)
	  if (existingIdx !== -1 && existingIdx !== qpEditingIndex) { setQpFormError(`A preset with id "${id}" already exists.`); return }

	  const nextPreset = {
	    id,
	    label,
	    os,
	    select: String(qpDraft?.select || '').trim(),
	    where: String(qpDraft?.where || '').trim(),
	    orderBy: String(qpDraft?.orderBy || '').trim(),
	    pageSize,
	    lean: qpDraft?.lean !== false,
	    showAsChip: qpDraft?.showAsChip !== false,
	  }
	  const next = [...queryPresets]
	  if (qpEditingIndex != null && qpEditingIndex >= 0) next[qpEditingIndex] = nextPreset
	  else next.push(nextPreset)
	  setLocal((prev) => ({ ...prev, maximo: { ...(prev.maximo || {}), queryPresets: next } }))
	  setQpEditorOpen(false)
	}

	const qpHeaders = useMemo(() => ([
	  { key: 'label', header: 'Label' },
	  { key: 'os', header: 'OS' },
	  { key: 'pageSize', header: 'Page Size' },
	  { key: 'chip', header: 'Chip' },
	  { key: 'where', header: 'Where' },
	  { key: 'select', header: 'Select' },
	  { key: 'actions', header: '' },
	]), [])

	const qpRows = useMemo(() => {
	  return queryPresets.map((p) => ({
	    id: String(p?.id || ''),
	    label: String(p?.label || p?.id || ''),
	    os: String(p?.os || ''),
	    pageSize: String(p?.pageSize ?? ''),
	    chip: p?.showAsChip !== false ? 'Yes' : 'No',
	    where: String(p?.where || ''),
	    select: String(p?.select || ''),
	    actions: '',
	  }))
	}, [queryPresets])

  return (
    <div className="mx-page">
      <h2 className="mx-h2">Settings</h2>
      <p className="mx-muted">Shared settings are stored on the server and apply to all users. Only admins can edit and save them. Appearance is stored locally in your browser.</p>

      <details className="mx-card" open>
        <summary className="mx-h3" style={{ cursor: 'pointer' }}>Appearance</summary>
        <div className="mx-form" style={{ marginTop: '0.75rem' }}>
          <Toggle
            id="ui-darkmode"
            labelText="Dark mode (pages only)"
            toggled={!!darkMode}
            onToggle={(v) => setDarkMode(!!v)}
          />
          <p className="mx-muted" style={{ marginTop: 0 }}>
            The header and navigation pane always use a fixed black background and white foreground.
          </p>
        </div>
      </details>

      {!isAdmin ? (
        <InlineNotification kind="info" lowContrast title="Read-only settings" subtitle="Only admins can change and save shared settings. Contact an admin to update Maximo, tenant, AI provider, query presets, avatars, and link templates." hideCloseButton />
      ) : null}

      <details className="mx-card" open>
        <summary className="mx-h3" style={{ cursor: 'pointer' }}>Results & Actions</summary>
        <div className="mx-form" style={{ marginTop: '0.75rem' }}>
          <Toggle
            id="res-report"
            labelText="Show summary report under tables"
            toggled={!!local?.results?.showReport}
            disabled={!isAdmin}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), showReport: !!v } }))}
          />
          <Toggle
            id="res-excel"
            labelText="Enable Download Excel button"
            toggled={!!local?.results?.enableExcelDownload}
            disabled={!isAdmin}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), enableExcelDownload: !!v } }))}
          />
          <Toggle
            id="res-open"
            labelText="Enable Open-in-Maximo links per row"
            toggled={!!local?.results?.enableOpenInMaximo}
            disabled={!isAdmin}
            onToggle={(v) => setLocal((p) => ({ ...p, results: { ...(p.results||{}), enableOpenInMaximo: !!v } }))}
          />

          <Toggle
            id="dbg-nlq"
            labelText="Debug: show NLQ query expansion (oslc.where)"
            toggled={!!local?.debug?.nlq}
            onToggle={(v) => setLocal((p) => ({ ...p, debug: { ...(p.debug||{}), nlq: !!v } }))}
          />
        </div>
        {!isUserRole ? (
          <>
            <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
              "Open in Maximo" uses a per-Object-Structure link template. Defaults are best-effort and may vary by tenant.
            </p>
            <TextArea
              id="mx-link-templates"
              labelText="Record link templates (JSON; optional)"
              rows={8}
              value={linkTplText}
              onChange={(e) => {
                const txt = e.target.value
                setLinkTplText(txt)
                try {
                  const parsed = JSON.parse(txt || '{}')
                  setLinkTplWarning('')
                  setLocal((p) => ({ ...p, maximoUi: { ...(p.maximoUi||{}), recordLinkTemplates: parsed } }))
                } catch {
                  setLinkTplWarning('Invalid JSON (changes not applied yet).')
                }
              }}
            />
            {linkTplWarning ? <InlineNotification kind="warning" lowContrast title="Record links" subtitle={linkTplWarning} /> : null}
            <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
              Template placeholders: <code>{'{baseUrl}'}</code> <code>{'{os}'}</code> <code>{'{field}'}</code> <code>{'{id}'}</code>.
            </p>
          </>
        ) : null}
      </details>


      <details className="mx-card" open>
        <summary className="mx-h3" style={{ cursor: 'pointer' }}>Maximo</summary>
        <div className="mx-form" style={{ marginTop: '0.75rem' }}>
          <TextInput id="mx-base-p" labelText="Maximo Base URL" value={local?.maximo?.baseUrl || ''} readOnly={!isAdmin}
            onChange={(e) => { if (!isAdmin) return; setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), baseUrl:e.target.value } })) }} />
          {!isUserRole ? (
            <>
              <TextInput id="mx-key-p" labelText="Maximo API Key" type="password" value={local?.maximo?.apiKey || ''}
                onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), apiKey:e.target.value } }))} />
              <TextInput id="mx-site-p" labelText="Default Site" value={local?.maximo?.defaultSite || ''}
                onChange={(e) => setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), defaultSite:e.target.value } }))} />
            </>
          ) : null}
{!mcpUrl ? (
  <InlineNotification
    kind="info"
    lowContrast
    title="Tenants"
    subtitle="Configure Settings → MCP Tool Orchestration → MCP URL to select tenants from the MCP Server."
  />
) : null}
{tenantCatalogError ? (
  <InlineNotification
    kind="warning"
    lowContrast
    title="Tenants"
    subtitle={tenantCatalogError}
  />
) : null}
{(!isUserRole && tenantCatalogRawError) ? (
  <InlineNotification
    kind="info"
    lowContrast
    title="Tenant secrets"
    subtitle={tenantCatalogRawError}
  />
) : null}

<ComboBox
  id="mx-tenant-p"
  titleText="Tenant"
  placeholder={tenantCatalogBusy ? "Loading tenants..." : "Select tenant"}
  items={tenantItems}
  itemToString={(i) => i?.label || ''}
  selectedItem={selectedTenantItem}
  onChange={({ selectedItem }) => {
    if (!isAdmin) return
    if (selectedItem?.id) applyTenantSelection(selectedItem.id)
  }}
  onInputChange={(value) => {
    if (!isAdmin) return
    const v = String(value || '').trim()
    if (v) setLocal((p) => ({ ...p, maximo:{ ...(p.maximo||{}), defaultTenant: v } }))
  }}
  disabled={!mcpUrl || tenantCatalogBusy || !isAdmin}
/>
<div style={{ marginTop: '0.25rem' }}>
  <Button size="sm" kind="ghost" onClick={refreshTenantCatalog} disabled={!mcpUrl || tenantCatalogBusy || !isAdmin}>
    Refresh tenants from MCP
  </Button>
</div>
        </div>
      </details>


	      {!isUserRole ? (
	        <details className="mx-card" open>
	          <summary className="mx-h3" style={{ cursor: 'pointer' }}>QueryOS presets (dynamic object structures)</summary>
	          <div className="mx-form">
	            <p className="mx-muted" style={{ marginTop: 0 }}>
	              Manage reusable Object Structure queries with <code>oslc.select</code>, <code>oslc.where</code>, and <code>pageSize</code>.
	              These presets appear as chips in Chat and are executed via your selected AI provider, which plans a structured <code>maximo_queryOS</code> tool call.
	            </p>
	            <p className="mx-muted" style={{ marginTop: 0 }}>
	              Tip: use <code>{'{siteid}'}</code> in the <code>Where</code> field to substitute your default site (e.g. <code>siteid="{'{siteid}'}"</code>).
	            </p>
	            <div style={{ marginBottom: '0.75rem' }}>
	              <Button size="sm" kind="primary" onClick={openAddQueryPreset}>Add preset</Button>
	            </div>
	            <DataTable rows={qpRows} headers={qpHeaders} isSortable>
	          {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
	            <Table {...getTableProps()} size="sm" useZebraStyles>
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
	                    {row.cells.map((cell) => {
	                      const headerKey = cell?.info?.header
	                      if (headerKey === 'actions') {
	                        const idx = queryPresets.findIndex((p) => String(p?.id) === String(row.id))
	                        return (
	                          <TableCell key={cell.id}>
	                            <div style={{ display: 'flex', gap: '0.5rem' }}>
	                              <Button size="sm" kind="tertiary" onClick={() => openEditQueryPreset(idx)}>Edit</Button>
	                              <Button size="sm" kind="danger--tertiary" onClick={() => deleteQueryPreset(row.id)}>Delete</Button>
	                            </div>
	                          </TableCell>
	                        )
	                      }
	                      if (headerKey === 'where' || headerKey === 'select') {
	                        const v = String(cell.value || '')
	                        const clipped = v.length > 90 ? (v.slice(0, 90) + '…') : v
	                        return (
	                          <TableCell key={cell.id} className="mx-td">
	                            <code style={{ fontSize: '0.75rem' }}>{clipped || '—'}</code>
	                          </TableCell>
	                        )
	                      }
	                      return <TableCell key={cell.id} className="mx-td">{cell.value || '—'}</TableCell>
	                    })}
	                  </TableRow>
	                ))}
	              </TableBody>
	            </Table>
	          )}
		        </DataTable>

	      <Modal
	        open={qpEditorOpen}
	        modalHeading={qpEditingIndex != null ? `Edit query preset` : `Add query preset`}
	        primaryButtonText="Save"
	        secondaryButtonText="Cancel"
	        onRequestClose={() => setQpEditorOpen(false)}
	        onRequestSubmit={saveQueryPreset}
	      >
	        <div className="mx-form">
	          {qpFormError ? <InlineNotification kind="error" lowContrast title="Query preset" subtitle={qpFormError} /> : null}
	          <TextInput
	            id="qp-id"
	            labelText="Preset id"
	            value={qpDraft.id}
	            onChange={(e) => setQpDraft((p) => ({ ...p, id: e.target.value }))}
	            placeholder="e.g. purchaseorders"
	          />
	          <TextInput
	            id="qp-label"
	            labelText="Label (chip text)"
	            value={qpDraft.label}
	            onChange={(e) => setQpDraft((p) => ({ ...p, label: e.target.value }))}
	            placeholder="e.g. Purchase Orders"
	          />
	          <TextInput
	            id="qp-os"
	            labelText="Object Structure (os)"
	            value={qpDraft.os}
	            onChange={(e) => setQpDraft((p) => ({ ...p, os: e.target.value }))}
	            placeholder="e.g. mxapipo"
	          />
	          <TextInput
	            id="qp-pagesize"
	            labelText="Page Size"
	            value={String(qpDraft.pageSize ?? '')}
	            onChange={(e) => setQpDraft((p) => ({ ...p, pageSize: e.target.value }))}
	          />
	          <TextInput
	            id="qp-orderby"
	            labelText="Order By (optional)"
	            value={qpDraft.orderBy}
	            onChange={(e) => setQpDraft((p) => ({ ...p, orderBy: e.target.value }))}
	            placeholder="e.g. -changedate"
	          />
	          <TextArea
	            id="qp-where"
	            labelText="Where (oslc.where)"
	            rows={3}
	            value={qpDraft.where}
	            onChange={(e) => setQpDraft((p) => ({ ...p, where: e.target.value }))}
	            placeholder='e.g. siteid="{siteid}" and status!="CLOSE"'
	          />
	          <TextArea
	            id="qp-select"
	            labelText="Select (oslc.select)"
	            rows={3}
	            value={qpDraft.select}
	            onChange={(e) => setQpDraft((p) => ({ ...p, select: e.target.value }))}
	            placeholder="e.g. ponum,description,status,siteid,changedate"
	          />
	          <Toggle
	            id="qp-show"
	            labelText="Show as chip"
	            toggled={qpDraft.showAsChip !== false}
	            onToggle={(v) => setQpDraft((p) => ({ ...p, showAsChip: !!v }))}
	          />
	          <Toggle
	            id="qp-lean"
	            labelText="Lean response (faster, fewer fields)"
	            toggled={qpDraft.lean !== false}
	            onToggle={(v) => setQpDraft((p) => ({ ...p, lean: !!v }))}
	          />
	        </div>
	      </Modal>
	          </div>
	        </details>
	      ) : null}
      {!isUserRole ? (
        <details className="mx-card" open>
          <summary className="mx-h3" style={{ cursor: 'pointer' }}>MCP Tool Orchestration</summary>
          <div className="mx-form">
            <Toggle id="mcp-enable-p" labelText="Enable MCP tool orchestration" toggled={!!local?.mcp?.enableTools}
              onToggle={(v) => setLocal((p) => ({ ...p, mcp:{ ...(p.mcp||{}), enableTools: !!v } }))} />
            <TextInput id="mcp-url-p" labelText="MCP Server URL" value={local?.mcp?.url || ''}
              onChange={(e) => setLocal((p) => ({ ...p, mcp:{ ...(p.mcp||{}), url:e.target.value } }))} />
          </div>
        </details>
      ) : null}

      <details className="mx-card" open>
        <summary className="mx-h3" style={{ cursor: 'pointer' }}>AI Provider</summary>
        <div className="mx-form">
          <Dropdown
            id="ai-provider-dd"
            titleText="Provider"
            label=""
            items={PROVIDERS}
            itemToString={(it) => (it ? it.label : '')}
            selectedItem={PROVIDERS.find(p => p.id === (local?.ai?.provider || 'openai')) || PROVIDERS[0]}
            onChange={({ selectedItem }) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), provider:(selectedItem?.id || 'openai') } }))}
          />
          <Dropdown
            id="ai-model-dd"
            titleText="Model"
            label=""
            items={modelItems}
            itemToString={(it) => (it ? it.label : '')}
            selectedItem={selectedModelItem}
            onChange={({ selectedItem }) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), model:(selectedItem?.id || '') } }))}
          />
          {modelsWarning ? (
            <InlineNotification kind="warning" lowContrast title="Model list" subtitle={modelsWarning} />
          ) : null}
          <TextArea
            id="ai-system-p"
            labelText="System prompt"
            rows={6}
            value={local?.ai?.system || ''}
            onChange={(e) => setLocal((p) => ({ ...p, ai:{ ...(p.ai||{}), system:e.target.value } }))}
          />
        </div>
        {!isUserRole ? (
          <p className="mx-muted" style={{ marginTop: '0.5rem' }}>
            Tip: set an avatar per provider in the section below.
          </p>
        ) : null}
      </details>

      {!isUserRole ? (
      <details className="mx-card" open>
        <summary className="mx-h3" style={{ cursor: 'pointer' }}>Avatars (optional)</summary>
        <p className="mx-muted" style={{ marginTop: 0 }}>
          Paste a <code>data:</code> URL, a normal image URL, or a website URL (we'll show its favicon).
        </p>
        <div className="mx-form">
          {[
            { key:'default', label:'Global default' },
            { key:'openai', label:'OpenAI' },
            { key:'anthropic', label:'Anthropic' },
            { key:'gemini', label:'Gemini' },
            { key:'watsonx', label:'IBM watsonx' },
            { key:'mistral', label:'Mistral' },
            { key:'deepseek', label:'DeepSeek' },
            { key:'user', label:'User' },
          ].map((row) => {
            const v = (local?.avatars?.[row.key] || '').trim()
            return (
              <div key={row.key} className="mx-ava-row">
                <div className="mx-ava-label">{row.label}</div>
                <TextInput
                  id={`ava-${row.key}`}
                  labelText=""
                  value={v}
                  placeholder={row.key === 'default' || row.key === 'user' ? 'data:… or URL' : ''}
                  onChange={(e) => setLocal((p) => ({ ...p, avatars:{ ...(p.avatars||{}), [row.key]: e.target.value } }))}
                />
                <div className="mx-ava-preview">
                  {v ? <img src={resolveAvatarSrc(v)} alt={`${row.key} avatar`} /> : <div className="mx-ava-fallback">{row.key === 'user' ? 'U' : 'AI'}</div>}
                </div>
              </div>
            )
          })}
        </div>
      </details>
      ) : null}
      {showSaveButton ? (
        <div style={{ display:'flex', gap:'0.5rem', marginTop:'1rem' }}>
          <Button onClick={onSave}>Save settings</Button>
        </div>
      ) : null}
    </div>
  )
}


function SettingsDialog({ open, onClose, settings, setSettings, darkMode, setDarkMode, role }) {
  const [local, setLocal] = useState(settings)
  useEffect(() => { if(open) setLocal(settings) }, [open])

  const save = () => {
    setSettings(local)
    persistSettings(local)
    // Also persist server-side so settings survive cleared browser storage.
    apiSaveSettings(local).catch(() => {})
  }

  const saveAndClose = () => {
    save()
    onClose()
  }

  return (
    <Modal
      open={open}
      onRequestClose={saveAndClose}
      modalHeading="Settings"
      primaryButtonText="Save & Close"
      onRequestSubmit={saveAndClose}
      size="lg"
      className="mx-settings-modal"
    >
      <SettingsBody
        local={local}
        setLocal={setLocal}
        onSave={save}
        darkMode={darkMode}
        setDarkMode={setDarkMode}
        showSaveButton={String(role || "user").toLowerCase()==="admin"}
        role={role}
      />
    </Modal>
  )
}


function SettingsPage({ settings, setSettings, darkMode, setDarkMode, role }) {
  const [local, setLocal] = useState(settings)
  useEffect(() => setLocal(settings), [settings])
    const isAdmin = String(role || "user").toLowerCase() === "admin"
  const save = () => {
    setSettings(local)
    persistSettings(local)
    if (isAdmin) apiSaveSettings(local).catch(() => {})
  }

  return (
    <SettingsBody
      local={local}
      setLocal={setLocal}
      onSave={save}
      darkMode={darkMode}
      setDarkMode={setDarkMode}
      showSaveButton={String(role || "user").toLowerCase()==="admin"}
      role={role}
    />
  )
}


function HelpModal({ open, onClose }) {
  const [html, setHtml] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    let cancelled = false
    ;(async () => {
      try {
        setError('')
        const res = await fetch('/help.html', { cache: 'no-cache' })
        if (!res.ok) throw new Error(`Unable to load help content (HTTP ${res.status})`)
        const t = await res.text()
        if (!cancelled) setHtml(t)
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e))
      }
    })()
    return () => { cancelled = true }
  }, [open])

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
  )
}

function PromptHistoryModal({ open, onClose, onPick }) {
  const [query, setQuery] = useState('')
  const [items, setItems] = useState([])

  useEffect(() => {
    if (!open) return
    setQuery('')
    setItems(readPromptHistory())
  }, [open])

  const filtered = useMemo(() => {
    const q = String(query || '').trim().toLowerCase()
    if (!q) return items
    return (items || []).filter((it) => String(it?.text || '').toLowerCase().includes(q))
  }, [items, query])

  return (
    <Modal
      open={open}
      modalHeading="Prompt history"
      primaryButtonText="Close"
      onRequestClose={onClose}
      onRequestSubmit={onClose}
      size="md"
    >
      <Stack gap={5}>
        <TextInput
          id="prompt-history-search"
          labelText="Search"
          placeholder="Filter prompts…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />

        <div style={{ maxHeight: 360, overflow: 'auto', border: '1px solid var(--cds-border-subtle)', borderRadius: 8, padding: 8 }}>
          {filtered.length ? filtered.map((it, idx) => (
            <Button
              key={`${it.ts || idx}-${idx}`}
              kind="ghost"
              size="sm"
              style={{ width: '100%', justifyContent: 'flex-start', marginBottom: 4, whiteSpace: 'normal' }}
              onClick={() => { onPick?.(String(it.text || '')); onClose?.() }}
            >
              {String(it.text || '')}
            </Button>
          )) : (
            <div style={{ padding: 12, opacity: 0.75 }}>
              No prompts yet.
            </div>
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ opacity: 0.7 }}>{items.length} saved</div>
          <Button
            kind="danger--tertiary"
            size="sm"
            onClick={() => {
              writePromptHistory([])
              setItems([])
            }}
          >
            Clear history
          </Button>
        </div>
      </Stack>
    </Modal>
  )
}

function Layout({ children, darkMode, setDarkMode, navExpanded, setNavExpanded }) {
  const nav = useNavigate()
  const loc = useLocation()
  const theme = darkMode ? 'g100' : 'white'
  const navW = navExpanded ? NAV_EXPANDED_W : NAV_COLLAPSED_W
  const [helpOpen, setHelpOpen] = useState(false)

  return (
    <Theme theme={theme}>
      <div className="mx-root">
        <Header aria-label="Maximo AI Agent" className="mx-header">
          <HeaderGlobalAction aria-label="Toggle navigation" onClick={() => setNavExpanded((v)=>!v)}>
            <Menu />
          </HeaderGlobalAction>
          <HeaderName prefix="" onClick={() => nav('/chat')} style={{ cursor:'pointer' }}>
            Maximo AI Agent
          </HeaderName>
          <HeaderGlobalBar>
            <HeaderGlobalAction aria-label="Settings (dialog)" onClick={() => window.dispatchEvent(new CustomEvent('mx-open-settings'))}>
              <Settings />
            </HeaderGlobalAction>
            
            <HeaderGlobalAction aria-label="Help" onClick={() => setHelpOpen(true)}>
              <Information />
            </HeaderGlobalAction>
<HeaderGlobalAction
              aria-label="Logout"
              onClick={async () => {
                try {
                  await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
                } finally {
                  // Always clear ephemeral chat state and prompt history on logout.
                  // sessionStorage survives reloads in the same tab; explicitly remove it.
                  try { sessionStorage.removeItem(CHAT_STORAGE_KEY) } catch {}
                  try { localStorage.removeItem(LAST_TOOL_RESULT_KEY) } catch {}
                  try { localStorage.removeItem(PROMPT_HISTORY_KEY) } catch {}
                  try { localStorage.removeItem(SETTINGS_KEY) } catch {}
                  window.location.reload()
                }
              }}
            >
              <Logout />
            </HeaderGlobalAction>
          </HeaderGlobalBar>
        </Header>

        <HelpModal open={helpOpen} onClose={() => setHelpOpen(false)} />

        <div className="mx-body">
          <div className="mx-sidenav" style={{ width: navW }}>
            <SideNav isFixedNav expanded={navExpanded} isChildOfHeader aria-label="Side navigation" className="mx-sidenav-inner">
              <SideNavItems>
                <SideNavLink
                  href="/chat"
                  isActive={loc.pathname.startsWith('/chat')}
                  onClick={(e) => {
                    e.preventDefault()
                    nav('/chat')
                  }}
                >
                  <Chat /> {navExpanded ? 'Chat' : ''}
                </SideNavLink>
                <SideNavLink
                  href="/settings"
                  isActive={loc.pathname.startsWith('/settings')}
                  onClick={(e) => {
                    e.preventDefault()
                    nav('/settings')
                  }}
                >
                  <Settings /> {navExpanded ? 'Settings' : ''}
                </SideNavLink>
              </SideNavItems>

              <div className="mx-sidenav-footer">
                <Toggle id="theme-toggle" labelText="" labelA="Light" labelB="Dark" toggled={darkMode} onToggle={(v)=>setDarkMode(!!v)} />
              </div>
            </SideNav>
          </div>

          <Content className="mx-content" style={{ marginLeft: navW }}>
            {children}
          </Content>
        </div>
      </div>
    </Theme>
  )
}

function ChatPage({ settings, setSettings, mode, setMode }) {
  const [messages, setMessages] = useState(() => {
    try {
      const raw = sessionStorage.getItem(CHAT_STORAGE_KEY)
      if (!raw) return []
      const parsed = JSON.parse(raw)
      return Array.isArray(parsed?.messages) ? parsed.messages : []
    } catch { return [] }
  })
  const [input, setInput] = useState(() => {
    try {
      const raw = sessionStorage.getItem(CHAT_STORAGE_KEY)
      if (!raw) return ''
      const parsed = JSON.parse(raw)
      return String(parsed?.draft || '')
    } catch { return '' }
  })
  const [busy, setBusy] = useState(false)
  const [traceOpen, setTraceOpen] = useState(false)
  const [traceData, setTraceData] = useState(null)
	  const [historyOpen, setHistoryOpen] = useState(false)
	  const prompts = useMemo(() => buildPromptList(settings), [settings])
	  const [hasAnalysis, setHasAnalysis] = useState(() => {
	    try { return !!localStorage.getItem(LAST_ANALYSIS_TEXT_KEY) } catch { return false }
	  })

  // Guided modal: Create WO/SR
  const [createOpen, setCreateOpen] = useState(false)
  const [createType, setCreateType] = useState('wo')
  const [createTenant, setCreateTenant] = useState(() => String(settings?.maximo?.defaultTenant || 'default'))
  const [headerTenants, setHeaderTenants] = useState([])
  const [headerTenantsBusy, setHeaderTenantsBusy] = useState(false)
  const [headerTenantsError, setHeaderTenantsError] = useState('')
  const [headerTenantCatalog, setHeaderTenantCatalog] = useState([])
  const [headerTenantCatalogRaw, setHeaderTenantCatalogRaw] = useState([])

  const [createSite, setCreateSite] = useState(() => String(settings?.maximo?.defaultSite || '').trim().toUpperCase())
  const [createPriority, setCreatePriority] = useState('3')
  const [createDesc, setCreateDesc] = useState('')
  const [createAsset, setCreateAsset] = useState('')
  const [assetItems, setAssetItems] = useState([])
  const [assetsBusy, setAssetsBusy] = useState(false)
  const [assetsError, setAssetsError] = useState('')

  const openCreate = async (type) => {
    setCreateType(type)
    setCreateTenant(String(settings?.maximo?.defaultTenant || 'default'))
    setCreateSite(String(settings?.maximo?.defaultSite || '').trim().toUpperCase())
    setCreatePriority('3')
    setCreateDesc('')
    setCreateAsset('')
    setAssetItems([])
    setAssetsError('')
    setCreateOpen(true)
  }

  // Keep tenant/site aligned with Settings while the modal is open.
  useEffect(() => {
    if (!createOpen) return
    setCreateTenant(String(settings?.maximo?.defaultTenant || 'default'))
    setCreateSite(String(settings?.maximo?.defaultSite || '').trim().toUpperCase())
  }, [createOpen, settings?.maximo?.defaultTenant, settings?.maximo?.defaultSite])

  // Load tenants for the chat header tenant selector (best-effort; requires MCP URL).
  // Also load tenant metadata so selecting a tenant immediately updates baseUrl/apiKey/defaultSite.
  useEffect(() => {
    let alive = true
    const load = async () => {
      const mcpUrl = String(settings?.mcp?.url || '').trim()
      if (!mcpUrl) {
        setHeaderTenants([])
        setHeaderTenantCatalog([])
        setHeaderTenantCatalogRaw([])
        setHeaderTenantsError('')
        return
      }
      setHeaderTenantsBusy(true)
      setHeaderTenantsError('')
      try {
        // IDs
        const resp = await apiValueListTenants({ settings })
        const tenants = (resp && resp.tenants) ? resp.tenants : []
        const items = (Array.isArray(tenants) ? tenants : [])
          .map((t) => String(t))
          .filter(Boolean)
        if (alive) setHeaderTenants(items)

        // Info (no secrets): baseUrl/defaultSite
        try {
          const info = await apiTenantsInfo({ settings })
          const list = Array.isArray(info?.tenants) ? info.tenants : []
          if (alive) setHeaderTenantCatalog(list)
        } catch {
          if (alive) setHeaderTenantCatalog([])
        }

        // Raw (secrets): apiKey (admin-only). Ignore if not permitted.
        try {
          const raw = await apiTenantsRaw({ settings })
          const rawList = Array.isArray(raw?.tenants) ? raw.tenants : []
          if (alive) setHeaderTenantCatalogRaw(rawList)
        } catch {
          if (alive) setHeaderTenantCatalogRaw([])
        }
      } catch (e) {
        if (alive) setHeaderTenantsError(String(e?.message || e))
      } finally {
        if (alive) setHeaderTenantsBusy(false)
      }
    }
    load()
    return () => { alive = false }
  }, [settings?.mcp?.url])

  // (Create modal) We use the tenant/site stored in Settings.
  // Tenants can still be managed in the MCP Server admin UI.

  // Load assets value list whenever the modal is open and tenant/site changes
  useEffect(() => {
    if (!createOpen) return
    if (!createSite) return
    let cancelled = false
    ;(async () => {
      try {
        setAssetsError('')
        setAssetsBusy(true)
        const resp = await apiValueListAssets({ settings, tenant: String(createTenant || '').trim(), site: String(createSite || '').trim().toUpperCase(), pageSize: 120 })
        const unwrapped = resp?.content?.[0]?.text ? safeJsonParse(resp.content[0].text) : resp
        const items = unwrapped?.items || []
        if (!cancelled) setAssetItems(items)
      } catch (e) {
        if (!cancelled) {
          setAssetItems([])
          setAssetsError(String(e?.message || e))
        }
      } finally {
        if (!cancelled) setAssetsBusy(false)
      }
    })()
    return () => { cancelled = true }
  }, [createOpen, createTenant, createSite])

  useEffect(() => {
    try {
      sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify({ messages, draft: input }))
    } catch {}
  }, [messages, input])

  const openTrace = (t) => { setTraceData(t); setTraceOpen(true) }
  const downloadPdf = async (pdf) => {
    try {
      await downloadPdfFromApi({
        title: pdf?.title || 'AI Agent Result',
        content: pdf?.content || '',
        filename: pdf?.filename || pdf?.title || 'ai-report',
      })
    } catch (e) {
      setMessages((m) => [...m, { role:'assistant', source:'ai', text: `PDF download failed: ${String(e?.message || e)}` }])
    }
  }
  const clearChat = () => { setMessages([]); setInput(''); try { sessionStorage.removeItem(CHAT_STORAGE_KEY) } catch {} }

  const send = async (forced, action = null) => {
    const text = String(forced ?? input).trim()
    const effectiveMode = action ? 'ai' : mode
    const defaultSite = String(settings?.maximo?.defaultSite || '').trim().toUpperCase()
    const textForMaximo = (defaultSite && !/\bsiteid\s*=\s*/i.test(text)) ? `${text} siteid = ${defaultSite}` : text
    const systemForAI = `${String(settings?.ai?.system || '')}${defaultSite ? `

Default Maximo siteid: ${defaultSite}.` : ''}

Tooling rules (MCP):
- When users ask for Preventive Maintenance (PMs), call MCP tool maximo_queryOS with os set to mxapipm.
- When users ask for Job Plans, call MCP tool maximo_queryOS with os set to mxapijobplan.
- When users ask for corrective work orders (CM), call MCP tool maximo_queryOS with os set to mxapiwo and ensure the query filters worktype="CM".
- When users ask for open work orders, filter out status CLOSE and COMP.`.trim()
    if (!text) return
    appendPromptHistory(text)
    setBusy(true)
    setMessages((m) => [...m, { role:'user', text }])
    setInput('')
    try {
      if (effectiveMode === 'maximo') {
        const resp = await apiMaximoQuery({ text: textForMaximo, settings })
        setMessages((m) => [...m, { role:'assistant', source:'maximo', text: resp.summary || 'OK', table: resp.table || null, trace: resp.trace || null , provider:'maximo', model:'' }])
      } else {
        const resp = await apiAgentChat({
          action: action || undefined,
          provider: settings?.ai?.provider || 'openai',
          model: settings?.ai?.model || '',
          system: systemForAI,
          temperature: settings?.ai?.temperature ?? 0.7,
          text,
          settings
        })
        // Store last tool result (if present) for "Analyze / Summarize last response"
        try {
          if (resp && resp.lastToolResult != null) localStorage.setItem(LAST_TOOL_RESULT_KEY, JSON.stringify(resp.lastToolResult))
        } catch {}
        // ✅ UPDATED (minimal): attach resp.table so AI Agent mode renders the same table view
        let assistantText = (resp && (resp.reply ?? resp.text)) ?? (resp && resp.error ? `Error: ${resp.detail || resp.error}` : '');
      if (!assistantText && resp && typeof resp === 'object') {
        try { assistantText = JSON.stringify(resp, null, 2); } catch {}
      }
      setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '',  text: assistantText, table: resp?.table || null, trace: resp?.trace || null }])
        return resp
      }
    } catch (e) {
      setMessages((m) => [...m, { role:'assistant', source: effectiveMode==='maximo' ? 'maximo' : 'ai', text: `Error: ${String(e.message || e)}` }])
    } finally {
      setBusy(false)
    }
  }

	  const runQueryPreset = async (presetId) => {
	    const presets = Array.isArray(settings?.maximo?.queryPresets) ? settings.maximo.queryPresets : []
	    const preset = presets.find((p) => String(p?.id) === String(presetId))
	    if (!preset) {
	      setMessages((m) => [...m, { role:'assistant', source:'maximo', text: `Error: preset not found (${String(presetId)})` }])
	      return
	    }
	    const mcpUrl = String(settings?.mcp?.url || '').trim()
	    if (!mcpUrl) {
	      setMessages((m) => [...m, { role:'assistant', source:'maximo', text: 'Error: MCP URL is not configured. Set it in Settings → MCP Tool.' }])
	      return
	    }
	    const tenant = String(settings?.maximo?.defaultTenant || 'default') || 'default'
	    const defaultSite = String(settings?.maximo?.defaultSite || '').trim().toUpperCase()
	    const os = String(preset?.os || '').trim()
	    if (!os) {
	      setMessages((m) => [...m, { role:'assistant', source:'maximo', text: `Error: preset "${preset.label || preset.id}" has no Object Structure (os) configured.` }])
	      return
	    }
	
	    let where = String(preset?.where || '').trim()
	    const select = String(preset?.select || '').trim()
	    const orderBy = String(preset?.orderBy || '').trim()
	    const pageSize = Number(preset?.pageSize || 100)
	    const lean = preset?.lean !== false

	    // Replace placeholders if present.
	    if (where.includes('{siteid}') || where.includes('{site}')) {
	      if (!defaultSite) {
	        setMessages((m) => [...m, { role:'assistant', source:'maximo', text: 'Error: This preset uses {siteid} but no default site is configured (Settings → Maximo → Default Site).' }])
	        return
	      }
	      where = where.replaceAll('{siteid}', defaultSite).replaceAll('{site}', defaultSite)
	    }

	    const args = {
	      os,
	      ...(where ? { where } : {}),
	      ...(orderBy ? { orderBy } : {}),
	      ...(Number.isFinite(pageSize) ? { pageSize } : {}),
	      ...(select ? { select } : {}),
	      lean,
	    }

	    // Add a lightweight user message so the run is visible in history.
	    const userText = `Run query preset: ${preset.label || preset.id}`
	    appendPromptHistory(userText)
	    setMessages((m) => [...m, { role:'user', text: userText }])
	
	    try {
	      setBusy(true)
	      const resp = await apiAgentQueryOS({ settings, tenant, args })
	      const unwrapped = resp?.content?.[0]?.text ? (safeJsonParse(resp.content[0].text) || resp) : resp
	      try { localStorage.setItem(LAST_TOOL_RESULT_KEY, JSON.stringify(unwrapped)) } catch {}
	
	      const columns = Array.isArray(unwrapped?.columns) ? unwrapped.columns : []
	      const rows = Array.isArray(unwrapped?.rows) ? unwrapped.rows : []
	      const title = String(unwrapped?.title || os)

	      const summary = `Found ${rows.length} record(s) from ${os}${defaultSite ? ` (siteid=${defaultSite})` : ''}.`
	      setMessages((m) => [...m, { role:'assistant', source:'maximo', text: summary, table: { title, columns, rows }, trace: { tool: 'maximo_queryOS', tenant, args, ...(settings?.debug?.nlq && unwrapped?._nlq ? { nlq: unwrapped._nlq } : {}) } }])
	    } catch (e) {
	      setMessages((m) => [...m, { role:'assistant', source:'maximo', text: `Error: ${String(e?.message || e)}` }])
	    } finally {
	      setBusy(false)
	    }
	  }

  const pickPrompt = async (p) => {
    if (p?.action === "create_wo") { setMode('ai'); return openCreate("wo") }
    if (p?.action === "create_sr") { setMode('ai'); return openCreate("sr") }
    if (p?.action === "query_preset") {
      setMode('ai')
      return send(`Run query preset: ${p?.label || p?.presetId || ''}`, { type: 'query_preset', presetId: p?.presetId })
    }
    if (p?.action === "analyze_last") {
      try {
        const raw = localStorage.getItem(LAST_TOOL_RESULT_KEY)
        if (!raw) {
          setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: "No previous tool response found yet. Run a tool-based prompt first." }])
          return
        }
        const lastToolResult = safeJsonParse(raw) || raw
        setBusy(true)
        appendPromptHistory("Analyze / Summarize last response")
        setMessages((m) => [...m, { role:'user', text: "Analyze / Summarize last response" }])
        const systemForAI = String(settings?.ai?.system || '').trim()
        const resp = await apiAnalyzeLast({ provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', system: systemForAI, temperature: Math.min(0.4, Number(settings?.ai?.temperature ?? 0.2)), lastToolResult, settings })
        const reply = resp?.reply || ''
        try { localStorage.setItem(LAST_ANALYSIS_TEXT_KEY, JSON.stringify({ ts: Date.now(), text: reply })) } catch {}
        setHasAnalysis(true)
        setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: reply }])
      } catch (e) {
        setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: `Error: ${String(e?.message || e)}` }])
      } finally {
        setBusy(false)
      }
      return
    }

    if (p?.action === "followup_reasoning" || p?.action === "followup_eli5") {
      const userText = p?.action === "followup_reasoning"
        ? "Provide me the reasoning, evidence and confidence score behind your response"
        : "Explain like I'm not familiar with Maximo or Asset Management"

      try {
        const raw = localStorage.getItem(LAST_ANALYSIS_TEXT_KEY)
        if (!raw) {
          setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: "Run 'Analyze / Summarize last response' first." }])
          return
        }
        const parsed = safeJsonParse(raw)
        const lastAnalysisText = String((parsed && parsed.text) ? parsed.text : raw)

        setBusy(true)
        appendPromptHistory(userText)
        setMessages((m) => [...m, { role:'user', text: userText }])

        const systemForAI = String(settings?.ai?.system || '').trim()
        const instruction = p?.action === "followup_reasoning"
          ? `You previously gave a summary/analysis. Now expand it with:
1) High-level reasoning (no hidden chain-of-thought; keep it brief)
2) Evidence: cite the specific fields/numbers/records you relied on from the prior summary
3) Confidence score 0-100 and why

Format:
- Answer
- Reasoning (high-level)
- Evidence
- Confidence`
          : `Rewrite the prior analysis for a reader who is new to IBM Maximo / Asset Management.

Requirements:
- Use plain language and short sections
- Define key terms (work order, asset, location, preventive maintenance, ...)
- Include a brief "What to do next" section
`

        const resp = await apiFollowup({
          provider: settings?.ai?.provider || 'openai',
          model: settings?.ai?.model || '',
          system: systemForAI,
          temperature: Math.min(0.3, Number(settings?.ai?.temperature ?? 0.2)),
          context: lastAnalysisText,
          instruction,
          settings,
        })
        const reply = resp?.reply || ''
        const title = p?.action === "followup_reasoning" ? 'Reasoning, Evidence & Confidence' : 'Explain Like I\'m New to Maximo'
        const filename = p?.action === "followup_reasoning" ? 'reasoning-evidence-confidence' : 'eli5-maximo'

        setMessages((m) => [...m, {
          role:'assistant',
          source:'ai',
          provider: settings?.ai?.provider || 'openai',
          model: settings?.ai?.model || '',
          text: reply,
          pdf: { title, filename, content: reply }
        }])
      } catch (e) {
        setMessages((m) => [...m, { role:'assistant', source:'ai', provider: settings?.ai?.provider || 'openai', model: settings?.ai?.model || '', text: `Error: ${String(e?.message || e)}` }])
      } finally {
        setBusy(false)
      }
      return
    }
	    return send(p?.prompt || p?.label)
  }

  return (
    <div className="mx-chat-page">
      <div className="mx-chat-toolbar">
        <Dropdown
          id="mode"
          titleText=""
          label="Mode"
          size="sm"
          items={[{ id:'maximo', label:'Maximo Mode' }, { id:'ai', label:'AI Agent Mode' }]}
          itemToString={(i)=>i?.label||''}
          selectedItem={{ id: mode, label: mode === 'maximo' ? 'Maximo Mode' : 'AI Agent Mode' }}
          onChange={({ selectedItem }) => setMode(selectedItem?.id || 'maximo')}
        />

        <Tag className="mx-toolbar-chip" type={mode === 'ai' ? "cool-gray" : "green"}>
          {(settings?.ai?.provider || 'openai') + (settings?.ai?.model ? ` · ${settings.ai.model}` : '')}
        </Tag>

        <div
          className="mx-mcp-toggle"
          title="When enabled, requests route through the MCP Server (tools/orchestration). Disable to run the AI Agent directly."
        >
          <span className="mx-mcp-label">MCP</span>
          <Toggle
            id="mx-mcp-toggle"
            labelText=""
            toggled={!!settings?.mcp?.enableTools}
            onToggle={(v) => {
              const next = { ...settings, mcp: { ...(settings?.mcp || {}), enableTools: !!v } }
              setSettings?.(next)
              // Save immediately so tenant+mode changes feel “sticky” without visiting Settings.
              apiSaveSettings(next).catch(() => {})
            }}
            disabled={!String(settings?.mcp?.url || '').trim()}
          />
          <span className="mx-mcp-hint">On: MCP · Off: direct</span>
        </div>

        <ComboBox
          id="mx-tenant-header"
          titleText=""
          placeholder={headerTenantsBusy ? "Loading tenants..." : "Tenant"}
          size="sm"
          items={(headerTenants || []).map((t) => ({ id: String(t || ''), label: String(t || '') })).filter((x)=>!!x.id)}
          itemToString={(i) => i?.label || ''}
          selectedItem={(() => {
            const cur = String(settings?.maximo?.defaultTenant || 'default')
            const items = (headerTenants || []).map((t) => ({ id: String(t || ''), label: String(t || '') })).filter((x)=>!!x.id)
            return items.find((it) => it.id === cur) || null
          })()}
          onChange={({ selectedItem }) => {
            const id = String(selectedItem?.id || '').trim()
            if (!id || !setSettings) return

            const info = (headerTenantCatalog || []).find((t) => String(t?.id || '') === id) || null
            const raw = (headerTenantCatalogRaw || []).find((t) => String(t?.id || '') === id) || null

            const next = {
              ...settings,
              maximo: {
                ...(settings?.maximo || {}),
                defaultTenant: id,
                ...(info ? { baseUrl: String(info?.baseUrl || ''), defaultSite: String(info?.defaultSite || '') } : {}),
                ...(raw && raw.apiKey ? { apiKey: String(raw.apiKey || '') } : {}),
              }
            }

            setSettings(next)
            // Save immediately so the tenant change takes effect without visiting Settings.
            apiSaveSettings(next).catch(() => {})
          }}
          disabled={!String(settings?.mcp?.url || '').trim()}
          invalid={!!headerTenantsError}
          invalidText={headerTenantsError || undefined}
        />
      </div>

      <div className="mx-chat-card">
        <ChatPane messages={messages} settings={settings} onOpenTrace={openTrace} onDownloadPdf={downloadPdf} />
        <PromptBar input={input} setInput={setInput} busy={busy} onSend={() => send()} onClear={clearChat} onHistory={() => setHistoryOpen(true)} />
      </div>

	      <PromptChips onPick={pickPrompt} prompts={prompts} hasAnalysis={hasAnalysis} />

      <PromptHistoryModal
        open={historyOpen}
        onClose={() => setHistoryOpen(false)}
        onPick={(t) => setInput(String(t || ''))}
      />

	      <Modal
        open={createOpen}
        onRequestClose={() => setCreateOpen(false)}
        modalHeading={createType === 'wo' ? 'Create Work Order' : 'Create Service Request'}
        primaryButtonText={createType === 'wo' ? 'Create WO' : 'Create SR'}
        secondaryButtonText="Cancel"
        size="md"
        onRequestSubmit={async () => {
          const site = String(createSite || '').trim().toUpperCase()
          const description = String(createDesc || '').trim()
          const priority = String(createPriority || '').trim()
          const assetnum = String(createAsset || '').trim()

          const label = createType === 'wo' ? 'Work Order' : 'Service Request'
          const promptText = `Create ${label} (tenant ${createTenant}, site ${site}): ${description}`
          const action = {
            type: 'create_record',
            recordType: createType,
            tenant: createTenant,
            site,
            assetnum: assetnum || undefined,
            priority: priority || undefined,
            description,
          }
          const resp = await send(promptText, action)
          if (resp && !resp.error) setCreateOpen(false)
        }}
      >
        <Stack gap={5}>
          {!String(settings?.mcp?.url || '').trim() ? (
            <InlineNotification
              kind="warning"
              lowContrast
              title="MCP"
              subtitle="MCP URL is not configured. Go to Settings → MCP Tool Orchestration and set the MCP URL so value lists and create actions can work."
            />
          ) : null}
          {assetsError ? (
            <InlineNotification kind="warning" lowContrast title="Assets" subtitle={assetsError} />
          ) : null}
          <TextInput
            id="cr-tenant"
            labelText="Tenant"
            value={String(createTenant || '')}
            readOnly
          />
          <TextInput
            id="cr-site"
            labelText="Site"
            value={String(createSite || '')}
            readOnly
          />
          <Button
            kind="ghost"
            size="sm"
            onClick={() => window.dispatchEvent(new Event('mx-open-settings'))}
          >
            Change tenant/site in Settings
          </Button>
          <ComboBox
            id="cr-asset"
            titleText={assetsBusy ? 'Asset (loading...)' : 'Asset (optional)'}
            placeholder="Select an asset (optional)"
	            invalid={!!assetsError}
	            invalidText={assetsError || undefined}
            items={(assetItems || []).map((it) => ({
              id: String(it.assetnum || it.id || ''),
              label: String(it.label || it.assetnum || it.id || ''),
            })).filter((it) => !!it.id)}
            itemToString={(i) => i?.label || ''}
            selectedItem={(() => {
              const items = (assetItems || []).map((it) => ({
                id: String(it.assetnum || it.id || ''),
                label: String(it.label || it.assetnum || it.id || ''),
              })).filter((it) => !!it.id)
              return items.find((it) => it.id === String(createAsset || '')) || null
            })()}
            onChange={({ selectedItem }) => setCreateAsset(selectedItem?.id || '')}
            disabled={assetsBusy || !createSite}
          />
	          {!createSite ? (
	            <InlineNotification kind="info" lowContrast title="Assets" subtitle="No default Site is configured. Set Settings → Maximo → Default Site to load available assets." />
	          ) : (createSite && !assetsBusy && !assetsError && (assetItems || []).length === 0) ? (
	            <InlineNotification kind="info" lowContrast title="Assets" subtitle="No assets were returned for the configured tenant/site. Verify Settings → Maximo (Default Tenant/Site) and Maximo permissions (or MCP allowlists)." />
	          ) : null}
          <Dropdown
            id="cr-priority"
            titleText="Priority"
            label="Priority"
            items={['1','2','3','4','5']}
            itemToString={(it) => String(it || '')}
            selectedItem={String(createPriority || '3')}
            onChange={({ selectedItem }) => setCreatePriority(String(selectedItem || '3'))}
          />
          <TextArea
            id="cr-desc"
            labelText="Description"
            value={createDesc}
            onChange={(e) => setCreateDesc(e.target.value)}
            rows={4}
          />
        </Stack>
      </Modal>

      <Modal
        open={traceOpen}
        onRequestClose={() => setTraceOpen(false)}
        modalHeading="Trace"
        primaryButtonText="Close"
        onRequestSubmit={() => setTraceOpen(false)}
        size="lg"
      >
        <CodeSnippet type="multi" wrapText hideCopyButton={false}>
          {JSON.stringify(traceData, null, 2)}
        </CodeSnippet>
      </Modal>
    </div>
  )
}

function AppInner() {
  const prefersDark = usePrefersDark()
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('agent_ui_dark_v2')
    if (saved === '1') return true
    if (saved === '0') return false
    return prefersDark
  })
  useEffect(() => { localStorage.setItem('agent_ui_dark_v2', darkMode ? '1' : '0') }, [darkMode])

  const [navExpanded, setNavExpanded] = useState(true)

  // Current user (role-based UI)
  const [me, setMe] = useState(null)
  useEffect(() => {
    let alive = true
    fetch('/api/auth/me', { credentials: 'include' })
      .then(async (r) => (r.ok ? await r.json() : null))
      .then((j) => { if (alive) setMe(j) })
      .catch(() => { if (alive) setMe(null) })
    return () => { alive = false }
  }, [])
  const userRole = me?.role || 'user'

  const [settings, setSettings] = useState(() => loadSettings() || DEFAULT_SETTINGS)
  const [serverSettingsLoaded, setServerSettingsLoaded] = useState(false)

  // Persist locally for fast reloads.
  useEffect(() => persistSettings(settings), [settings])

  // Load server-side settings for the current user so settings survive cleared browser storage.
  useEffect(() => {
    if (!me?.username) return
    let alive = true
    ;(async () => {
      try {
        const server = await apiGetSettings()
        if (!alive) return
        if (server && typeof server === 'object' && Object.keys(server).length) {
          const merged = normalizeSettings(server)
          setSettings(merged)
          persistSettings(merged)
        }
      } catch {
        // ignore; fall back to localStorage/defaults
      } finally {
        if (alive) setServerSettingsLoaded(true)
      }
    })()
    return () => { alive = false }
  }, [me?.username])

  // Debounced server sync whenever settings change (after initial load).
  useEffect(() => {
    if (!me?.username) return
    if (!serverSettingsLoaded) return
    const id = setTimeout(() => {
      apiSaveSettings(settings).catch(() => {})
    }, 800)
    return () => clearTimeout(id)
  }, [settings, me?.username, serverSettingsLoaded])


  const [mode, setMode] = useState(settings.mode || 'maximo')
  useEffect(() => { if ((settings.mode || 'maximo') !== mode) setMode(settings.mode || 'maximo') }, [settings.mode])
  useEffect(() => setSettings((p) => ({ ...p, mode })), [mode])

  const [settingsDialog, setSettingsDialog] = useState(false)
  useEffect(() => {
    const onOpen = () => setSettingsDialog(true)
    window.addEventListener('mx-open-settings', onOpen)
    return () => window.removeEventListener('mx-open-settings', onOpen)
  }, [])

  return (
    <Layout darkMode={darkMode} setDarkMode={setDarkMode} navExpanded={navExpanded} setNavExpanded={setNavExpanded}>
      <Routes>
        <Route path="/chat" element={<ChatPage settings={settings} setSettings={setSettings} mode={mode} setMode={setMode} />} />
        <Route path="/settings" element={<SettingsPage settings={settings} setSettings={setSettings} darkMode={darkMode} setDarkMode={setDarkMode} role={userRole} />} />        
        <Route path="*" element={<Navigate to="/chat" replace />} />
      </Routes>

      <SettingsDialog open={settingsDialog} onClose={() => setSettingsDialog(false)} settings={settings} setSettings={setSettings} darkMode={darkMode} setDarkMode={setDarkMode} role={userRole} />
    </Layout>
  )
}

export default function AppCore() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to="/chat" replace />} />
        <Route path="/*" element={<AppInner />} />
      </Routes>
    </BrowserRouter>
  )
}


