import React, { useEffect, useState } from 'react'
import { Tile, InlineNotification } from '@carbon/react'

// Fallback content in case the backend help endpoint is unavailable.
const FALLBACK_HELP_HTML = `<h1>Maximo AI Agent Help &amp; UI Guide</h1>

<p>This page explains how the <strong>Maximo AI Agent</strong> works end-to-end and what you can do in the UI.</p>

<hr />

<h2>1. Architecture – How the AI Agent Works</h2>

<p>The AI Agent is the user-facing application that turns natural-language instructions into structured actions. It can operate in two main ways:</p>
<ul>
  <li><strong>Direct Maximo mode</strong> – the agent calls Maximo REST endpoints directly (when configured).</li>
  <li><strong>MCP mode</strong> – the agent delegates actions to the <strong>MCP Server</strong>, which exposes a governed toolset and handles Maximo REST translation.</li>
</ul>

<h3>1.1 High-level request flow</h3>
<ol>
  <li><strong>User prompt</strong> (Chat UI) → agent creates a structured request.</li>
  <li><strong>Model call</strong> (OpenAI / configured provider) → model produces a response and optionally a tool call plan.</li>
  <li><strong>Tool execution</strong>:
    <ul>
      <li>If <em>MCP tools</em> are enabled: call the MCP Server tool endpoint(s).</li>
      <li>Otherwise: call Maximo directly (if configured).</li>
    </ul>
  </li>
  <li><strong>Results rendering</strong> → the UI shows a readable summary plus raw payloads (when enabled), and stores the chat in session storage for the current browser session.</li>
</ol>

<h3>1.2 Message / tool-call shape (conceptual)</h3>
<p>The agent keeps a conversation history (system + user + assistant messages). When a tool is needed, it sends structured parameters either to MCP or to Maximo:</p>
<pre><code>{
  "intent": "create_workorder",
  "parameters": {
    "description": "Replace broken pump",
    "assetnum": "PUMP-1001",
    "siteid": "BEDFORD"
  }
}
</code></pre>

<p>When running via MCP, the agent calls the MCP tool dispatcher, and receives normalized results back. Those results are then summarized for the user in the chat.</p>

<hr />

<h2>2. UI Pages</h2>

<h3>2.1 Chat</h3>
<ul>
  <li>Primary interface for asking questions, generating reports, and requesting actions.</li>
  <li>Conversation is kept in the current browser session (refresh-safe, but not intended as long-term storage).</li>
  <li>Depending on settings, the UI can show structured results, raw payloads, and links to open items in Maximo.</li>
</ul>

<h3>2.2 MCP Tool Orchestration</h3>
<ul>
  <li>Controls whether MCP tools are enabled and where the MCP Server lives (URL).</li>
  <li>Shows the tool orchestration status and helps validate MCP connectivity.</li>
  <li>Use this page when you want the AI Agent to call Maximo through the MCP Server rather than directly.</li>
</ul>

<h3>2.3 Settings</h3>
<ul>
  <li>Maximo connection: base URL, API key, default site.</li>
  <li>AI provider &amp; model selection: model name, temperature, and optional system prompt.</li>
  <li>Result display toggles: report visibility, Excel download, “Open in Maximo”.</li>
  <li>Theme: light/dark toggle in the left navigation.</li>
</ul>

<hr />

<h2>3. Tips &amp; Troubleshooting</h2>

<ul>
  <li>If tool calls fail, verify Maximo base URL / API key (direct mode) or MCP URL (MCP mode).</li>
  <li>If responses look incomplete, check model selection and ensure the system prompt matches your workflow.</li>
  <li>For governance and auditing, prefer <strong>MCP mode</strong> so all actions are visible in MCP logs/traces.</li>
</ul>

<p><em>Note:</em> This Help content is shipped with the app and can be updated alongside UI releases.</p>
`

export default function HelpPage() {
  const [html, setHtml] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        const r = await fetch('/api/help', { credentials: 'same-origin' })
        if (!r.ok) throw new Error(await r.text())
        const t = await r.text()
        if (mounted) setHtml(t)
      } catch (e) {
        if (mounted) {
          setError(e?.message || 'Failed to load help')
          setHtml(FALLBACK_HELP_HTML)
        }
      }
    })()
    return () => { mounted = false }
  }, [])

  return (
    <div style={{ maxWidth: 1100 }}>
      <Tile style={{ padding: '1.25rem' }}>
        {error && (
          <div style={{ marginBottom: 12 }}>
            <InlineNotification kind="warning" lowContrast title="Help fallback" subtitle={error} hideCloseButton />
          </div>
        )}
        <div className="mx-help" dangerouslySetInnerHTML={{ __html: html || FALLBACK_HELP_HTML }} />
      </Tile>
    </div>
  )
}
