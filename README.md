# MAS AI Agent & MCP Server – Build and Deployment Guide (OpenShift)

This README describes **how to build and deploy both the MAS AI Agent UI and the MCP Server** on **OpenShift**, based on the provided archive. It is intentionally concise but complete enough to reproduce the setup end‑to‑end.

---

## 1. Components Overview

### AI Agent UI
- React single‑page application
- Source located under `app/ui/`
- Main files:
  - `App.jsx` (all UI logic)
  - `Main.jsx` (bootstrap)
  - `Overrides.css` (layout & theming)

### MCP Server
- Node.js service providing MCP endpoints
- Handles tool calls, logging, and agent communication
- Typically located under `mcp-server/`

Both components are deployed as **separate containers** on OpenShift.

---

## 2. Prerequisites

- Node.js ≥ 18
- npm
- Docker or Podman
- OpenShift CLI (`oc`)

```bash
node --version
npm --version
oc version
```

# Architecture

This repository contains two Node/Express services plus two React UIs.

## Services

### AI Agent (`./app`)
- **Agent server**: `app/src/server.mjs`
- **Web UI** (Vite + React): `app/ui/src/*`

The agent UI talks to the agent server, which tool-calls the MCP server.

### MCP Server (`./mcp-server`)
- **Server**: `mcp-server/server.mjs`
- **Observability UI** (Vite + React): `mcp-server/ui/src/*`
- **Saved tools persistence** (runtime): stored per-tenant under the mounted data directory (`/data` by default) as `mcp_tools_<tenant>.json`.

## Saved Tools

Saved tools let you define new `mxapi...` query presets (OS + `oslc.select` + `oslc.where` etc.) and persist them in the MCP server.

- MCP UI provides a **Tools** page for CRUD.
- MCP Server exposes saved tools as MCP tools via `/mcp/tools`.
- Calls are resolved in `/mcp/call` by mapping the saved tool name to `maximo_queryOS` with merged args.

## Redaction

`mcp-server/redaction.js` implements a best-effort redaction policy engine.

- Default is **disabled**.
- If enabled with `mode: "logs-only"`, it only redacts logged request/response bodies.
- If enabled with `mode: "full"`, it redacts request bodies **before** they are sent to Maximo (use carefully).

Redaction is configured in `mcp_settings.json` under `redaction`.

## Full file manifest

The following files are included in this ZIP:
- `.gitignore`
- `README.md`
- `app/.npmrc`
- `app/Dockerfile`
- `app/package.json`
- `app/public/index.html`
- `app/src/server.mjs`
- `app/ui/index.html`
- `app/ui/package.json`
- `app/ui/src/App.jsx`
- `app/ui/src/main.jsx`
- `app/ui/src/overrides.css`
- `app/ui/vite.config.js`
- `architecture.md`
- `mcp-server/Dockerfile`
- `mcp-server/data/.gitkeep`
- `mcp-server/package.json`
- `mcp-server/redaction.js`
- `mcp-server/server.mjs`
- `mcp-server/ui/index.html`
- `mcp-server/ui/package-lock.json`
- `mcp-server/ui/package.json`
- `mcp-server/ui/src/App.jsx`
- `mcp-server/ui/src/components/JsonModal.jsx`
- `mcp-server/ui/src/components/ToolsPage.jsx`
- `mcp-server/ui/src/main.jsx`
- `mcp-server/ui/src/overrides.css`
- `mcp-server/ui/vite.config.js`
- `openshift/buildconfigs.yaml`
- `openshift/k8s.yaml`
- `openshift/pvc.yaml`


# OpenShift installation & first-time deployment

This guide deploys **both** containers from this repository to OpenShift:
- **AI Agent** (`app`) – serves the UI and API on port **8080**
- **MCP Server** (`mcp-server`) – serves its UI/API on port **8081**

It uses the provided OpenShift manifests in `openshift/`:
- `openshift/buildconfigs.yaml` – ImageStreams + BuildConfigs (binary Docker builds)
- `openshift/k8s.yaml` – Namespace, PVC, Secret, Deployments, Services, Routes
- `openshift/pvc.yaml` – legacy PVC example (optional; `k8s.yaml` already includes a PVC)

> **Tip:** The manifests default to the namespace/project name **`maximo-ai-agent`**.

---

## Prerequisites

1. OpenShift CLI installed and logged in:
   ```bash
   oc version
   oc whoami
   ```

2. You have permission to:
   - create a project/namespace
   - create BuildConfigs + start builds
   - create Routes
   - create PVCs using a StorageClass available in your cluster

3. You have your Maximo details ready:
   - `MAXIMO_URL` (base URL to Maximo)
   - `MAXIMO_APIKEY` (API key)
   - `DEFAULT_SITEID` (site)
   - Optional: OpenAI (or other provider) credentials depending on your setup

---

## Step 0 — Unpack the repo

Unzip the project locally and `cd` into it so `openshift/` is present:

```bash
unzip mas-ai-agent-v2-optionA-complete.zip
cd mas-ai-agent-v2
```

---

## Step 1 — Create (or select) the project

Recommended first-time setup:

```bash
oc new-project maximo-ai-agent
```

If it already exists:

```bash
oc project maximo-ai-agent
```

> The `openshift/k8s.yaml` file also contains a `Namespace` resource. If your cluster blocks creating namespaces from manifests, you can keep using `oc new-project` and still apply the rest.

---

## Step 2 — Verify / adjust storage class

`openshift/k8s.yaml` and `openshift/pvc.yaml` reference `storageClassName: managed-nfs-storage`.

Check what StorageClasses exist:

```bash
oc get sc
```

If `managed-nfs-storage` does not exist in your cluster, edit:
- `openshift/k8s.yaml` (PVC `maximo-ai-agent-data`)
- and/or `openshift/pvc.yaml` (PVC `settings-pvc`)

and set `storageClassName` to one that exists (or remove the field to use the default).

---

## Step 3 — Apply BuildConfigs (ImageStreams + BuildConfigs)

```bash
oc apply -f openshift/buildconfigs.yaml
```

Confirm:

```bash
oc get is
oc get bc
```

You should see:
- ImageStreams: `app`, `mcp-server`
- BuildConfigs: `app`, `mcp-server`

---

## Step 4 — Start the first builds (binary build)

These BuildConfigs are **binary** builds; you upload your local source directory.

From the repo root (`mas-ai-agent-v2/`):

```bash
# Build the AI Agent image
oc start-build app --from-dir=. --follow

# Build the MCP Server image
oc start-build mcp-server --from-dir=. --follow
```

Check build status:

```bash
oc get builds
oc logs -f build/<build-name>
```

Once builds complete, confirm images exist:

```bash
oc get istag
```

---

## Step 5 — Configure secrets (Maximo + provider credentials)

`openshift/k8s.yaml` creates a Secret named `maximo-ai-agent-secrets` with **placeholder** values.

Open and edit it before deploying:

```bash
oc apply -f openshift/k8s.yaml --dry-run=client -o yaml > /tmp/rendered.yaml
```

Now edit `/tmp/rendered.yaml` and update `stringData` values under:

```yaml
kind: Secret
metadata:
  name: maximo-ai-agent-secrets
stringData:
  MAXIMO_URL: "https://your-maximo.example.com/maximo"
  MAXIMO_APIKEY: "REPLACE_ME"
  DEFAULT_SITEID: "ATTR"
  ...
```

Then apply:

```bash
oc apply -f /tmp/rendered.yaml
```

Alternative (recommended for automation): patch only the secret:

```bash
oc -n maximo-ai-agent create secret generic maximo-ai-agent-secrets \
  --from-literal=MAXIMO_URL="https://your-maximo.example.com/maximo" \
  --from-literal=MAXIMO_APIKEY="REPLACE_ME" \
  --from-literal=DEFAULT_SITEID="ATTR" \
  --from-literal=MAXIMO_TENANT="default" \
  --from-literal=MCP_URL="http://mcp-server:8081" \
  --from-literal=ENABLE_MCP_TOOLS="true" \
  --from-literal=TENANTS_JSON="" \
  --from-literal=OPENAI_API_KEY="" \
  --from-literal=OPENAI_BASE="https://api.openai.com/v1" \
  --dry-run=client -o yaml | oc apply -f -
```

---

## Step 6 — Deploy workloads (Deployments, Services, Routes)

Apply the runtime resources:

```bash
oc apply -f openshift/k8s.yaml
```

Wait for pods to become ready:

```bash
oc get pods -w
```

---

## Step 7 — Get URLs (Routes)

List routes:

```bash
oc get routes
```

You should see routes for:
- `app`
- `mcp-server`

Open them in your browser.

---

## Step 8 — Quick health checks

From your terminal:

```bash
# App
oc -n maximo-ai-agent get route app -o jsonpath='{.spec.host}{"\n"}'
# MCP Server
oc -n maximo-ai-agent get route mcp-server -o jsonpath='{.spec.host}{"\n"}'
```

Both services also expose `/healthz`:
- App: `http(s)://<app-route>/healthz`
- MCP: `http(s)://<mcp-route>/healthz`

---

## Updating after changes

Rebuild and redeploy:

```bash
oc start-build app --from-dir=. --follow
oc start-build mcp-server --from-dir=. --follow

# Restart deployments to pick up :latest (if your image pull policy is IfNotPresent)
oc rollout restart deploy/app
oc rollout restart deploy/mcp-server
```

Check rollout:

```bash
oc rollout status deploy/app
oc rollout status deploy/mcp-server
```

---

## Troubleshooting

### Build can’t fetch npm packages
If the cluster cannot reach npm registries, build the UI locally before starting the build:

```bash
# Build Agent UI locally
(cd app/ui && npm ci && npm run build)

# Build MCP UI locally
(cd mcp-server/ui && npm ci && npm run build)

# Then start builds (Dockerfiles will detect ui/dist and skip npm install)
oc start-build app --from-dir=. --follow
oc start-build mcp-server --from-dir=. --follow
```

### Pods crashlooping
Check logs:

```bash
oc logs deploy/app
oc logs deploy/mcp-server
```

Most issues are missing/incorrect Secret values (`MAXIMO_URL`, `MAXIMO_APIKEY`, etc.).

### Storage errors
If PVCs remain Pending:
- verify `storageClassName`
- verify your account can provision PVs
- check events:
  ```bash
  oc describe pvc maximo-ai-agent-data
  ```


## Login (MAS-style) + Local Users

Both the AI Agent and MCP Server now require login. Users are stored locally in `/data/users.json` (created on first start).

- Default username: `admin`
- Default password: `ReAtEt-wAInve-M0UsER`

### Persisting users on OpenShift
Apply `openshift/k8s.yaml` (or create an equivalent PVC + volume mount) so both Deployments mount the same PVC at `/data`.

