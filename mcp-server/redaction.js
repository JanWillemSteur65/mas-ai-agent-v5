// mcp-server/redaction.js
// Best-effort redaction engine.
// Designed to be safe by default: if policy is disabled, it's a no-op.

function toLowerSet(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((x) => String(x).toLowerCase()));
}

function redactObject(value, fieldsSet) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redactObject(v, fieldsSet));
  if (typeof value !== "object") return value;

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    const keyLower = String(k).toLowerCase();
    if (fieldsSet.has(keyLower)) {
      out[k] = "***";
    } else {
      out[k] = redactObject(v, fieldsSet);
    }
  }
  return out;
}

function redactString(s, regexes) {
  let out = String(s || "");
  for (const r of Array.isArray(regexes) ? regexes : []) {
    try {
      const re = new RegExp(String(r.pattern || ""), String(r.flags || ""));
      out = out.replace(re, "***");
    } catch {
      // ignore invalid regex
    }
  }
  return out;
}

/**
 * Applies the provided redaction policy to a request/response payload.
 *
 * Policy shape:
 * {
 *   enabled: boolean,
 *   mode: "logs-only" | "full",
 *   fields: string[],
 *   regexes: [{ pattern: string, flags?: string }]
 * }
 */
export function applyRedactionPolicy(payload, policy) {
  const p = policy || {};
  if (!p.enabled) {
    return { payload, changed: false };
  }

  const fieldsSet = toLowerSet(p.fields);
  let next = payload;
  let changed = false;

  // Object-level redaction
  if (fieldsSet.size && typeof next === "object" && next !== null) {
    next = redactObject(next, fieldsSet);
    changed = true;
  }

  // String/JSON string redaction
  if (Array.isArray(p.regexes) && p.regexes.length) {
    if (typeof next === "string") {
      next = redactString(next, p.regexes);
      changed = true;
    } else {
      try {
        const s = JSON.stringify(next);
        const red = redactString(s, p.regexes);
        if (red !== s) {
          next = JSON.parse(red);
          changed = true;
        }
      } catch {
        // ignore
      }
    }
  }

  return { payload: next, changed };
}
