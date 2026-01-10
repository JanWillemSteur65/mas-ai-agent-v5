import React, { useEffect, useMemo, useState } from "react";
import {
  Theme,
  Stack,
  TextInput,
  PasswordInput,
  Button,
  InlineNotification,
  Checkbox
} from "@carbon/react";

import diagram from "./assets/architecture.png";

export default function AuthGate({ children }) {
  const [checking, setChecking] = useState(true);
  const [me, setMe] = useState(null);
  const [username, setUsername] = useState(() => {
    try {
      return localStorage.getItem("mx.username") || "admin";
    } catch {
      return "admin";
    }
  });
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(() => {
    try {
      return localStorage.getItem("mx.remember") === "1";
    } catch {
      return true;
    }
  });
  const [error, setError] = useState(null);

  const productName = useMemo(() => "Maximo MCP Server", []);

  async function refreshMe() {
    try {
      const r = await fetch("/api/auth/me", { credentials: "same-origin" });
      if (!r.ok) return null;
      return await r.json();
    } catch {
      return null;
    }
  }

  useEffect(() => {
    let mounted = true;
    (async () => {
      const m = await refreshMe();
      if (!mounted) return;
      setMe(m);
      setChecking(false);
    })();
    return () => { mounted = false; };
  }, []);

  async function login() {
    setError(null);
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password })
      });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(t || "Login failed");
      }
      const m = await refreshMe();
      setMe(m);
      setPassword("");

      try {
        if (remember) {
          localStorage.setItem("mx.username", username);
          localStorage.setItem("mx.remember", "1");
        } else {
          localStorage.removeItem("mx.username");
          localStorage.setItem("mx.remember", "0");
        }
      } catch {}
    } catch (e) {
      setError(e?.message || "Login failed");
    }
  }

  if (checking) {
    return (
      <Theme theme="g100">
        <div className="mx-login">
          <div className="mx-login__shell">
            <div className="mx-login__panel">
              <div className="mx-login__card">
                <div className="mx-login__loading">Loading…</div>
              </div>
            </div>
          </div>
        </div>
      </Theme>
    );
  }

  if (!me) {
    return (
      <Theme theme="g100">
        <div className="mx-login">
          <div className="mx-login__shell">
            <aside className="mx-login__brand" aria-hidden="true">
              <div className="mx-login__brandInner">
                <div className="mx-login__brandText">
                  <div className="mx-login__suite">Maximo Application Suite</div>
                  <div className="mx-login__product">{productName}</div>
                  <div className="mx-login__tagline">
                    Sign in to access your workspace and tools.
                  </div>
                </div>

                <div className="mx-login__illustrationWrap">
                  <img className="mx-login__illustration" src={diagram} alt="Architecture overview" />
                </div>
              </div>
            </aside>

            <main className="mx-login__panel">
              <div className="mx-login__card">
                <Stack gap={6}>
                  <div>
                    <h1 className="mx-login__title">Sign in</h1>
                    <p className="mx-login__subtitle">{productName}</p>
                  </div>

                  {error && (
                    <InlineNotification
                      kind="error"
                      lowContrast
                      title="Sign in failed"
                      subtitle={error}
                      hideCloseButton
                    />
                  )}

                  <TextInput
                    id="username"
                    labelText="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                  />

                  <PasswordInput
                    id="password"
                    labelText="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") login(); }}
                    autoComplete="current-password"
                  />

                  <div className="mx-login__row">
                    <Checkbox
                      id="remember"
                      labelText="Remember username"
                      checked={remember}
                      onChange={(_, { checked }) => setRemember(Boolean(checked))}
                    />
                  </div>

                  <Button onClick={login} size="lg">
                    Sign in
                  </Button>

                  <div className="mx-login__hint">
                    Default admin user: <code>admin</code>
                  </div>
                </Stack>
              </div>
            </main>
          </div>
        </div>
      </Theme>
    );
  }

  return <>{children}</>;
}
