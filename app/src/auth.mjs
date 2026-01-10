import fs from "fs";
import path from "path";
import crypto from "crypto";

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}
function b64urlJson(obj) {
  return b64url(Buffer.from(JSON.stringify(obj)));
}
function fromB64url(str) {
  str = str.replace(/-/g,"+").replace(/_/g,"/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

export function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const out = {};
  header.split(";").forEach(part => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx+1).trim();
    if (!k) return;
    out[k] = decodeURIComponent(v);
  });
  return out;
}

export function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 32).toString("hex");
  return { salt, hash };
}

export function verifyPassword(password, salt, hash) {
  const h = crypto.scryptSync(String(password), String(salt), 32).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(h, "hex"), Buffer.from(String(hash), "hex"));
}

export function ensureUsersFile(usersFile, defaultAdminPassword) {
  try {
    fs.mkdirSync(path.dirname(usersFile), { recursive: true });
    if (!fs.existsSync(usersFile)) {
      const { salt, hash } = hashPassword(defaultAdminPassword);
      const users = [{ username: "admin", role: "admin", salt, hash, createdAt: new Date().toISOString() }];
      fs.writeFileSync(usersFile, JSON.stringify({ users }, null, 2), "utf-8");
    }
  } catch (e) {
    // best-effort; caller will handle failures on read/write
    console.error("ensureUsersFile error", e);
  }
}

export function readUsers(usersFile) {
  const raw = fs.readFileSync(usersFile, "utf-8");
  const data = JSON.parse(raw);
  return Array.isArray(data?.users) ? data.users : [];
}

export function writeUsers(usersFile, users) {
  const tmp = usersFile + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify({ users }, null, 2), "utf-8");
  fs.renameSync(tmp, usersFile);
}

export function findUser(users, username) {
  const u = String(username || "").trim();
  return users.find(x => String(x.username).toLowerCase() === u.toLowerCase());
}

// Stateless signed token cookie (HMAC-SHA256)
export function createToken(secret, username, role, ttlSeconds = 60*60*8) {
  const now = Math.floor(Date.now()/1000);
  const payload = { u: username, r: role, iat: now, exp: now + ttlSeconds };
  const body = b64urlJson(payload);
  const sig = b64url(crypto.createHmac("sha256", secret).update(body).digest());
  return body + "." + sig;
}

export function verifyToken(secret, token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = b64url(crypto.createHmac("sha256", secret).update(body).digest());
  try {
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
  } catch {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(fromB64url(body).toString("utf-8"));
  } catch {
    return null;
  }
  const now = Math.floor(Date.now()/1000);
  if (!payload?.u || !payload?.exp || payload.exp < now) return null;
  return payload;
}

export function setAuthCookie(res, token, secure=false) {
  const parts = [
    `session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax"
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

export function clearAuthCookie(res, secure=false) {
  const parts = [
    "session=",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0"
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

export function authMiddleware(secret) {
  return function(req, _res, next) {
    const cookies = parseCookies(req);
    const token = cookies.session;
    const payload = verifyToken(secret, token);
    if (payload) {
      req.user = { username: payload.u, role: payload.r };
    }
    next();
  }
}

export function requireAuth() {
  return function(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    next();
  }
}

export function requireAdmin() {
  return function(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
    next();
  }
}
