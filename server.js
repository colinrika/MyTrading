import express from "express";
import cors from "cors";
import KrakenClient from "kraken-api";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import fs from "fs";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import pkg from "pg";

const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

function nowMs() { return Date.now(); }
function nowIso() { return new Date().toISOString(); }

const SIMULATOR_MODE = String(process.env.SIMULATOR_MODE || "false").toLowerCase() === "true";

const JWT_SECRET = process.env.JWT_SECRET || process.env.APP_SECRET || "";
const ENC_KEY_B64 = process.env.ENC_KEY_BASE64 || "";
const ENC_KEY = ENC_KEY_B64 ? Buffer.from(ENC_KEY_B64, "base64") : null;

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET (or APP_SECRET) in env");
  process.exit(1);
}
if (!ENC_KEY || ENC_KEY.length !== 32) {
  console.error("ENC_KEY_BASE64 must decode to 32 bytes");
  process.exit(1);
}

const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL in env");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function dbQuery(text, params = []) {
  const res = await pool.query(text, params);
  return res.rows;
}

async function dbOne(text, params = []) {
  const rows = await dbQuery(text, params);
  return rows[0] || null;
}

async function dbExec(text, params = []) {
  await pool.query(text, params);
}

async function initDb() {
  await dbExec(`
    create table if not exists users (
      id bigserial primary key,
      name text not null,
      email text not null unique,
      phone text not null,
      pass_hash text not null,
      is_verified boolean not null default false,
      verify_code text,
      verify_expires bigint,
      created_at bigint not null
    );
  `);

  await dbExec(`
    create table if not exists kraken_keys (
      user_id bigint primary key references users(id) on delete cascade,
      api_key text not null,
      api_secret_enc text not null,
      created_at bigint not null,
      updated_at bigint not null
    );
  `);

  await dbExec(`
    create table if not exists kraken_nonces (
      user_id bigint primary key references users(id) on delete cascade,
      last_nonce bigint not null default 0,
      updated_at bigint not null
    );
  `);

  await dbExec(`
    create table if not exists safe_trades_latest (
      user_id bigint primary key references users(id) on delete cascade,
      ts bigint not null,
      safe_trades jsonb not null default '[]'::jsonb
    );
  `);

  await dbExec(`
    create table if not exists safe_alert_state (
      user_id bigint primary key references users(id) on delete cascade,
      last_sig text not null default '',
      last_sent_ts bigint not null default 0
    );
  `);

  await dbExec(`
    create table if not exists trades (
      id bigserial primary key,
      user_id bigint not null references users(id) on delete cascade,
      ts bigint not null,
      time_iso text not null,
      pair text not null default '',
      side text not null default '',
      order_type text not null default '',
      invest_usd numeric,
      volume text not null default '',
      entry_price numeric,
      take_profit numeric,
      stop_loss numeric,
      est_profit_usd numeric,
      est_loss_usd numeric,
      status text not null default '',
      message text not null default '',
      txid text not null default '',
      is_auto boolean not null default false
    );
  `);
}

await initDb();

function makeVerifyCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function encryptText(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decryptText(b64) {
  const raw = Buffer.from(String(b64), "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function authRequired(req, res, next) {
  try {
    const token = req.cookies?.session || "";
    if (!token) return res.status(401).json({ error: "Not logged in" });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Not logged in" });
  }
}

function pageAuthRequired(req, res, next) {
  try {
    const token = req.cookies?.session || "";
    if (!token) {
      const nextUrl = encodeURIComponent(req.originalUrl || "/dashboard.html");
      return res.redirect("/login.html?next=" + nextUrl);
    }
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    const nextUrl = encodeURIComponent(req.originalUrl || "/dashboard.html");
    return res.redirect("/login.html?next=" + nextUrl);
  }
}

async function getUserKrakenClient(uid) {
  const row = await dbOne(
    `select api_key, api_secret_enc from kraken_keys where user_id = $1`,
    [uid]
  );
  if (!row) return null;
  const secret = decryptText(row.api_secret_enc);
  return new KrakenClient(row.api_key, secret);
}

function numOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function roundToDecimals(value, decimals) {
  const n = numOrNull(value);
  if (n === null) return null;
  const d = Math.max(0, Math.min(12, Number(decimals) || 0));
  return Number(n.toFixed(d));
}

function trimNumberString(s) {
  if (s === null || s === undefined) return null;
  const str = String(s);
  if (!str.includes(".")) return str;
  return str.replace(/\.?0+$/, "");
}

async function nextNonce(uid) {
  const now = Date.now() * 1000;
  const row = await dbOne(
    `select last_nonce from kraken_nonces where user_id = $1`,
    [uid]
  );
  const last = Number(row?.last_nonce || 0);
  const nonce = Math.max(last + 1, now);

  await dbExec(
    `
    insert into kraken_nonces (user_id, last_nonce, updated_at)
    values ($1, $2, $3)
    on conflict (user_id)
    do update set last_nonce = excluded.last_nonce, updated_at = excluded.updated_at
    `,
    [uid, nonce, nowMs()]
  );

  return nonce;
}

async function krakenApiWithNonceRetry(client, uid, method, params) {
  const finalParams = { ...(params || {}), nonce: await nextNonce(uid) };
  try {
    return await client.api(method, finalParams);
  } catch (err) {
    const msg = String(err?.message || err || "").toLowerCase();
    if (msg.includes("invalid nonce")) {
      await new Promise(r => setTimeout(r, 350));
      finalParams.nonce = await nextNonce(uid);
      return await client.api(method, finalParams);
    }
    throw err;
  }
}

const pairMetaCache = new Map();
let lastPairMetaRefreshMs = 0;
const PAIR_META_TTL_MS = 10 * 60 * 1000;

async function ensurePairMetaLoaded(krakenClient) {
  const now = Date.now();
  if (pairMetaCache.size && (now - lastPairMetaRefreshMs) < PAIR_META_TTL_MS) return;

  const resp = await krakenClient.api("AssetPairs");
  const result = resp?.result || {};

  pairMetaCache.clear();
  for (const key of Object.keys(result)) {
    const info = result[key] || {};
    pairMetaCache.set(key, {
      wsname: info.wsname || "",
      pair_decimals: numOrNull(info.pair_decimals) ?? 5,
      lot_decimals: numOrNull(info.lot_decimals) ?? 8,
      ordermin: numOrNull(info.ordermin),
      costmin: numOrNull(info.costmin)
    });
  }

  lastPairMetaRefreshMs = now;
}

async function getPairMeta(krakenClient, pair) {
  await ensurePairMetaLoaded(krakenClient);

  if (pairMetaCache.has(pair)) return pairMetaCache.get(pair);

  for (const [, v] of pairMetaCache.entries()) {
    if (v.wsname && v.wsname.replace("/", "") === String(pair).replace("/", "")) return v;
    if (v.wsname && v.wsname === pair) return v;
  }

  return { wsname: "", pair_decimals: 5, lot_decimals: 8, ordermin: null, costmin: null };
}

function formatOrderNumbers(meta, payload) {
  const pd = meta.pair_decimals ?? 5;
  const ld = meta.lot_decimals ?? 8;

  const price = roundToDecimals(payload.price, pd);
  const price2 = payload.price2 !== null && payload.price2 !== undefined ? roundToDecimals(payload.price2, pd) : null;

  const takeProfit = payload.takeProfit !== null && payload.takeProfit !== undefined ? roundToDecimals(payload.takeProfit, pd) : null;
  const stopLoss = payload.stopLoss !== null && payload.stopLoss !== undefined ? roundToDecimals(payload.stopLoss, pd) : null;

  const volNum = roundToDecimals(payload.volume, ld);
  const volumeStr = volNum === null ? null : trimNumberString(volNum.toFixed(ld));

  return { price, price2, takeProfit, stopLoss, volumeStr };
}

function clampPrice(meta, p) {
  const pd = meta.pair_decimals ?? 5;
  const v = roundToDecimals(p, pd);
  return v === null ? null : v;
}

function validateMinimums(meta, price, volumeStr) {
  const vol = numOrNull(volumeStr);
  if (price === null || vol === null) {
    return { ok: false, reason: "Invalid price or volume" };
  }

  if (meta.ordermin !== null && vol < meta.ordermin) {
    const minUsd = meta.costmin !== null ? meta.costmin : (meta.ordermin * price);
    return { ok: false, reason: "volume minimum not met", ordermin: meta.ordermin, minUsdEstimate: minUsd };
  }

  if (meta.costmin !== null) {
    const cost = vol * price;
    if (cost < meta.costmin) {
      return { ok: false, reason: "cost minimum not met", costmin: meta.costmin, costNow: cost };
    }
  }

  return { ok: true };
}

async function queryOrder(krakenClient, uid, txid) {
  const resp = await krakenApiWithNonceRetry(krakenClient, uid, "QueryOrders", { txid });
  const result = resp?.result || {};
  const order = result[txid];
  return order || null;
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

async function logTradeDb(uid, entry) {
  const ts = nowMs();
  const timeIso = nowIso();

  await dbExec(
    `
    insert into trades
    (user_id, ts, time_iso, pair, side, order_type, invest_usd, volume, entry_price, take_profit, stop_loss, est_profit_usd, est_loss_usd, status, message, txid, is_auto)
    values
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
    `,
    [
      uid,
      ts,
      timeIso,
      safeStr(entry.pair),
      safeStr(entry.side),
      safeStr(entry.orderType),
      entry.investUsd ?? null,
      safeStr(entry.volume),
      entry.entryPrice ?? null,
      entry.takeProfit ?? null,
      entry.stopLoss ?? null,
      entry.estProfitUsd ?? null,
      entry.estLossUsd ?? null,
      safeStr(entry.status),
      safeStr(entry.message),
      safeStr(entry.txid || ""),
      entry.isAuto === true
    ]
  );
}

const ALERT_COOLDOWN_MS = 10 * 60 * 1000;

function telegramConfigured() {
  const enabled = String(process.env.TELEGRAM_ENABLED || "").toLowerCase() === "true";
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  return enabled && !!token && !!chatId;
}

async function sendTelegram(text) {
  if (!telegramConfigured()) throw new Error("Missing TELEGRAM env values");

  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      disable_web_page_preview: true
    })
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || data.ok !== true) {
    throw new Error(data?.description || `Telegram send failed ${resp.status}`);
  }
  return data;
}

function prettyPair(pair) {
  return String(pair || "").replace("X", "").replace("ZUSD", "/USD");
}

function safeTradesSignature(safeTrades) {
  return safeTrades
    .slice(0, 3)
    .map(t => {
      const pair = String(t.pair || "");
      const tag = String(t.recommended?.tag || "");
      const q = Number(t.recommended?.quality || 0);
      const side = String(t.recommended?.side || "");
      const entry = Number(t.recommended?.price ?? t.last ?? 0).toFixed(6);
      return pair + "|" + tag + "|" + q + "|" + side + "|" + entry;
    })
    .join(";");
}

function buildTelegramMessage(safeTrades) {
  const now = new Date().toLocaleString();
  let msg = `Namu safest trades ${now}\n\n`;

  for (const t of safeTrades.slice(0, 3)) {
    const rec = t.recommended || {};
    const side = String(rec.side || "").toUpperCase();
    const entry = Number(rec.price ?? t.last ?? 0);
    const tp = rec.takeProfit ?? null;
    const sl = rec.stopLoss ?? null;

    msg += `${prettyPair(t.pair)}\n`;
    msg += `Signal ${side}  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${entry.toFixed(6)}\n`;
    if (tp !== null) msg += `TP ${Number(tp).toFixed(6)}\n`;
    if (sl !== null) msg += `SL ${Number(sl).toFixed(6)}\n`;
    if (rec.actionTitle) msg += `${rec.actionTitle}\n`;
    if (rec.tag) msg += `Tag ${rec.tag}\n`;
    msg += `\n`;
  }

  msg += `Generated by your strategy rules.\n`;
  return msg;
}

/* Protected pages */
app.get("/dashboard.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/account.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "account.html")));
app.get("/connect-kraken.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "connect-kraken.html")));
app.get("/strategy.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "strategy.html")));

/* Public pages */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/register.html", (req, res) => res.sendFile(path.join(__dirname, "register.html")));
app.get("/verify.html", (req, res) => res.sendFile(path.join(__dirname, "verify.html")));

/* Static assets after protected routes */
app.use(express.static(__dirname));

/* Health */
app.get("/healthz", (req, res) => res.json({ ok: true }));

/* Mode */
app.get("/mode", (req, res) => res.json({ simulator: SIMULATOR_MODE }));

/* Auth */
app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const phone = String(req.body?.phone || "").trim();
    const password = String(req.body?.password || "");

    if (!name || !email || !phone || password.length < 6) {
      return res.status(400).json({ error: "Missing fields or password too short" });
    }

    const pass_hash = await bcrypt.hash(password, 12);
    const code = makeVerifyCode();
    const expires = nowMs() + 10 * 60 * 1000;

    await dbExec(
      `
      insert into users (name, email, phone, pass_hash, is_verified, verify_code, verify_expires, created_at)
      values ($1, $2, $3, $4, false, $5, $6, $7)
      `,
      [name, email, phone, pass_hash, code, expires, nowMs()]
    );

    console.log("Verification code for", email, "is", code);
    return res.json({ ok: true });
  } catch (err) {
    const msg = String(err?.message || "");
    if (msg.toLowerCase().includes("duplicate") || msg.toLowerCase().includes("unique")) {
      return res.status(400).json({ error: "Email already registered" });
    }
    return res.status(500).json({ error: "Register failed", details: msg });
  }
});

app.post("/api/verify", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();

    const user = await dbOne(`select * from users where email = $1`, [email]);
    if (!user) return res.status(400).json({ error: "Invalid email" });
    if (user.is_verified === true) return res.json({ ok: true });

    const exp = Number(user.verify_expires || 0);
    if (!user.verify_code || nowMs() > exp) return res.status(400).json({ error: "Code expired" });
    if (String(user.verify_code) !== code) return res.status(400).json({ error: "Invalid code" });

    await dbExec(
      `update users set is_verified = true, verify_code = null, verify_expires = null where id = $1`,
      [user.id]
    );

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Verify failed", details: String(err?.message || err) });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    const user = await dbOne(`select * from users where email = $1`, [email]);
    if (!user) return res.status(400).json({ error: "Invalid login" });
    if (user.is_verified !== true) return res.status(403).json({ error: "Account not verified" });

    const ok = await bcrypt.compare(password, user.pass_hash);
    if (!ok) return res.status(400).json({ error: "Invalid login" });

    const token = signToken(user);
    res.cookie("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: String(process.env.NODE_ENV || "").toLowerCase() === "production"
    });

    const keys = await dbOne(`select user_id from kraken_keys where user_id = $1`, [user.id]);
    return res.json({ ok: true, hasKraken: !!keys });
  } catch (err) {
    return res.status(500).json({ error: "Login failed", details: String(err?.message || err) });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

/* Kraken */
app.post("/api/kraken/save", authRequired, async (req, res) => {
  try {
    const apiKey = String(req.body?.apiKey || "").trim();
    const apiSecret = String(req.body?.apiSecret || "").trim();
    if (!apiKey || !apiSecret) return res.status(400).json({ error: "Missing Kraken credentials" });

    const encSecret = encryptText(apiSecret);

    await dbExec(
      `
      insert into kraken_keys (user_id, api_key, api_secret_enc, created_at, updated_at)
      values ($1, $2, $3, $4, $5)
      on conflict (user_id)
      do update set api_key = excluded.api_key, api_secret_enc = excluded.api_secret_enc, updated_at = excluded.updated_at
      `,
      [req.user.uid, apiKey, encSecret, nowMs(), nowMs()]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Save failed", details: String(err?.message || err) });
  }
});

app.get("/api/kraken/test", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balance = await krakenApiWithNonceRetry(client, req.user.uid, "Balance");
    res.json({ ok: true, status: "Connected", balance: balance.result });
  } catch (err) {
    res.status(500).json({ error: "Connection failed", details: String(err?.message || err) });
  }
});

app.get("/api/account/status", authRequired, async (req, res) => {
  try {
    const keys = await dbOne(`select user_id from kraken_keys where user_id = $1`, [req.user.uid]);
    const user = await dbOne(`select is_verified from users where id = $1`, [req.user.uid]);

    res.json({
      krakenConnected: !!keys,
      emailVerified: user?.is_verified === true
    });
  } catch (e) {
    res.status(500).json({ error: "Status failed", details: String(e?.message || e) });
  }
});

app.get("/pair-info", authRequired, async (req, res) => {
  try {
    const pair = String(req.query.pair || "");
    if (!pair) return res.status(400).json({ error: "pair is required" });

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const meta = await getPairMeta(client, pair);
    res.json({
      pair,
      wsname: meta.wsname,
      pair_decimals: meta.pair_decimals,
      lot_decimals: meta.lot_decimals,
      ordermin: meta.ordermin,
      costmin: meta.costmin
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to load pair info", details: String(err?.message || err) });
  }
});

app.get("/balance", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balanceResp = await krakenApiWithNonceRetry(client, req.user.uid, "Balance");

    let tradeBalanceResp = null;
    try {
      tradeBalanceResp = await krakenApiWithNonceRetry(client, req.user.uid, "TradeBalance", { asset: "ZUSD" });
    } catch (err) {
      console.warn("TradeBalance failed", String(err?.message || err));
      tradeBalanceResp = null;
    }

    const balance = balanceResp?.result || {};
    const tradeBalance = tradeBalanceResp?.result || null;

    const availableZusd =
      numOrNull(tradeBalance?.mf) ??
      numOrNull(tradeBalance?.tb) ??
      numOrNull(tradeBalance?.eb) ??
      numOrNull(tradeBalance?.e) ??
      numOrNull(balance?.ZUSD) ?? 0;

    res.json({ status: "Connected", balance, tradeBalance, availableZusd });
  } catch (err) {
    res.status(500).json({ error: "Failed to connect to Kraken", details: String(err?.message || err) });
  }
});

/* Trades list for account.html */
app.get("/trades", authRequired, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || req.query.pageSize || 10)));
  const q = String(req.query.q || "").trim().toLowerCase();

  const offset = (page - 1) * limit;

  if (q) {
    const items = await dbQuery(
      `
      select * from trades
      where user_id = $1
        and (lower(pair) like $2 or lower(side) like $2 or lower(order_type) like $2 or lower(status) like $2 or lower(message) like $2)
      order by id desc
      limit $3 offset $4
      `,
      [req.user.uid, "%" + q + "%", limit, offset]
    );

    const totalRow = await dbOne(
      `
      select count(*)::bigint as c from trades
      where user_id = $1
        and (lower(pair) like $2 or lower(side) like $2 or lower(order_type) like $2 or lower(status) like $2 or lower(message) like $2)
      `,
      [req.user.uid, "%" + q + "%"]
    );

    return res.json({ page, limit, total: Number(totalRow?.c || 0), items });
  }

  const items = await dbQuery(
    `
    select * from trades
    where user_id = $1
    order by id desc
    limit $2 offset $3
    `,
    [req.user.uid, limit, offset]
  );

  const totalRow = await dbOne(
    `select count(*)::bigint as c from trades where user_id = $1`,
    [req.user.uid]
  );

  res.json({ page, limit, total: Number(totalRow?.c || 0), items });
});

/* Dashboard safe trades now come from Postgres, not memory */
app.get("/api/alerts/safest", authRequired, async (req, res) => {
  const uid = Number(req.user.uid);

  const row = await dbOne(
    `select ts, safe_trades from safe_trades_latest where user_id = $1`,
    [uid]
  );

  const ts = Number(row?.ts || 0);
  const safeTrades = Array.isArray(row?.safe_trades) ? row.safe_trades : (row?.safe_trades || []);

  res.json({ ok: true, safeTrades: Array.isArray(safeTrades) ? safeTrades : [], ts });
});

/* Alerts store to Postgres then optionally send Telegram */
app.post("/api/alerts/safest", authRequired, async (req, res) => {
  try {
    const uid = Number(req.user.uid);
    const safeTrades = Array.isArray(req.body?.safeTrades) ? req.body.safeTrades : [];

    await dbExec(
      `
      insert into safe_trades_latest (user_id, ts, safe_trades)
      values ($1, $2, $3::jsonb)
      on conflict (user_id)
      do update set ts = excluded.ts, safe_trades = excluded.safe_trades
      `,
      [uid, nowMs(), JSON.stringify(safeTrades)]
    );

    if (!safeTrades.length) {
      await dbExec(
        `
        insert into safe_alert_state (user_id, last_sig, last_sent_ts)
        values ($1, '', 0)
        on conflict (user_id)
        do update set last_sig = excluded.last_sig, last_sent_ts = excluded.last_sent_ts
        `,
        [uid]
      );
      return res.json({ ok: true, sent: false, reason: "empty" });
    }

    if (!telegramConfigured()) {
      return res.json({ ok: false, sent: false, error: "Missing TELEGRAM env values" });
    }

    const sig = safeTradesSignature(safeTrades);
    const prev = await dbOne(
      `select last_sig, last_sent_ts from safe_alert_state where user_id = $1`,
      [uid]
    );

    const prevSig = String(prev?.last_sig || "");
    const prevTs = Number(prev?.last_sent_ts || 0);
    const now = nowMs();

    const same = prevSig === sig;
    const inCooldown = (now - prevTs) < ALERT_COOLDOWN_MS;

    if (same || inCooldown) {
      return res.json({ ok: true, sent: false, reason: same ? "already_sent_for_this_set" : "cooldown" });
    }

    await dbExec(
      `
      insert into safe_alert_state (user_id, last_sig, last_sent_ts)
      values ($1, $2, $3)
      on conflict (user_id)
      do update set last_sig = excluded.last_sig, last_sent_ts = excluded.last_sent_ts
      `,
      [uid, sig, now]
    );

    const msg = buildTelegramMessage(safeTrades);
    const tg = await sendTelegram(msg);

    return res.json({ ok: true, sent: true, telegram: tg });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.get("/api/telegram/test", authRequired, async (req, res) => {
  try {
    const r = await sendTelegram("Test ping from server " + new Date().toISOString());
    res.json({ ok: true, telegram: r });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

/* Trade endpoint */
app.post("/trade", authRequired, async (req, res) => {
  const raw = req.body || {};
  const pair = raw.pair;
  const side = raw.side;
  const orderType = raw.orderType || "limit";
  const investUsd = numOrNull(raw.investUsd);

  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    if (!pair || !side) {
      await logTradeDb(req.user.uid, { pair, side, orderType, investUsd, volume: "", status: "error", message: "Missing pair or side" });
      return res.status(400).json({ error: "Missing required trade parameters" });
    }

    const meta = await getPairMeta(client, pair);
    const nums = formatOrderNumbers(meta, raw);

    if (!nums.price) {
      await logTradeDb(req.user.uid, { pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid price" });
      return res.status(400).json({ error: "Invalid price" });
    }

    let volumeStr = null;

    if (investUsd && investUsd > 0) {
      const vol = investUsd / nums.price;
      const ld = meta.lot_decimals ?? 8;
      const vRounded = roundToDecimals(vol, ld);
      volumeStr = vRounded === null ? null : trimNumberString(vRounded.toFixed(ld));
    } else {
      volumeStr = nums.volumeStr;
    }

    if (!volumeStr || Number(volumeStr) <= 0) {
      await logTradeDb(req.user.uid, { pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid volume" });
      return res.status(400).json({ error: "Invalid volume" });
    }

    const minCheck = validateMinimums(meta, nums.price, volumeStr);
    if (!minCheck.ok) {
      const hint = meta.ordermin
        ? "Increase trade amount. Minimum volume is " + meta.ordermin + ". Estimated minimum USD is about " + Number(minCheck.minUsdEstimate || 0).toFixed(2)
        : "Increase trade amount.";

      const requiredUsd =
        meta.costmin !== null
          ? meta.costmin
          : (meta.ordermin !== null ? meta.ordermin * nums.price : null);

      await logTradeDb(req.user.uid, {
        pair, side, orderType, investUsd, volume: volumeStr,
        entryPrice: nums.price,
        takeProfit: nums.takeProfit ?? clampPrice(meta, nums.price * 1.05),
        stopLoss: nums.stopLoss ?? clampPrice(meta, nums.price * 0.93),
        status: "rejected",
        message: "Minimum not met. " + hint
      });

      return res.status(400).json({
        error: "Invalid arguments:volume minimum not met",
        pair,
        pairRules: { ordermin: meta.ordermin, costmin: meta.costmin, pair_decimals: meta.pair_decimals, lot_decimals: meta.lot_decimals },
        requiredUsd,
        hint
      });
    }

    const entryPrice = nums.price;
    const entryPrice2 = nums.price2;

    const takeProfit = nums.takeProfit ?? clampPrice(meta, entryPrice * 1.05);
    const stopLoss = nums.stopLoss ?? clampPrice(meta, entryPrice * 0.93);

    const volNum = Number(volumeStr);
    const estProfitUsd = (takeProfit !== null) ? (takeProfit - entryPrice) * volNum : null;
    const estLossUsd = (stopLoss !== null) ? (entryPrice - stopLoss) * volNum : null;

    const entryParams = {
      pair,
      type: side,
      ordertype: orderType,
      volume: volumeStr
    };

    if (orderType === "limit") {
      entryParams.price = String(entryPrice);
    }

    if (orderType === "stop-loss-limit") {
      entryParams.price = String(entryPrice);
      entryParams.price2 = String(entryPrice2 ?? entryPrice);
    }

    if (SIMULATOR_MODE) {
      const fakeTxid = "SIM_" + Date.now() + "_" + Math.floor(Math.random() * 100000);
      const msgTxt = "Simulator mode. No Kraken order was placed.";

      await logTradeDb(req.user.uid, {
        pair, side, orderType, investUsd,
        volume: volumeStr,
        entryPrice,
        takeProfit,
        stopLoss,
        estProfitUsd,
        estLossUsd,
        status: "simulated",
        message: msgTxt,
        txid: fakeTxid,
        isAuto: raw.isAuto === true
      });

      return res.json({
        message: msgTxt,
        entryTxid: fakeTxid,
        normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeStr },
        simulator: true
      });
    }

    const mainOrder = await krakenApiWithNonceRetry(client, req.user.uid, "AddOrder", entryParams);
    const txid = Array.isArray(mainOrder?.result?.txid) ? mainOrder.result.txid[0] : "";

    let entryStatus = null;
    if (txid) {
      try { entryStatus = await queryOrder(client, req.user.uid, txid); } catch { entryStatus = null; }
    }

    const isFilledNow =
      entryStatus &&
      (String(entryStatus.status).toLowerCase() === "closed") &&
      Number(entryStatus.vol_exec || 0) > 0;

    const msgTxt = isFilledNow
      ? "Entry placed and filled. Exits can be handled after fill."
      : "Entry placed. Exits will be handled after fill.";

    await logTradeDb(req.user.uid, {
      pair, side, orderType, investUsd,
      volume: volumeStr,
      entryPrice,
      takeProfit,
      stopLoss,
      estProfitUsd,
      estLossUsd,
      status: isFilledNow ? "filled" : "submitted",
      message: msgTxt,
      txid,
      isAuto: raw.isAuto === true
    });

    res.json({
      message: msgTxt,
      entry: mainOrder.result,
      entryTxid: txid,
      entryStatus: entryStatus ? { status: entryStatus.status, vol: entryStatus.vol, vol_exec: entryStatus.vol_exec } : null,
      normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeStr }
    });

  } catch (err) {
    const details = err?.response?.error || err?.message || "Trade execution failed";

    await logTradeDb(req.user.uid, {
      pair, side, orderType, investUsd,
      volume: safeStr(raw.volume),
      entryPrice: numOrNull(raw.price),
      takeProfit: numOrNull(raw.takeProfit),
      stopLoss: numOrNull(raw.stopLoss),
      status: "error",
      message: safeStr(details),
      isAuto: raw.isAuto === true
    });

    res.status(500).json({ error: "Trade execution failed", details: safeStr(details) });
  }
});

/* JSON parse guard */
app.use((err, req, res, next) => {
  const isJsonParseError =
    err instanceof SyntaxError &&
    err.status === 400 &&
    "body" in err;

  if (isJsonParseError) {
    return res.status(400).json({ error: "Invalid JSON request" });
  }

  next(err);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
