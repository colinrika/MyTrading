import express from "express";
import cors from "cors";
import KrakenClient from "kraken-api";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

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

const APP_SECRET = process.env.APP_SECRET || "";
const ENC_KEY_B64 = process.env.ENC_KEY_BASE64 || "";
const ENC_KEY = ENC_KEY_B64 ? Buffer.from(ENC_KEY_B64, "base64") : null;

if (!APP_SECRET) {
  console.error("Missing APP_SECRET in env");
  process.exit(1);
}
if (!ENC_KEY || ENC_KEY.length !== 32) {
  console.error("ENC_KEY_BASE64 must decode to 32 bytes");
  process.exit(1);
}

const DB_PATH = process.env.DB_PATH || "./app.db";
const db = new sqlite3.Database(DB_PATH);

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row || null);
    });
  });
}

async function initDb() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      pass_hash TEXT NOT NULL,
      is_verified INTEGER NOT NULL DEFAULT 0,
      verify_code TEXT,
      verify_expires INTEGER,
      created_at INTEGER NOT NULL
    );
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS kraken_keys (
      user_id INTEGER PRIMARY KEY,
      api_key TEXT NOT NULL,
      api_secret_enc TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
  return jwt.sign({ uid: user.id, email: user.email }, APP_SECRET, { expiresIn: "7d" });
}

function authRequired(req, res, next) {
  try {
    const token = req.cookies?.session || "";
    if (!token) return res.status(401).json({ error: "Not logged in" });
    const payload = jwt.verify(token, APP_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Not logged in" });
  }
}

async function getUserKrakenClient(uid) {
  const row = await dbGet(`SELECT api_key, api_secret_enc FROM kraken_keys WHERE user_id = ?`, [uid]);
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

async function queryOrder(krakenClient, txid) {
  const resp = await krakenClient.api("QueryOrders", { txid });
  const result = resp?.result || {};
  const order = result[txid];
  return order || null;
}

/* Trades log in memory */
const tradeLog = [];
let tradeIdSeq = 1;

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

function logTrade(entry) {
  const item = {
    id: tradeIdSeq++,
    time: nowIso(),
    pair: safeStr(entry.pair),
    side: safeStr(entry.side),
    orderType: safeStr(entry.orderType),
    investUsd: entry.investUsd ?? null,
    volume: safeStr(entry.volume),
    entryPrice: entry.entryPrice ?? null,
    takeProfit: entry.takeProfit ?? null,
    stopLoss: entry.stopLoss ?? null,
    estProfitUsd: entry.estProfitUsd ?? null,
    estLossUsd: entry.estLossUsd ?? null,
    status: safeStr(entry.status),
    message: safeStr(entry.message),
    txid: safeStr(entry.txid || ""),
    isAuto: entry.isAuto === true,
    userId: entry.userId ?? null
  };

  tradeLog.unshift(item);
  if (tradeLog.length > 2000) tradeLog.length = 2000;
  return item;
}

/* Telegram alerts */
const ALERT_COOLDOWN_MS = 10 * 60 * 1000;
const lastSafeAlertByUser = new Map();

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

/* Pages that must be protected */
app.get("/dashboard.html", authRequired, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/account.html", authRequired, (req, res) => res.sendFile(path.join(__dirname, "account.html")));
app.get("/connect-kraken.html", authRequired, (req, res) => res.sendFile(path.join(__dirname, "connect-kraken.html")));

/* Public pages */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/register.html", (req, res) => res.sendFile(path.join(__dirname, "register.html")));
app.get("/verify.html", (req, res) => res.sendFile(path.join(__dirname, "verify.html")));

app.get("/dashboard", authRequired, (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/account", authRequired, (req, res) => {
  res.sendFile(path.join(__dirname, "account.html"));
});

app.get("/connect", authRequired, (req, res) => {
  res.sendFile(path.join(__dirname, "connect-kraken.html"));
});

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

    await dbRun(
      `INSERT INTO users (name, email, phone, pass_hash, is_verified, verify_code, verify_expires, created_at)
       VALUES (?, ?, ?, ?, 0, ?, ?, ?)`,
      [name, email, phone, pass_hash, code, expires, nowMs()]
    );

    console.log("Verification code for", email, "is", code);

    return res.json({ ok: true });
  } catch (err) {
    if (String(err.message || "").includes("UNIQUE")) {
      return res.status(400).json({ error: "Email already registered" });
    }
    return res.status(500).json({ error: "Register failed", details: err.message });
  }
});

app.post("/api/verify", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();

    const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) return res.status(400).json({ error: "Invalid email" });
    if (Number(user.is_verified) === 1) return res.json({ ok: true });

    const exp = Number(user.verify_expires || 0);
    if (!user.verify_code || nowMs() > exp) return res.status(400).json({ error: "Code expired" });
    if (String(user.verify_code) !== code) return res.status(400).json({ error: "Invalid code" });

    await dbRun(`UPDATE users SET is_verified = 1, verify_code = NULL, verify_expires = NULL WHERE id = ?`, [user.id]);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Verify failed", details: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) return res.status(400).json({ error: "Invalid login" });
    if (Number(user.is_verified) !== 1) return res.status(403).json({ error: "Account not verified" });

    const ok = await bcrypt.compare(password, user.pass_hash);
    if (!ok) return res.status(400).json({ error: "Invalid login" });

    const token = signToken(user);
    res.cookie("session", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: String(process.env.NODE_ENV || "").toLowerCase() === "production"
    });

    const keys = await dbGet(`SELECT user_id FROM kraken_keys WHERE user_id = ?`, [user.id]);
    return res.json({ ok: true, hasKraken: !!keys });
  } catch (err) {
    return res.status(500).json({ error: "Login failed", details: err.message });
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

    const existing = await dbGet(`SELECT user_id FROM kraken_keys WHERE user_id = ?`, [req.user.uid]);
    if (existing) {
      await dbRun(
        `UPDATE kraken_keys SET api_key = ?, api_secret_enc = ?, updated_at = ? WHERE user_id = ?`,
        [apiKey, encSecret, nowMs(), req.user.uid]
      );
    } else {
      await dbRun(
        `INSERT INTO kraken_keys (user_id, api_key, api_secret_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
        [req.user.uid, apiKey, encSecret, nowMs(), nowMs()]
      );
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Save failed", details: err.message });
  }
});

app.get("/api/kraken/test", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balance = await client.api("Balance");
    res.json({ ok: true, status: "Connected", balance: balance.result });
  } catch (err) {
    res.status(500).json({ error: "Connection failed", details: err.message });
  }
});

app.get("/api/account/status", authRequired, async (req, res) => {
  try {
    const keys = await dbGet(`SELECT user_id FROM kraken_keys WHERE user_id = ?`, [req.user.uid]);
    const user = await dbGet(`SELECT is_verified FROM users WHERE id = ?`, [req.user.uid]);

    res.json({
      krakenConnected: !!keys,
      emailVerified: Number(user?.is_verified || 0) === 1
    });
  } catch (e) {
    res.status(500).json({ error: "Status failed", details: String(e.message || e) });
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
    res.status(500).json({ error: "Failed to load pair info", details: err.message });
  }
});

/* Trade balance (available funds) */
app.get("/api/trade-balance", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const asset = String(req.query.asset || "ZUSD");
    const tb = await client.api("TradeBalance", { asset });
    const result = tb?.result || {};

    const available =
      numOrNull(result.mf) ??
      numOrNull(result.tb) ??
      numOrNull(result.eb) ??
      null;

    res.json({
      ok: true,
      asset,
      raw: result,
      available
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: "TradeBalance failed", details: String(err?.message || err) });
  }
});

/* Balance (totals) plus best effort available */
app.get("/balance", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balance = await client.api("Balance");
    let tradeBalance = null;

    try {
      const tb = await client.api("TradeBalance", { asset: "ZUSD" });
      const r = tb?.result || {};
      tradeBalance = {
        asset: "ZUSD",
        raw: r,
        available: numOrNull(r.mf) ?? numOrNull(r.tb) ?? numOrNull(r.eb) ?? null
      };
    } catch {
      tradeBalance = null;
    }

    res.json({ status: "Connected", balance: balance.result, tradeBalance });
  } catch (err) {
    res.status(500).json({ error: "Failed to connect to Kraken", details: err.message });
  }
});

/* Trades list for account.html */
app.get("/trades", authRequired, async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || req.query.pageSize || 10)));
  const q = String(req.query.q || "").trim().toLowerCase();

  let filtered = tradeLog.filter(t => String(t.userId) === String(req.user.uid));
  if (q) {
    filtered = filtered.filter(t => {
      const hay = (t.pair + " " + t.side + " " + t.orderType + " " + t.status + " " + t.message).toLowerCase();
      return hay.includes(q);
    });
  }

  const total = filtered.length;
  const start = (page - 1) * limit;
  const items = filtered.slice(start, start + limit);

  res.json({ page, limit, total, items });
});

/* Price cache so you do not spam Kraken every refresh */
const priceCache = new Map(); // pair -> { price, ts }
const PRICE_TTL_MS = 10 * 1000;

async function getLastPrices(pairs) {
  const now = Date.now();
  const out = {};

  const need = [];
  for (const p of pairs) {
    const hit = priceCache.get(p);
    if (hit && (now - hit.ts) < PRICE_TTL_MS) out[p] = hit.price;
    else need.push(p);
  }

  if (!need.length) return out;

  const url = "https://api.kraken.com/0/public/Ticker?pair=" + encodeURIComponent(need.join(","));
  const r = await fetch(url);
  const j = await r.json().catch(() => ({}));
  const result = j.result || {};

  for (const [k, v] of Object.entries(result)) {
    const last = Number(v?.c?.[0]);
    if (Number.isFinite(last)) {
      priceCache.set(k, { price: last, ts: now });
      out[k] = last;
    }
  }

  for (const p of need) {
    if (out[p] !== undefined) continue;
    const needle = String(p).replace("/", "");
    const foundKey = Object.keys(out).find(x => String(x).replace("/", "") === needle);
    if (foundKey) out[p] = out[foundKey];
  }

  return out;
}

/* Batch prices for account page */
app.get("/api/prices", authRequired, async (req, res) => {
  try {
    const raw = String(req.query.pairs || "");
    const pairs = raw.split(",").map(s => s.trim()).filter(Boolean);
    if (!pairs.length) return res.json({ ok: true, prices: {} });

    const prices = await getLastPrices(pairs);
    return res.json({ ok: true, prices });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Live order status by txid */
app.get("/api/order/status", authRequired, async (req, res) => {
  try {
    const txid = String(req.query.txid || "").trim();
    if (!txid) return res.status(400).json({ ok: false, error: "txid required" });

    const mine = tradeLog.find(t => String(t.userId) === String(req.user.uid) && String(t.txid) === txid);
    if (!mine) return res.status(404).json({ ok: false, error: "Order not found" });

    if (SIMULATOR_MODE) {
      return res.json({
        ok: true,
        status: mine.status || "simulated",
        vol_exec: "0.0",
        price: mine.entryPrice ?? null
      });
    }

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ ok: false, error: "No Kraken keys saved" });

    const o = await queryOrder(client, txid);
    if (!o) return res.json({ ok: true, status: "unknown" });

    const status = String(o.status || "");
    const vol_exec = String(o.vol_exec || "0");
    const price = Number(o.price || 0);

    if (status) mine.status = status;

    return res.json({
      ok: true,
      status,
      vol: String(o.vol || ""),
      vol_exec,
      price: Number.isFinite(price) ? price : null,
      descr: o.descr || null
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Cancel an open order */
app.post("/api/order/cancel", authRequired, async (req, res) => {
  try {
    const txid = String(req.body?.txid || "").trim();
    if (!txid) return res.status(400).json({ ok: false, error: "txid required" });

    const mine = tradeLog.find(t => String(t.userId) === String(req.user.uid) && String(t.txid) === txid);
    if (!mine) return res.status(404).json({ ok: false, error: "Order not found" });

    if (SIMULATOR_MODE || String(txid).startsWith("SIM_")) {
      mine.status = "canceled";
      return res.json({ ok: true, canceled: true, simulator: true });
    }

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ ok: false, error: "No Kraken keys saved" });

    const resp = await client.api("CancelOrder", { txid });
    const count = Number(resp?.result?.count || 0);

    if (count > 0) mine.status = "canceled";

    return res.json({ ok: true, canceled: count > 0, result: resp?.result || {} });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Close immediately using a market order */
app.post("/api/order/close", authRequired, async (req, res) => {
  try {
    const tradeId = Number(req.body?.tradeId || 0);
    if (!tradeId) return res.status(400).json({ ok: false, error: "tradeId required" });

    const mine = tradeLog.find(t => Number(t.id) === tradeId && String(t.userId) === String(req.user.uid));
    if (!mine) return res.status(404).json({ ok: false, error: "Trade not found" });

    const pair = String(mine.pair || "");
    const volume = String(mine.volume || "");
    const entrySide = String(mine.side || "").toLowerCase();

    if (!pair || !volume || Number(volume) <= 0) {
      return res.status(400).json({ ok: false, error: "Missing pair or volume on this trade" });
    }

    const closeSide = entrySide === "buy" ? "sell" : "buy";

    if (SIMULATOR_MODE) {
      mine.status = "closed_by_user";
      logTrade({
        pair,
        side: closeSide,
        orderType: "market",
        investUsd: null,
        volume,
        entryPrice: null,
        takeProfit: null,
        stopLoss: null,
        status: "simulated",
        message: "Simulator close. No Kraken order was placed.",
        txid: "SIM_CLOSE_" + Date.now(),
        isAuto: false,
        userId: req.user.uid
      });

      return res.json({ ok: true, closed: true, simulator: true });
    }

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ ok: false, error: "No Kraken keys saved" });

    const closeParams = {
      pair,
      type: closeSide,
      ordertype: "market",
      volume
    };

    const resp = await client.api("AddOrder", closeParams);
    const txid = Array.isArray(resp?.result?.txid) ? resp.result.txid[0] : "";

    mine.status = "closed_by_user";

    logTrade({
      pair,
      side: closeSide,
      orderType: "market",
      investUsd: null,
      volume,
      entryPrice: null,
      takeProfit: null,
      stopLoss: null,
      status: "submitted",
      message: "Close sent as market order",
      txid,
      isAuto: false,
      userId: req.user.uid
    });

    return res.json({ ok: true, closed: true, txid });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Alerts endpoint called by dashboard */
app.post("/api/alerts/safest", authRequired, async (req, res) => {
  try {
    const safeTrades = Array.isArray(req.body?.safeTrades) ? req.body.safeTrades : [];
    const uid = String(req.user.uid);

    if (!safeTrades.length) {
      lastSafeAlertByUser.set(uid, { sig: "", ts: 0 });
      return res.json({ ok: true, sent: false, reason: "empty" });
    }

    if (!telegramConfigured()) {
      return res.json({ ok: false, sent: false, error: "Missing TELEGRAM env values" });
    }

    const sig = safeTradesSignature(safeTrades);
    const prev = lastSafeAlertByUser.get(uid) || { sig: "", ts: 0 };
    const now = Date.now();

    const same = prev.sig === sig;
    const inCooldown = (now - prev.ts) < ALERT_COOLDOWN_MS;

    if (same || inCooldown) {
      return res.json({ ok: true, sent: false, reason: same ? "already_sent_for_this_set" : "cooldown" });
    }

    lastSafeAlertByUser.set(uid, { sig, ts: now });

    const msg = buildTelegramMessage(safeTrades);
    const tg = await sendTelegram(msg);

    return res.json({ ok: true, sent: true, telegram: tg });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Telegram test should be protected */
app.get("/api/telegram/test", authRequired, async (req, res) => {
  try {
    const r = await sendTelegram("Test ping from server " + new Date().toISOString());
    res.json({ ok: true, telegram: r });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
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
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Missing pair or side", userId: req.user.uid });
      return res.status(400).json({ error: "Missing required trade parameters" });
    }

    const meta = await getPairMeta(client, pair);
    const nums = formatOrderNumbers(meta, raw);

    if (!nums.price) {
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid price", userId: req.user.uid });
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
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid volume", userId: req.user.uid });
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

      logTrade({
        pair, side, orderType, investUsd, volume: volumeStr,
        entryPrice: nums.price,
        takeProfit: nums.takeProfit ?? clampPrice(meta, nums.price * 1.05),
        stopLoss: nums.stopLoss ?? clampPrice(meta, nums.price * 0.93),
        status: "rejected",
        message: "Minimum not met. " + hint,
        userId: req.user.uid
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

      logTrade({
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
        isAuto: raw.isAuto === true,
        userId: req.user.uid
      });

      return res.json({
        message: msgTxt,
        entryTxid: fakeTxid,
        normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeStr },
        simulator: true
      });
    }

    /* Helpful funds check before AddOrder */
    if (String(side).toLowerCase() === "buy") {
      let availableUsd = null;
      try {
        const tb = await client.api("TradeBalance", { asset: "ZUSD" });
        const r = tb?.result || {};
        availableUsd = numOrNull(r.mf) ?? numOrNull(r.tb) ?? numOrNull(r.eb) ?? null;
      } catch {
        availableUsd = null;
      }

      if (availableUsd !== null) {
        const feeBufferRate = 0.01;
        const required = (volNum * entryPrice) * (1 + feeBufferRate);
        if (required > availableUsd + 1e-10) {
          const msg = "Insufficient available ZUSD for this buy. Your funds might be in another asset, or not available for trading.";
          logTrade({
            pair, side, orderType, investUsd,
            volume: volumeStr,
            entryPrice,
            takeProfit,
            stopLoss,
            estProfitUsd,
            estLossUsd,
            status: "rejected",
            message: msg + " Available " + availableUsd.toFixed(4) + " Required about " + required.toFixed(4),
            isAuto: raw.isAuto === true,
            userId: req.user.uid
          });

          return res.status(400).json({
            error: "Insufficient funds",
            hint: msg,
            availableZUSD: availableUsd,
            requiredZUSDApprox: required
          });
        }
      }
    }

    const mainOrder = await client.api("AddOrder", entryParams);
    const txid = Array.isArray(mainOrder?.result?.txid) ? mainOrder.result.txid[0] : "";

    let entryStatus = null;
    if (txid) {
      try { entryStatus = await queryOrder(client, txid); } catch { entryStatus = null; }
    }

    const isFilledNow =
      entryStatus &&
      (String(entryStatus.status).toLowerCase() === "closed") &&
      Number(entryStatus.vol_exec || 0) > 0;

    const msgTxt = isFilledNow
      ? "Entry placed and filled. Exits can be handled after fill."
      : "Entry placed. Exits will be handled after fill.";

    logTrade({
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
      isAuto: raw.isAuto === true,
      userId: req.user.uid
    });

    res.json({
      message: msgTxt,
      entry: mainOrder.result,
      entryTxid: txid,
      entryStatus: entryStatus ? { status: entryStatus.status, vol: entryStatus.vol, vol_exec: entryStatus.vol_exec } : null,
      normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeStr }
    });

  } catch (err) {
    const details = err.response?.error || err.message || "Trade execution failed";

    logTrade({
      pair, side, orderType, investUsd,
      volume: safeStr(raw.volume),
      entryPrice: numOrNull(raw.price),
      takeProfit: numOrNull(raw.takeProfit),
      stopLoss: numOrNull(raw.stopLoss),
      status: "error",
      message: safeStr(details),
      isAuto: raw.isAuto === true,
      userId: req.user.uid
    });

    res.status(500).json({ error: "Trade execution failed", details });
  }
});

app.post("/api/orders/cancel", authRequired, async (req, res) => {
  try {
    const txid = String(req.body?.txid || "").trim();
    if (!txid) return res.status(400).json({ ok: false, error: "Missing txid" });

    if (String(txid).startsWith("SIM_")) {
      return res.json({ ok: true, canceled: true, simulator: true });
    }

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ ok: false, error: "No Kraken keys saved" });

    const r = await client.api("CancelOrder", { txid });

    return res.json({
      ok: true,
      canceled: true,
      result: r?.result || null
    });
  } catch (err) {
    const msg = String(err?.message || err);
    const apiErr = Array.isArray(err?.response?.error) ? err.response.error.join(", ") : "";

    const combined = (apiErr || msg || "").toString();

    if (combined.includes("EOrder:Unknown order")) {
      return res.status(400).json({
        ok: false,
        error: "Unknown order",
        hint: "This order is not open anymore, or you are not sending the real txid."
      });
    }

    return res.status(500).json({ ok: false, error: "Cancel failed", details: combined });
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
