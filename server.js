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
import pg from "pg";

const { Pool } = pg;

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
const AGGRESSIVE_MODE = String(process.env.AGGRESSIVE_MODE || "false").toLowerCase() === "true";

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

const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL in env");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SAFE_TRADES_FILE = process.env.SAFE_TRADES_FILE || "./latest_safe_trades.json";
const QUICK_PROFIT_PCT = 0.02;
const KRAKEN_FEE_PCT = Number(process.env.KRAKEN_FEE_PCT || 0.0026);

function targetMovePct() {
  const feePct = Number.isFinite(KRAKEN_FEE_PCT) ? KRAKEN_FEE_PCT : 0;
  return QUICK_PROFIT_PCT + Math.max(0, feePct);
}

async function dbRun(sql, params = []) {
  return pool.query(sql, params);
}

async function dbAll(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows || [];
}

async function dbGet(sql, params = []) {
  const r = await pool.query(sql, params);
  return r.rows && r.rows.length ? r.rows[0] : null;
}

async function updateTrade(id, patch) {
  const keys = Object.keys(patch || {});
  if (!keys.length) return;

  const sets = [];
  const vals = [];
  let i = 1;

  for (const k of keys) {
    sets.push(`${k} = $${i}`);
    vals.push(patch[k]);
    i += 1;
  }

  vals.push(id);
  const q = `update public.trades set ${sets.join(", ")} where id = $${i}`;
  await pool.query(q, vals);
}

async function getTradeById(id) {
  return await dbGet(`select * from public.trades where id = $1`, [id]);
}

async function initDb() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      pass_hash TEXT NOT NULL,
      is_verified BOOLEAN NOT NULL DEFAULT FALSE,
      verify_code TEXT,
      verify_expires BIGINT,
      created_at BIGINT NOT NULL
    );
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS kraken_keys (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      api_key TEXT NOT NULL,
      api_secret_enc TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS kraken_nonces (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      last_nonce BIGINT NOT NULL DEFAULT 0,
      updated_at BIGINT NOT NULL
    );
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS public.trades (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      time_ms BIGINT NOT NULL,
      pair TEXT NOT NULL,
      side TEXT NOT NULL,
      order_type TEXT NOT NULL,
      invest_usd NUMERIC,
      volume NUMERIC,
      entry_price NUMERIC,
      take_profit NUMERIC,
      stop_loss NUMERIC,
      est_profit_usd NUMERIC,
      est_loss_usd NUMERIC,
      status TEXT NOT NULL,
      message TEXT,
      txid TEXT,
      exit_tp_txid TEXT,
      exit_sl_txid TEXT,
      exit_status TEXT NOT NULL DEFAULT 'none',
      is_auto BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  await dbRun(`
    CREATE INDEX IF NOT EXISTS trades_user_time_idx ON public.trades (user_id, time_ms DESC);
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

function pageAuthRequired(req, res, next) {
  try {
    const token = req.cookies?.session || "";
    if (!token) {
      const nextUrl = encodeURIComponent(req.originalUrl || "/dashboard.html");
      return res.redirect("/login.html?next=" + nextUrl);
    }
    const payload = jwt.verify(token, APP_SECRET);
    req.user = payload;
    next();
  } catch {
    const nextUrl = encodeURIComponent(req.originalUrl || "/dashboard.html");
    return res.redirect("/login.html?next=" + nextUrl);
  }
}

async function getUserKrakenClient(uid) {
  const row = await dbGet(`SELECT api_key, api_secret_enc FROM kraken_keys WHERE user_id = $1`, [uid]);
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

  const row = await dbGet(`SELECT last_nonce FROM kraken_nonces WHERE user_id = $1`, [uid]);
  const last = Number(row?.last_nonce || 0);
  const nonce = Math.max(last + 1, now);

  await dbRun(
    `
    INSERT INTO kraken_nonces (user_id, last_nonce, updated_at)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id)
    DO UPDATE SET last_nonce = EXCLUDED.last_nonce, updated_at = EXCLUDED.updated_at
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
      await new Promise(r => setTimeout(r, 300));
      finalParams.nonce = await nextNonce(uid);
      return await client.api(method, finalParams);
    }
    throw err;
  }
}

const STABLE_BASES = new Set([
  "USDT", "USDC", "DAI", "USDG", "TUSD", "PYUSD"
]);

function baseFromPair(pair) {
  const s = String(pair || "").toUpperCase();
  if (s.endsWith("ZUSD")) return s.slice(0, -4);
  if (s.includes("/")) return s.split("/")[0];
  return s;
}

function isStablePair(pair) {
  const base = baseFromPair(pair);
  return STABLE_BASES.has(base);
}

async function getTopUsdPairsByVolume(limit = 20) {
  const r = await fetch("https://api.kraken.com/0/public/Ticker");
  const j = await r.json();
  const result = j.result || {};

  const rows = [];

  for (const pair of Object.keys(result)) {
    if (!pair.endsWith("ZUSD")) continue;

    const base = baseFromPair(pair);
    if (STABLE_BASES.has(base)) continue;

    const vol = Number(result[pair]?.v?.[1]);
    if (!Number.isFinite(vol)) continue;

    rows.push({ pair, vol });
  }

  rows.sort((a, b) => b.vol - a.vol);
  return rows.slice(0, limit).map(x => x.pair);
}

async function fetchOHLC_Public(pair, intervalMin, candles) {
  const url = "https://api.kraken.com/0/public/OHLC?pair=" + encodeURIComponent(pair) + "&interval=" + intervalMin;
  const r = await fetch(url);
  const j = await r.json();
  const k = Object.keys(j.result || {}).find(x => x !== "last");
  if (!k || !Array.isArray(j.result[k])) return [];

  return j.result[k].slice(-(candles || 60)).map(x => ({
    ts: Number(x[0]) * 1000,
    open: Number(x[1]),
    high: Number(x[2]),
    low: Number(x[3]),
    close: Number(x[4]),
    volume: Number(x[6])
  }));
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

function capStopLossForBuy(meta, entryPrice, stopLoss) {
  if (!entryPrice || !stopLoss) return stopLoss;
  const maxLossStop = clampPrice(meta, entryPrice * 0.95);
  if (maxLossStop === null) return stopLoss;
  return stopLoss < maxLossStop ? maxLossStop : stopLoss;
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

async function logTrade(entry) {
  const item = {
    time_ms: Date.now(),
    pair: safeStr(entry.pair),
    side: safeStr(entry.side),
    order_type: safeStr(entry.orderType),
    invest_usd: entry.investUsd ?? null,
    volume: safeStr(entry.volume),
    entry_price: entry.entryPrice ?? null,
    take_profit: entry.takeProfit ?? null,
    stop_loss: entry.stopLoss ?? null,
    est_profit_usd: entry.estProfitUsd ?? null,
    est_loss_usd: entry.estLossUsd ?? null,
    status: safeStr(entry.status),
    message: safeStr(entry.message),
    txid: safeStr(entry.txid || ""),
    is_auto: entry.isAuto === true,
    user_id: entry.userId ?? null
  };

  if (!item.user_id) return null;

  const q = `
    insert into public.trades
      (user_id, time_ms, pair, side, order_type, invest_usd, volume, entry_price, take_profit, stop_loss, est_profit_usd, est_loss_usd, status, message, txid, is_auto)
    values
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    returning id
  `;

  const vals = [
    item.user_id,
    item.time_ms,
    item.pair,
    item.side,
    item.order_type,
    item.invest_usd,
    item.volume,
    item.entry_price,
    item.take_profit,
    item.stop_loss,
    item.est_profit_usd,
    item.est_loss_usd,
    item.status,
    item.message,
    item.txid,
    item.is_auto
  ];

  const r = await pool.query(q, vals);
  return { ...item, id: r.rows?.[0]?.id ?? null };
}

function readSafeTradesFile() {
  try {
    const raw = fs.readFileSync(SAFE_TRADES_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.safeTrades)) return { ts: 0, safeTrades: [] };
    const ts = numOrNull(parsed.ts) ?? 0;
    return { ts, safeTrades: parsed.safeTrades };
  } catch {
    return { ts: 0, safeTrades: [] };
  }
}

function writeSafeTradesFile(safeTrades) {
  try {
    const payload = { ts: Date.now(), safeTrades: Array.isArray(safeTrades) ? safeTrades : [] };
    fs.writeFileSync(SAFE_TRADES_FILE, JSON.stringify(payload, null, 2), "utf8");
  } catch {
  }
}

/* Telegram alerts */
const ALERT_COOLDOWN_MS = 10 * 60 * 1000;
const lastSafeAlertByUser = new Map();

/* Latest safe trades per user */
const latestSafeTradesByUser = new Map();

function actionableBuysOnly(safeTrades) {
  return (Array.isArray(safeTrades) ? safeTrades : [])
    .filter(t => String(t?.recommended?.side || "").toLowerCase() === "buy")
    .filter(t => Number(t?.recommended?.quality || 0) >= 70)
    .filter(t => {
      const p = Number(t?.recommended?.price);
      return Number.isFinite(p) && p > 0;
    });
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

function buildTelegramMessage(actionableBuys) {
  const now = new Date().toLocaleString();
  let msg = `Trade available ${now}\n\n`;

  for (const t of actionableBuys.slice(0, 3)) {
    const rec = t.recommended || {};
    const entry = Number(rec.price ?? t.last ?? 0);

    msg += `${prettyPair(t.pair)}\n`;
    msg += `BUY  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${entry.toFixed(6)}\n`;
    if (rec.takeProfit != null) msg += `TP ${Number(rec.takeProfit).toFixed(6)}\n`;
    if (rec.stopLoss != null) msg += `SL ${Number(rec.stopLoss).toFixed(6)}\n`;
    msg += `\n`;
  }

  return msg;
}

async function computeSafestTradesNow(uid) {
  const client = await getUserKrakenClient(uid);
  if (!client) return [];

  await ensurePairMetaLoaded(client);

  const candidates = await getTopUsdPairsByVolume(20);
  const safeTrades = [];

  for (const pair of candidates) {
    try {
      if (isStablePair(pair)) continue;

      const h1 = await fetchOHLC_Public(pair, 60, 260);
      const h4 = await fetchOHLC_Public(pair, 240, 260);
      const m5 = await fetchOHLC_Public(pair, 5, 120);

      if (!h1.length || !h4.length || !m5.length) continue;

      const last = Number(m5[m5.length - 1].close);
      if (!Number.isFinite(last) || last <= 0) continue;

      const res = { pair, last, h1, h4, m5 };

      const recommended = decideStrategyOrder(res, last, AGGRESSIVE_MODE);

      const side = String(recommended?.side || "");
      const price = Number(recommended?.price);

      const actionable =
        side === "buy" &&
        Number.isFinite(price) &&
        price > 0 &&
        Number(recommended?.quality || 0) >= 70;

      if (!actionable) continue;

      safeTrades.push({ pair, last, recommended });
    } catch {
    }
  }

  safeTrades.sort((a, b) => Number(b.recommended.quality || 0) - Number(a.recommended.quality || 0));
  return safeTrades.slice(0, 5);
}

/*
  Strategy decision is assumed to be defined elsewhere in your file.
  You included it in strategy.html, but server references it too.
  Keep your existing decideStrategyOrder function here as you already had it.
*/
function decideStrategyOrder(res, currentPrice, aggressive) {
  // This placeholder keeps your server compiling if you forgot to include it here.
  // Replace with your existing implementation if it was below in your original server file.
  return { side: null, price: null, quality: 0, tag: "No strategy", takeProfit: null, stopLoss: null };
}

/* Exit placement */

async function placeExitOrders({ uid, tradeId, pair, volumeStr, takeProfit, stopLoss }) {
  const client = await getUserKrakenClient(uid);
  if (!client) throw new Error("No Kraken keys saved");

  const meta = await getPairMeta(client, pair);

  const tp = clampPrice(meta, takeProfit);
  const sl = clampPrice(meta, stopLoss);
  if (!tp || !sl) throw new Error("Invalid TP or SL");

  const volume = String(volumeStr);

  // Spot friendly. Remove reduce only flags since they can fail on spot.
  const tpParams = {
    pair,
    type: "sell",
    ordertype: "take-profit",
    price: String(tp),
    volume
  };

  const slParams = {
    pair,
    type: "sell",
    ordertype: "stop-loss",
    price: String(sl),
    volume
  };

  const tpResp = await krakenApiWithNonceRetry(client, uid, "AddOrder", tpParams);
  const tpTxid = Array.isArray(tpResp?.result?.txid) ? tpResp.result.txid[0] : "";

  const slResp = await krakenApiWithNonceRetry(client, uid, "AddOrder", slParams);
  const slTxid = Array.isArray(slResp?.result?.txid) ? slResp.result.txid[0] : "";

  await updateTrade(tradeId, {
    exit_tp_txid: tpTxid || null,
    exit_sl_txid: slTxid || null,
    exit_status: "open"
  });

  return { tpTxid, slTxid };
}

/* Protected pages */
app.get("/dashboard.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/account.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "account.html")));
app.get("/connect-kraken.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "connect-kraken.html")));
app.get("/strategy.html", pageAuthRequired, (req, res) => res.sendFile(path.join(__dirname, "strategy.html")));

/* Public pages */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/login", (req, res) => res.redirect("/login.html"));
app.get("/register", (req, res) => res.redirect("/register.html"));
app.get("/verify", (req, res) => res.redirect("/verify.html"));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/register.html", (req, res) => res.sendFile(path.join(__dirname, "register.html")));
app.get("/verify.html", (req, res) => res.sendFile(path.join(__dirname, "verify.html")));
app.get("/dashboard", pageAuthRequired, (req, res) => res.redirect("/dashboard.html"));
app.get("/account", pageAuthRequired, (req, res) => res.redirect("/account.html"));
app.get("/connect", pageAuthRequired, (req, res) => res.redirect("/connect.html"));
app.get("/strategy", pageAuthRequired, (req, res) => res.redirect("/strategy.html"));

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
      `
      INSERT INTO users (name, email, phone, pass_hash, is_verified, verify_code, verify_expires, created_at)
      VALUES ($1, $2, $3, $4, FALSE, $5, $6, $7)
      `,
      [name, email, phone, pass_hash, code, expires, nowMs()]
    );

    console.log("Verification code for", email, "is", code);

    return res.json({ ok: true });
  } catch (err) {
    const msg = String(err.message || "");
    if (msg.toLowerCase().includes("duplicate") || msg.toLowerCase().includes("unique")) {
      return res.status(400).json({ error: "Email already registered" });
    }
    return res.status(500).json({ error: "Register failed", details: err.message });
  }
});

app.post("/api/verify", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();

    const user = await dbGet(`SELECT * FROM users WHERE email = $1`, [email]);
    if (!user) return res.status(400).json({ error: "Invalid email" });
    if (user.is_verified === true) return res.json({ ok: true });

    const exp = Number(user.verify_expires || 0);
    if (!user.verify_code || nowMs() > exp) return res.status(400).json({ error: "Code expired" });
    if (String(user.verify_code) !== code) return res.status(400).json({ error: "Invalid code" });

    await dbRun(
      `UPDATE users SET is_verified = TRUE, verify_code = NULL, verify_expires = NULL WHERE id = $1`,
      [user.id]
    );

    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: "Verify failed", details: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    const user = await dbGet(`SELECT * FROM users WHERE email = $1`, [email]);
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

    const keys = await dbGet(`SELECT user_id FROM kraken_keys WHERE user_id = $1`, [user.id]);
    return res.json({ ok: true, hasKraken: !!keys });
  } catch (err) {
    return res.status(500).json({ error: "Login failed", details: err.message });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

/* Kraken keys */
app.post("/api/kraken/save", authRequired, async (req, res) => {
  try {
    const apiKey = String(req.body?.apiKey || "").trim();
    const apiSecret = String(req.body?.apiSecret || "").trim();
    if (!apiKey || !apiSecret) return res.status(400).json({ error: "Missing Kraken credentials" });

    const encSecret = encryptText(apiSecret);

    await dbRun(
      `
      INSERT INTO kraken_keys (user_id, api_key, api_secret_enc, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (user_id)
      DO UPDATE SET api_key = EXCLUDED.api_key, api_secret_enc = EXCLUDED.api_secret_enc, updated_at = EXCLUDED.updated_at
      `,
      [req.user.uid, apiKey, encSecret, nowMs(), nowMs()]
    );

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Save failed", details: err.message });
  }
});

app.get("/api/kraken/test", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balance = await krakenApiWithNonceRetry(client, req.user.uid, "Balance");
    res.json({ ok: true, status: "Connected", balance: balance.result });
  } catch (err) {
    res.status(500).json({ error: "Connection failed", details: err.message });
  }
});

app.get("/api/account/status", authRequired, async (req, res) => {
  try {
    const keys = await dbGet(`SELECT user_id FROM kraken_keys WHERE user_id = $1`, [req.user.uid]);
    const user = await dbGet(`SELECT is_verified FROM users WHERE id = $1`, [req.user.uid]);

    res.json({
      krakenConnected: !!keys,
      emailVerified: user?.is_verified === true
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

app.get("/balance", authRequired, async (req, res) => {
  try {
    const client = await getUserKrakenClient(req.user.uid);
    if (!client) return res.status(400).json({ error: "No Kraken keys saved" });

    const balanceResp = await krakenApiWithNonceRetry(client, req.user.uid, "Balance");

    let tradeBalanceResp = null;
    try {
      tradeBalanceResp = await krakenApiWithNonceRetry(client, req.user.uid, "TradeBalance", { asset: "ZUSD" });
    } catch (err) {
      const msg = String(err?.message || err || "");
      console.warn("TradeBalance failed", msg);
      tradeBalanceResp = null;
    }

    const balance = balanceResp?.result || {};
    const tradeBalance = tradeBalanceResp?.result || null;

    const availableZusd =
      numOrNull(tradeBalance?.mf) ??
      numOrNull(tradeBalance?.tb) ??
      numOrNull(tradeBalance?.eb) ??
      numOrNull(tradeBalance?.e) ??
      numOrNull(balance?.ZUSD) ??
      0;

    res.json({ status: "Connected", balance, tradeBalance, availableZusd });
  } catch (err) {
    res.status(500).json({ error: "Failed to connect to Kraken", details: err.message });
  }
});

/* Trades list */
app.get("/trades", authRequired, async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.max(1, Math.min(100, Number(req.query.limit || req.query.pageSize || 10)));
    const q = String(req.query.q || "").trim().toLowerCase();

    const uid = Number(req.user.uid);
    const offset = (page - 1) * limit;

    const whereParts = ["user_id = $1"];
    const vals = [uid];
    let idx = 2;

    if (q) {
      whereParts.push(`(
        lower(pair) like $${idx} or
        lower(side) like $${idx} or
        lower(status) like $${idx} or
        lower(message) like $${idx} or
        lower(order_type) like $${idx} or
        lower(coalesce(txid,'')) like $${idx}
      )`);
      vals.push(`%${q}%`);
      idx += 1;
    }

    const whereSql = whereParts.join(" and ");

    const countSql = `select count(*)::bigint as c from public.trades where ${whereSql}`;
    const listSql = `
      select
        id,
        to_timestamp(time_ms / 1000.0) as time,
        pair,
        side,
        status,
        order_type as "orderType",
        invest_usd as "investUsd",
        volume,
        entry_price as "entryPrice",
        take_profit as "takeProfit",
        stop_loss as "stopLoss",
        est_profit_usd as "estProfitUsd",
        est_loss_usd as "estLossUsd",
        message,
        txid,
        is_auto as "isAuto"
      from public.trades
      where ${whereSql}
      order by time_ms desc
      limit $${idx} offset $${idx + 1}
    `;

    const countRes = await pool.query(countSql, vals);
    const total = Number(countRes.rows?.[0]?.c || 0);

    const listRes = await pool.query(listSql, [...vals, limit, offset]);
    const items = listRes.rows || [];

    res.json({ page, limit, total, items });
  } catch (e) {
    res.status(500).json({ error: "Failed to load trades", details: String(e.message || e) });
  }
});

/* Dashboard safe trades */
app.get("/api/alerts/safest", authRequired, async (req, res) => {
  try {
    const uid = String(req.user.uid);

    const safeTrades = await computeSafestTradesNow(uid);

    latestSafeTradesByUser.set(uid, { ts: Date.now(), safeTrades });
    writeSafeTradesFile(safeTrades);

    res.json({ ok: true, safeTrades, ts: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Cron safest alert */
app.post("/api/cron/safest", async (req, res) => {
  try {
    const headerKey = String(req.headers["x-cron-key"] || "");
    const queryKey = String(req.query?.cron_key || "");
    const key = headerKey || queryKey;
    if (!process.env.CRON_KEY || key !== process.env.CRON_KEY) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    if (!telegramConfigured()) {
      return res.status(400).json({ ok: false, error: "Telegram not configured" });
    }

    // Your tables are not in schema public. Query users, not public.users.
    const users = await dbAll(`select id from users where is_verified = true`);

    let sentCount = 0;

    for (const u of users) {
      const uid = String(u.id);

      const safeTrades = await computeSafestTradesNow(uid);

      latestSafeTradesByUser.set(uid, { ts: Date.now(), safeTrades });
      writeSafeTradesFile(safeTrades);

      const actionable = actionableBuysOnly(safeTrades);
      if (!actionable.length) continue;

      const sig = safeTradesSignature(actionable);
      const prev = lastSafeAlertByUser.get(uid) || { sig: "", ts: 0 };
      const now = Date.now();

      const same = prev.sig === sig;
      const inCooldown = (now - prev.ts) < ALERT_COOLDOWN_MS;
      if (same || inCooldown) continue;

      lastSafeAlertByUser.set(uid, { sig, ts: now });

      const msg = buildTelegramMessage(actionable);
      await sendTelegram(msg);
      sentCount += 1;
    }

    res.json({ ok: true, sentCount });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Manual alert endpoint */
app.post("/api/alerts/safest", authRequired, async (req, res) => {
  try {
    const safeTradesAll = Array.isArray(req.body?.safeTrades) ? req.body.safeTrades : [];
    const uid = String(req.user.uid);

    latestSafeTradesByUser.set(uid, { ts: Date.now(), safeTrades: safeTradesAll });
    writeSafeTradesFile(safeTradesAll);

    if (!safeTradesAll.length) {
      lastSafeAlertByUser.set(uid, { sig: "", ts: 0 });
      return res.json({ ok: true, sent: false, reason: "empty" });
    }

    const actionable = actionableBuysOnly(safeTradesAll);
    if (!actionable.length) {
      return res.json({ ok: true, sent: false, reason: "no_buy_signals" });
    }

    if (!telegramConfigured()) {
      return res.json({ ok: false, sent: false, error: "Missing TELEGRAM env values" });
    }

    const sig = safeTradesSignature(actionable);
    const prev = lastSafeAlertByUser.get(uid) || { sig: "", ts: 0 };
    const now = Date.now();

    const same = prev.sig === sig;
    const inCooldown = (now - prev.ts) < ALERT_COOLDOWN_MS;

    if (same || inCooldown) {
      return res.json({ ok: true, sent: false, reason: same ? "already_sent_for_this_set" : "cooldown" });
    }

    lastSafeAlertByUser.set(uid, { sig, ts: now });

    const msg = buildTelegramMessage(actionable);
    const tg = await sendTelegram(msg);

    return res.json({ ok: true, sent: true, telegram: tg });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* Force close */
app.post("/api/order/close", authRequired, async (req, res) => {
  try {
    const tradeId = Number(req.body?.tradeId);
    if (!tradeId) {
      return res.status(400).json({ error: "Missing tradeId" });
    }

    const trade = await dbGet(
      `select * from public.trades where id = $1 and user_id = $2`,
      [tradeId, req.user.uid]
    );

    if (!trade) {
      return res.status(404).json({ error: "Trade not found" });
    }

    if (String(trade.side).toLowerCase() !== "buy") {
      return res.status(400).json({ error: "Only BUY trades can be force closed" });
    }

    const client = await getUserKrakenClient(req.user.uid);
    if (!client) {
      return res.status(400).json({ error: "No Kraken keys saved" });
    }

    const volume = Number(trade.volume);
    if (!Number.isFinite(volume) || volume <= 0) {
      return res.status(400).json({ error: "Invalid trade volume" });
    }

    const sellParams = {
      pair: trade.pair,
      type: "sell",
      ordertype: "market",
      volume: volume.toString()
    };

    const result = await krakenApiWithNonceRetry(
      client,
      req.user.uid,
      "AddOrder",
      sellParams
    );

    const txid = Array.isArray(result?.result?.txid)
      ? result.result.txid[0]
      : "";

    await dbRun(
      `update public.trades
       set status = 'closed', message = 'Force sold at market'
       where id = $1`,
      [tradeId]
    );

    res.json({ ok: true, closed: true, txid });
  } catch (e) {
    res.status(500).json({ error: "Force close failed", details: String(e.message || e) });
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
      await logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Missing pair or side", userId: req.user.uid });
      return res.status(400).json({ error: "Missing required trade parameters" });
    }

    const meta = await getPairMeta(client, pair);
    const nums = formatOrderNumbers(meta, raw);

    if (!nums.price) {
      await logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid price", userId: req.user.uid });
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

    const volumeNum = Number(volumeStr);

    if (!volumeStr || Number(volumeStr) <= 0) {
      await logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid volume", userId: req.user.uid });
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

      await logTrade({
        pair, side, orderType, investUsd, volume: volumeNum,
        entryPrice: nums.price,
        takeProfit: nums.takeProfit ?? clampPrice(meta, nums.price * 1.05),
        stopLoss: nums.stopLoss ?? clampPrice(meta, nums.price * 0.95),
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

    const movePct = targetMovePct();
    const takeProfit = nums.takeProfit ?? clampPrice(meta, entryPrice * (1 + movePct));
    let stopLoss = nums.stopLoss ?? clampPrice(meta, entryPrice * (1 - movePct));
    if (String(side).toLowerCase() === "buy") {
      stopLoss = capStopLossForBuy(meta, entryPrice, stopLoss);
    }

    const estProfitUsd = (takeProfit !== null) ? (takeProfit - entryPrice) * volumeNum : null;
    const estLossUsd = (stopLoss !== null) ? (entryPrice - stopLoss) * volumeNum : null;

    const entryParams = {
      pair,
      type: side,
      ordertype: orderType,
      volume: volumeNum
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

      const logged = await logTrade({
        pair, side, orderType, investUsd,
        volume: volumeNum,
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
        normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeNum },
        simulator: true,
        tradeId: logged?.id ?? null
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
      ? "Entry placed and filled. Exit orders will be placed now."
      : "Entry placed. Exit orders will be placed after fill.";

    const logged = await logTrade({
      pair, side, orderType, investUsd,
      volume: volumeNum,
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

    // Critical fix. If it filled immediately, place exits immediately.
    let exitPlaced = false;
    let exitTxids = null;

    if (isFilledNow && logged?.id) {
      try {
        const execVol = Number(entryStatus?.vol_exec || 0);
        const volForExit = (Number.isFinite(execVol) && execVol > 0) ? String(execVol) : String(volumeNum);

        // Optionally keep DB volume aligned with actual fill
        if (Number.isFinite(execVol) && execVol > 0 && Number(execVol) !== Number(volumeNum)) {
          await updateTrade(logged.id, { volume: execVol });
        }

        exitTxids = await placeExitOrders({
          uid: String(req.user.uid),
          tradeId: logged.id,
          pair,
          volumeStr: volForExit,
          takeProfit,
          stopLoss
        });

        exitPlaced = true;

        await updateTrade(logged.id, {
          message: "Entry filled. Exit orders placed.",
          exit_status: "open",
          exit_tp_txid: exitTxids?.tpTxid || null,
          exit_sl_txid: exitTxids?.slTxid || null
        });
      } catch (e) {
        await updateTrade(logged.id, {
          message: "Entry filled but exit placement failed: " + String(e?.message || e),
          exit_status: "none"
        });
      }
    }

    res.json({
      message: msgTxt,
      entry: mainOrder.result,
      entryTxid: txid,
      entryStatus: entryStatus ? { status: entryStatus.status, vol: entryStatus.vol, vol_exec: entryStatus.vol_exec } : null,
      normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeNum },
      tradeId: logged?.id ?? null,
      exits: exitPlaced ? exitTxids : null
    });

  } catch (err) {
    const details = err.response?.error || err.message || "Trade execution failed";

    await logTrade({
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

const EXIT_WATCH_INTERVAL_MS = Number(process.env.EXIT_WATCH_INTERVAL_MS || 15000);

async function cancelOrder(client, uid, txid) {
  if (!txid) return;
  try {
    await krakenApiWithNonceRetry(client, uid, "CancelOrder", { txid });
  } catch {
  }
}

async function watchExitsOnce() {
  const rows = await dbAll(
    `select id, user_id, pair, volume, entry_price, side, take_profit, stop_loss, txid, exit_tp_txid, exit_sl_txid, exit_status, status
     from public.trades
     where status in ('filled','submitted') and exit_status in ('open','none')`
  );

  for (const t of rows) {
    const uid = String(t.user_id);

    const client = await getUserKrakenClient(uid);
    if (!client) continue;

    const entryTxid = String(t.txid || "");
    const tpTxid = String(t.exit_tp_txid || "");
    const slTxid = String(t.exit_sl_txid || "");

    let execVol = null;

    if (t.status !== "filled") {
      if (entryTxid) {
        try {
          const entry = await queryOrder(client, uid, entryTxid);
          const filled =
            entry &&
            String(entry.status || "").toLowerCase() === "closed" &&
            Number(entry.vol_exec || 0) > 0;

          if (!filled) continue;

          execVol = Number(entry.vol_exec || 0);
          await updateTrade(t.id, { status: "filled" });

          if (Number.isFinite(execVol) && execVol > 0) {
            await updateTrade(t.id, { volume: execVol });
          }
        } catch {
          continue;
        }
      } else {
        continue;
      }
    }

    if (t.exit_status === "none") {
      if (!t.take_profit || !t.stop_loss) continue;

      const volForExit =
        Number.isFinite(execVol) && execVol > 0
          ? String(execVol)
          : String(t.volume);

      if (!volForExit || Number(volForExit) <= 0) continue;

      try {
        let stopLoss = Number(t.stop_loss);
        if (String(t.side || "").toLowerCase() === "buy") {
          const entryPrice = Number(t.entry_price);
          const cappedStopLoss = capStopLossForBuy(await getPairMeta(client, t.pair), entryPrice, stopLoss);
          if (Number.isFinite(cappedStopLoss) && cappedStopLoss !== stopLoss) {
            stopLoss = cappedStopLoss;
            await updateTrade(t.id, { stop_loss: stopLoss });
          }
        }

        await placeExitOrders({
          uid,
          tradeId: t.id,
          pair: t.pair,
          volumeStr: volForExit,
          takeProfit: Number(t.take_profit),
          stopLoss
        });
      } catch {
        continue;
      }
      continue;
    }

    if (t.exit_status !== "open") continue;

    let tpOrder = null;
    let slOrder = null;

    try { if (tpTxid) tpOrder = await queryOrder(client, uid, tpTxid); } catch { }
    try { if (slTxid) slOrder = await queryOrder(client, uid, slTxid); } catch { }

    const tpClosed = tpOrder && String(tpOrder.status || "").toLowerCase() === "closed" && Number(tpOrder.vol_exec || 0) > 0;
    const slClosed = slOrder && String(slOrder.status || "").toLowerCase() === "closed" && Number(slOrder.vol_exec || 0) > 0;

    if (tpClosed) {
      await cancelOrder(client, uid, slTxid);
      await updateTrade(t.id, { exit_status: "tp_filled", status: "closed", message: "Take profit filled. Stop loss canceled." });
      continue;
    }

    if (slClosed) {
      await cancelOrder(client, uid, tpTxid);
      await updateTrade(t.id, { exit_status: "sl_filled", status: "closed", message: "Stop loss filled. Take profit canceled." });
      continue;
    }
  }
}

setInterval(() => {
  watchExitsOnce().catch(() => { });
}, EXIT_WATCH_INTERVAL_MS);

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
