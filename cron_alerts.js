import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

const TELEGRAM_ENABLED = String(process.env.TELEGRAM_ENABLED || "").toLowerCase() === "true";
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || "");
const TELEGRAM_CHAT_ID = String(process.env.TELEGRAM_CHAT_ID || "");

const APP_BASE_URL = String(process.env.APP_BASE_URL || "").replace(/\/+$/, "");

const MAX_SCAN_PAIRS = Number(process.env.ALERT_MAX_SCAN_PAIRS || 30);
const QUALITY_MIN = Number(process.env.ALERT_BUY_QUALITY_MIN || 90);
const POTENTIAL_QUALITY_MIN = Number(process.env.ALERT_POTENTIAL_QUALITY_MIN || 70);
const TOP_TO_SEND = Number(process.env.ALERT_TOP_TO_SEND || 3);

const ALERT_SIG_FILE_RAW = String(process.env.ALERT_SIG_FILE || "./last_alert_sig.txt");
const ALERT_COOLDOWN_MS = Number(process.env.ALERT_COOLDOWN_MS || (10 * 60 * 1000));

const SAFE_TRADES_FILE_RAW = String(process.env.SAFE_TRADES_FILE || "./latest_safe_trades.json");
const SAFE_TRADES_KEEP_LAST_MS = Number(process.env.SAFE_TRADES_KEEP_LAST_MS || (20 * 60 * 1000));
const QUICK_PROFIT_PCT = 0.02;
const KRAKEN_FEE_PCT = Number(process.env.KRAKEN_FEE_PCT || 0.0026);

function targetMovePct() {
  const feePct = Number.isFinite(KRAKEN_FEE_PCT) ? KRAKEN_FEE_PCT : 0;
  return QUICK_PROFIT_PCT + Math.max(0, feePct);
}

function toAbs(p) {
  const s = String(p || "");
  return path.isAbsolute(s) ? s : path.resolve(process.cwd(), s);
}

const ALERT_SIG_FILE = toAbs(ALERT_SIG_FILE_RAW);
const SAFE_TRADES_FILE = toAbs(SAFE_TRADES_FILE_RAW);

function telegramConfigured() {
  return TELEGRAM_ENABLED && !!TELEGRAM_BOT_TOKEN && !!TELEGRAM_CHAT_ID;
}

async function sendTelegram(text) {
  if (!telegramConfigured()) {
    throw new Error("Missing TELEGRAM env values");
  }

  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text,
      disable_web_page_preview: true
    })
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || data.ok !== true) {
    throw new Error(data?.description || `Telegram failed ${resp.status}`);
  }

  return data;
}

const STABLE_BASES = new Set([
  "USDT", "USDC", "DAI", "USDG", "TUSD", "PYUSD"
]);

function baseFromPairKey(pairKey) {
  const s = String(pairKey || "").toUpperCase();

  if (s.endsWith("ZUSD")) return s.slice(0, -4);
  if (s.endsWith("USD")) return s.slice(0, -3);

  return s;
}

function baseFromWsname(wsname) {
  const s = String(wsname || "").toUpperCase();
  if (!s.includes("/")) return s;
  return s.split("/")[0];
}

function isStablePair(pairKey, wsname) {
  const a = baseFromPairKey(pairKey);
  const b = baseFromWsname(wsname);
  return STABLE_BASES.has(a) || STABLE_BASES.has(b);
}

function ema(values, period) {
  if (!Array.isArray(values) || values.length < period) return null;
  const k = 2 / (period + 1);

  let e = values.slice(0, period).reduce((a, b) => a + b, 0) / period;
  for (let i = period; i < values.length; i++) {
    e = values[i] * k + e * (1 - k);
  }
  return e;
}

function vwapFromCandles(candles) {
  if (!Array.isArray(candles) || !candles.length) return null;

  let pv = 0;
  let vol = 0;

  for (const c of candles) {
    const high = Number(c.high);
    const low = Number(c.low);
    const close = Number(c.close);
    const volume = Number(c.volume);

    if (!Number.isFinite(high) || !Number.isFinite(low) || !Number.isFinite(close) || !Number.isFinite(volume)) continue;

    const tp = (high + low + close) / 3;
    pv += tp * volume;
    vol += volume;
  }

  if (vol <= 0) return null;
  return pv / vol;
}

function approxPullbackSwingLow(closes, lookbackBars) {
  const n = Math.max(3, Number(lookbackBars || 10));
  if (!Array.isArray(closes) || closes.length < n) return null;
  let m = Infinity;
  for (let i = closes.length - n; i < closes.length; i++) m = Math.min(m, closes[i]);
  return Number.isFinite(m) ? m : null;
}

function approxPullbackSwingHigh(closes, lookbackBars) {
  const n = Math.max(3, Number(lookbackBars || 10));
  if (!Array.isArray(closes) || closes.length < n) return null;
  let m = -Infinity;
  for (let i = closes.length - n; i < closes.length; i++) m = Math.max(m, closes[i]);
  return Number.isFinite(m) ? m : null;
}

function prettyPair(pair) {
  const s = String(pair || "");
  if (s.includes("/")) return s;
  if (s.endsWith("ZUSD")) return s.replace("ZUSD", "/USD").replace(/^X/, "");
  if (s.endsWith("USD")) return s.replace("USD", "/USD").replace(/^X/, "");
  return s.replace(/^X/, "");
}

function round6(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return "0";
  return x.toFixed(6);
}

function decideStrategyOrder(res, currentPrice) {
  const h1 = res.h1 || [];
  const h4 = res.h4 || [];
  const m5 = res.m5 || [];

  const h1Closes = h1.map(x => x.close);
  const h4Closes = h4.map(x => x.close);
  const m5Closes = m5.map(x => x.close);

  if (h1Closes.length < 220 || h4Closes.length < 220 || m5Closes.length < 60) {
    return { quality: 0, tag: "Not enough data", side: null };
  }

  const ema200H1 = ema(h1Closes, 200);
  const ema200H4 = ema(h4Closes, 200);
  if (!Number.isFinite(ema200H1) || !Number.isFinite(ema200H4)) {
    return { quality: 0, tag: "EMA not ready", side: null };
  }

  const lastH1 = h1Closes[h1Closes.length - 1];
  const lastH4 = h4Closes[h4Closes.length - 1];

  const upBias = lastH1 > ema200H1 && lastH4 > ema200H4;
  const downBias = lastH1 < ema200H1 && lastH4 < ema200H4;

  const m5Ema20 = ema(m5Closes, 20);
  const m5Vwap = vwapFromCandles(m5);

  if (!Number.isFinite(m5Ema20) || !Number.isFinite(m5Vwap)) {
    return { quality: 0, tag: "M5 indicators missing", side: null };
  }

  const lastM5 = m5Closes[m5Closes.length - 1];
  const prevM5 = m5Closes[m5Closes.length - 2];

  const aboveEma = lastM5 > m5Ema20;
  const aboveVwap = lastM5 > m5Vwap;
  const reclaimLong = (prevM5 <= m5Ema20 || prevM5 <= m5Vwap) && (aboveEma && aboveVwap);

  const belowEma = lastM5 < m5Ema20;
  const belowVwap = lastM5 < m5Vwap;
  const reclaimShort = (prevM5 >= m5Ema20 || prevM5 >= m5Vwap) && (belowEma && belowVwap);

  if (!upBias && !downBias) return { quality: 0, tag: "Chop zone", side: null };

  const lastVol = Number(m5[m5.length - 1].volume || 0);
  const volWindow = m5.slice(-20).map(x => Number(x.volume || 0));
  const avgVol = volWindow.length ? volWindow.reduce((a, b) => a + b, 0) / volWindow.length : 0;
  const volSpike = avgVol > 0 && lastVol > avgVol * 1.2;

  if (upBias && reclaimLong && volSpike) {
    const entry = currentPrice;
    const movePct = targetMovePct();
    const stop = entry * (1 - movePct);
    const tp = entry * (1 + movePct);

    return {
      quality: 92,
      tag: "Trend pullback reclaim + volume",
      actionTitle: "Buy after pullback confirms",
      side: "buy",
      orderType: "limit",
      price: entry,
      stopLoss: stop,
      takeProfit: tp
    };
  }

  if (downBias && reclaimShort) {
    const entry = currentPrice;
    const movePct = targetMovePct();
    const stop = entry * (1 + movePct);
    const tp = entry * (1 - movePct);

    return {
      quality: 82,
      tag: "Trend pullback reclaim",
      actionTitle: "Sell after pullback confirms",
      side: "sell",
      orderType: "limit",
      price: entry,
      stopLoss: stop,
      takeProfit: tp
    };
  }

  if (upBias) {
    return {
      quality: 72,
      tag: "Uptrend building",
      actionTitle: "Potential upclimb",
      side: null,
      potential: true,
      price: currentPrice
    };
  }

  return { quality: 0, tag: "No reclaim yet", side: null };
}

async function getAllUsdPairs() {
  const r = await fetch("https://api.kraken.com/0/public/AssetPairs");
  const j = await r.json();
  const result = j.result || {};
  const pairs = [];

  for (const key of Object.keys(result)) {
    const info = result[key];
    const wsname = info?.wsname || "";

    if (!wsname.endsWith("/USD")) continue;
    if (String(key).includes(".")) continue;

    if (isStablePair(key, wsname)) continue;

    pairs.push(key);
  }

  return pairs;
}

async function fetchTickerBatch(pairsChunk) {
  const url = "https://api.kraken.com/0/public/Ticker?pair=" + encodeURIComponent(pairsChunk.join(","));
  const r = await fetch(url);
  const j = await r.json();
  return j.result || {};
}

async function getTopPairsByVolumeUsd(allPairs, topN) {
  const batchSize = 20;
  const scores = [];

  for (let i = 0; i < allPairs.length; i += batchSize) {
    const chunk = allPairs.slice(i, i + batchSize);
    let tick = {};
    try { tick = await fetchTickerBatch(chunk); } catch { tick = {}; }

    for (const pairKey of chunk) {
      const t = tick[pairKey];
      if (!t) continue;

      const last = Number(t.c && t.c[0]) || 0;
      const vol24 = Number(t.v && t.v[1]) || 0;
      const volUsd = last * vol24;

      if (volUsd > 0) scores.push({ pair: pairKey, volUsd });
    }
  }

  scores.sort((a, b) => b.volUsd - a.volUsd);
  return scores.slice(0, topN).map(x => x.pair);
}

async function fetchOHLC(pair, intervalMin, candles) {
  const url = `https://api.kraken.com/0/public/OHLC?pair=${encodeURIComponent(pair)}&interval=${intervalMin}`;
  const r = await fetch(url);
  const j = await r.json();

  const err = Array.isArray(j.error) ? j.error.join(",") : "";
  if (err) throw new Error(err);

  const k = Object.keys(j.result || {}).find(x => x !== "last");
  const arr = (k && Array.isArray(j.result[k])) ? j.result[k] : [];

  return arr.slice(-(candles || 60)).map(x => ({
    time: Number(x[0]),
    open: Number(x[1]),
    high: Number(x[2]),
    low: Number(x[3]),
    close: Number(x[4]),
    volume: Number(x[6])
  }));
}

function buildTradeLink(pair) {
  if (!APP_BASE_URL) return "";
  const p = encodeURIComponent(String(pair || ""));
  return `${APP_BASE_URL}/strategy.html?pair=${p}`;
}

function buildTelegramMessage(trades) {
  const now = new Date().toISOString();
  let msg = `Trade available ${now}\n\n`;

  for (const t of trades) {
    const rec = t.recommended || {};
    const link = buildTradeLink(t.pair);

    msg += `${prettyPair(t.pair)}\n`;
    msg += `BUY  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${round6(rec.price ?? t.last ?? 0)}\n`;
    if (rec.takeProfit != null) msg += `TP ${round6(rec.takeProfit)}\n`;
    if (rec.stopLoss != null) msg += `SL ${round6(rec.stopLoss)}\n`;
    if (link) msg += `Open ${link}\n`;
    msg += `\n`;
  }

  return msg;
}

function usd(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return "$0.00";
  return "$" + x.toFixed(2);
}

function buildPotentialMessage(trades) {
  const now = new Date().toISOString();
  let msg = `Potential upclimb watch ${now}\n\n`;

  for (const t of trades) {
    const rec = t.recommended || {};
    msg += `${prettyPair(t.pair)}\n`;
    msg += `Watch  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${round6(rec.price ?? t.last ?? 0)}\n`;
    msg += `\n`;
  }

  return msg;
}

function buildBuyNowMessage(trades, pairMetaMap) {
  const now = new Date().toISOString();
  let msg = `BUY NOW alert ${now}\n\n`;

  for (const t of trades) {
    const rec = t.recommended || {};
    const link = buildTradeLink(t.pair);
    const entry = Number(rec.price ?? t.last ?? 0);
    const tp = Number(rec.takeProfit);
    const meta = pairMetaMap[t.pair] || {};
    const ordermin = Number(meta.ordermin);
    const costmin = Number(meta.costmin);
    const minUsd = Number.isFinite(costmin)
      ? costmin
      : (Number.isFinite(ordermin) && Number.isFinite(entry) && entry > 0 ? ordermin * entry : null);

    let profitUsd = null;
    if (Number.isFinite(minUsd) && Number.isFinite(entry) && entry > 0 && Number.isFinite(tp)) {
      const qty = minUsd / entry;
      profitUsd = (tp - entry) * qty;
    }

    msg += `${prettyPair(t.pair)}\n`;
    msg += `BUY  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${round6(entry)}\n`;
    if (rec.takeProfit != null) msg += `TP ${round6(rec.takeProfit)}\n`;
    if (rec.stopLoss != null) msg += `SL ${round6(rec.stopLoss)}\n`;
    if (Number.isFinite(minUsd)) msg += `Min amount ${usd(minUsd)}\n`;
    if (Number.isFinite(profitUsd)) msg += `Est profit ${usd(profitUsd)}\n`;
    if (link) msg += `Open ${link}\n`;
    msg += `\n`;
  }

  return msg;
}

function makeAlertSignature(trades) {
  return trades.map(t => {
    const r = t.recommended || {};
    return [
      String(t.pair || ""),
      String(r.side || ""),
      String(r.tag || ""),
      round6(r.price ?? t.last ?? 0),
      r.takeProfit == null ? "" : round6(r.takeProfit),
      r.stopLoss == null ? "" : round6(r.stopLoss),
      String(r.quality || 0)
    ].join("|");
  }).join(";");
}

function readPrevAlertState() {
  try {
    const raw = fs.readFileSync(ALERT_SIG_FILE, "utf8");
    if (raw.trim().startsWith("{")) {
      const parsed = JSON.parse(raw);
      const buy = parsed?.buy || {};
      const potential = parsed?.potential || {};
      return {
        buy: { ts: Number(buy.ts || 0), sig: String(buy.sig || "") },
        potential: { ts: Number(potential.ts || 0), sig: String(potential.sig || "") }
      };
    }

    const parts = raw.split("\n");
    const ts = Number(parts[0] || 0);
    const sig = String(parts.slice(1).join("\n") || "").trim();
    return {
      buy: { ts: Number.isFinite(ts) ? ts : 0, sig },
      potential: { ts: 0, sig: "" }
    };
  } catch {
    return { buy: { ts: 0, sig: "" }, potential: { ts: 0, sig: "" } };
  }
}

function writePrevAlertState(state) {
  try {
    const payload = {
      buy: state.buy || { ts: 0, sig: "" },
      potential: state.potential || { ts: 0, sig: "" }
    };
    fs.writeFileSync(ALERT_SIG_FILE, JSON.stringify(payload, null, 2), "utf8");
  } catch {
  }
}

function readSafeTradesFile() {
  try {
    const raw = fs.readFileSync(SAFE_TRADES_FILE, "utf8");
    const j = JSON.parse(raw);
    if (!j || typeof j !== "object") return null;
    return j;
  } catch {
    return null;
  }
}

function writeSafeTrades(trades) {
  try {
    const payload = { ts: Date.now(), safeTrades: Array.isArray(trades) ? trades : [] };
    fs.writeFileSync(SAFE_TRADES_FILE, JSON.stringify(payload, null, 2), "utf8");
  } catch {
  }
}

function isActionableBuy(rec) {
  const side = String(rec?.side || "").toLowerCase();
  const q = Number(rec?.quality || 0);
  const price = Number(rec?.price);

  return side === "buy" && q >= QUALITY_MIN && Number.isFinite(price) && price > 0;
}

function isPotentialUpclimb(rec) {
  const q = Number(rec?.quality || 0);
  return rec?.potential === true && q >= POTENTIAL_QUALITY_MIN;
}

async function fetchPairMetaMap() {
  const r = await fetch("https://api.kraken.com/0/public/AssetPairs");
  const j = await r.json();
  const result = j.result || {};
  const map = {};

  for (const key of Object.keys(result)) {
    const info = result[key] || {};
    map[key] = {
      ordermin: Number(info.ordermin),
      costmin: Number(info.costmin)
    };
  }

  return map;
}

async function runOnce() {
  if (!telegramConfigured()) throw new Error("Missing TELEGRAM env values");

  console.log("SAFE_TRADES_FILE:", SAFE_TRADES_FILE);
  console.log("ALERT_SIG_FILE:", ALERT_SIG_FILE);

  const allPairs = await getAllUsdPairs();
  const topPairs = allPairs;

  const results = [];
  const pairMetaMap = await fetchPairMetaMap();

  for (const p of topPairs) {
    try {
      const [h1, h4, m5] = await Promise.all([
        fetchOHLC(p, 60, 260),
        fetchOHLC(p, 240, 260),
        fetchOHLC(p, 5, 120)
      ]);

      const last = m5.length ? m5[m5.length - 1].close : (h1.length ? h1[h1.length - 1].close : 0);
      const rowObj = { pair: p, h1, h4, m5, last };

      rowObj.recommended = decideStrategyOrder(rowObj, last);
      results.push(rowObj);
    } catch {
    }
  }

  results.sort((a, b) => Number(b.recommended.quality || 0) - Number(a.recommended.quality || 0));
  const top = results.slice(0, TOP_TO_SEND);
  const toSend = top.filter(x => isActionableBuy(x.recommended));
  const potential = top.filter(x => isPotentialUpclimb(x.recommended));
  const buyNowEligible = toSend.length >= 3;

  if (!toSend.length && !potential.length) {
    console.log("No actionable BUY or potential trades right now");

    const prev = readSafeTradesFile();
    const prevTs = Number(prev?.ts || 0);
    const ageMs = Date.now() - prevTs;

    if (!prev || !prevTs || !Number.isFinite(ageMs) || ageMs > SAFE_TRADES_KEEP_LAST_MS) {
      writeSafeTrades([]);
      console.log("Wrote empty safe trades payload");
    } else {
      console.log("Keeping previous safe trades payload for dashboard, age_ms:", ageMs);
    }

    return;
  }

  const sigs = {
    buy: makeAlertSignature(buyNowEligible ? toSend : []),
    potential: makeAlertSignature(potential)
  };
  const prevAlert = readPrevAlertState();
  const now = Date.now();

  writeSafeTrades(toSend);

  const buyFresh = sigs.buy && (sigs.buy !== prevAlert.buy.sig || (now - prevAlert.buy.ts) >= ALERT_COOLDOWN_MS);
  const potentialFresh = sigs.potential && (sigs.potential !== prevAlert.potential.sig || (now - prevAlert.potential.ts) >= ALERT_COOLDOWN_MS);

  if (buyNowEligible && buyFresh) {
    const msg = buildBuyNowMessage(toSend, pairMetaMap);
    await sendTelegram(msg);
    prevAlert.buy = { sig: sigs.buy, ts: now };
    console.log("Sent BUY NOW alert for", toSend.map(x => x.pair).join(", "));
  } else if (!buyNowEligible && toSend.length) {
    console.log("Skipping BUY NOW alert: need at least 3 actionable coins");
  }

  if (potential.length && potentialFresh) {
    const msg = buildPotentialMessage(potential);
    await sendTelegram(msg);
    prevAlert.potential = { sig: sigs.potential, ts: now };
    console.log("Sent potential alert for", potential.map(x => x.pair).join(", "));
  }

  writePrevAlertState(prevAlert);
}

(async () => {
  await runOnce();
})().catch(err => {
  console.error("cron_alerts failed:", err?.message || err);
  process.exit(1);
});
