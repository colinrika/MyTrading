import dotenv from "dotenv";

dotenv.config();

const TELEGRAM_ENABLED = String(process.env.TELEGRAM_ENABLED || "").toLowerCase() === "true";
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || "");
const TELEGRAM_CHAT_ID = String(process.env.TELEGRAM_CHAT_ID || "");

const APP_BASE_URL = String(process.env.APP_BASE_URL || "").replace(/\/+$/, "");

const MAX_SCAN_PAIRS = Number(process.env.ALERT_MAX_SCAN_PAIRS || 30);
const QUALITY_MIN = Number(process.env.ALERT_QUALITY_MIN || 80);
const TOP_TO_SEND = Number(process.env.ALERT_TOP_TO_SEND || 3);

function telegramConfigured() {
  return TELEGRAM_ENABLED && !!TELEGRAM_BOT_TOKEN && !!TELEGRAM_CHAT_ID;
}

function requireAppBaseUrl() {
  if (!APP_BASE_URL) throw new Error("Missing APP_BASE_URL env value");
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

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
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
  return String(pair || "").replace("X", "").replace("ZUSD", "/USD");
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

  if (upBias && reclaimLong) {
    const entry = currentPrice;
    const swingLow = approxPullbackSwingLow(m5Closes, 12);
    const stop = swingLow ? (swingLow * 0.999) : (entry * 0.992);
    const r = entry - stop;
    const tp = entry + (r * 2.0);

    return {
      quality: 85,
      tag: "Trend pullback reclaim",
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
    const swingHigh = approxPullbackSwingHigh(m5Closes, 12);
    const stop = swingHigh ? (swingHigh * 1.001) : (entry * 1.008);
    const r = stop - entry;
    const tp = entry - (r * 2.0);

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
  const p = encodeURIComponent(String(pair || ""));
  return `${APP_BASE_URL}/strategy.html?pair=${p}`;
}

function buildTelegramMessage(trades) {
  const now = new Date().toISOString();
  let msg = `Namu alert ${now}\n\n`;

  for (const t of trades) {
    const rec = t.recommended || {};
    const side = String(rec.side || "").toUpperCase();
    const link = buildTradeLink(t.pair);

    msg += `${prettyPair(t.pair)}\n`;
    msg += `Signal ${side}  Quality ${Number(rec.quality || 0)}\n`;
    msg += `Entry ${round6(rec.price ?? t.last ?? 0)}\n`;
    msg += `TP ${round6(rec.takeProfit ?? 0)}\n`;
    msg += `SL ${round6(rec.stopLoss ?? 0)}\n`;
    if (rec.actionTitle) msg += `${rec.actionTitle}\n`;
    if (rec.tag) msg += `Tag ${rec.tag}\n`;
    msg += `Open strategy ${link}\n`;
    msg += `\n`;
  }

  msg += "Generated by your trend pullback reclaim rules.\n";
  return msg;
}

async function runOnce() {
  if (!telegramConfigured()) throw new Error("Missing TELEGRAM env values");
  requireAppBaseUrl();

  const allPairs = await getAllUsdPairs();
  const topPairs = await getTopPairsByVolumeUsd(allPairs, MAX_SCAN_PAIRS);

  const results = [];

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

      if (rowObj.recommended && Number(rowObj.recommended.quality || 0) >= QUALITY_MIN) {
        results.push(rowObj);
      }
    } catch {
      // ignore noisy pairs
    }
  }

  results.sort((a, b) => Number(b.recommended.quality || 0) - Number(a.recommended.quality || 0));
  const toSend = results.slice(0, TOP_TO_SEND);

  if (!toSend.length) {
    console.log("No actionable safe trades right now");
    return;
  }

  const msg = buildTelegramMessage(toSend);
  await sendTelegram(msg);
  console.log("Sent Telegram alert for", toSend.map(x => x.pair).join(", "));
}

(async () => {
  await runOnce();
})().catch(err => {
  console.error("cron_alerts failed:", err?.message || err);
  process.exit(1);
});
