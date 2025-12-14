import express from "express";
import cors from "cors";
import KrakenClient from "kraken-api";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const kraken = new KrakenClient(process.env.KRAKEN_API_KEY, process.env.KRAKEN_API_SECRET);

// Simulator mode, set SIMULATOR_MODE=true in .env
const SIMULATOR_MODE = String(process.env.SIMULATOR_MODE || "false").toLowerCase() === "true";

const pairMetaCache = new Map();
let lastPairMetaRefreshMs = 0;
const PAIR_META_TTL_MS = 10 * 60 * 1000;

const tradeLog = [];
let tradeIdSeq = 1;

function nowIso() {
  return new Date().toISOString();
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
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

async function ensurePairMetaLoaded() {
  const now = Date.now();
  if (pairMetaCache.size && (now - lastPairMetaRefreshMs) < PAIR_META_TTL_MS) return;

  const resp = await kraken.api("AssetPairs");
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

async function getPairMeta(pair) {
  await ensurePairMetaLoaded();

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

async function queryOrder(txid) {
  const resp = await kraken.api("QueryOrders", { txid });
  const result = resp?.result || {};
  const order = result[txid];
  return order || null;
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
    isAuto: entry.isAuto === true
  };

  tradeLog.unshift(item);
  if (tradeLog.length > 2000) tradeLog.length = 2000;
  return item;
}

app.get("/mode", (req, res) => {
  res.json({ simulator: SIMULATOR_MODE });
});

app.get("/pair-info", async (req, res) => {
  try {
    const pair = String(req.query.pair || "");
    if (!pair) return res.status(400).json({ error: "pair is required" });

    const meta = await getPairMeta(pair);
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

app.get("/balance", async (req, res) => {
  try {
    const balance = await kraken.api("Balance");
    res.json({ status: "Connected", balance: balance.result });
  } catch (err) {
    console.error("Balance check failed:", err);
    res.status(500).json({ error: "Failed to connect to Kraken", details: err.message });
  }
});

app.get("/trades", async (req, res) => {
  const page = Math.max(1, Number(req.query.page || 1));
  const pageSize = Math.max(1, Math.min(100, Number(req.query.pageSize || 10)));
  const q = String(req.query.q || "").trim().toLowerCase();

  let filtered = tradeLog.slice();
  if (q) {
    filtered = filtered.filter(t => {
      const hay = (t.pair + " " + t.side + " " + t.orderType + " " + t.status + " " + t.message).toLowerCase();
      return hay.includes(q);
    });
  }

  const total = filtered.length;
  const start = (page - 1) * pageSize;
  const items = filtered.slice(start, start + pageSize);

  res.json({ page, pageSize, total, items });
});

app.post("/trade", async (req, res) => {
  const raw = req.body || {};
  const pair = raw.pair;
  const side = raw.side;
  const orderType = raw.orderType || "limit";
  const investUsd = numOrNull(raw.investUsd);

  try {
    if (!pair || !side) {
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Missing pair or side" });
      return res.status(400).json({ error: "Missing required trade parameters" });
    }

    const meta = await getPairMeta(pair);
    const nums = formatOrderNumbers(meta, raw);

    if (!nums.price) {
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid price" });
      return res.status(400).json({ error: "Invalid price" });
    }

    let volumeStr = null;

    // Prefer investUsd for volume calculation
    if (investUsd && investUsd > 0) {
      const vol = investUsd / nums.price;
      const ld = meta.lot_decimals ?? 8;
      const vRounded = roundToDecimals(vol, ld);
      volumeStr = vRounded === null ? null : trimNumberString(vRounded.toFixed(ld));
    } else {
      volumeStr = nums.volumeStr;
    }

    if (!volumeStr || Number(volumeStr) <= 0) {
      logTrade({ pair, side, orderType, investUsd, volume: "", status: "error", message: "Invalid volume" });
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

    // Simulator short circuit
    if (SIMULATOR_MODE) {
      const fakeTxid = "SIM_" + Date.now() + "_" + Math.floor(Math.random() * 100000);
      const statusTxt = "simulated";
      const msgTxt = "Simulator mode. No Kraken order was placed.";

      logTrade({
        pair, side, orderType, investUsd,
        volume: volumeStr,
        entryPrice,
        takeProfit,
        stopLoss,
        estProfitUsd,
        estLossUsd,
        status: statusTxt,
        message: msgTxt,
        txid: fakeTxid,
        isAuto: raw.isAuto === true
      });

      return res.json({
        message: msgTxt,
        entry: { descr: entryParams },
        entryTxid: fakeTxid,
        entryStatus: { status: "simulated", vol: volumeStr, vol_exec: "0.0" },
        normalized: { entryPrice, entryPrice2, takeProfit, stopLoss, volume: volumeStr },
        simulator: true
      });
    }

    const mainOrder = await kraken.api("AddOrder", entryParams);
    const txid = Array.isArray(mainOrder?.result?.txid) ? mainOrder.result.txid[0] : "";

    let entryStatus = null;
    if (txid) {
      try { entryStatus = await queryOrder(txid); } catch { entryStatus = null; }
    }

    const isFilledNow =
      entryStatus &&
      (String(entryStatus.status).toLowerCase() === "closed") &&
      Number(entryStatus.vol_exec || 0) > 0;

    const statusTxt = isFilledNow ? "filled" : "submitted";
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
      status: statusTxt,
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
    const details = err.response?.error || err.message || "Trade execution failed";

    logTrade({
      pair, side, orderType, investUsd,
      volume: safeStr(raw.volume),
      entryPrice: numOrNull(raw.price),
      takeProfit: numOrNull(raw.takeProfit),
      stopLoss: numOrNull(raw.stopLoss),
      status: "error",
      message: safeStr(details),
      isAuto: raw.isAuto === true
    });

    console.error("Trade error:", err);
    res.status(500).json({ error: "Trade execution failed", details });
  }
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/trades.html", (req, res) => {
  res.sendFile(path.join(__dirname, "trades.html"));
});

app.use((err, req, res, next) => {
  console.error("JSON parse error:", err.message);
  res.status(400).json({ error: "Invalid JSON request" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
