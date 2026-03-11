import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3001;
const VER = 'v4.5-2026-03-09';
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/* ═══════════ DATABASE ═══════════ */
let pool = null;
try {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'expeditee',
    waitForConnections: true, connectionLimit: 10, queueLimit: 0,
    connectTimeout: 10000,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  });
  console.log('✅ MySQL pool created');
} catch (e) { console.warn('⚠️ MySQL pool failed:', e.message); }

async function q(sql, params = [], timeoutMs = 30000) {
  if (!pool) throw new Error('Database not connected');
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error(`Query timeout ${timeoutMs/1000}s`)), timeoutMs));
  return Promise.race([pool.execute(sql, params).then(([rows]) => rows), timeout]);
}

/* ═══════════ SALES TABLE ═══════════ */
function salesFrom(alias = 'sc') { return `seller_board_sales ${alias}`; }

/* ═══════════ HELPERS ═══════════ */
async function getShopMap() {
  const rows = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL');
  const m = {}; rows.forEach(r => { m[r.id] = r.shop; }); return m;
}
async function getShopReverseMap() {
  const rows = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL');
  const m = {}; rows.forEach(r => { m[r.shop] = r.id; }); return m;
}
async function storeToAccId(storeName) {
  if (!storeName || storeName === 'All') return null;
  const rm = await getShopReverseMap();
  return rm[storeName] || null;
}
function defDates(start, end) {
  return {
    s: start || new Date(Date.now()-30*86400000).toISOString().slice(0,10),
    e: end || new Date().toISOString().slice(0,10),
  };
}

/* ═══════════ SAFE SQL FRAGMENTS ═══════════ */
const SC_SALES = 'COALESCE(sc.salesOrganic,0)+COALESCE(sc.salesPPC,0)';
const SC_UNITS = 'COALESCE(sc.unitsOrganic,0)+COALESCE(sc.unitsPPC,0)';
const SC_ADS   = 'COALESCE(sc.sponsoredProducts,0)+COALESCE(sc.sponsoredDisplay,0)+COALESCE(sc.sponsoredBrands,0)+COALESCE(sc.sponsoredBrandsVideo,0)';
const P_SALES  = 'COALESCE(p.salesOrganic,0)+COALESCE(p.salesPPC,0)';
const P_UNITS  = 'COALESCE(p.unitsOrganic,0)+COALESCE(p.unitsPPC,0)';
const P_ADS    = 'COALESCE(p.sponsoredProducts,0)+COALESCE(p.sponsoredDisplay,0)+COALESCE(p.sponsoredBrands,0)+COALESCE(p.sponsoredBrandsVideo,0)+COALESCE(p.googleAds,0)+COALESCE(p.facebookAds,0)';

function pWhere(sd, ed, accId, seller, af) {
  let w = 'WHERE p.date BETWEEN ? AND ?'; const p = [sd, ed];
  if (accId) { w += ' AND p.accountId = ?'; p.push(accId); }
  if (seller && seller !== 'All') { w += ' AND a.seller = ?'; p.push(seller); }
  if (af && af !== 'All') { w += ' AND p.asin = ?'; p.push(af); }
  return { w, p };
}
function scWhere(sd, ed, accId) {
  let w = 'WHERE sc.date BETWEEN ? AND ?'; const p = [sd, ed];
  if (accId) { w += ' AND sc.accountId = ?'; p.push(accId); }
  return { w, p };
}
function useProduct(seller, af) {
  return (seller && seller !== 'All') || (af && af !== 'All');
}

/* ═══════════ HEALTH ═══════════ */
app.get('/api/health', async (req, res) => {
  try {
    if (pool) { await q('SELECT 1'); res.json({ status: 'ok', database: 'connected', version: VER }); }
    else res.json({ status: 'ok', database: 'not configured', version: VER });
  } catch (e) { res.json({ status: 'ok', database: 'error: ' + e.message, version: VER }); }
});

/* ═══════════ DEBUG ═══════════ */
app.get('/api/debug/filters', async (req, res) => {
  const R = { version: VER, steps: {} };
  try {
    R.steps.accounts = (await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL LIMIT 3'));
    const tables = (await q("SHOW TABLES")).map(r => Object.values(r)[0]);
    R.steps.tables = tables;
    try {
      const dr = await q(`SELECT MIN(sc.date) as mi, MAX(sc.date) as mx FROM ${salesFrom()}`);
      R.steps.salesRange = { min: dr[0]?.mi, max: dr[0]?.mx };
    } catch(e) { R.steps.salesRange = e.message; }
    R.steps.planMetrics = (await q('SELECT DISTINCT metrics FROM asin_plan LIMIT 20').catch(()=>[])).map(m=>`${m.metrics}→${mapMetric(m.metrics)}`);
    try { R.steps.analyticsCols = (await q('SHOW COLUMNS FROM analytics_search_catalog_performance')).map(c=>c.Field); } catch(e) { R.steps.analyticsCols = e.message; }
  } catch (e) { R.globalError = e.message; }
  res.json(R);
});

/* ═══════════ DATE RANGE ═══════════ */
app.get('/api/date-range', async (req, res) => {
  try {
    const rows = await q(`SELECT MIN(sc.date) as minDate, MAX(sc.date) as maxDate FROM ${salesFrom()}`);
    const r = rows[0] || {};
    const maxDate = r.maxDate ? new Date(r.maxDate).toISOString().slice(0,10) : null;
    const minDate = r.minDate ? new Date(r.minDate).toISOString().slice(0,10) : null;
    const today = new Date().toISOString().slice(0,10);
    let defaultStart = new Date(Date.now()-29*86400000).toISOString().slice(0,10);
    if (minDate && defaultStart < minDate) defaultStart = minDate;
    // End date = today always
    res.json({ minDate, maxDate, defaultStart, defaultEnd: today });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ FILTERS ═══════════ */
app.get('/api/filters', async (req, res) => {
  try {
    const shops = await q('SELECT id, shop as name FROM accounts WHERE deleted_at IS NULL ORDER BY shop');
    const sellers = await q('SELECT DISTINCT seller FROM asin WHERE seller IS NOT NULL AND LENGTH(seller) > 0 ORDER BY seller');
    const asinShops = await q("SELECT DISTINCT p.asin, p.accountId FROM seller_board_product p WHERE p.date >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)");
    const sm = {}; shops.forEach(s => { sm[s.id] = s.name; });
    const asm = {};
    asinShops.forEach(r => { if (!asm[r.asin]) asm[r.asin] = []; const sn = sm[r.accountId]; if (sn && !asm[r.asin].includes(sn)) asm[r.asin].push(sn); });
    const asins = await q("SELECT DISTINCT a.asin, a.seller FROM asin a WHERE a.asin REGEXP '^(AU-)?B0[A-Za-z0-9]{8}$' ORDER BY a.asin");
    res.json({ shops: shops.map(s=>({id:s.id,name:s.name})), sellers: sellers.map(s=>s.seller), asins: asins.map(a=>({asin:a.asin,seller:a.seller,shops:asm[a.asin]||[]})) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC SUMMARY ═══════════ */
app.get('/api/exec/summary', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let rows, cogsVal = 0;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT SUM(${P_SALES}) as sales, SUM(${P_UNITS}) as units, 0 as orders,
        SUM(COALESCE(p.refunds,0)) as refunds, SUM(${P_ADS}) as advCost,
        0 as shippingCost, 0 as refundCost,
        SUM(COALESCE(p.amazonFees,0)) as amazonFees, SUM(COALESCE(p.costOfGoods,0)) as cogs,
        SUM(COALESCE(p.netProfit,0)) as netProfit, SUM(COALESCE(p.estimatedPayout,0)) as estPayout,
        SUM(COALESCE(p.sessions,0)) as sessions, SUM(COALESCE(p.grossProfit,0)) as grossProfit
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${f.w}`, f.p, 45000);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT SUM(${SC_SALES}) as sales, SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders,
        SUM(COALESCE(sc.refunds,0)) as refunds, SUM(${SC_ADS}) as advCost,
        SUM(COALESCE(sc.shipping,0)) as shippingCost, SUM(COALESCE(sc.refundCost,0)) as refundCost,
        SUM(COALESCE(sc.amazonFees,0)) as amazonFees,
        SUM(COALESCE(sc.netProfit,0)) as netProfit, SUM(COALESCE(sc.estimatedPayout,0)) as estPayout,
        SUM(COALESCE(sc.sessions,0)) as sessions, SUM(COALESCE(sc.grossProfit,0)) as grossProfit
        FROM ${salesFrom()} ${f.w}`, f.p, 45000);
      // COGS from seller_board_product (not in sales tables)
      try {
        let cw = 'WHERE p.date BETWEEN ? AND ?'; const cp = [s, e];
        if (accId) { cw += ' AND p.accountId = ?'; cp.push(accId); }
        const cr = await q(`SELECT SUM(COALESCE(p.costOfGoods,0)) as cogs FROM seller_board_product p ${cw}`, cp);
        cogsVal = parseFloat(cr[0]?.cogs) || 0;
      } catch(ce) {}
    }
    const r = rows[0] || {};
    const sales = parseFloat(r.sales)||0, np = parseFloat(r.netProfit)||0, cogs = parseFloat(r.cogs)||cogsVal;
    res.json({
      sales, units: parseInt(r.units)||0, orders: parseInt(r.orders)||0, refunds: parseInt(r.refunds)||0,
      advCost: parseFloat(r.advCost)||0, shippingCost: parseFloat(r.shippingCost)||0,
      refundCost: parseFloat(r.refundCost)||0, amazonFees: parseFloat(r.amazonFees)||0,
      cogs, netProfit: np, estPayout: parseFloat(r.estPayout)||0,
      grossProfit: parseFloat(r.grossProfit)||0, sessions: parseFloat(r.sessions)||0,
      realAcos: sales>0 ? (Math.abs(parseFloat(r.advCost)||0)/sales*100) : 0,
      pctRefunds: (parseInt(r.orders)||0)>0 ? ((parseInt(r.refunds)||0)/parseInt(r.orders)*100) : 0,
      margin: sales>0 ? (np/sales*100) : 0,
    });
  } catch (e) { console.error('exec/summary:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC DAILY ═══════════ */
app.get('/api/exec/daily', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let rows;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT p.date,
        SUM(${P_SALES}) as revenue,
        SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(${P_UNITS}) as units,
        SUM(ABS(COALESCE(p.sponsoredProducts,0))+ABS(COALESCE(p.sponsoredBrands,0))+ABS(COALESCE(p.sponsoredBrandsVideo,0))+ABS(COALESCE(p.sponsoredDisplay,0))) as advCost,
        SUM(COALESCE(p.sessions,0)) as sessions
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${f.w} GROUP BY p.date ORDER BY p.date`, f.p, 45000);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT sc.date,
        SUM(${SC_SALES}) as revenue,
        SUM(COALESCE(sc.netProfit,0)) as netProfit,
        SUM(${SC_UNITS}) as units,
        SUM(${SC_ADS}) as advCost,
        SUM(COALESCE(sc.sessions,0)) as sessions
        FROM ${salesFrom()} ${f.w} GROUP BY sc.date ORDER BY sc.date`, f.p, 45000);
    }
    console.log('exec/daily:', rows?.length||0, 'rows, first:', rows?.[0]);
    res.json((rows || []).map(r => ({
      date: r.date,
      revenue: parseFloat(r.revenue)||0,
      netProfit: parseFloat(r.netProfit)||0,
      units: parseInt(r.units)||0,
      advCost: parseFloat(r.advCost)||0,
      sessions: parseFloat(r.sessions)||0,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ PRODUCT ASINS ═══════════ */
app.get('/api/product/asins', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    const f = pWhere(s, e, accId, seller, af);
    const shopMap = await getShopMap();
    const rows = await q(`SELECT p.asin, p.accountId, a.seller,
      SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
      SUM(${P_UNITS}) as units, AVG(COALESCE(p.realACOS,0)) as acos,
      SUM(COALESCE(p.sessions,0)) as sessions, AVG(COALESCE(p.unitSessionPercentage,0)) as cr
      FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
      ${f.w} GROUP BY p.asin, p.accountId, a.seller ORDER BY revenue DESC LIMIT 500`, f.p, 45000);
    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue)||0, np = parseFloat(r.netProfit)||0;
      const acos=Math.round((parseFloat(r.acos)||0)*100)/100, cr=Math.round((parseFloat(r.cr)||0)*100)/100;
      return { asin: r.asin, shop: shopMap[r.accountId]||'', seller: r.seller||'', revenue: rev, netProfit: np, units: parseInt(r.units)||0,
        margin: rev>0?Math.round(np/rev*1000)/10:0, acos, roas: acos>0?Math.round(100/acos*100)/100:0, cr };
    }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ SHOPS ═══════════ */
app.get('/api/shops', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const shopMap = await getShopMap();
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let rows;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT p.accountId, SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(${P_UNITS}) as units, 0 as orders
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT sc.accountId, SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.netProfit,0)) as netProfit,
        SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders
        FROM ${salesFrom()} ${f.w} GROUP BY sc.accountId ORDER BY revenue DESC`, f.p, 45000);
    }
    let stockMap = {};
    try {
      // seller_board_stock is a snapshot table (no date column) — query all records
      (await q('SELECT accountId, SUM(FBAStock) as fba, SUM(COALESCE(stockValue,0)) as sv FROM seller_board_stock GROUP BY accountId'))
        .forEach(s => { stockMap[s.accountId] = { fba: parseInt(s.fba)||0, sv: parseFloat(s.sv)||0 }; });
    } catch (e) {
      try { (await q('SELECT f.accountId, SUM(CAST(f.available AS SIGNED)) as fba FROM fba_iventory_planning f JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest ON f.accountId = latest.aid AND f.date = latest.maxDate GROUP BY f.accountId')).forEach(s=>{stockMap[s.accountId]={ fba: parseInt(s.fba)||0, sv: 0 };}); } catch(e2){}
    }
    // Ads spend per shop from seller_board_product (always needed for shop-level ads)
    let adsMap = {}; // { accountId: { ads, gp } }
    try {
      const pF2 = pWhere(s, e, accId, null, null);
      const adsRows = await q(`SELECT p.accountId, SUM(ABS(${P_ADS})) as ads, SUM(COALESCE(p.grossProfit,0)) as gp
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${pF2.w} GROUP BY p.accountId`, pF2.p, 45000);
      adsRows.forEach(r => { adsMap[r.accountId] = { ads: parseFloat(r.ads)||0, gp: parseFloat(r.gp)||0 }; });
    } catch(ea) { console.warn('shops ads query:', ea.message); }

    // Plan data per shop: aggregate asin_plan → seller_board_product.accountId
    let planMap = {}; // { accountId: { gp, rv, ad, un } }
    try {
      const yr = new Date().getFullYear();
      const planRows = await q(`SELECT p.accountId, ap.metrics, SUM(ap.value) as val
        FROM asin_plan ap
        JOIN (SELECT DISTINCT asin, accountId FROM seller_board_product WHERE YEAR(date)=?) p
          ON ap.asin COLLATE utf8mb4_0900_ai_ci = p.asin
        WHERE ap.year = ?
        GROUP BY p.accountId, ap.metrics`, [yr, yr], 45000);
      planRows.forEach(r => {
        if (!planMap[r.accountId]) planMap[r.accountId] = { gp: 0, rv: 0, ad: 0, un: 0 };
        const pm = planMap[r.accountId];
        const mk = mapMetric(r.metrics);
        const v = parseFloat(r.val) || 0;
        if (mk === 'gp') pm.gp += v;
        else if (mk === 'rv') pm.rv += v;
        else if (mk === 'ad') pm.ad += v;
        else if (mk === 'un') pm.un += v;
      });
    } catch (ep) { console.warn('shops plan aggregation failed:', ep.message); }

    res.json(rows.map(r => {
      const rev=parseFloat(r.revenue)||0, np=parseFloat(r.netProfit)||0;
      const stk = stockMap[r.accountId] || { fba: 0, sv: 0 };
      const plan = planMap[r.accountId] || { gp: 0, rv: 0, ad: 0, un: 0 };
      const ad = adsMap[r.accountId] || { ads: 0, gp: 0 };
      const gp = ad.gp || np; // prefer GP from product table, fallback to NP
      return { shop: shopMap[r.accountId]||`Account ${r.accountId}`, accountId: r.accountId, revenue: rev, grossProfit: gp, netProfit: np, ads: ad.ads, units: parseInt(r.units)||0, orders: parseInt(r.orders)||0, margin: rev>0?(gp/rev*100):0, fbaStock: stk.fba, stockValue: stk.sv, gpPlan: plan.gp, rvPlan: plan.rv, adPlan: plan.ad, unPlan: plan.un };
    }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ TEAM ═══════════ */
app.get('/api/team', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let w = 'WHERE p.date BETWEEN ? AND ?'; const params = [s, e];
    if (af && af !== 'All') { w += ' AND p.asin = ?'; params.push(af); }
    if (accId) { w += ' AND p.accountId = ?'; params.push(accId); }
    if (seller && seller !== 'All') { w += " AND COALESCE(NULLIF(a.seller,''),'Unassigned') = ?"; params.push(seller); }
    const rows = await q(`SELECT COALESCE(NULLIF(a.seller,''),'Unassigned') as seller,
      SUM(COALESCE(p.salesOrganic,0)+COALESCE(p.salesPPC,0)) as revenue,
      SUM(COALESCE(p.netProfit,0)) as netProfit,
      SUM(COALESCE(p.unitsOrganic,0)+COALESCE(p.unitsPPC,0)) as units,
      COUNT(DISTINCT p.asin) as asinCount
      FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
      ${w} GROUP BY COALESCE(NULLIF(a.seller,''),'Unassigned')
      ORDER BY revenue DESC LIMIT 100`, params, 60000);
    res.json(rows.map(r => {
      const rev=parseFloat(r.revenue)||0, np=parseFloat(r.netProfit)||0;
      return { seller: r.seller, revenue: rev, netProfit: np, units: parseInt(r.units)||0,
        margin: rev>0?(np/rev*100):0, asinCount: parseInt(r.asinCount)||0 };
    }));
  } catch (e) { console.error('TEAM:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ INVENTORY ═══════════ */
app.get('/api/inventory/snapshot', async (req, res) => {
  try {
    const accId = await storeToAccId(req.query.store);
    let extra = ''; const params = [];
    if (accId) { extra = ' AND f.accountId = ?'; params.push(accId); }

    // FBA Stock from seller_board_stock (snapshot table, no date column)
    let fbaFromStock = 0;
    try {
      let sw = 'WHERE 1=1';
      const sp = [];
      if (accId) { sw += ' AND accountId = ?'; sp.push(accId); }
      const sr = await q(`SELECT SUM(FBAStock) as fba FROM seller_board_stock ${sw}`, sp);
      fbaFromStock = parseInt(sr[0]?.fba) || 0;
    } catch (e) { /* seller_board_stock may not exist */ }

    const rows = await q(`SELECT
      MAX(f.date) as snapshotDate,
      MIN(f.date) as oldestDate,
      SUM(GREATEST(CAST(f.available AS SIGNED), 0)) as availableInv,
      SUM(COALESCE(f.totalReservedQuantity,0)) as reserved, SUM(COALESCE(f.inboundQuantity,0)) as inbound,
      COUNT(DISTINCT CASE WHEN f.daysOfSupply<=30 THEN f.sku END) as criticalSkus,
      AVG(CASE WHEN f.daysOfSupply > 0 THEN f.daysOfSupply ELSE NULL END) as avgDaysOfSupply,
      SUM(COALESCE(f.invAge0To90Days,0)) as a0,
      SUM(COALESCE(f.invAge91To180Days,0)) as a91, SUM(COALESCE(f.invAge181To270Days,0)) as a181,
      SUM(COALESCE(f.invAge271To365Days,0)) as a271, SUM(COALESCE(f.invAge365PlusDays,0)) as a365,
      SUM(COALESCE(f.estimatedStorageCostNextMonth,0)) as storageFee,
      AVG(COALESCE(f.sellThrough,0)) as avgSellThrough
      FROM fba_iventory_planning f
      JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest
        ON f.accountId = latest.aid AND f.date = latest.maxDate
      WHERE 1=1${extra}`, params);
    const r = rows[0]||{};
    const avail=parseInt(r.availableInv)||0;
    const reserved=parseInt(r.reserved)||0;
    const inbound=parseInt(r.inbound)||0;
    // FBA Stock = Available + Reserved (inbound not yet at FC)
    // Prefer seller_board_stock snapshot; fallback to fba_iventory_planning sum
    const fbaStock = fbaFromStock > 0 ? fbaFromStock : (avail + reserved);
    res.json({
      snapshotDate: r.snapshotDate ? String(r.snapshotDate).slice(0,10) : null,
      oldestDate: r.oldestDate ? String(r.oldestDate).slice(0,10) : null,
      fbaStock, availableInv: avail,
      totalInventory: avail+reserved+inbound,
      reserved, inbound,
      criticalSkus: parseInt(r.criticalSkus)||0, avgDaysOfSupply: Math.round(parseFloat(r.avgDaysOfSupply)||0),
      age0_90: parseInt(r.a0)||0, age91_180: parseInt(r.a91)||0, age181_270: parseInt(r.a181)||0,
      age271_365: parseInt(r.a271)||0, age365plus: parseInt(r.a365)||0,
      storageFee: parseFloat(r.storageFee)||0, avgSellThrough: parseFloat(r.avgSellThrough)||0
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/stock-trend', async (req, res) => {
  try {
    const accId = await storeToAccId(req.query.store);
    let extra = ''; const params = [];
    if (accId) { extra = ' AND accountId = ?'; params.push(accId); }
    res.json(await q(`SELECT date, SUM(FBAStock) as fbaStock, SUM(GREATEST(FBAStock - COALESCE(reserved,0), 0)) as available FROM seller_board_stock_daily WHERE date>=DATE_SUB(CURDATE(), INTERVAL 60 DAY)${extra} GROUP BY date ORDER BY date`, params));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ STOCK HISTORY PER ASIN ═══════════ */
app.get('/api/stock/history', async (req, res) => {
  try {
    const { asin } = req.query;
    if (!asin) return res.status(400).json({ error: 'asin required' });
    // Daily FBAStock (12 months, aggregate across accounts)
    const rows = await q(`SELECT d.date, SUM(d.FBAStock) as fba, AVG(d.estimatedSalesVelocity) as velocity,
      MIN(d.daysOfStockLeft) as daysLeft, SUM(d.reserved) as reserved, SUM(d.sentToFBA) as sentToFBA
      FROM seller_board_stock_daily d WHERE d.asin=?
      AND d.date>=DATE_SUB(CURDATE(), INTERVAL 365 DAY)
      GROUP BY d.date ORDER BY d.date`, [asin], 15000);
    // Snapshot: aggregate all accounts for this ASIN
    const snap = await q(`SELECT
      MAX(s.name) as name, MAX(s.sku) as sku,
      SUM(s.FBAStock) as fba, SUM(COALESCE(s.stockValue,0)) as stockValue,
      SUM(COALESCE(s.reserved,0)) as reserved, SUM(COALESCE(s.sentToFBA,0)) as sentToFBA,
      SUM(COALESCE(s.FBAPrepStock,0)) as prepStock, AVG(s.estimatedSalesVelocity) as velocity,
      MIN(NULLIF(s.daysOfStockLeft,0)) as daysLeft, AVG(s.roi) as roi, AVG(s.margin) as margin,
      MIN(s.accountId) as accountId
      FROM seller_board_stock s WHERE s.asin=?`, [asin], 5000).catch(()=>[]);
    const info = snap[0] || {};
    const acc = info.accountId ? await q('SELECT shop FROM accounts WHERE id=?',[info.accountId],5000).catch(()=>[]) : [];
    const fba=parseInt(info.fba)||0;const sv=parseFloat(info.stockValue)||0;
    const cogs=fba>0?Math.round(sv/fba*100)/100:0;
    // Also get on-hand stock from daily (latest)
    const onHand = rows.length>0 ? rows[rows.length-1].fba : fba;
    res.json({
      asin, name: info.name||'', sku: info.sku||'', shop: acc[0]?.shop||'',
      current: { fba, onHand: parseInt(onHand)||0, stockValue: sv, cogs,
        reserved: parseInt(info.reserved)||0, sentToFBA: parseInt(info.sentToFBA)||0,
        prepStock: parseInt(info.prepStock)||0, velocity: Math.round((parseFloat(info.velocity)||0)*100)/100,
        daysLeft: parseInt(info.daysLeft)||0, roi: parseInt(info.roi)||0,
        margin: Math.round((parseFloat(info.margin)||0)*100)/100 },
      history: rows.map(r=>({ date: r.date, fba: parseInt(r.fba)||0,
        velocity: Math.round((parseFloat(r.velocity)||0)*100)/100,
        daysLeft: parseInt(r.daysLeft)||0, reserved: parseInt(r.reserved)||0 }))
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/storage-monthly', async (req, res) => {
  try {
    const accId = await storeToAccId(req.query.store);
    let extra = ''; const params = [];
    if (accId) { extra = ' AND accountId = ?'; params.push(accId); }
    // Get last snapshot of each month (most accurate monthly fee)
    const rows = await q(`
      SELECT DATE_FORMAT(date,'%Y-%m') as ym,
        MAX(date) as lastDate,
        SUM(COALESCE(estimatedStorageCostNextMonth,0)) as fee
      FROM fba_iventory_planning
      WHERE date IN (
        SELECT MAX(date) FROM fba_iventory_planning GROUP BY DATE_FORMAT(date,'%Y-%m')
      )${extra}
      GROUP BY DATE_FORMAT(date,'%Y-%m')
      ORDER BY ym
    `, params);
    res.json((rows||[]).map(r => ({ month: r.ym, fee: Math.round((parseFloat(r.fee)||0)*100)/100 })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/by-shop', async (req, res) => {
  try {
    const shopMap = await getShopMap();
    const accId = await storeToAccId(req.query.store);
    let accFilter = ''; const accParams = [];
    if (accId) { accFilter = ' AND accountId = ?'; accParams.push(accId); }
    // Separate qualified filter for JOIN queries on fba_iventory_planning (alias f)
    const invFilter = accId ? ' AND f.accountId = ?' : '';
    const invParams = accId ? [accId] : [];

    // FBA Stock per shop from seller_board_stock (snapshot)
    let stockMap = {};
    try {
      (await q(`SELECT accountId, SUM(FBAStock) as fba FROM seller_board_stock WHERE 1=1${accFilter} GROUP BY accountId`, accParams))
        .forEach(r => { stockMap[r.accountId] = parseInt(r.fba) || 0; });
    } catch (e) { /* ok */ }

    // Units sold last 30 days per shop (for sell-through & days of supply calc)
    let unitsMap = {}; // { accountId: { units, days } }
    try {
      const salesRows = await q(`SELECT p.accountId, SUM(${P_UNITS}) as units, DATEDIFF(MAX(p.date),MIN(p.date))+1 as days
        FROM seller_board_product p WHERE p.date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)${accFilter}
        GROUP BY p.accountId`, accParams, 15000);
      salesRows.forEach(r => { unitsMap[r.accountId] = { units: parseInt(r.units)||0, days: parseInt(r.days)||1 }; });
    } catch(e) { /* ok */ }

    // Inventory planning data (for inbound, reserved, critical SKUs)
    const inv = await q(`SELECT f.accountId, SUM(GREATEST(CAST(f.available AS SIGNED), 0)) as avail, SUM(COALESCE(f.inboundQuantity,0)) as inb, SUM(COALESCE(f.totalReservedQuantity,0)) as res, COUNT(DISTINCT CASE WHEN f.daysOfSupply<=30 THEN f.sku END) as crit
      FROM fba_iventory_planning f
      JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest
        ON f.accountId = latest.aid AND f.date = latest.maxDate
      WHERE 1=1${invFilter}
      GROUP BY f.accountId`, invParams).catch(()=>[]);

    // Combine all data
    const allAccIds = new Set([...Object.keys(stockMap).map(Number), ...inv.map(r=>r.accountId)]);
    const combined = [...allAccIds].map(aid => {
      const fba = stockMap[aid] || 0;
      const invRow = inv.find(r => r.accountId === aid) || {};
      const sales = unitsMap[aid] || { units: 0, days: 30 };
      const avgDaily = sales.days > 0 ? sales.units / sales.days : 0;
      // Sell-Through = Units Sold / (Units Sold + FBA Stock)
      const sellThrough = (sales.units + fba) > 0 ? sales.units / (sales.units + fba) : 0;
      // Days of Supply = FBA Stock / Avg Daily Sales
      const daysOfSupply = avgDaily > 0 ? Math.round(fba / avgDaily) : (fba > 0 ? 999 : 0);
      return {
        shop: shopMap[aid] || `Account ${aid}`,
        fbaStock: fba,
        available: parseInt(invRow.avail) || 0,
        inbound: parseInt(invRow.inb) || 0,
        reserved: parseInt(invRow.res) || 0,
        criticalSkus: parseInt(invRow.crit) || 0,
        sellThrough: Math.round(sellThrough * 10000) / 10000,
        daysOfSupply
      };
    }).filter(r => r.fbaStock > 0 || r.sellThrough > 0);
    combined.sort((a, b) => b.fbaStock - a.fbaStock);
    res.json(combined);
  } catch (e) { res.status(500).json({ error: e.message }); }
});


/* ═══════════ INVENTORY BY ASIN ═══════════ */
app.get('/api/inventory/by-asin', async (req, res) => {
  try {
    const { store, seller } = req.query;
    const shopMap = await getShopMap();
    const accId = await storeToAccId(store);

    // Build filters
    let stockWhere = 'WHERE 1=1'; const stockParams = [];
    if (accId) { stockWhere += ' AND s.accountId = ?'; stockParams.push(accId); }

    let planWhere = 'JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest ON f.accountId = latest.aid AND f.date = latest.maxDate WHERE 1=1'; const planParams = [];
    if (accId) { planWhere += ' AND f.accountId = ?'; planParams.push(accId); }

    // Seller filter via asin table
    let sellerJoin = '', sellerWhere = '';
    if (seller && seller !== 'All') {
      sellerJoin = ' LEFT JOIN asin a ON s.asin COLLATE utf8mb4_0900_ai_ci = a.asin';
      sellerWhere = ' AND a.seller = ?';
      stockParams.push(seller);
    }

    // Main ASIN stock from seller_board_stock — try with price cols, fallback without
    let stockRows = [];
    try {
      stockRows = await q(`SELECT s.asin, s.name, s.sku, s.accountId,
        SUM(s.FBAStock) as fba,
        SUM(COALESCE(s.reserved,0)) as reserved,
        SUM(COALESCE(s.sentToFBA,0)) as sentToFBA,
        SUM(COALESCE(s.stockValue,0)) as stockValue,
        AVG(COALESCE(s.estimatedSalesVelocity,0)) as velocity,
        MIN(NULLIF(s.daysOfStockLeft,0)) as daysLeft,
        MAX(COALESCE(s.price,0)) as salePrice,
        MAX(COALESCE(s.businessPrice,0)) as businessPrice
        FROM seller_board_stock s${sellerJoin}
        ${stockWhere}${sellerWhere}
        GROUP BY s.asin, s.name, s.sku, s.accountId
        ORDER BY fba DESC LIMIT 300`, stockParams, 30000);
    } catch(e1) {
      // Fallback: without price/businessPrice columns
      try {
        stockRows = await q(`SELECT s.asin, s.name, s.sku, s.accountId,
          SUM(s.FBAStock) as fba,
          SUM(COALESCE(s.reserved,0)) as reserved,
          SUM(COALESCE(s.sentToFBA,0)) as sentToFBA,
          SUM(COALESCE(s.stockValue,0)) as stockValue,
          AVG(COALESCE(s.estimatedSalesVelocity,0)) as velocity,
          MIN(NULLIF(s.daysOfStockLeft,0)) as daysLeft,
          0 as salePrice, 0 as businessPrice
          FROM seller_board_stock s${sellerJoin}
          ${stockWhere}${sellerWhere}
          GROUP BY s.asin, s.name, s.sku, s.accountId
          ORDER BY fba DESC LIMIT 300`, stockParams, 30000);
      } catch(e2) { console.error('stockRows fallback failed:', e2.message); }
    }

    // Storage fee + inbound — try with longterm/unfulfillable cols, fallback without
    let planRows = [];
    try {
      planRows = await q(`SELECT f.asin, f.accountId,
        SUM(CAST(f.available AS SIGNED)) as available,
        SUM(COALESCE(f.inboundQuantity,0)) as inbound,
        SUM(COALESCE(f.totalReservedQuantity,0)) as planReserved,
        SUM(COALESCE(f.estimatedStorageCostNextMonth,0)) as storageFee,
        SUM(COALESCE(f.estimatedLongTermStorageFee,0)) as longTermFee,
        SUM(COALESCE(f.unfulfillableQuantity,0)) as unfulfillable,
        AVG(COALESCE(f.daysOfSupply,0)) as daysOfSupply,
        SUM(COALESCE(f.invAge0To90Days,0)) as age0_90,
        SUM(COALESCE(f.invAge91To180Days,0)) as age91_180,
        SUM(COALESCE(f.invAge181To270Days,0)) as age181_270,
        SUM(COALESCE(f.invAge271To365Days,0)) as age271_365,
        SUM(COALESCE(f.invAge365PlusDays,0)) as age365plus
        FROM fba_iventory_planning f
        ${planWhere}
        GROUP BY f.asin, f.accountId`, planParams, 30000);
    } catch(e1) {
      // Fallback: without longTermFee / unfulfillable
      try {
        planRows = await q(`SELECT f.asin, f.accountId,
          SUM(CAST(f.available AS SIGNED)) as available,
          SUM(COALESCE(f.inboundQuantity,0)) as inbound,
          SUM(COALESCE(f.totalReservedQuantity,0)) as planReserved,
          SUM(COALESCE(f.estimatedStorageCostNextMonth,0)) as storageFee,
          0 as longTermFee, 0 as unfulfillable,
          AVG(COALESCE(f.daysOfSupply,0)) as daysOfSupply,
          SUM(COALESCE(f.invAge0To90Days,0)) as age0_90,
          SUM(COALESCE(f.invAge91To180Days,0)) as age91_180,
          SUM(COALESCE(f.invAge181To270Days,0)) as age181_270,
          SUM(COALESCE(f.invAge271To365Days,0)) as age271_365,
          SUM(COALESCE(f.invAge365PlusDays,0)) as age365plus
          FROM fba_iventory_planning f
          ${planWhere}
          GROUP BY f.asin, f.accountId`, planParams, 30000);
      } catch(e2) { console.error('planRows fallback failed:', e2.message); }
    }

    // Build plan lookup: asin+accountId -> planRow
    const planMap = {};
    planRows.forEach(r => { planMap[r.asin+'_'+r.accountId] = r; });

    const result = stockRows.map(r => {
      const plan = planMap[r.asin+'_'+r.accountId] || {};
      const fba = parseInt(r.fba)||0;
      const available = parseInt(plan.available) ?? fba;
      const reserved = parseInt(plan.planReserved) || parseInt(r.reserved)||0;
      const inbound = parseInt(plan.inbound)||0;
      const storageFee = parseFloat(plan.storageFee)||0;
      const daysLeft = parseInt(r.daysLeft) || Math.round(parseFloat(plan.daysOfSupply)||0);
      const aged = (parseInt(plan.age91_180)||0)+(parseInt(plan.age181_270)||0)+(parseInt(plan.age271_365)||0)+(parseInt(plan.age365plus)||0);
      return {
        asin: r.asin,
        name: (r.name||'').substring(0,60),
        sku: r.sku||'',
        shop: shopMap[r.accountId]||`Account ${r.accountId}`,
        accountId: r.accountId,
        fba, available, reserved, inbound,
        stockValue: parseFloat(r.stockValue)||0,
        velocity: Math.round((parseFloat(r.velocity)||0)*100)/100,
        daysLeft, storageFee,
        longTermFee: parseFloat(plan.longTermFee)||0,
        unfulfillable: parseInt(plan.unfulfillable)||0,
        salePrice: parseFloat(r.salePrice)||0,
        businessPrice: parseFloat(r.businessPrice)||0,
        age0_90: parseInt(plan.age0_90)||0,
        age91_180: parseInt(plan.age91_180)||0,
        age181_270: parseInt(plan.age181_270)||0,
        age271_365: parseInt(plan.age271_365)||0,
        age365plus: parseInt(plan.age365plus)||0,
        aged, // units aged >90 days
        oos45: daysLeft > 0 && daysLeft <= 45,
      };
    });

    res.json(result);
  } catch (e) { console.error('inventory/by-asin:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ PLAN DEBUG ═══════════ */
/* ═══════════ DEBUG ENDPOINTS ═══════════ */
app.get('/api/debug/all', async (req, res) => {
  const R = { ts: new Date().toISOString(), tests: {} };
  const test = async (name, fn) => { try { R.tests[name] = await fn(); } catch(e) { R.tests[name] = { error: e.message }; } };
  await test('sales_count', () => q('SELECT COUNT(*) as cnt, MIN(date) as minD, MAX(date) as maxD FROM seller_board_sales'));
  await test('sales_daily_sample', () => q(`SELECT date, SUM(COALESCE(salesOrganic,0)+COALESCE(salesPPC,0)) as rev FROM seller_board_sales WHERE date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) GROUP BY date ORDER BY date LIMIT 5`));
  await test('product_count', () => q('SELECT COUNT(*) as cnt, MIN(date) as minD, MAX(date) as maxD FROM seller_board_product'));
  await test('plan_count', () => q('SELECT COUNT(*) as cnt FROM asin_plan'));
  await test('plan_years', () => q('SELECT DISTINCT `year`, COUNT(*) as cnt FROM asin_plan GROUP BY `year`').catch(()=>'no year col'));
  await test('inventory', () => q('SELECT COUNT(*) as cnt, MAX(date) as maxD FROM fba_iventory_planning'));
  await test('analytics', () => q('SELECT COUNT(*) as cnt, MIN(startDate) as minD, MAX(startDate) as maxD FROM analytics_search_catalog_performance'));
  await test('accounts', () => q('SELECT id, shop FROM accounts'));
  await test('stock_columns', () => q('SHOW COLUMNS FROM seller_board_stock').then(r=>r.map(c=>c.Field)));
  await test('stock_daily_columns', () => q('SHOW COLUMNS FROM seller_board_stock_daily').then(r=>r.map(c=>c.Field)));
  await test('stock_sample', () => q('SELECT * FROM seller_board_stock LIMIT 2'));
  await test('stock_daily_sample', () => q('SELECT * FROM seller_board_stock_daily ORDER BY date DESC LIMIT 2'));
  res.json(R);
});

app.get('/api/debug/plan', async (req, res) => {
  const yr = req.query.year || new Date().getFullYear();
  const R = { year: yr, steps: {} };
  try {
    R.steps.cols = (await q('SHOW COLUMNS FROM asin_plan')).map(c=>c.Field);
    R.steps.hasYear = R.steps.cols.includes('year');
    R.steps.sampleRows = await q('SELECT * FROM asin_plan LIMIT 3');
    R.steps.yearValues = await q('SELECT DISTINCT `year` FROM asin_plan LIMIT 10').catch(()=>'no year col');
    R.steps.totalRows = (await q('SELECT COUNT(*) as cnt FROM asin_plan'))[0]?.cnt;
    // Test sales query
    try { const sr = await q(`SELECT COUNT(*) as cnt FROM seller_board_sales WHERE date BETWEEN '${yr}-01-01' AND '${yr}-12-31'`); R.steps.salesRows = sr[0]?.cnt; } catch(e) { R.steps.salesRows = e.message; }
    // Test product query
    try { const pr = await q(`SELECT COUNT(*) as cnt FROM seller_board_product WHERE date BETWEEN '${yr}-01-01' AND '${yr}-12-31'`); R.steps.productRows = pr[0]?.cnt; } catch(e) { R.steps.productRows = e.message; }
    // Test analytics query
    try { const ar = await q(`SELECT COUNT(*) as cnt FROM analytics_search_catalog_performance WHERE YEAR(startDate) = ?`, [yr]); R.steps.analyticsRows = ar[0]?.cnt; } catch(e) { R.steps.analyticsRows = e.message; }
  } catch(e) { R.error = e.message; }
  res.json(R);
});

/* ═══════════ ASIN PLAN ═══════════ */
const MS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const METRICS_MAP={'Rev':'rv','Unit':'un','Ads':'ad','GP':'gp','NP':'np','Session':'se','Impression':'im','CR':'cr','CTR':'ct','Price':'pr','CPM':'cpm','CPC':'cpc','Cogs':'cg','AMZ fee':'af','Gross Profit':'gp','Net Profit':'np','rev':'rv','unit':'un','ads':'ad','gp':'gp','np':'np','session':'se','impression':'im','cr':'cr','ctr':'ct','price':'pr','cpm':'cpm','cpc':'cpc','cogs':'cg','amz fee':'af','gross profit':'gp','net profit':'np','revenue':'rv','Revenue':'rv','units':'un','Units':'un','grossProfit':'gp','netProfit':'np','adSpend':'ad','Ad Spend':'ad','sessions':'se','Sessions':'se','impressions':'im','Impressions':'im'};
function mapMetric(m) {
  if (!m) return null;
  const t = m.trim();
  if (METRICS_MAP[t]) return METRICS_MAP[t];
  const lm = t.toLowerCase();
  if (METRICS_MAP[lm]) return METRICS_MAP[lm];
  if (lm.includes('revenue')||lm.includes('sales')) return 'rv';
  if (lm==='np'||lm.includes('net profit')) return 'np';
  if (lm==='gp'||lm.includes('gross profit')) return 'gp';
  if (lm==='ads'||lm==='ad'||lm==='ad spend') return 'ad';
  if (lm.includes('unit')) return 'un';
  if (lm.includes('session')) return 'se';
  if (lm.includes('impression')) return 'im';
  if (lm==='cr'||lm==='conversion') return 'cr';
  if (lm==='ctr'||lm==='click') return 'ct';
  if (lm==='price') return 'pr';
  if (lm==='cpm') return 'cpm'; if (lm==='cpc') return 'cpc';
  if (lm==='cogs'||lm==='cost of goods') return 'cg';
  if (lm.includes('amz')||lm.includes('amazon fee')) return 'af';
  return null;
}

app.get('/api/plan/data', async (req, res) => {
  try {
    const { year, month, store, seller, asin: af } = req.query;
    const yr = parseInt(year) || new Date().getFullYear();
    let cols;
    try { cols = (await q('SHOW COLUMNS FROM asin_plan')).map(c=>c.Field); }
    catch { return res.json({kpi:{},monthlyPlan:{},asinPlan:{}}); }
    const hasYear = cols.includes('year');
    const hasCreatedAt = cols.includes('created_at');
    let where, params;
    if (hasYear) { where = 'WHERE ap.`year` = ?'; params = [yr]; }
    else if (hasCreatedAt) { where = 'WHERE YEAR(ap.created_at) = ?'; params = [yr]; }
    else { where = 'WHERE 1=1'; params = []; }
    if (month && month !== 'All') { const mn=parseInt(month); if(mn>=1&&mn<=12){where+=' AND ap.month_num = ?';params.push(mn);} }
    if (store && store !== 'All') {
      const accId2 = await storeToAccId(store);
      if (accId2) {
        // Pre-fetch ASINs for this store (faster than subquery)
        const storeAsins = (await q('SELECT DISTINCT asin FROM seller_board_product WHERE accountId = ? AND date >= DATE_SUB(CURDATE(), INTERVAL 365 DAY) LIMIT 2000', [accId2], 15000).catch(()=>[])).map(r=>r.asin);
        if (storeAsins.length) {
          const placeholders = storeAsins.map(()=>'?').join(',');
          where += ` AND (ap.brand_name = ? OR ap.asin IN (${placeholders}))`;
          params.push(store, ...storeAsins);
        } else {
          where += ' AND ap.brand_name = ?'; params.push(store);
        }
      } else { where += ' AND ap.brand_name = ?'; params.push(store); }
    }
    if (af && af !== 'All') { where+=' AND ap.asin = ?'; params.push(af); }
    if (seller && seller !== 'All') { where+=' AND a.seller = ?'; params.push(seller); }
    const rows = await q(`SELECT ap.asin, ap.brand_name, ap.month_num, ap.metrics, COALESCE(CAST(ap.value AS DECIMAL(20,4)),0) as value
      FROM asin_plan ap LEFT JOIN asin a ON ap.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${where} ORDER BY ap.month_num`, params, 45000);

    const monthlyPlan={}, asinPlan={};
    rows.forEach(r => {
      const mk=mapMetric(r.metrics); if(!mk) return;
      const mn=r.month_num, val=parseFloat(r.value)||0;
      if(!monthlyPlan[mn]) monthlyPlan[mn]={};
      monthlyPlan[mn][mk]=(monthlyPlan[mn][mk]||0)+val;
      const key=r.asin;
      if(!asinPlan[key]) asinPlan[key]={brand:r.brand_name,months:{}};
      if(!asinPlan[key].months[mn]) asinPlan[key].months[mn]={};
      asinPlan[key].months[mn][mk]=(asinPlan[key].months[mn][mk]||0)+val;
    });

    // KPI: CR weighted = Units/Sessions, CTR weighted = Sessions/Impressions
    const kpi={gp:{a:0,p:0},np:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    const crDirect=[], ctDirect=[];
    Object.values(monthlyPlan).forEach(mp => {
      ['gp','np','rv','ad','un','se','im'].forEach(k=>{if(kpi[k])kpi[k].p+=mp[k]||0;});
      if(mp.cr) crDirect.push(mp.cr);
      if(mp.ct) ctDirect.push(mp.ct);
    });
    // Weighted CR (preferred) or fallback
    if(kpi.se.p>0&&kpi.un.p>0) kpi.cr.p=kpi.un.p/kpi.se.p;
    else if(crDirect.length) {
      const avg=crDirect.reduce((s,v)=>s+v,0)/crDirect.length;
      kpi.cr.p=avg>1?avg/100:avg; // auto-detect: >1 means whole %, <=1 means ratio
    }
    // Weighted CTR or fallback
    if(kpi.im.p>0&&kpi.se.p>0) kpi.ct.p=kpi.se.p/kpi.im.p;
    else if(ctDirect.length) {
      const avg=ctDirect.reduce((s,v)=>s+v,0)/ctDirect.length;
      kpi.ct.p=avg>1?avg/100:avg; // auto-detect: >1 means whole %, <=1 means ratio
    }

    // Per-month plan CR/CTR (weighted per month)
    for (const mn in monthlyPlan) {
      const mp = monthlyPlan[mn];
      if (mp.un && mp.se) mp.crW = mp.un / mp.se;
      else if (mp.cr) mp.crW = mp.cr > 1 ? mp.cr / 100 : mp.cr;
      else mp.crW = 0;
      if (mp.se && mp.im) mp.ctW = mp.se / mp.im;
      else if (mp.ct) mp.ctW = mp.ct > 1 ? mp.ct / 100 : mp.ct;
      else mp.ctW = 0;
    }

    res.json({kpi,monthlyPlan,asinPlan});
  } catch (e) { console.error('plan/data ERROR:', e.message, e.stack?.split('\n')[1]); res.status(500).json({error:'Plan data: '+e.message}); }
});

app.get('/api/plan/actuals', async (req, res) => {
  const t0=Date.now();
  try {
    const { year, store, seller, asin: af } = req.query;
    const yr = parseInt(year) || new Date().getFullYear();
    const accId = await storeToAccId(store);
    const debug = { yr, accId, seller, af, useProduct: useProduct(seller,af) };
    const pF = pWhere(`${yr}-01-01`,`${yr}-12-31`,accId,seller,af);

    // Pre-fetch seller ASINs if needed (for impression filtering)
    let selAsins = [];
    if(seller && seller!=='All' && (!af || af==='All')){
      selAsins=(await q('SELECT DISTINCT asin FROM asin WHERE seller=?',[seller],10000).catch(()=>[])).map(r=>r.asin);
    }

    // ═══ BATCH 1: Run main queries in PARALLEL (was sequential → ~3x faster) ═══
    const impWhere=(prefix)=>{
      let iw=`WHERE YEAR(${prefix}.startDate)=?`; const ip=[yr];
      if(accId){iw+=` AND ${prefix}.accountId=?`;ip.push(accId);}
      if(af && af!=='All'){iw+=` AND ${prefix}.asin=?`;ip.push(af);}
      else if(selAsins.length){iw+=` AND ${prefix}.asin IN (${selAsins.map(()=>'?').join(',')})`;ip.push(...selAsins);}
      return{iw,ip};
    };

    const [salesRes, adsRes, impRes, asinRes, asinImpRes, ucRes] = await Promise.allSettled([
      // Q1: Monthly sales
      (async()=>{
        if(useProduct(seller,af)){
          const r=await q(`SELECT MONTH(p.date) as mn,
            SUM(${P_SALES}) as revenue, SUM(COALESCE(p.grossProfit,0)) as gp, SUM(COALESCE(p.netProfit,0)) as np,
            SUM(${P_UNITS}) as units, SUM(COALESCE(p.sessions,0)) as sessions, SUM(ABS(${P_ADS})) as ads
            FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${pF.w} GROUP BY MONTH(p.date)`,pF.p,45000);
          debug.salesSource='product';debug.salesRows=r.length;return r;
        } else {
          const scF=scWhere(`${yr}-01-01`,`${yr}-12-31`,accId);
          const r=await q(`SELECT MONTH(sc.date) as mn,
            SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.grossProfit,0)) as gp, SUM(COALESCE(sc.netProfit,0)) as np,
            SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.sessions,0)) as sessions, SUM(ABS(${SC_ADS})) as ads
            FROM ${salesFrom()} ${scF.w} GROUP BY MONTH(sc.date)`,scF.p,45000);
          debug.salesSource='sales';debug.salesRows=r.length;debug.salesTable=salesFrom();return r;
        }
      })(),
      // Q2: Ads (only when using seller_board_sales)
      (async()=>{
        if(useProduct(seller,af)) return [];
        return q(`SELECT MONTH(p.date) as mn, SUM(ABS(${P_ADS})) as ads
          FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${pF.w} GROUP BY MONTH(p.date)`,pF.p,45000);
      })(),
      // Q3: Monthly impressions
      (async()=>{
        const{iw,ip}=impWhere('isc');
        return q(`SELECT MONTH(isc.startDate) as mn, SUM(COALESCE(isc.impressionCount,0)) as imp, SUM(COALESCE(isc.clickCount,0)) as clicks
          FROM analytics_search_catalog_performance isc ${iw} GROUP BY MONTH(isc.startDate)`,ip,45000);
      })(),
      // Q4: ASIN breakdown (the main data query)
      (async()=>{
        const r=await q(`SELECT p.asin, ap2.brand_name as planBrand, a.seller, MONTH(p.date) as mn,
          SUM(${P_SALES}) as revenue, SUM(COALESCE(p.grossProfit,0)) as gp, SUM(COALESCE(p.netProfit,0)) as np,
          SUM(${P_UNITS}) as units, SUM(COALESCE(p.sessions,0)) as sessions, SUM(ABS(${P_ADS})) as ads
          FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
          LEFT JOIN (SELECT DISTINCT asin, brand_name FROM asin_plan) ap2 ON p.asin COLLATE utf8mb4_0900_ai_ci=ap2.asin
          ${pF.w} GROUP BY p.asin, ap2.brand_name, a.seller, MONTH(p.date) ORDER BY gp DESC`,pF.p,45000);
        debug.asinRows=r.length;return r;
      })(),
      // Q5: ASIN-level impressions
      (async()=>{
        const{iw,ip}=impWhere('asc2');
        return q(`SELECT asc2.asin, MONTH(asc2.startDate) as mn,
          SUM(COALESCE(asc2.impressionCount,0)) as imp, SUM(COALESCE(asc2.clickCount,0)) as clicks
          FROM analytics_search_catalog_performance asc2 ${iw}
          GROUP BY asc2.asin, MONTH(asc2.startDate)`,ip,45000);
      })(),
      // Q6: Stock Value snapshot (seller_board_stock — giá trị tại thời điểm hiện tại)
      (async()=>{
        let ucw='WHERE FBAStock>0'; const ucp=[];
        if(accId){ucw+=' AND s.accountId=?';ucp.push(accId);}
        if(af && af!=='All'){ucw+=' AND s.asin=?';ucp.push(af);}
        else if(seller && seller!=='All'){
          ucw+=' AND s.asin IN (SELECT asin FROM asin WHERE seller=?)';ucp.push(seller);
        }
        return q(`SELECT s.asin, SUM(COALESCE(s.stockValue,0)) as sv, SUM(s.FBAStock) as fba
          FROM seller_board_stock s ${ucw} GROUP BY s.asin`,ucp,10000);
      })()
    ]);

    // Extract results (fulfilled → data, rejected → empty + log error)
    const val=(r,label)=>{ if(r.status==='fulfilled') return r.value||[]; debug[label+'Err']=r.reason?.message; return []; };
    const salesRows=val(salesRes,'sales');
    const adsRows=val(adsRes,'ads');
    const impRows=val(impRes,'imp');
    const asinRows=val(asinRes,'asin');
    const asinImpRows=val(asinImpRes,'asinImp');
    const ucRows=val(ucRes,'uc');

    // Build snapshot stock value map (直接 from seller_board_stock, no estimation)
    let asinStockMap = {}; // { asin: { sv, fba } }
    ucRows.forEach(r=>{
      const sv=parseFloat(r.sv)||0;const fba=parseInt(r.fba)||0;
      asinStockMap[r.asin]={sv,fba};
    });
    debug.stockAsins=Object.keys(asinStockMap).length;

    // ═══ Merge monthly data ═══
    const monthly = {};
    for(let m=1;m<=12;m++) monthly[m]={rv:0,gp:0,np:0,un:0,se:0,ad:0,im:0,clicks:0};
    salesRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.rv=parseFloat(r.revenue)||0;m.gp=parseFloat(r.gp)||0;m.np=parseFloat(r.np)||0;m.un=parseInt(r.units)||0;m.se=parseFloat(r.sessions)||0;m.ad=parseFloat(r.ads)||0;});
    adsRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.ad=parseFloat(r.ads)||0;});
    impRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.im=parseFloat(r.imp)||0;m.clicks=parseFloat(r.clicks)||0;});

    const monthlyArr=[];
    for(let m=1;m<=12;m++){
      const d=monthly[m];
      const cr=d.se>0?d.un/d.se:0;
      const ctr=d.im>0?d.clicks/d.im:0;
      monthlyArr.push({m:MS[m-1],mn:m,ra:d.rv,gpa:d.gp,npa:d.np,aa:d.ad,ua:d.un,sa:d.se,ia:d.im,
        cra:Math.round(cr*10000)/10000, cta:Math.round(ctr*10000)/10000});
    }

    // ═══ Build ASIN breakdown ═══
    const asinData={};
    asinRows.forEach(r=>{
      const key=r.asin, mn=r.mn;
      if(!asinData[key]) asinData[key]={brand:r.planBrand||'',seller:r.seller||'',months:{}};
      if(!asinData[key].months[mn]) asinData[key].months[mn]={rv:0,gp:0,np:0,ad:0,un:0,se:0,im:0,clicks:0,cr:0,ct:0};
      const md=asinData[key].months[mn];
      md.rv+=parseFloat(r.revenue)||0;md.gp+=parseFloat(r.gp)||0;md.np+=parseFloat(r.np)||0;md.ad+=parseFloat(r.ads)||0;
      md.un+=parseInt(r.units)||0;md.se+=parseFloat(r.sessions)||0;
      md.cr=md.se>0?md.un/md.se:0;
    });
    // Merge ASIN impressions
    const asinImpMap={};
    asinImpRows.forEach(r=>{
      if(!asinImpMap[r.asin]) asinImpMap[r.asin]={};
      asinImpMap[r.asin][r.mn]={imp:parseInt(r.imp)||0,clicks:parseInt(r.clicks)||0};
    });
    for(const [asin,months] of Object.entries(asinImpMap)){
      if(!asinData[asin]) continue;
      for(const [mn,imp] of Object.entries(months)){
        if(!asinData[asin].months[mn]) asinData[asin].months[mn]={rv:0,gp:0,np:0,ad:0,un:0,se:0,im:0,clicks:0,cr:0,ct:0,sv:0};
        asinData[asin].months[mn].im=imp.imp;
        asinData[asin].months[mn].clicks=imp.clicks;
        asinData[asin].months[mn].ct=imp.imp>0?imp.clicks/imp.imp:0;
      }
    }
    const asinBreakdown=Object.entries(asinData).map(([asin,d])=>{
      const t={rv:0,gp:0,np:0,ad:0,un:0,se:0,im:0,clicks:0};
      Object.values(d.months).forEach(m=>{t.rv+=m.rv;t.gp+=m.gp;t.np+=m.np;t.ad+=m.ad;t.un+=m.un;t.se+=m.se;t.im+=m.im||0;t.clicks+=m.clicks||0;});
      // Stock Value: snapshot from seller_board_stock (giá trị tại thời điểm hiện tại)
      const snapSv=asinStockMap[asin]?.sv||0;
      const cr=t.se>0?t.un/t.se:0;
      const ctr=t.im>0?t.clicks/t.im:0;
      return{a:asin,br:d.brand,sl:d.seller,ra:t.rv,ga:t.gp,na:t.np,aa:t.ad,ua:t.un,sa:t.se,ia:t.im,
        sv:snapSv,
        cra:Math.round(cr*10000)/10000,cta:Math.round(ctr*10000)/10000,months:d.months};
    }).sort((a,b)=>b.ga-a.ga);

    debug.asinBreakdownCount=asinBreakdown.length;
    debug.ms=Date.now()-t0;
    res.json({monthly:monthlyArr,asinBreakdown,_debug:debug});
  } catch (e) { console.error('plan/actuals:', e.message); res.status(500).json({error:e.message,_debug:{ms:Date.now()-t0}}); }
});

/* ═══════════ OPS DAILY ═══════════ */
app.get('/api/ops/daily', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let rows;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT p.date, SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(${P_UNITS}) as units, 0 as orders, SUM(${P_ADS}) as adSpend
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${f.w} GROUP BY p.date ORDER BY p.date DESC LIMIT 60`, f.p);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT sc.date, SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.netProfit,0)) as netProfit,
        SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders, SUM(${SC_ADS}) as adSpend
        FROM ${salesFrom()} ${f.w} GROUP BY sc.date ORDER BY sc.date DESC LIMIT 60`, f.p);
    }
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ AI INSIGHT ═══════════ */
app.post('/api/ai/insight', async (req, res) => {
  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(400).json({ error: 'No API key configured. Add ANTHROPIC_API_KEY to Railway Variables.' });
    const { context, question, history } = req.body;
    const page = context?.page || 'Executive Overview';
    const period = context?.period || '';

    const systemPrompt = `You are an AI assistant embedded in an Amazon FBA analytics dashboard for an e-commerce holding company (32+ brands, US market).

CURRENT PAGE: ${page}
PERIOD: ${period}

YOUR ROLE:
- Answer the user's SPECIFIC question directly. Do NOT give a generic analysis unless asked.
- Use numbers from the dashboard data to support your answers.
- Be concise: 150-400 words depending on question complexity.
- If asked in Vietnamese, respond in Vietnamese. If English, respond in English.
- Use **bold** for key numbers, bullet points for lists.
- When relevant, compare against Amazon FBA benchmarks (ACOS 15-25%, healthy margin >15%, sell-through >2%).
- End with 1-2 actionable next steps when appropriate.

DASHBOARD DATA:
${JSON.stringify(context, null, 2)}`;

    // Build messages with conversation history
    const messages = [];
    if (history && history.length > 0) {
      history.forEach(h => {
        messages.push({ role: h.role === 'user' ? 'user' : 'assistant', content: h.text });
      });
    }
    messages.push({ role: 'user', content: question });

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 2000, system: systemPrompt, messages }),
    });
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.error.message || 'API error' });
    res.json({ insight: data.content?.[0]?.text || 'Không thể phân tích.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC SHOP EXTENDED ═══════════ */
/* Returns per-shop: revenue, GP, ads, units, margin, FBA stock, AWD, storageFee, promoValue */
app.get('/api/exec/shop-extended', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    const shopMap = await getShopMap();
    const f = pWhere(s, e, accId, seller, af);
    // Main P&L per shop
    const rows = await q(`SELECT p.accountId,
      SUM(COALESCE(p.salesOrganic,0)+COALESCE(p.salesPPC,0)) as revenue,
      SUM(COALESCE(p.grossProfit,0)) as gp,
      SUM(COALESCE(p.netProfit,0)) as np,
      SUM(ABS(COALESCE(p.sponsoredProducts,0))+ABS(COALESCE(p.sponsoredBrands,0))+ABS(COALESCE(p.sponsoredBrandsVideo,0))+ABS(COALESCE(p.sponsoredDisplay,0))) as ads,
      SUM(COALESCE(p.unitsOrganic,0)+COALESCE(p.unitsPPC,0)) as units,
      SUM(COALESCE(p.sessions,0)) as sessions,
      SUM(COALESCE(p.promoValue,0)) as promo,
      SUM(COALESCE(p.estimatedStorageFee,0)) as storageFee
      FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
      ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p, 45000);
    // FBA Stock from snapshot
    let stockMap = {};
    try {
      const sp = accId ? ['WHERE accountId=?', [accId]] : ['WHERE 1=1', []];
      (await q(`SELECT accountId, SUM(FBAStock) as fba, SUM(COALESCE(stockValue,0)) as sv FROM seller_board_stock ${sp[0]} GROUP BY accountId`, sp[1]))
        .forEach(s => { stockMap[s.accountId] = { fba: parseInt(s.fba)||0, sv: parseFloat(s.sv)||0 }; });
    } catch(e) {}
    res.json(rows.map(r => {
      const rev=parseFloat(r.revenue)||0, gp=parseFloat(r.gp)||0;
      const stk=stockMap[r.accountId]||{fba:0,sv:0};
      return {
        shop: shopMap[r.accountId]||`Account ${r.accountId}`,
        accountId: r.accountId,
        revenue: rev, gp, np: parseFloat(r.np)||0,
        ads: parseFloat(r.ads)||0,
        units: parseInt(r.units)||0,
        sessions: parseFloat(r.sessions)||0,
        promo: parseFloat(r.promo)||0,
        storageFee: parseFloat(r.storageFee)||0,
        margin: rev>0?(gp/rev*100):0,
        fbaStock: stk.fba, stockValue: stk.sv,
      };
    }));
  } catch (e) { console.error('shop-extended:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC DETAIL METRICS ═══════════ */
/* Breakdown columns for Exec Overview — each sub-query isolated so one bad column can't kill others */
/* Source of truth: DAX measures in Power BI (seller_board_product + seller_board_sales) */
app.get('/api/exec/detail', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    const fp = pWhere(s, e, accId, seller, af);   // seller_board_product filter
    // seller_board_sales uses sc alias
    let sw = 'WHERE sc.date BETWEEN ? AND ?'; const sp = [s, e];
    if (accId) { sw += ' AND sc.accountId = ?'; sp.push(accId); }

    // ── Q1: ADS BREAKDOWN (SP / SB / SBV / SD) ──
    // DAX: seller_board_product[sponsoredProducts/Brands/BrandsVideo/Display]
    // Values stored as negative in DB → ABS()
    let sp_=0, sb=0, sbv=0, sd=0;
    try {
      const r = await q(`SELECT
        ABS(SUM(COALESCE(p.sponsoredProducts,0)))    as sp,
        ABS(SUM(COALESCE(p.sponsoredBrands,0)))      as sb,
        ABS(SUM(COALESCE(p.sponsoredBrandsVideo,0))) as sbv,
        ABS(SUM(COALESCE(p.sponsoredDisplay,0)))     as sd
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
        ${fp.w}`, fp.p, 45000);
      sp_=parseFloat(r[0]?.sp)||0; sb=parseFloat(r[0]?.sb)||0;
      sbv=parseFloat(r[0]?.sbv)||0; sd=parseFloat(r[0]?.sd)||0;
    } catch(e1) { console.warn('exec/detail ads:', e1.message); }

    // ── Q2: UNITS BREAKDOWN (Organic / PPC) ──
    // DAX: seller_board_product[unitsOrganic] + seller_board_product[unitsPPC]
    // NOTE: NO unitsSD column — DAX confirms only 2 types
    let unitsOrganic=0, unitsSP=0;
    try {
      const r = await q(`SELECT
        SUM(COALESCE(p.unitsOrganic,0)) as uo,
        SUM(COALESCE(p.unitsPPC,0))     as up
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
        ${fp.w}`, fp.p, 45000);
      unitsOrganic=parseInt(r[0]?.uo)||0; unitsSP=parseInt(r[0]?.up)||0;
    } catch(e2) { console.warn('exec/detail units:', e2.message); }

    // ── Q3: AMAZON FEES (FBA Fulfillment + Referral Commission) ──
    // These columns may or may not exist in seller_board_product — isolated try/catch
    let fbaFulfillment=0, commission=0;
    try {
      const r = await q(`SELECT
        ABS(SUM(COALESCE(p.FBAPerUnitFulfillmentFee,0))) as fba,
        ABS(SUM(COALESCE(p.commission,0)))               as comm
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
        ${fp.w}`, fp.p, 45000);
      fbaFulfillment=parseFloat(r[0]?.fba)||0; commission=parseFloat(r[0]?.comm)||0;
    } catch(e3) { console.warn('exec/detail fees:', e3.message); }

    // ── Q4: PROMO VALUE ──
    // DAX: seller_board_product[promoValue]
    let promo=0;
    try {
      const r = await q(`SELECT SUM(COALESCE(p.promoValue,0)) as pv
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
        ${fp.w}`, fp.p, 30000);
      promo=parseFloat(r[0]?.pv)||0;
    } catch(e4) { console.warn('exec/detail promo:', e4.message); }

    // ── Q5: SESSIONS BROWSER/MOBILE BREAKDOWN ──
    // DAX total sessions = seller_board_sales[sessions]
    // Browser/mobile split from analytics_sale_traffic_by_date (optional table)
    let browserSessions=0, mobileSessions=0;
    try {
      let tw='WHERE date BETWEEN ? AND ?'; const tp=[s,e];
      if(accId){tw+=' AND accountId=?';tp.push(accId);}
      const r=await q(`SELECT
        SUM(COALESCE(browserSessions,0))   as bs,
        SUM(COALESCE(mobileAppSessions,0)) as ms
        FROM analytics_sale_traffic_by_date ${tw}`,tp,30000);
      browserSessions=parseFloat(r[0]?.bs)||0; mobileSessions=parseFloat(r[0]?.ms)||0;
    } catch(e5) { /* table may not exist — silently skip */ }

    // ── Q6: SALES BREAKDOWN (Organic / PPC) ──
    // Source: seller_board_product[salesOrganic] + seller_board_product[salesPPC]
    // Uses same fp (product) filter as other sub-queries
    let salesOrganic=0, salesPPC=0;
    try {
      // Try seller_board_product first (filtered by seller/asin if needed)
      const r=await q(`SELECT
        SUM(COALESCE(p.salesOrganic,0)) as so,
        SUM(COALESCE(p.salesPPC,0))     as sp_s
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
        ${fp.w}`, fp.p, 45000);
      salesOrganic=parseFloat(r[0]?.so)||0; salesPPC=parseFloat(r[0]?.sp_s)||0;
    } catch(e6) {
      // Fallback: seller_board_sales (no seller/asin filter available)
      try {
        const r=await q(`SELECT
          SUM(COALESCE(sc.salesOrganic,0)) as so,
          SUM(COALESCE(sc.salesPPC,0))     as sp_s
          FROM ${salesFrom()} ${sw}`, sp, 45000);
        salesOrganic=parseFloat(r[0]?.so)||0; salesPPC=parseFloat(r[0]?.sp_s)||0;
      } catch(e6b) { console.warn('exec/detail sales breakdown:', e6b.message); }
    }

    res.json({ sp:sp_, sb, sbv, sd, fbaFulfillment, commission, unitsOrganic, unitsSP, promo, browserSessions, mobileSessions, salesOrganic, salesPPC });
  } catch (e) { console.error('exec/detail:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ SERVE FRONTEND ═══════════ */
const distPath = join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (req, res) => { res.sendFile(join(distPath, 'index.html')); });
app.listen(PORT, '0.0.0.0', () => { console.log(`\n🚀 Dashboard ${VER} on :${PORT} | DB: ${process.env.DB_HOST||'none'}\n`); });
