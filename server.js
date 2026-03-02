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
const VER = 'v3.6-2026-03-02';
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

async function q(sql, params = []) {
  if (!pool) throw new Error('Database not connected');
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('Query timeout 25s')), 25000));
  return Promise.race([pool.execute(sql, params).then(([rows]) => rows), timeout]);
}

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
// Build WHERE for seller_board_product p + asin a
function pWhere(sd, ed, accId, seller, af) {
  let w = 'WHERE p.date BETWEEN ? AND ?'; const p = [sd, ed];
  if (accId) { w += ' AND p.accountId = ?'; p.push(accId); }
  if (seller && seller !== 'All') { w += ' AND a.seller = ?'; p.push(seller); }
  if (af && af !== 'All') { w += ' AND p.asin = ?'; p.push(af); }
  return { w, p };
}
// Build WHERE for seller_board_day
function dWhere(sd, ed, accId) {
  let w = 'WHERE date BETWEEN ? AND ?'; const p = [sd, ed];
  if (accId) { w += ' AND accountId = ?'; p.push(accId); }
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
    R.steps.accounts = { ok: true, sample: (await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL LIMIT 3')) };
    R.steps.sellers = { ok: true, sample: (await q('SELECT DISTINCT seller FROM asin WHERE seller IS NOT NULL AND LENGTH(seller) > 0 LIMIT 5')) };
    const cols = await q('SHOW COLUMNS FROM asin_plan');
    const sample = await q('SELECT * FROM asin_plan LIMIT 3');
    R.steps.asinPlan = { ok: true, columns: cols.map(c => c.Field), sampleRows: sample };
    const crit = await q('SELECT COUNT(DISTINCT CASE WHEN daysOfSupply <= 7 THEN sku END) as criticalSkus FROM fba_iventory_planning WHERE date = (SELECT MAX(date) FROM fba_iventory_planning)');
    R.steps.criticalSkus = { ok: true, value: crit[0] };
  } catch (e) { R.globalError = e.message; }
  res.json(R);
});

app.get('/api/debug/data', async (req, res) => {
  const R = { version: VER, tests: {} };
  try {
    const dr = await q('SELECT MIN(date) as mi, MAX(date) as mx FROM seller_board_day');
    const maxD = dr[0]?.mx;
    if (!maxD) return res.json({ error: 'No data' });
    const sd = new Date(new Date(maxD).getTime() - 29*86400000).toISOString().slice(0,10);
    const ed = new Date(maxD).toISOString().slice(0,10);
    R.dateRange = { dbMax: maxD, queryStart: sd, queryEnd: ed };

    const r1 = await q('SELECT SUM(salesOrganic+salesPPC) as sales, COUNT(*) as rows FROM seller_board_day WHERE date BETWEEN ? AND ?', [sd, ed]);
    R.tests.dayTable = { ok: true, data: r1[0] };

    const sellerMap = {};
    (await q("SELECT asin, COALESCE(NULLIF(seller,''), 'Unassigned') as seller FROM asin")).forEach(r => { sellerMap[r.asin] = r.seller; });
    const agg = await q('SELECT asin, SUM(salesOrganic+salesPPC) as rev FROM seller_board_product WHERE date BETWEEN ? AND ? GROUP BY asin', [sd, ed]);
    const byS = {};
    agg.forEach(r => { const sl = sellerMap[r.asin] || 'Unassigned'; byS[sl] = (byS[sl]||0) + (parseFloat(r.rev)||0); });
    R.tests.team = { ok: true, sellers: Object.entries(byS).map(([s,r])=>({s,r})).sort((a,b)=>b.r-a.r).slice(0,5) };

    const metrics = await q('SELECT DISTINCT metrics FROM asin_plan LIMIT 20');
    R.tests.planMetrics = { ok: true, list: metrics.map(m => `${m.metrics}→${mapMetric(m.metrics)}`) };
  } catch(e) { R.globalError = e.message; }
  res.json(R);
});

/* ═══════════ DATE RANGE ═══════════ */
app.get('/api/date-range', async (req, res) => {
  try {
    const rows = await q('SELECT MIN(date) as minDate, MAX(date) as maxDate FROM seller_board_day');
    const r = rows[0] || {};
    const maxDate = r.maxDate ? new Date(r.maxDate).toISOString().slice(0,10) : null;
    const minDate = r.minDate ? new Date(r.minDate).toISOString().slice(0,10) : null;
    let defaultStart = null;
    if (maxDate) { const d = new Date(maxDate); d.setDate(d.getDate()-29); defaultStart = d.toISOString().slice(0,10); if (minDate && defaultStart < minDate) defaultStart = minDate; }
    res.json({ minDate, maxDate, defaultStart, defaultEnd: maxDate });
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
    res.json({
      shops: shops.map(s => ({ id: s.id, name: s.name })),
      sellers: sellers.map(s => s.seller),
      asins: asins.map(a => ({ asin: a.asin, seller: a.seller, shops: asm[a.asin] || [] })),
    });
  } catch (e) { console.error('FILTER ERROR:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC SUMMARY ═══════════ */
app.get('/api/exec/summary', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    let rows;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT
        SUM(p.salesOrganic+p.salesPPC) as sales, SUM(p.unitsOrganic+p.unitsPPC) as units, 0 as orders,
        SUM(COALESCE(p.refunds,0)) as refunds,
        SUM(p.sponsoredProducts+p.sponsoredDisplay+p.sponsoredBrands+COALESCE(p.sponsoredBrandsVideo,0)+COALESCE(p.googleAds,0)+COALESCE(p.facebookAds,0)) as advCost,
        0 as shippingCost, 0 as refundCost,
        SUM(COALESCE(p.amazonFees,0)) as amazonFees, SUM(COALESCE(p.costOfGoods,0)) as cogs,
        SUM(COALESCE(p.netProfit,0)) as netProfit, SUM(COALESCE(p.estimatedPayout,0)) as estPayout,
        SUM(COALESCE(p.sessions,0)) as sessions, SUM(COALESCE(p.grossProfit,0)) as grossProfit
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w}`, f.p);
    } else {
      const f = dWhere(s, e, accId);
      rows = await q(`SELECT
        SUM(salesOrganic+salesPPC) as sales, SUM(unitsOrganic+unitsPPC) as units, SUM(orders) as orders,
        SUM(refunds) as refunds,
        SUM(sponsoredProducts+sponsoredDisplay+sponsoredBrands+sponsoredBrandsVideo+COALESCE(googleAds,0)+COALESCE(facebookAds,0)) as advCost,
        SUM(COALESCE(shipping,0)) as shippingCost, SUM(COALESCE(refundCost,0)) as refundCost,
        SUM(COALESCE(amazonFees,0)) as amazonFees, SUM(COALESCE(costOfGoods,0)) as cogs,
        SUM(COALESCE(netProfit,0)) as netProfit, SUM(COALESCE(estimatedPayout,0)) as estPayout,
        SUM(COALESCE(sessions,0)) as sessions, SUM(COALESCE(grossProfit,0)) as grossProfit
        FROM seller_board_day ${f.w}`, f.p);
    }
    const r = rows[0] || {};
    const sales = parseFloat(r.sales)||0, np = parseFloat(r.netProfit)||0;
    res.json({
      sales, units: parseInt(r.units)||0, orders: parseInt(r.orders)||0, refunds: parseInt(r.refunds)||0,
      advCost: parseFloat(r.advCost)||0, shippingCost: parseFloat(r.shippingCost)||0,
      refundCost: parseFloat(r.refundCost)||0, amazonFees: parseFloat(r.amazonFees)||0,
      cogs: parseFloat(r.cogs)||0, netProfit: np, estPayout: parseFloat(r.estPayout)||0,
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
      rows = await q(`SELECT p.date, SUM(p.salesOrganic+p.salesPPC) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit, SUM(p.unitsOrganic+p.unitsPPC) as units
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.date ORDER BY p.date`, f.p);
    } else {
      const f = dWhere(s, e, accId);
      rows = await q(`SELECT date, SUM(salesOrganic+salesPPC) as revenue, SUM(netProfit) as netProfit, SUM(unitsOrganic+unitsPPC) as units
        FROM seller_board_day ${f.w} GROUP BY date ORDER BY date`, f.p);
    }
    res.json(rows);
  } catch (e) { console.error('exec/daily:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ PRODUCT ASINS ═══════════ */
app.get('/api/product/asins', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    const f = pWhere(s, e, accId, seller, af);
    const rows = await q(`SELECT p.asin, a.store as brand, a.seller,
      SUM(p.salesOrganic+p.salesPPC) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
      SUM(p.unitsOrganic+p.unitsPPC) as units, AVG(p.realACOS) as acos,
      AVG(p.sessions) as sessions, AVG(p.unitSessionPercentage) as cr
      FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin
      ${f.w} GROUP BY p.asin, a.store, a.seller ORDER BY revenue DESC LIMIT 500`, f.p);
    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue)||0, np = parseFloat(r.netProfit)||0;
      return { asin: r.asin, brand: r.brand||'', seller: r.seller||'', revenue: rev, netProfit: np, units: parseInt(r.units)||0,
        margin: rev>0?(np/rev*100):0, acos: parseFloat(r.acos)||0, roas: parseFloat(r.acos)>0?(100/parseFloat(r.acos)):0, cr: parseFloat(r.cr)||0 };
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
      rows = await q(`SELECT p.accountId, SUM(p.salesOrganic+p.salesPPC) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(p.unitsOrganic+p.unitsPPC) as units, 0 as orders
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p);
    } else {
      const f = dWhere(s, e, accId);
      rows = await q(`SELECT accountId, SUM(salesOrganic+salesPPC) as revenue, SUM(netProfit) as netProfit,
        SUM(unitsOrganic+unitsPPC) as units, SUM(orders) as orders
        FROM seller_board_day ${f.w} GROUP BY accountId ORDER BY revenue DESC`, f.p);
    }
    let stockMap = {};
    try { (await q('SELECT accountId, SUM(CAST(available AS SIGNED)) as fba FROM fba_iventory_planning WHERE date=(SELECT MAX(date) FROM fba_iventory_planning) GROUP BY accountId')).forEach(s=>{stockMap[s.accountId]=s.fba;}); } catch(e){}
    res.json(rows.map(r => {
      const rev=parseFloat(r.revenue)||0, np=parseFloat(r.netProfit)||0;
      return { shop: shopMap[r.accountId]||`Account ${r.accountId}`, revenue: rev, netProfit: np, units: parseInt(r.units)||0, orders: parseInt(r.orders)||0, margin: rev>0?(np/rev*100):0, fbaStock: parseInt(stockMap[r.accountId])||0 };
    }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ TEAM ═══════════ */
app.get('/api/team', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccId(store);
    console.log('Team:', { s, e, seller, store, af, accId });
    // 2 fast queries instead of 1 slow JOIN
    const sellerMap = {};
    (await q("SELECT asin, COALESCE(NULLIF(seller,''), 'Unassigned') as seller FROM asin")).forEach(r=>{sellerMap[r.asin]=r.seller;});
    let w = 'WHERE date BETWEEN ? AND ?'; const params = [s, e];
    if (af && af !== 'All') { w += ' AND asin = ?'; params.push(af); }
    if (accId) { w += ' AND accountId = ?'; params.push(accId); }
    const rows = await q(`SELECT asin, SUM(salesOrganic+salesPPC) as revenue, SUM(COALESCE(netProfit,0)) as netProfit, SUM(unitsOrganic+unitsPPC) as units FROM seller_board_product ${w} GROUP BY asin`, params);
    const agg = {};
    rows.forEach(r => {
      const sl = sellerMap[r.asin] || 'Unassigned';
      if (seller && seller !== 'All' && sl !== seller) return;
      if (!agg[sl]) agg[sl] = { revenue: 0, netProfit: 0, units: 0, asins: new Set() };
      agg[sl].revenue += parseFloat(r.revenue)||0;
      agg[sl].netProfit += parseFloat(r.netProfit)||0;
      agg[sl].units += parseInt(r.units)||0;
      agg[sl].asins.add(r.asin);
    });
    const result = Object.entries(agg).map(([sl,d])=>({
      seller: sl, revenue: d.revenue, netProfit: d.netProfit, units: d.units,
      margin: d.revenue>0?(d.netProfit/d.revenue*100):0, asinCount: d.asins.size,
    })).sort((a,b)=>b.revenue-a.revenue).slice(0,100);
    console.log('Team returned', result.length, 'sellers');
    res.json(result);
  } catch (e) { console.error('TEAM:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ INVENTORY ═══════════ */
app.get('/api/inventory/snapshot', async (req, res) => {
  try {
    const accId = await storeToAccId(req.query.store);
    let extra = ''; const params = [];
    if (accId) { extra = ' AND accountId = ?'; params.push(accId); }
    const rows = await q(`SELECT
      SUM(CAST(available AS SIGNED)) as fbaStock,
      SUM(CAST(available AS SIGNED)+COALESCE(totalReservedQuantity,0)+COALESCE(inboundQuantity,0)) as totalInventory,
      SUM(COALESCE(totalReservedQuantity,0)) as reserved, SUM(COALESCE(inboundQuantity,0)) as inbound,
      COUNT(DISTINCT CASE WHEN daysOfSupply<=7 THEN sku END) as criticalSkus,
      AVG(COALESCE(daysOfSupply,0)) as avgDaysOfSupply,
      SUM(COALESCE(invAge91To180Days,0)) as a91, SUM(COALESCE(invAge181To270Days,0)) as a181,
      SUM(COALESCE(invAge271To365Days,0)) as a271, SUM(COALESCE(invAge365PlusDays,0)) as a365,
      SUM(COALESCE(estimatedStorageCostNextMonth,0)) as storageFee,
      AVG(COALESCE(sellThrough,0)) as avgSellThrough
      FROM fba_iventory_planning WHERE date=(SELECT MAX(date) FROM fba_iventory_planning)${extra}`, params);
    const r = rows[0]||{};
    const fba=parseInt(r.fbaStock)||0, a91=parseInt(r.a91)||0, a181=parseInt(r.a181)||0, a271=parseInt(r.a271)||0, a365=parseInt(r.a365)||0;
    res.json({ fbaStock: fba, availableInv: fba, totalInventory: parseInt(r.totalInventory)||0, reserved: parseInt(r.reserved)||0, inbound: parseInt(r.inbound)||0,
      criticalSkus: parseInt(r.criticalSkus)||0, avgDaysOfSupply: Math.round(parseFloat(r.avgDaysOfSupply)||0),
      age0_90: Math.max(0,fba-a91-a181-a271-a365), age91_180: a91, age181_270: a181, age271_365: a271, age365plus: a365,
      storageFee: parseFloat(r.storageFee)||0, avgSellThrough: parseFloat(r.avgSellThrough)||0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/stock-trend', async (req, res) => {
  try { res.json(await q('SELECT date, SUM(FBAStock) as fbaStock FROM seller_board_stock_daily WHERE date>=DATE_SUB(CURDATE(), INTERVAL 60 DAY) GROUP BY date ORDER BY date')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/by-shop', async (req, res) => {
  try {
    const shopMap = await getShopMap();
    const inv = await q('SELECT f.accountId, SUM(CAST(f.available AS SIGNED)) as fba, SUM(COALESCE(f.inboundQuantity,0)) as inb, SUM(COALESCE(f.totalReservedQuantity,0)) as res, COUNT(DISTINCT CASE WHEN f.daysOfSupply<=7 THEN f.sku END) as crit, AVG(COALESCE(f.sellThrough,0)) as st, AVG(COALESCE(f.daysOfSupply,0)) as dos FROM fba_iventory_planning f WHERE f.date=(SELECT MAX(date) FROM fba_iventory_planning) GROUP BY f.accountId').catch(()=>[]);
    const ids = new Set(inv.map(r=>r.accountId));
    let stk = []; try { stk = await q('SELECT accountId, SUM(FBAStock) as fba FROM seller_board_stock_daily WHERE date=(SELECT MAX(date) FROM seller_board_stock_daily) GROUP BY accountId'); } catch(e){}
    const combined = inv.map(r=>({ shop: shopMap[r.accountId]||`Account ${r.accountId}`, fbaStock: parseInt(r.fba)||0, inbound: parseInt(r.inb)||0, reserved: parseInt(r.res)||0, criticalSkus: parseInt(r.crit)||0, sellThrough: parseFloat(r.st)||0, daysOfSupply: parseFloat(r.dos)||0 }));
    stk.forEach(r=>{ if(!ids.has(r.accountId)) combined.push({ shop: shopMap[r.accountId]||`Account ${r.accountId}`, fbaStock: parseInt(r.fba)||0, inbound:0, reserved:0, criticalSkus:0, sellThrough:0, daysOfSupply:0 }); });
    combined.sort((a,b)=>b.fbaStock-a.fbaStock);
    res.json(combined);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ ASIN PLAN ═══════════ */
const MS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const METRICS_MAP = {
  // Exact DB values (from asin_plan table)
  Rev:'rv', Unit:'un', Ads:'ad', GP:'gp', NP:'gp',
  Session:'se', Impression:'im', CR:'cr', CTR:'ct',
  Price:'pr', CPM:'cpm', CPC:'cpc', Cogs:'cg', 'AMZ fee':'af', 'Gross Profit':'gp',
  // Lowercase variants
  rev:'rv', unit:'un', ads:'ad', gp:'gp', np:'gp',
  session:'se', impression:'im', cr:'cr', ctr:'ct',
  price:'pr', cpm:'cpm', cpc:'cpc', cogs:'cg', 'amz fee':'af', 'gross profit':'gp',
  // Full names
  revenue:'rv', Revenue:'rv', units:'un', Units:'un',
  grossProfit:'gp', adSpend:'ad', 'Ad Spend':'ad',
  sessions:'se', Sessions:'se', impressions:'im', Impressions:'im',
};
function mapMetric(m) {
  if (!m) return null;
  const mapped = METRICS_MAP[m]||METRICS_MAP[m.toLowerCase()]||METRICS_MAP[m.trim()];
  if (mapped) return mapped;
  const lm = m.toLowerCase().trim();
  if (lm.includes('revenue')||lm.includes('sales')||lm==='rv'||lm==='rev') return 'rv';
  if (lm==='gp'||lm==='np'||(lm.includes('gross')&&lm.includes('profit'))||(lm.includes('net')&&lm.includes('profit'))) return 'gp';
  if (lm==='ads'||lm==='ad spend'||lm==='adspend') return 'ad';
  if (lm.includes('unit')||lm==='un') return 'un';
  if (lm.includes('session')||lm==='se') return 'se';
  if (lm.includes('impression')||lm==='im') return 'im';
  if (lm==='cr'||lm==='conversion'||lm==='conv. rate') return 'cr';
  if (lm==='ctr'||lm==='click') return 'ct';
  if (lm==='price'||lm==='pr') return 'pr';
  if (lm==='cpm') return 'cpm';
  if (lm==='cpc') return 'cpc';
  if (lm==='cogs'||lm==='cost of goods') return 'cg';
  if (lm.includes('amz')||lm.includes('amazon fee')) return 'af';
  console.log('Unknown metric:', m); return null;
}

app.get('/api/plan/data', async (req, res) => {
  try {
    const { year, month, store, seller, asin: af } = req.query;
    const yr = year || new Date().getFullYear();
    let cols; try { cols = (await q('SHOW COLUMNS FROM asin_plan')).map(c=>c.Field); } catch { return res.json({ kpi:{}, monthlyPlan:{}, asinPlan:{} }); }
    const hasYear = cols.includes('year');
    let where = hasYear ? 'WHERE ap.`year` = ?' : 'WHERE 1=1';
    let params = hasYear ? [yr] : [];
    if (month && month !== 'All') { const mn=parseInt(month); if(mn>=1&&mn<=12){where+=' AND ap.month_num = ?';params.push(mn);} }
    if (store && store !== 'All') { const accId=await storeToAccId(store); if(accId){where+=' AND ap.asin IN (SELECT DISTINCT asin FROM seller_board_product WHERE accountId=?)';params.push(accId);} }
    if (af && af !== 'All') { where += ' AND ap.asin = ?'; params.push(af); }
    if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }
    const rows = await q(`SELECT ap.asin, ap.brand_name, ap.month_num, ap.metrics, ap.value FROM asin_plan ap LEFT JOIN asin a ON ap.asin=a.asin ${where} ORDER BY ap.month_num`, params);
    const distinctMetrics = [...new Set(rows.map(r=>r.metrics))];
    console.log('Plan:', rows.length, 'rows, metrics:', distinctMetrics.map(m=>`${m}→${mapMetric(m)}`).join(', '));
    const monthlyPlan={}, asinPlan={};
    rows.forEach(r => {
      const mk=mapMetric(r.metrics); if(!mk) return;
      const mn=r.month_num, val=parseFloat(r.value)||0;
      if(!monthlyPlan[mn]) monthlyPlan[mn]={}; monthlyPlan[mn][mk]=(monthlyPlan[mn][mk]||0)+val;
      const key=r.asin; if(!asinPlan[key]) asinPlan[key]={brand:r.brand_name,months:{}}; if(!asinPlan[key].months[mn]) asinPlan[key].months[mn]={}; asinPlan[key].months[mn][mk]=(asinPlan[key].months[mn][mk]||0)+val;
    });
    const kpi={gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    Object.values(monthlyPlan).forEach(mp=>{ ['gp','rv','ad','un','se','im','cr','ct'].forEach(k=>{kpi[k].p+=mp[k]||0;}); });
    const mc=Object.keys(monthlyPlan).length||1; kpi.cr.p/=mc; kpi.ct.p/=mc;
    res.json({ kpi, monthlyPlan, asinPlan });
  } catch (e) { console.error('plan/data:', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/plan/actuals', async (req, res) => {
  try {
    const { year, store, seller, asin: af } = req.query;
    const yr = year || new Date().getFullYear();
    const accId = await storeToAccId(store);
    const f = pWhere(`${yr}-01-01`, `${yr}-12-31`, accId, seller, af);
    const rows = await q(`SELECT p.asin, a.store as brand, a.seller, MONTH(p.date) as month_num,
      SUM(p.unitsOrganic+p.unitsPPC) as units, SUM(p.salesOrganic+p.salesPPC) as revenue,
      SUM(p.sponsoredProducts+p.sponsoredDisplay+p.sponsoredBrands+COALESCE(p.sponsoredBrandsVideo,0)) as ads,
      SUM(COALESCE(p.grossProfit,0)) as grossProfit, AVG(p.sessions) as sessions, AVG(p.unitSessionPercentage) as cr
      FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w}
      GROUP BY p.asin, a.store, a.seller, MONTH(p.date) ORDER BY grossProfit DESC`, f.p);
    const monthly={}, asinData={};
    rows.forEach(r => {
      const mn=r.month_num;
      if(!monthly[mn]) monthly[mn]={rv:0,gp:0,ad:0,un:0,se:0,cr:[]};
      monthly[mn].rv+=parseFloat(r.revenue)||0; monthly[mn].gp+=parseFloat(r.grossProfit)||0; monthly[mn].ad+=parseFloat(r.ads)||0; monthly[mn].un+=parseInt(r.units)||0; monthly[mn].se+=parseFloat(r.sessions)||0; if(r.cr) monthly[mn].cr.push(parseFloat(r.cr));
      const key=r.asin; if(!asinData[key]) asinData[key]={brand:r.brand,seller:r.seller,months:{}}; if(!asinData[key].months[mn]) asinData[key].months[mn]={rv:0,gp:0,ad:0,un:0,se:0,cr:0};
      asinData[key].months[mn].rv+=parseFloat(r.revenue)||0; asinData[key].months[mn].gp+=parseFloat(r.grossProfit)||0; asinData[key].months[mn].ad+=parseFloat(r.ads)||0; asinData[key].months[mn].un+=parseInt(r.units)||0; asinData[key].months[mn].se+=parseFloat(r.sessions)||0; asinData[key].months[mn].cr=parseFloat(r.cr)||0;
    });
    const monthlyArr=[]; for(let m=1;m<=12;m++){ const d=monthly[m]||{rv:0,gp:0,ad:0,un:0,se:0,cr:[]}; const crAvg=d.cr.length?d.cr.reduce((s,v)=>s+v,0)/d.cr.length:0; monthlyArr.push({m:MS[m-1],mn:m,ra:d.rv,gpa:d.gp,aa:d.ad,ua:d.un,sa:d.se,ia:0,cra:crAvg,cta:0}); }
    const asinBreakdown=Object.entries(asinData).map(([asin,d])=>{
      const t={rv:0,gp:0,ad:0,un:0,se:0,cr:[]};
      Object.values(d.months).forEach(m=>{t.rv+=m.rv;t.gp+=m.gp;t.ad+=m.ad;t.un+=m.un;t.se+=m.se;if(m.cr)t.cr.push(m.cr);});
      const crAvg=t.cr.length?t.cr.reduce((s,v)=>s+v,0)/t.cr.length:0;
      return{a:asin,br:d.brand||'',sl:d.seller||'',ra:t.rv,ga:t.gp,aa:t.ad,ua:t.un,sa:t.se,ia:0,cra:crAvg,cta:0,months:d.months};
    }).sort((a,b)=>b.ga-a.ga);
    res.json({ monthly: monthlyArr, asinBreakdown });
  } catch (e) { console.error('plan/actuals:', e.message); res.status(500).json({ error: e.message }); }
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
      rows = await q(`SELECT p.date, SUM(p.salesOrganic+p.salesPPC) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(p.unitsOrganic+p.unitsPPC) as units, 0 as orders,
        SUM(p.sponsoredProducts+p.sponsoredDisplay+p.sponsoredBrands+COALESCE(p.sponsoredBrandsVideo,0)) as adSpend
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.date ORDER BY p.date DESC LIMIT 60`, f.p);
    } else {
      const f = dWhere(s, e, accId);
      rows = await q(`SELECT date, SUM(salesOrganic+salesPPC) as revenue, SUM(netProfit) as netProfit,
        SUM(unitsOrganic+unitsPPC) as units, SUM(orders) as orders,
        SUM(sponsoredProducts+sponsoredDisplay+sponsoredBrands+COALESCE(sponsoredBrandsVideo,0)) as adSpend
        FROM seller_board_day ${f.w} GROUP BY date ORDER BY date DESC LIMIT 60`, f.p);
    }
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ AI INSIGHT ═══════════ */
app.post('/api/ai/insight', async (req, res) => {
  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(400).json({ error: 'No API key' });
    const { context, question } = req.body;
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST', headers:{'Content-Type':'application/json','x-api-key':apiKey,'anthropic-version':'2023-06-01'},
      body: JSON.stringify({ model:'claude-sonnet-4-20250514', max_tokens:1500, system:'You are an Amazon FBA analyst. Give actionable insights in 300-500 words.',
        messages:[{role:'user',content:`Data:\n${JSON.stringify(context,null,2)}\n\n${question||'Analyze.'}`}] }),
    });
    const data = await r.json();
    res.json({ insight: data.content?.[0]?.text || 'Unable to generate' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ═══════════ SERVE FRONTEND ═══════════ */
const distPath = join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (req, res) => { res.sendFile(join(distPath, 'index.html')); });
app.listen(PORT, '0.0.0.0', () => { console.log(`\n🚀 Dashboard ${VER} on :${PORT} | DB: ${process.env.DB_HOST||'none'}\n`); });
