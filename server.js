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
const VER = 'v3.8-2026-03-02';
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
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w}`, f.p, 45000);
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
      rows = await q(`SELECT p.date, SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit, SUM(${P_UNITS}) as units
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.date ORDER BY p.date`, f.p, 45000);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT sc.date, SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.netProfit,0)) as netProfit, SUM(${SC_UNITS}) as units
        FROM ${salesFrom()} ${f.w} GROUP BY sc.date ORDER BY sc.date`, f.p, 45000);
    }
    console.log('exec/daily:', rows?.length||0, 'rows');
    res.json(rows || []);
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
      FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin
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
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p);
    } else {
      const f = scWhere(s, e, accId);
      rows = await q(`SELECT sc.accountId, SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.netProfit,0)) as netProfit,
        SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders
        FROM ${salesFrom()} ${f.w} GROUP BY sc.accountId ORDER BY revenue DESC`, f.p, 45000);
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
    let w = 'WHERE p.date BETWEEN ? AND ?'; const params = [s, e];
    if (af && af !== 'All') { w += ' AND p.asin = ?'; params.push(af); }
    if (accId) { w += ' AND p.accountId = ?'; params.push(accId); }
    if (seller && seller !== 'All') { w += " AND COALESCE(NULLIF(a.seller,''),'Unassigned') = ?"; params.push(seller); }
    const rows = await q(`SELECT COALESCE(NULLIF(a.seller,''),'Unassigned') as seller,
      SUM(COALESCE(p.salesOrganic,0)+COALESCE(p.salesPPC,0)) as revenue,
      SUM(COALESCE(p.netProfit,0)) as netProfit,
      SUM(COALESCE(p.unitsOrganic,0)+COALESCE(p.unitsPPC,0)) as units,
      COUNT(DISTINCT p.asin) as asinCount
      FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin
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
    if (accId) { extra = ' AND accountId = ?'; params.push(accId); }
    const rows = await q(`SELECT
      SUM(CAST(available AS SIGNED)) as availableInv,
      SUM(COALESCE(totalReservedQuantity,0)) as reserved, SUM(COALESCE(inboundQuantity,0)) as inbound,
      COUNT(DISTINCT CASE WHEN daysOfSupply<=7 THEN sku END) as criticalSkus,
      AVG(COALESCE(daysOfSupply,0)) as avgDaysOfSupply,
      SUM(COALESCE(invAge0To90Days,0)) as a0,
      SUM(COALESCE(invAge91To180Days,0)) as a91, SUM(COALESCE(invAge181To270Days,0)) as a181,
      SUM(COALESCE(invAge271To365Days,0)) as a271, SUM(COALESCE(invAge365PlusDays,0)) as a365,
      SUM(COALESCE(estimatedStorageCostNextMonth,0)) as storageFee,
      AVG(COALESCE(sellThrough,0)) as avgSellThrough
      FROM fba_iventory_planning WHERE date=(SELECT MAX(date) FROM fba_iventory_planning)${extra}`, params);
    const r = rows[0]||{};
    const avail=parseInt(r.availableInv)||0;
    const reserved=parseInt(r.reserved)||0;
    const inbound=parseInt(r.inbound)||0;
    // FBA Stock = Available + Reserved (same source: fba_iventory_planning)
    const fbaStock = avail + reserved;
    res.json({
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
  try { res.json(await q('SELECT date, SUM(FBAStock) as fbaStock FROM seller_board_stock_daily WHERE date>=DATE_SUB(CURDATE(), INTERVAL 60 DAY) GROUP BY date ORDER BY date')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/by-shop', async (req, res) => {
  try {
    const shopMap = await getShopMap();
    const inv = await q('SELECT f.accountId, SUM(CAST(f.available AS SIGNED)) as fba, SUM(COALESCE(f.inboundQuantity,0)) as inb, SUM(COALESCE(f.totalReservedQuantity,0)) as res, COUNT(DISTINCT CASE WHEN f.daysOfSupply<=7 THEN f.sku END) as crit, AVG(COALESCE(f.sellThrough,0)) as st, AVG(COALESCE(f.daysOfSupply,0)) as dos FROM fba_iventory_planning f WHERE f.date=(SELECT MAX(date) FROM fba_iventory_planning) GROUP BY f.accountId').catch(()=>[]);
    const ids = new Set(inv.map(r=>r.accountId));
    let stk = []; try { stk = await q('SELECT accountId, SUM(FBAStock) as fba FROM seller_board_stock_daily WHERE date=(SELECT MAX(date) FROM seller_board_stock_daily) GROUP BY accountId'); } catch(e){}
    const combined = inv.map(r=>({shop:shopMap[r.accountId]||`Account ${r.accountId}`,fbaStock:parseInt(r.fba)||0,inbound:parseInt(r.inb)||0,reserved:parseInt(r.res)||0,criticalSkus:parseInt(r.crit)||0,sellThrough:parseFloat(r.st)||0,daysOfSupply:parseFloat(r.dos)||0}));
    stk.forEach(r=>{if(!ids.has(r.accountId))combined.push({shop:shopMap[r.accountId]||`Account ${r.accountId}`,fbaStock:parseInt(r.fba)||0,inbound:0,reserved:0,criticalSkus:0,sellThrough:0,daysOfSupply:0});});
    combined.sort((a,b)=>b.fbaStock-a.fbaStock);
    res.json(combined);
  } catch (e) { res.status(500).json({ error: e.message }); }
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
const METRICS_MAP={'Rev':'rv','Unit':'un','Ads':'ad','GP':'gp','NP':'gp','Session':'se','Impression':'im','CR':'cr','CTR':'ct','Price':'pr','CPM':'cpm','CPC':'cpc','Cogs':'cg','AMZ fee':'af','Gross Profit':'gp','rev':'rv','unit':'un','ads':'ad','gp':'gp','np':'gp','session':'se','impression':'im','cr':'cr','ctr':'ct','price':'pr','cpm':'cpm','cpc':'cpc','cogs':'cg','amz fee':'af','gross profit':'gp','revenue':'rv','Revenue':'rv','units':'un','Units':'un','grossProfit':'gp','adSpend':'ad','Ad Spend':'ad','sessions':'se','Sessions':'se','impressions':'im','Impressions':'im'};
function mapMetric(m) {
  if (!m) return null;
  const t = m.trim();
  if (METRICS_MAP[t]) return METRICS_MAP[t];
  const lm = t.toLowerCase();
  if (METRICS_MAP[lm]) return METRICS_MAP[lm];
  if (lm.includes('revenue')||lm.includes('sales')) return 'rv';
  if (lm==='gp'||lm==='np'||lm.includes('gross profit')||lm.includes('net profit')) return 'gp';
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
    let where = hasYear ? 'WHERE ap.`year` = ?' : 'WHERE 1=1';
    let params = hasYear ? [yr] : [];
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
      FROM asin_plan ap LEFT JOIN asin a ON ap.asin=a.asin ${where} ORDER BY ap.month_num`, params, 45000);

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
    const kpi={gp:{a:0,p:0},rv:{a:0,p:0},ad:{a:0,p:0},un:{a:0,p:0},se:{a:0,p:0},im:{a:0,p:0},cr:{a:0,p:0},ct:{a:0,p:0}};
    const crDirect=[], ctDirect=[];
    Object.values(monthlyPlan).forEach(mp => {
      ['gp','rv','ad','un','se','im'].forEach(k=>{kpi[k].p+=mp[k]||0;});
      if(mp.cr) crDirect.push(mp.cr);
      if(mp.ct) ctDirect.push(mp.ct);
    });
    // Weighted CR (preferred) or fallback direct/100
    if(kpi.se.p>0&&kpi.un.p>0) kpi.cr.p=kpi.un.p/kpi.se.p;
    else if(crDirect.length) kpi.cr.p=(crDirect.reduce((s,v)=>s+v,0)/crDirect.length)/100;
    // Weighted CTR or fallback
    if(kpi.im.p>0&&kpi.se.p>0) kpi.ct.p=kpi.se.p/kpi.im.p;
    else if(ctDirect.length) kpi.ct.p=(ctDirect.reduce((s,v)=>s+v,0)/ctDirect.length)/100;

    // Per-month plan CR/CTR (weighted per month)
    for (const mn in monthlyPlan) {
      const mp = monthlyPlan[mn];
      if (mp.un && mp.se) mp.crW = mp.un / mp.se;
      else if (mp.cr) mp.crW = mp.cr / 100;
      else mp.crW = 0;
      if (mp.se && mp.im) mp.ctW = mp.se / mp.im;
      else if (mp.ct) mp.ctW = mp.ct / 100;
      else mp.ctW = 0;
    }

    res.json({kpi,monthlyPlan,asinPlan});
  } catch (e) { console.error('plan/data ERROR:', e.message, e.stack?.split('\n')[1]); res.status(500).json({error:'Plan data: '+e.message}); }
});

app.get('/api/plan/actuals', async (req, res) => {
  try {
    const { year, store, seller, asin: af } = req.query;
    const yr = parseInt(year) || new Date().getFullYear();
    const accId = await storeToAccId(store);

    // Source 1: Revenue, GP, Units, Sessions from seller_board_sales
    let salesRows = [];
    try {
      const scF = scWhere(`${yr}-01-01`,`${yr}-12-31`,accId);
      salesRows = await q(`SELECT MONTH(sc.date) as mn,
        SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.grossProfit,0)) as gp,
        SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.sessions,0)) as sessions
        FROM ${salesFrom()} ${scF.w} GROUP BY MONTH(sc.date)`, scF.p, 45000);
    } catch(e1) { console.warn('plan/actuals sales query failed:', e1.message); }

    // Source 2: Ads from seller_board_product
    let adsRows = [];
    const pF = pWhere(`${yr}-01-01`,`${yr}-12-31`,accId,seller,af);
    try {
      adsRows = await q(`SELECT MONTH(p.date) as mn, SUM(ABS(${P_ADS})) as ads
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${pF.w} GROUP BY MONTH(p.date)`, pF.p, 45000);
    } catch(e2) { console.warn('plan/actuals ads query failed:', e2.message); }

    // Source 3: Impressions + Clicks from analytics_search_catalog_performance
    let impRows = [];
    try {
      let iw='WHERE YEAR(startDate)=?'; const ip=[yr];
      if(accId){iw+=' AND accountId=?';ip.push(accId);}
      impRows = await q(`SELECT MONTH(startDate) as mn, SUM(COALESCE(impressionCount,0)) as imp, SUM(COALESCE(clickCount,0)) as clicks
        FROM analytics_search_catalog_performance ${iw} GROUP BY MONTH(startDate)`, ip, 45000);
    } catch(e) { console.warn('analytics not available:', e.message); }

    // Merge all into monthly
    const monthly = {};
    for(let m=1;m<=12;m++) monthly[m]={rv:0,gp:0,un:0,se:0,ad:0,im:0,clicks:0};
    salesRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.rv=parseFloat(r.revenue)||0;m.gp=parseFloat(r.gp)||0;m.un=parseInt(r.units)||0;m.se=parseFloat(r.sessions)||0;});
    adsRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.ad=parseFloat(r.ads)||0;});
    impRows.forEach(r=>{const m=monthly[r.mn];if(!m)return;m.im=parseFloat(r.imp)||0;m.clicks=parseFloat(r.clicks)||0;});

    const monthlyArr=[];
    for(let m=1;m<=12;m++){
      const d=monthly[m];
      const cr=d.se>0?d.un/d.se:0;
      const ctr=d.im>0?d.clicks/d.im:0;
      monthlyArr.push({m:MS[m-1],mn:m,ra:d.rv,gpa:d.gp,aa:d.ad,ua:d.un,sa:d.se,ia:d.im,
        cra:Math.round(cr*10000)/10000, cta:Math.round(ctr*10000)/10000});
    }

    // ASIN breakdown from seller_board_product
    let asinRows = [];
    try {
      asinRows = await q(`SELECT p.asin, ap2.brand_name as planBrand, a.seller, MONTH(p.date) as mn,
      SUM(${P_SALES}) as revenue, SUM(COALESCE(p.grossProfit,0)) as gp,
      SUM(${P_UNITS}) as units, SUM(COALESCE(p.sessions,0)) as sessions, SUM(ABS(${P_ADS})) as ads
      FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin
      LEFT JOIN (SELECT DISTINCT asin, brand_name FROM asin_plan) ap2 ON p.asin=ap2.asin
      ${pF.w} GROUP BY p.asin, ap2.brand_name, a.seller, MONTH(p.date) ORDER BY gp DESC`, pF.p, 45000);
    } catch(e3) { console.warn('plan/actuals asin query failed:', e3.message); }

    const asinData={};
    asinRows.forEach(r=>{
      const key=r.asin, mn=r.mn;
      if(!asinData[key]) asinData[key]={brand:r.planBrand||'',seller:r.seller||'',months:{}};
      if(!asinData[key].months[mn]) asinData[key].months[mn]={rv:0,gp:0,ad:0,un:0,se:0,im:0,cr:0,ct:0};
      const md=asinData[key].months[mn];
      md.rv+=parseFloat(r.revenue)||0;md.gp+=parseFloat(r.gp)||0;md.ad+=parseFloat(r.ads)||0;
      md.un+=parseInt(r.units)||0;md.se+=parseFloat(r.sessions)||0;
      md.cr=md.se>0?md.un/md.se:0;
    });

    const asinBreakdown=Object.entries(asinData).map(([asin,d])=>{
      const t={rv:0,gp:0,ad:0,un:0,se:0,im:0};
      Object.values(d.months).forEach(m=>{t.rv+=m.rv;t.gp+=m.gp;t.ad+=m.ad;t.un+=m.un;t.se+=m.se;});
      const cr=t.se>0?t.un/t.se:0;
      return{a:asin,br:d.brand,sl:d.seller,ra:t.rv,ga:t.gp,aa:t.ad,ua:t.un,sa:t.se,ia:t.im,
        cra:Math.round(cr*10000)/10000,cta:0,months:d.months};
    }).sort((a,b)=>b.ga-a.ga);

    res.json({monthly:monthlyArr,asinBreakdown});
  } catch (e) { console.error('plan/actuals:', e.message); res.status(500).json({error:e.message}); }
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
        FROM seller_board_product p LEFT JOIN asin a ON p.asin=a.asin ${f.w} GROUP BY p.date ORDER BY p.date DESC LIMIT 60`, f.p);
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
    if (!apiKey) return res.status(400).json({ error: 'No API key' });
    const { context, question } = req.body;
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST', headers:{'Content-Type':'application/json','x-api-key':apiKey,'anthropic-version':'2023-06-01'},
      body: JSON.stringify({model:'claude-sonnet-4-20250514',max_tokens:1500,system:'You are an Amazon FBA analyst. Give actionable insights in 300-500 words.',
        messages:[{role:'user',content:`Data:\n${JSON.stringify(context,null,2)}\n\n${question||'Analyze.'}`}]}),
    });
    const data = await r.json();
    res.json({insight:data.content?.[0]?.text||'Unable to generate'});
  } catch (e) { res.status(500).json({error:e.message}); }
});

/* ═══════════ SERVE FRONTEND ═══════════ */
const distPath = join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (req, res) => { res.sendFile(join(distPath, 'index.html')); });
app.listen(PORT, '0.0.0.0', () => { console.log(`\n🚀 Dashboard ${VER} on :${PORT} | DB: ${process.env.DB_HOST||'none'}\n`); });
