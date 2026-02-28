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
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/* ═══════════ DATABASE POOL ═══════════ */
let pool = null;
try {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'expeditee',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 10000,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  });
  console.log('✅ MySQL pool created');
} catch (e) {
  console.warn('⚠️ MySQL pool failed:', e.message);
}

async function q(sql, params = []) {
  if (!pool) throw new Error('Database not connected');
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/* ═══════════ HELPERS ═══════════ */
async function getShopMap() {
  const rows = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL');
  const map = {};
  rows.forEach(r => { map[r.id] = r.shop; });
  return map;
}

// Reverse: shopName → accountId
async function getShopReverseMap() {
  const rows = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL');
  const map = {};
  rows.forEach(r => { map[r.shop] = r.id; });
  return map;
}

// Build WHERE + params for entity filters on seller_board_product p + asin a
function entityWhere(query, baseWhere = '', baseParams = []) {
  let where = baseWhere;
  const params = [...baseParams];
  const { store, seller, brand, asin: af } = query;
  // store filter handled separately (needs accountId)
  if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }
  if (brand && brand !== 'All') { where += ' AND a.store = ?'; params.push(brand); }
  if (af && af !== 'All') { where += ' AND p.asin = ?'; params.push(af); }
  return { where, params };
}

/* ═══════════ HEALTH CHECK ═══════════ */
app.get('/api/health', async (req, res) => {
  try {
    if (pool) {
      await q('SELECT 1');
      res.json({ status: 'ok', database: 'connected' });
    } else {
      res.json({ status: 'ok', database: 'not configured' });
    }
  } catch (e) {
    res.json({ status: 'ok', database: 'error: ' + e.message });
  }
});

/* ═══════════ DATE RANGE ═══════════ */
app.get('/api/date-range', async (req, res) => {
  try {
    const rows = await q(`
      SELECT MIN(date) as minDate, MAX(date) as maxDate FROM seller_board_day
    `);
    const r = rows[0] || {};
    const maxDate = r.maxDate ? new Date(r.maxDate).toISOString().slice(0, 10) : null;
    const minDate = r.minDate ? new Date(r.minDate).toISOString().slice(0, 10) : null;
    // Default: last 30 days up to maxDate
    let defaultStart = null;
    if (maxDate) {
      const d = new Date(maxDate);
      d.setDate(d.getDate() - 29);
      defaultStart = d.toISOString().slice(0, 10);
      if (minDate && defaultStart < minDate) defaultStart = minDate;
    }
    res.json({ minDate, maxDate, defaultStart, defaultEnd: maxDate });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ FILTERS ═══════════ */
app.get('/api/filters', async (req, res) => {
  try {
    const shops = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL ORDER BY shop');
    const sellers = await q('SELECT DISTINCT seller FROM asin WHERE seller IS NOT NULL AND seller != "" ORDER BY seller');
    const brands = await q('SELECT DISTINCT store FROM asin WHERE store IS NOT NULL AND store != "" ORDER BY store');
    
    // Get ASIN → shop mapping from seller_board_product (which shop sells which ASIN)
    const asinShops = await q(`
      SELECT DISTINCT p.asin, p.accountId
      FROM seller_board_product p
      WHERE p.date >= DATE_SUB(CURDATE(), INTERVAL 90 DAY)
    `);
    const shopMap = {};
    shops.forEach(s => { shopMap[s.id] = s.shop; });
    const asinShopMap = {};
    asinShops.forEach(r => {
      if (!asinShopMap[r.asin]) asinShopMap[r.asin] = [];
      const sn = shopMap[r.accountId];
      if (sn && !asinShopMap[r.asin].includes(sn)) asinShopMap[r.asin].push(sn);
    });

    const asins = await q('SELECT DISTINCT a.asin, a.seller, a.store FROM asin a ORDER BY a.store, a.asin');
    res.json({
      shops: shops.map(s => ({ id: s.id, name: s.shop })),
      sellers: sellers.map(s => s.seller),
      brands: brands.map(b => b.store),
      asins: asins.map(a => ({
        asin: a.asin, seller: a.seller, brand: a.store,
        shops: asinShopMap[a.asin] || [],
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ EXEC SUMMARY ═══════════ */
app.get('/api/exec/summary', async (req, res) => {
  try {
    const { start, end, store, seller, brand, asin: af } = req.query;
    const s = start || '2025-01-01', e2 = end || '2025-01-31';
    const hasEntity = (seller && seller !== 'All') || (brand && brand !== 'All') || (af && af !== 'All');
    const hasStore = store && store !== 'All';

    let rows;
    if (hasEntity) {
      // Use seller_board_product for ASIN-level filtering
      let where = 'WHERE p.date BETWEEN ? AND ?';
      const params = [s, e2];
      if (hasStore) {
        const rm = await getShopReverseMap();
        const accId = rm[store];
        if (accId) { where += ' AND p.accountId = ?'; params.push(accId); }
      }
      const ew = entityWhere(req.query, where, params);
      rows = await q(`
        SELECT
          SUM(p.salesOrganic + p.salesPPC) as sales,
          SUM(p.unitsOrganic + p.unitsPPC) as units,
          0 as orders,
          SUM(COALESCE(p.refunds,0)) as refunds,
          SUM(p.sponsoredProducts + p.sponsoredDisplay + p.sponsoredBrands + COALESCE(p.sponsoredBrandsVideo,0) + COALESCE(p.googleAds,0) + COALESCE(p.facebookAds,0)) as advCost,
          0 as shippingCost,
          0 as refundCost,
          SUM(COALESCE(p.amazonFees,0)) as amazonFees,
          SUM(COALESCE(p.costOfGoods,0)) as cogs,
          SUM(COALESCE(p.netProfit,0)) as netProfit,
          SUM(COALESCE(p.estimatedPayout,0)) as estPayout,
          SUM(COALESCE(p.sessions,0)) as sessions,
          SUM(COALESCE(p.grossProfit,0)) as grossProfit
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin = a.asin
        ${ew.where}
      `, ew.params);
    } else if (hasStore) {
      // Store-only filter on seller_board_day
      const rm = await getShopReverseMap();
      const accId = rm[store];
      rows = await q(`
        SELECT
          SUM(salesOrganic + salesPPC) as sales,
          SUM(unitsOrganic + unitsPPC) as units,
          SUM(orders) as orders,
          SUM(refunds) as refunds,
          SUM(sponsoredProducts + sponsoredDisplay + sponsoredBrands + sponsoredBrandsVideo + COALESCE(googleAds,0) + COALESCE(facebookAds,0)) as advCost,
          SUM(COALESCE(shipping,0)) as shippingCost,
          SUM(COALESCE(refundCost,0)) as refundCost,
          SUM(COALESCE(amazonFees,0)) as amazonFees,
          SUM(COALESCE(costOfGoods,0)) as cogs,
          SUM(COALESCE(netProfit,0)) as netProfit,
          SUM(COALESCE(estimatedPayout,0)) as estPayout,
          SUM(COALESCE(sessions,0)) as sessions,
          SUM(COALESCE(grossProfit,0)) as grossProfit
        FROM seller_board_day
        WHERE date BETWEEN ? AND ? AND accountId = ?
      `, [s, e2, accId || -1]);
    } else {
      // No filters — use seller_board_day (fast)
      rows = await q(`
        SELECT
          SUM(salesOrganic + salesPPC) as sales,
          SUM(unitsOrganic + unitsPPC) as units,
          SUM(orders) as orders,
          SUM(refunds) as refunds,
          SUM(sponsoredProducts + sponsoredDisplay + sponsoredBrands + sponsoredBrandsVideo + COALESCE(googleAds,0) + COALESCE(facebookAds,0)) as advCost,
          SUM(COALESCE(shipping,0)) as shippingCost,
          SUM(COALESCE(refundCost,0)) as refundCost,
          SUM(COALESCE(amazonFees,0)) as amazonFees,
          SUM(COALESCE(costOfGoods,0)) as cogs,
          SUM(COALESCE(netProfit,0)) as netProfit,
          SUM(COALESCE(estimatedPayout,0)) as estPayout,
          SUM(COALESCE(sessions,0)) as sessions,
          SUM(COALESCE(grossProfit,0)) as grossProfit
        FROM seller_board_day
        WHERE date BETWEEN ? AND ?
      `, [s, e2]);
    }

    const r = rows[0] || {};
    const sales = parseFloat(r.sales) || 0;
    const np = parseFloat(r.netProfit) || 0;
    res.json({
      sales, units: parseInt(r.units) || 0, orders: parseInt(r.orders) || 0, refunds: parseInt(r.refunds) || 0,
      advCost: parseFloat(r.advCost) || 0,
      shippingCost: parseFloat(r.shippingCost) || 0,
      refundCost: parseFloat(r.refundCost) || 0,
      amazonFees: parseFloat(r.amazonFees) || 0,
      cogs: parseFloat(r.cogs) || 0,
      netProfit: np,
      estPayout: parseFloat(r.estPayout) || 0,
      grossProfit: parseFloat(r.grossProfit) || 0,
      sessions: parseFloat(r.sessions) || 0,
      realAcos: sales > 0 ? (Math.abs(parseFloat(r.advCost) || 0) / sales * 100) : 0,
      pctRefunds: (parseInt(r.orders) || 0) > 0 ? ((parseInt(r.refunds) || 0) / parseInt(r.orders) * 100) : 0,
      margin: sales > 0 ? (np / sales * 100) : 0,
    });
  } catch (e) {
    console.error('exec/summary error:', e);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ EXEC DAILY ═══════════ */
app.get('/api/exec/daily', async (req, res) => {
  try {
    const { start, end, store, seller, brand, asin: af } = req.query;
    const s = start || '2025-01-01', e2 = end || '2025-01-31';
    const hasEntity = (seller && seller !== 'All') || (brand && brand !== 'All') || (af && af !== 'All');
    const hasStore = store && store !== 'All';

    let rows;
    if (hasEntity) {
      let where = 'WHERE p.date BETWEEN ? AND ?';
      const params = [s, e2];
      if (hasStore) {
        const rm = await getShopReverseMap();
        const accId = rm[store];
        if (accId) { where += ' AND p.accountId = ?'; params.push(accId); }
      }
      const ew = entityWhere(req.query, where, params);
      rows = await q(`
        SELECT p.date,
          SUM(p.salesOrganic + p.salesPPC) as revenue,
          SUM(p.netProfit) as netProfit,
          SUM(p.unitsOrganic + p.unitsPPC) as units
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin = a.asin
        ${ew.where}
        GROUP BY p.date ORDER BY p.date
      `, ew.params);
    } else if (hasStore) {
      const rm = await getShopReverseMap();
      const accId = rm[store];
      rows = await q(`
        SELECT date,
          SUM(salesOrganic + salesPPC) as revenue,
          SUM(netProfit) as netProfit,
          SUM(unitsOrganic + unitsPPC) as units
        FROM seller_board_day
        WHERE date BETWEEN ? AND ? AND accountId = ?
        GROUP BY date ORDER BY date
      `, [s, e2, accId || -1]);
    } else {
      rows = await q(`
        SELECT date,
          SUM(salesOrganic + salesPPC) as revenue,
          SUM(netProfit) as netProfit,
          SUM(unitsOrganic + unitsPPC) as units
        FROM seller_board_day
        WHERE date BETWEEN ? AND ?
        GROUP BY date ORDER BY date
      `, [s, e2]);
    }
    res.json(rows);
  } catch (e) {
    console.error('exec/daily error:', e);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ PRODUCT / ASINS ═══════════ */
app.get('/api/product/asins', async (req, res) => {
  try {
    const { start, end, store, seller, brand, asin: af } = req.query;
    let where = 'WHERE p.date BETWEEN ? AND ?';
    const params = [start || '2025-01-01', end || '2025-01-31'];
    if (store && store !== 'All') {
      const rm = await getShopReverseMap();
      const accId = rm[store];
      if (accId) { where += ' AND p.accountId = ?'; params.push(accId); }
    }
    if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }
    if (brand && brand !== 'All') { where += ' AND a.store = ?'; params.push(brand); }
    if (af && af !== 'All') { where += ' AND p.asin = ?'; params.push(af); }

    const rows = await q(`
      SELECT p.asin, a.store as brand, a.seller,
        SUM(p.salesOrganic + p.salesPPC) as revenue,
        SUM(p.netProfit) as netProfit,
        SUM(p.unitsOrganic + p.unitsPPC) as units,
        AVG(p.margin) as margin,
        AVG(p.realACOS) as acos,
        AVG(p.sessions) as sessions,
        AVG(p.unitSessionPercentage) as cr
      FROM seller_board_product p
      LEFT JOIN asin a ON p.asin = a.asin
      ${where}
      GROUP BY p.asin, a.store, a.seller
      ORDER BY revenue DESC
      LIMIT 500
    `, params);

    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue) || 0;
      const np = parseFloat(r.netProfit) || 0;
      return {
        asin: r.asin, brand: r.brand || '', seller: r.seller || '',
        revenue: rev, netProfit: np, units: parseInt(r.units) || 0,
        margin: rev > 0 ? (np / rev * 100) : 0,
        acos: parseFloat(r.acos) || 0,
        roas: parseFloat(r.acos) > 0 ? (100 / parseFloat(r.acos)) : 0,
        cr: parseFloat(r.cr) || 0, sessions: parseFloat(r.sessions) || 0,
      };
    }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ SHOPS ═══════════ */
app.get('/api/shops', async (req, res) => {
  try {
    const { start, end, store, seller } = req.query;
    const shopMap = await getShopMap();
    let where = 'WHERE p.date BETWEEN ? AND ?';
    const params = [start || '2025-01-01', end || '2025-01-31'];
    if (store && store !== 'All') {
      const accId = Object.entries(shopMap).find(([k, v]) => v === store)?.[0];
      if (accId) { where += ' AND p.accountId = ?'; params.push(accId); }
    }

    const rows = await q(`
      SELECT p.accountId,
        SUM(p.salesOrganic + p.salesPPC) as revenue,
        SUM(p.netProfit) as netProfit,
        SUM(p.unitsOrganic + p.unitsPPC) as units,
        SUM(p.orders) as orders
      FROM seller_board_day p
      ${where}
      GROUP BY p.accountId ORDER BY revenue DESC
    `, params);

    let stockMap = {};
    try {
      const stocks = await q(`
        SELECT accountId, SUM(CAST(available AS SIGNED)) as fbaStock
        FROM fba_iventory_planning
        WHERE date = (SELECT MAX(date) FROM fba_iventory_planning)
        GROUP BY accountId
      `);
      stocks.forEach(s => { stockMap[s.accountId] = s.fbaStock; });
    } catch (e) { /* ignore */ }

    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue) || 0;
      const np = parseFloat(r.netProfit) || 0;
      return {
        shop: shopMap[r.accountId] || `Account ${r.accountId}`,
        revenue: rev, netProfit: np, units: parseInt(r.units) || 0, orders: parseInt(r.orders) || 0,
        margin: rev > 0 ? (np / rev * 100) : 0,
        fbaStock: parseInt(stockMap[r.accountId]) || 0,
      };
    }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ TEAM ═══════════ */
app.get('/api/team', async (req, res) => {
  try {
    const { start, end, seller, store } = req.query;
    let where = 'WHERE p.date BETWEEN ? AND ?';
    const params = [start || '2025-01-01', end || '2025-01-31'];
    if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }
    if (store && store !== 'All') {
      const rm = await getShopReverseMap();
      const accId = rm[store];
      if (accId) { where += ' AND p.accountId = ?'; params.push(accId); }
    }

    const rows = await q(`
      SELECT a.seller,
        SUM(p.salesOrganic + p.salesPPC) as revenue,
        SUM(p.netProfit) as netProfit,
        SUM(p.unitsOrganic + p.unitsPPC) as units,
        COUNT(DISTINCT p.asin) as asinCount
      FROM seller_board_product p
      LEFT JOIN asin a ON p.asin = a.asin
      ${where}
      AND a.seller IS NOT NULL AND a.seller != ''
      GROUP BY a.seller ORDER BY revenue DESC
    `, params);

    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue) || 0;
      const np = parseFloat(r.netProfit) || 0;
      return {
        seller: r.seller, revenue: rev, netProfit: np, units: parseInt(r.units) || 0,
        margin: rev > 0 ? (np / rev * 100) : 0, asinCount: parseInt(r.asinCount) || 0,
      };
    }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ INVENTORY ═══════════ */
app.get('/api/inventory/snapshot', async (req, res) => {
  try {
    const rows = await q(`
      SELECT
        SUM(CAST(available AS SIGNED)) as fbaStock,
        SUM(CAST(available AS SIGNED) + COALESCE(totalReservedQuantity,0) + COALESCE(inboundQuantity,0)) as totalInventory,
        SUM(COALESCE(totalReservedQuantity,0)) as reserved,
        SUM(COALESCE(inboundQuantity,0)) as inbound,
        SUM(CASE WHEN daysOfSupply <= 7 AND CAST(available AS SIGNED) > 0 THEN 1 ELSE 0 END) as criticalSkus,
        AVG(COALESCE(daysOfSupply,0)) as avgDaysOfSupply,
        SUM(COALESCE(invAge91To180Days,0)) as age91_180,
        SUM(COALESCE(invAge181To270Days,0)) as age181_270,
        SUM(COALESCE(invAge271To365Days,0)) as age271_365,
        SUM(COALESCE(invAge365PlusDays,0)) as age365plus,
        SUM(COALESCE(estimatedStorageCostNextMonth,0)) as storageFee,
        AVG(COALESCE(sellThrough,0)) as avgSellThrough
      FROM fba_iventory_planning
      WHERE date = (SELECT MAX(date) FROM fba_iventory_planning)
    `);
    const r = rows[0] || {};
    const fba = parseInt(r.fbaStock) || 0;
    const a91 = parseInt(r.age91_180) || 0;
    const a181 = parseInt(r.age181_270) || 0;
    const a271 = parseInt(r.age271_365) || 0;
    const a365 = parseInt(r.age365plus) || 0;
    const age0_90 = Math.max(0, fba - a91 - a181 - a271 - a365);
    res.json({
      fbaStock: fba,
      availableInv: fba,
      totalInventory: parseInt(r.totalInventory) || 0,
      reserved: parseInt(r.reserved) || 0,
      inbound: parseInt(r.inbound) || 0,
      criticalSkus: parseInt(r.criticalSkus) || 0,
      avgDaysOfSupply: Math.round(parseFloat(r.avgDaysOfSupply) || 0),
      age0_90,
      age91_180: a91, age181_270: a181, age271_365: a271, age365plus: a365,
      storageFee: parseFloat(r.storageFee) || 0,
      avgSellThrough: parseFloat(r.avgSellThrough) || 0,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/inventory/stock-trend', async (req, res) => {
  try {
    const rows = await q(`
      SELECT date, SUM(FBAStock) as fbaStock
      FROM seller_board_stock_daily
      WHERE date >= DATE_SUB(CURDATE(), INTERVAL 60 DAY)
      GROUP BY date ORDER BY date
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/inventory/by-shop', async (req, res) => {
  try {
    const shopMap = await getShopMap();
    // Try fba_iventory_planning first (most detailed)
    const invRows = await q(`
      SELECT f.accountId,
        SUM(CAST(f.available AS SIGNED)) as fbaStock,
        SUM(COALESCE(f.inboundQuantity,0)) as inbound,
        SUM(COALESCE(f.totalReservedQuantity,0)) as reserved,
        SUM(CASE WHEN f.daysOfSupply <= 7 AND CAST(f.available AS SIGNED) > 0 THEN 1 ELSE 0 END) as criticalSkus,
        AVG(COALESCE(f.sellThrough,0)) as sellThrough,
        AVG(COALESCE(f.daysOfSupply,0)) as daysOfSupply
      FROM fba_iventory_planning f
      WHERE f.date = (SELECT MAX(date) FROM fba_iventory_planning)
      GROUP BY f.accountId
    `).catch(() => []);
    
    // Also get stock data from seller_board_stock_daily for shops not in fba_iventory_planning
    const invAccountIds = new Set(invRows.map(r => r.accountId));
    let stockRows = [];
    try {
      stockRows = await q(`
        SELECT accountId, SUM(FBAStock) as fbaStock
        FROM seller_board_stock_daily
        WHERE date = (SELECT MAX(date) FROM seller_board_stock_daily)
        GROUP BY accountId
      `);
    } catch(e) { /* table might not exist */ }

    const combined = [...invRows.map(r => ({
      shop: shopMap[r.accountId] || `Account ${r.accountId}`,
      fbaStock: parseInt(r.fbaStock) || 0, inbound: parseInt(r.inbound) || 0, reserved: parseInt(r.reserved) || 0,
      criticalSkus: parseInt(r.criticalSkus) || 0,
      sellThrough: parseFloat(r.sellThrough) || 0,
      daysOfSupply: parseFloat(r.daysOfSupply) || 0,
    }))];
    
    // Add shops from stock_daily that aren't already in the list
    stockRows.forEach(r => {
      if (!invAccountIds.has(r.accountId)) {
        combined.push({
          shop: shopMap[r.accountId] || `Account ${r.accountId}`,
          fbaStock: parseInt(r.fbaStock) || 0, inbound: 0, reserved: 0,
          criticalSkus: 0, sellThrough: 0, daysOfSupply: 0,
        });
      }
    });

    combined.sort((a, b) => b.fbaStock - a.fbaStock);
    res.json(combined);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ ASIN PLAN ═══════════ */
const MS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const METRICS_MAP = {
  revenue: 'rv', grossProfit: 'gp', gross_profit: 'gp', adSpend: 'ad', ad_spend: 'ad',
  units: 'un', sessions: 'se', impressions: 'im', cr: 'cr', ctr: 'ct',
  conversion_rate: 'cr', click_through_rate: 'ct',
};

app.get('/api/plan/data', async (req, res) => {
  try {
    const { year, month, brand, seller, asin: af } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (month && month !== 'All') {
      const mn = parseInt(month);
      if (mn >= 1 && mn <= 12) { where += ' AND ap.month_num = ?'; params.push(mn); }
    }
    if (brand && brand !== 'All') { where += ' AND ap.brand_name = ?'; params.push(brand); }
    if (af && af !== 'All') { where += ' AND ap.asin = ?'; params.push(af); }
    if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }

    const rows = await q(`
      SELECT ap.asin, ap.brand_name, ap.month_num, ap.metrics, ap.value
      FROM asin_plan ap
      LEFT JOIN asin a ON ap.asin = a.asin
      ${where}
      ORDER BY ap.month_num, ap.metrics
    `, params);

    // Aggregate plan data by month and metric
    const monthlyPlan = {}; // {month_num: {rv: sum, gp: sum, ...}}
    const asinPlan = {};    // {asin: {month_num: {rv: sum, ...}}}
    rows.forEach(r => {
      const mk = METRICS_MAP[r.metrics] || METRICS_MAP[r.metrics?.toLowerCase()] || null;
      if (!mk) return;
      const mn = r.month_num;
      const val = parseFloat(r.value) || 0;
      if (!monthlyPlan[mn]) monthlyPlan[mn] = {};
      monthlyPlan[mn][mk] = (monthlyPlan[mn][mk] || 0) + val;
      
      const key = r.asin;
      if (!asinPlan[key]) asinPlan[key] = { brand: r.brand_name, months: {} };
      if (!asinPlan[key].months[mn]) asinPlan[key].months[mn] = {};
      asinPlan[key].months[mn][mk] = (asinPlan[key].months[mn][mk] || 0) + val;
    });

    // Build KPI totals
    const kpi = { gp: { a: 0, p: 0 }, rv: { a: 0, p: 0 }, ad: { a: 0, p: 0 }, un: { a: 0, p: 0 }, se: { a: 0, p: 0 }, im: { a: 0, p: 0 }, cr: { a: 0, p: 0 }, ct: { a: 0, p: 0 } };
    Object.values(monthlyPlan).forEach(mp => {
      ['gp', 'rv', 'ad', 'un', 'se', 'im', 'cr', 'ct'].forEach(k => {
        kpi[k].p += mp[k] || 0;
      });
    });
    // cr and ct are averages, not sums
    const monthCount = Object.keys(monthlyPlan).length || 1;
    kpi.cr.p = kpi.cr.p / monthCount;
    kpi.ct.p = kpi.ct.p / monthCount;

    res.json({ kpi, monthlyPlan, asinPlan });
  } catch (e) {
    console.error('plan/data error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/plan/actuals', async (req, res) => {
  try {
    const { year, brand, seller, asin: af } = req.query;
    const yr = year || new Date().getFullYear();
    const startDate = `${yr}-01-01`, endDate = `${yr}-12-31`;
    let where = 'WHERE p.date BETWEEN ? AND ?';
    const params = [startDate, endDate];
    if (brand && brand !== 'All') { where += ' AND a.store = ?'; params.push(brand); }
    if (seller && seller !== 'All') { where += ' AND a.seller = ?'; params.push(seller); }
    if (af && af !== 'All') { where += ' AND p.asin = ?'; params.push(af); }

    const rows = await q(`
      SELECT p.asin, a.store as brand, a.seller, MONTH(p.date) as month_num,
        SUM(p.unitsOrganic + p.unitsPPC) as units,
        SUM(p.salesOrganic + p.salesPPC) as revenue,
        SUM(p.sponsoredProducts + p.sponsoredDisplay + p.sponsoredBrands + COALESCE(p.sponsoredBrandsVideo,0)) as ads,
        SUM(COALESCE(p.grossProfit,0)) as grossProfit,
        SUM(COALESCE(p.netProfit,0)) as netProfit,
        AVG(p.sessions) as sessions,
        AVG(p.unitSessionPercentage) as cr,
        AVG(p.realACOS) as acos
      FROM seller_board_product p
      LEFT JOIN asin a ON p.asin = a.asin
      ${where}
      GROUP BY p.asin, a.store, a.seller, MONTH(p.date)
      ORDER BY grossProfit DESC
    `, params);

    // Aggregate monthly actuals
    const monthly = {}; // {month_num: {rv, gp, ad, un, se, cr, ...}}
    const asinData = {}; // {asin: {brand, months: {mn: {rv, gp, ...}}}}
    rows.forEach(r => {
      const mn = r.month_num;
      if (!monthly[mn]) monthly[mn] = { rv: 0, gp: 0, ad: 0, un: 0, se: 0, im: 0, cr: [], ct: [] };
      monthly[mn].rv += parseFloat(r.revenue) || 0;
      monthly[mn].gp += parseFloat(r.grossProfit) || 0;
      monthly[mn].ad += parseFloat(r.ads) || 0;
      monthly[mn].un += parseInt(r.units) || 0;
      monthly[mn].se += parseFloat(r.sessions) || 0;
      if (r.cr) monthly[mn].cr.push(parseFloat(r.cr));

      const key = r.asin;
      if (!asinData[key]) asinData[key] = { brand: r.brand, seller: r.seller, months: {} };
      if (!asinData[key].months[mn]) asinData[key].months[mn] = { rv: 0, gp: 0, ad: 0, un: 0, se: 0, cr: 0 };
      asinData[key].months[mn].rv += parseFloat(r.revenue) || 0;
      asinData[key].months[mn].gp += parseFloat(r.grossProfit) || 0;
      asinData[key].months[mn].ad += parseFloat(r.ads) || 0;
      asinData[key].months[mn].un += parseInt(r.units) || 0;
      asinData[key].months[mn].se += parseFloat(r.sessions) || 0;
      asinData[key].months[mn].cr = parseFloat(r.cr) || 0;
    });

    // Finalize monthly (avg for cr/ct)
    const monthlyArr = [];
    for (let m = 1; m <= 12; m++) {
      const d = monthly[m] || { rv: 0, gp: 0, ad: 0, un: 0, se: 0, cr: [], ct: [] };
      const crAvg = d.cr.length ? d.cr.reduce((s, v) => s + v, 0) / d.cr.length : 0;
      monthlyArr.push({ m: MS[m - 1], mn: m, ra: d.rv, gpa: d.gp, aa: d.ad, ua: d.un, sa: d.se, ia: 0, cra: crAvg, cta: 0 });
    }

    // ASIN breakdown (sum across all months for the year)
    const asinBreakdown = Object.entries(asinData).map(([asin, d]) => {
      const totals = { rv: 0, gp: 0, ad: 0, un: 0, se: 0, cr: [] };
      Object.values(d.months).forEach(m => {
        totals.rv += m.rv; totals.gp += m.gp; totals.ad += m.ad;
        totals.un += m.un; totals.se += m.se;
        if (m.cr) totals.cr.push(m.cr);
      });
      const crAvg = totals.cr.length ? totals.cr.reduce((s, v) => s + v, 0) / totals.cr.length : 0;
      return {
        a: asin, br: d.brand || '', sl: d.seller || '',
        ra: totals.rv, ga: totals.gp, aa: totals.ad, ua: totals.un, sa: totals.se, ia: 0, cra: crAvg, cta: 0,
      };
    }).sort((a, b) => b.ga - a.ga);

    res.json({ monthly: monthlyArr, asinBreakdown });
  } catch (e) {
    console.error('plan/actuals error:', e);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ DAILY / OPS ═══════════ */
app.get('/api/ops/daily', async (req, res) => {
  try {
    const { start, end, store } = req.query;
    let where = 'WHERE date BETWEEN ? AND ?';
    const params = [start || '2025-01-01', end || '2025-01-31'];
    if (store && store !== 'All') {
      const rm = await getShopReverseMap();
      const accId = rm[store];
      if (accId) { where += ' AND accountId = ?'; params.push(accId); }
    }
    const rows = await q(`
      SELECT date,
        SUM(salesOrganic + salesPPC) as revenue,
        SUM(netProfit) as netProfit,
        SUM(unitsOrganic + unitsPPC) as units,
        SUM(orders) as orders,
        SUM(sponsoredProducts + sponsoredDisplay + sponsoredBrands + COALESCE(sponsoredBrandsVideo,0)) as adSpend
      FROM seller_board_day
      ${where}
      GROUP BY date ORDER BY date DESC
      LIMIT 60
    `, params);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ AI INSIGHT ═══════════ */
app.post('/api/ai/insight', async (req, res) => {
  try {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.status(400).json({ error: 'ANTHROPIC_API_KEY not configured' });
    const { context, question } = req.body;
    const systemPrompt = `You are an expert Amazon FBA business analyst for Expeditee LLC, an e-commerce holding company managing 32+ brands.
Analyze the provided data and give actionable business insights. Focus on:
1. Revenue & profit drivers and drags
2. ASIN-level performance issues (high ACoS, negative margin, poor CR)
3. Inventory health concerns
4. Recommendations with specific actions
Be specific with numbers. Keep response 300-500 words.`;
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514', max_tokens: 1500, system: systemPrompt,
        messages: [{ role: 'user', content: `Dashboard data:\n${JSON.stringify(context, null, 2)}\n\n${question || 'Analyze and provide insights.'}` }],
      }),
    });
    const data = await response.json();
    res.json({ insight: data.content?.[0]?.text || 'Unable to generate insight' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ SERVE FRONTEND ═══════════ */
const distPath = join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (req, res) => { res.sendFile(join(distPath, 'index.html')); });

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Amazon Dashboard running on http://localhost:${PORT}`);
  console.log(`   Database: ${process.env.DB_HOST || 'not configured'}`);
  console.log(`   AI: ${process.env.ANTHROPIC_API_KEY ? 'enabled' : 'not configured'}\n`);
});
