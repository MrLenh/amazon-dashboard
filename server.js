import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import crypto from 'crypto';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3001;
const VER = 'v4.5-2026-03-11';
app.use(cors());
app.use(express.json({ limit: '10mb' }));

/* ═══════════ AUTH CONFIG ═══════════ */
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days
if (!process.env.JWT_SECRET) console.warn('⚠️ JWT_SECRET not set — using random (tokens invalidate on restart). Set JWT_SECRET in Railway env vars.');

// Password hashing (Node built-in crypto, zero dependencies)
function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}
function verifyPassword(password, hash, salt) {
  const { hash: check } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}
// Simple JWT-like token (HMAC-SHA256, no external lib needed)
function signToken(payload) {
  const data = { ...payload, exp: Date.now() + TOKEN_EXPIRY, iat: Date.now() };
  const b64 = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(b64).digest('base64url');
  return b64 + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const [b64, sig] = token.split('.');
  if (!b64 || !sig) return null;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(b64).digest('base64url');
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (data.exp && data.exp < Date.now()) return null; // expired
    return data;
  } catch { return null; }
}

/* ═══════════ DATABASE ═══════════ */
let pool = null;
try {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'expeditee',
    waitForConnections: true, connectionLimit: 20, queueLimit: 50,
    connectTimeout: 10000,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  });
  console.log('✅ MySQL pool created');
} catch (e) { console.warn('⚠️ MySQL pool failed:', e.message); }

/* ═══════════ IMAGE DB — same host, different credentials ═══════════ */
// Railway env vars needed: DB2_NAME, DB2_USER, DB2_PASSWORD
// DB2_HOST and DB2_PORT are optional — defaults to same as main DB
let pool2 = null;
if (process.env.DB2_NAME && process.env.DB2_USER) {
  try {
    pool2 = mysql.createPool({
      host:     process.env.DB2_HOST     || process.env.DB_HOST || 'localhost',
      port:     process.env.DB2_PORT     || process.env.DB_PORT || 3306,
      user:     process.env.DB2_USER,
      password: process.env.DB2_PASSWORD || '',
      database: process.env.DB2_NAME,
      waitForConnections: true, connectionLimit: 5, queueLimit: 20,
      connectTimeout: 10000,
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
    });
    console.log('✅ MySQL pool2 (image DB) created');
  } catch (e) { console.warn('⚠️ MySQL pool2 failed:', e.message); }
}

// IMG_DB = database containing product_metadata with imageUrl
// Set IMG_DB env var, or falls back to DB2_NAME
const IMG_DB = process.env.IMG_DB || process.env.DB2_NAME || null;

async function getImageMap(asinList) {
  if (!asinList || asinList.length === 0) return {};
  const ph = asinList.map(() => '?').join(',');

  // Try 1: cross-DB query on main pool
  if (pool && IMG_DB) {
    try {
      const rows = await q(
        `SELECT asin, imageUrl FROM \`${IMG_DB}\`.product_metadata WHERE asin IN (${ph}) AND imageUrl IS NOT NULL`,
        asinList, 10000
      );
      const map = {};
      rows.forEach(r => { if (r.imageUrl) map[r.asin] = r.imageUrl; });
      if (Object.keys(map).length > 0) return map;
    } catch (e) { console.warn('[getImageMap] cross-DB failed, trying pool2:', e.message); }
  }

  // Try 2: pool2
  if (!pool2) return {};
  try {
    const conn = await pool2.getConnection();
    try {
      const [rows] = await conn.execute(
        `SELECT asin, imageUrl FROM product_metadata WHERE asin IN (${ph}) AND imageUrl IS NOT NULL`,
        asinList
      );
      const map = {};
      rows.forEach(r => { if (r.imageUrl) map[r.asin] = r.imageUrl; });
      return map;
    } finally { conn.release(); }
  } catch (e) {
    console.warn('[getImageMap] pool2 also failed:', e.message);
    return {};
  }
}

// ADS_DB = name of amazon_ads_manager database
// Can be set via ADS_DB env var OR falls back to DB2_NAME
const ADS_DB = process.env.ADS_DB || process.env.DB2_NAME || null;

async function getAdsMetrics(asinList, startDate, endDate) {
  if (!asinList || asinList.length === 0 || !pool2) return {};
  try {
    const conn = await pool2.getConnection();
    try {
      await conn.query('SET SESSION max_execution_time=30000').catch(()=>{});

      // Strategy: aggregate report_sp_advertised_product by date range FIRST (uses date index),
      // then JOIN with product_ads (small table) to map campaignId+adGroupId → asin.
      // NO IN() with 3000 ASINs — scan report once, get all ASINs in one query.
      const [rows] = await conn.execute(`
        SELECT pa.asin,
          ROUND(SUM(r.clicks) / NULLIF(SUM(r.impressions), 0) * 100, 4) AS ctr,
          ROUND(SUM(r.cost)   / NULLIF(SUM(r.clicks), 0), 2)             AS cpc,
          SUM(r.impressions) AS impressions,
          SUM(r.clicks)      AS clicks
        FROM (
          SELECT campaignId, adGroupId,
                 SUM(clicks) AS clicks, SUM(impressions) AS impressions, SUM(cost) AS cost
          FROM report_sp_advertised_product
          WHERE date BETWEEN ? AND ?
          GROUP BY campaignId, adGroupId
        ) r
        JOIN product_ads pa ON pa.campaignId = r.campaignId AND pa.adGroupId = r.adGroupId
        WHERE pa.asin IS NOT NULL AND pa.asin != ''
        GROUP BY pa.asin
      `, [startDate, endDate]);

      const map = {};
      rows.forEach(r => {
        map[r.asin] = {
          ctr: r.ctr != null ? Math.round(parseFloat(r.ctr) * 100) / 100 : null,
          cpc: r.cpc != null ? parseFloat(r.cpc) : null,
          impressions: parseInt(r.impressions)||0,
          clicks: parseInt(r.clicks)||0,
        };
      });
      console.log(`[getAdsMetrics] ${rows.length} ASINs with CTR/CPC | ${startDate}→${endDate}`);
      return map;
    } finally { conn.release(); }
  } catch (e) {
    console.warn('[getAdsMetrics] failed:', e.message);
    return {};
  }
}

/* ═══════════ QUERY CACHE (TTL 2 min) ═══════════ */
const _qcache = new Map();
const CACHE_TTL = 2 * 60 * 1000; // 2 minutes
function cacheKey(sql, params) { return sql.replace(/\s+/g,' ').trim() + '|' + JSON.stringify(params); }
function cacheGet(key) {
  const e = _qcache.get(key);
  if (!e) return null;
  if (Date.now() - e.ts > CACHE_TTL) { _qcache.delete(key); return null; }
  return e.v;
}
function cacheSet(key, v) {
  if (_qcache.size > 500) { // evict oldest
    const first = _qcache.keys().next().value;
    _qcache.delete(first);
  }
  _qcache.set(key, { v, ts: Date.now() });
}
// Cached query wrapper — only caches SELECT statements
async function qc(sql, params = [], timeoutMs = 45000) {
  const key = cacheKey(sql, params);
  const hit = cacheGet(key);
  if (hit) return hit;
  const rows = await q(sql, params, timeoutMs);
  if (sql.trimStart().toUpperCase().startsWith('SELECT')) cacheSet(key, rows);
  return rows;
}

async function q(sql, params = [], timeoutMs = 45000) {
  if (!pool) throw new Error('Database not connected');
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error(`signal timed out`)), timeoutMs));
  return Promise.race([pool.execute(sql, params).then(([rows]) => rows), timeout]);
}

/* ═══════════ BOOT: create indexes if missing ═══════════ */
async function ensureIndexes() {
  if (!pool) return;
  // Check existing indexes first to avoid ALTER on already-indexed tables
  try {
    const existingIdx = await q(`SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS
      WHERE TABLE_SCHEMA = DATABASE() AND INDEX_NAME LIKE 'idx_%'`, [], 10000);
    const existing = new Set(existingIdx.map(r=>r.INDEX_NAME));

    const idxSQL = [
      ['idx_sbs_date',     `ALTER TABLE seller_board_sales ADD INDEX idx_sbs_date (date)`],
      ['idx_sbs_date_acc', `ALTER TABLE seller_board_sales ADD INDEX idx_sbs_date_acc (date, accountId)`],
      ['idx_sbp_date',     `ALTER TABLE seller_board_product ADD INDEX idx_sbp_date (date)`],
      ['idx_sbp_date_acc', `ALTER TABLE seller_board_product ADD INDEX idx_sbp_date_acc (date, accountId)`],
      ['idx_sbp_asin',     `ALTER TABLE seller_board_product ADD INDEX idx_sbp_asin (asin(20))`],
      ['idx_inv_date_acc', `ALTER TABLE fba_iventory_planning ADD INDEX idx_inv_date_acc (date, accountId)`],
    ];
    for (const [name, sql] of idxSQL) {
      if (existing.has(name)) { console.log('✓ Index exists:', name); continue; }
      try { await q(sql, [], 60000); console.log('✅ Index created:', name); }
      catch(e) { console.warn('⚠️ Index skip:', name, '-', e.message.slice(0,80)); }
    }
  } catch(e) { console.warn('ensureIndexes failed:', e.message); }
}
setTimeout(() => ensureIndexes(), 5000);

/* ═══════════ SALES TABLE ═══════════ */
function salesFrom(alias = 'sc') { return `seller_board_sales ${alias}`; }

/* ═══════════ HELPERS ═══════════ */
// In-memory shop map cache — refreshed every 5 min, avoids repeated DB hits
let _shopMapCache = null;
let _shopMapTs = 0;
async function getShopMap() {
  if (_shopMapCache && Date.now() - _shopMapTs < 5*60*1000) return _shopMapCache;
  const rows = await q('SELECT id, shop FROM accounts WHERE deleted_at IS NULL');
  _shopMapCache = {}; rows.forEach(r => { _shopMapCache[r.id] = r.shop; });
  _shopMapTs = Date.now();
  return _shopMapCache;
}
async function getShopReverseMap() {
  const m = await getShopMap();
  const rev = {}; Object.entries(m).forEach(([id,shop])=>{ rev[shop]=parseInt(id); }); return rev;
}
// storeToAccIds: accepts "All", "Shop1", or "Shop1,Shop2,Shop3"
// Returns null (= no filter) or array of integers
async function storeToAccIds(storeParam) {
  if (!storeParam || storeParam === 'All') return null;
  const rm = await getShopReverseMap();
  const names = storeParam.split(',').map(s=>s.trim()).filter(Boolean);
  const ids = names.map(n=>rm[n]).filter(Boolean);
  return ids.length ? ids : null;
}
// Legacy single-id helper (still used in some endpoints)
async function storeToAccId(storeParam) {
  const ids = await storeToAccIds(storeParam);
  return ids ? ids[0] : null;
}

// Build accountId WHERE fragment supporting single or multi
function accIdClause(alias, accIds) {
  if (!accIds || !accIds.length) return { w: '', p: [] };
  if (accIds.length === 1) return { w: ` AND ${alias}.accountId = ?`, p: [accIds[0]] };
  return { w: ` AND ${alias}.accountId IN (${accIds.map(()=>'?').join(',')})`, p: accIds };
}
// Unqualified version (no alias)
function accIdClauseRaw(accIds) {
  if (!accIds || !accIds.length) return { w: '', p: [] };
  if (accIds.length === 1) return { w: ` AND accountId = ?`, p: [accIds[0]] };
  return { w: ` AND accountId IN (${accIds.map(()=>'?').join(',')})`, p: accIds };
}

// Get ASIN list for seller filter (used by inventory endpoints)
async function getSellerAsins(seller, accId) {
  if (!seller || seller === 'All') return null;
  try {
    let w = 'WHERE p.seller = ?'; const p = [seller];
    const ac = accIdClauseRaw(accId); w += ac.w; p.push(...ac.p);
    const rows = await q(`SELECT DISTINCT asin FROM seller_board_product p ${w}`, p, 15000);
    return rows.map(r => r.asin);
  } catch(e) { return null; }
}


// Concurrency limiter — at most N simultaneous heavy queries
function makeLimiter(n) {
  let running = 0; const queue = [];
  return fn => new Promise((res, rej) => {
    const run = () => { running++; fn().then(v=>{running--;next();res(v)}).catch(e=>{running--;next();rej(e)}); };
    const next = () => { if (queue.length && running < n) queue.shift()(); };
    if (running < n) run(); else queue.push(run);
  });
}
const summaryLimiter = makeLimiter(2); // max 2 concurrent exec/summary (heavy, full-scan)
const detailLimiter  = makeLimiter(3); // max 3 concurrent exec/detail (single merged query, faster)

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

function pWhere(sd, ed, accIds, seller, af, productType) {
  let w = 'WHERE p.date BETWEEN ? AND ?'; const p = [sd, ed];
  const ac = accIdClause('p', accIds); w += ac.w; p.push(...ac.p);
  if (seller && seller !== 'All') { w += ' AND p.seller = ?'; p.push(seller); }
  if (af && af !== 'All') { w += ' AND p.asin = ?'; p.push(af); }
  if (productType && productType !== 'All') { w += ' AND p.productType = ?'; p.push(productType); }
  return { w, p };
}
function scWhere(sd, ed, accIds) {
  let w = 'WHERE sc.date BETWEEN ? AND ?'; const p = [sd, ed];
  const ac = accIdClause('sc', accIds); w += ac.w; p.push(...ac.p);
  return { w, p };
}
function useProduct(seller, af) {
  return (seller && seller !== 'All') || (af && af !== 'All');
}

/* ═══════════ HEALTH ═══════════ */
app.get('/api/health', async (req, res) => {
  try {
    if (pool) { await q('SELECT 1'); res.json({ status: 'ok', database: 'connected', version: VER, db2: pool2 ? 'connected' : 'not configured', ads_db: ADS_DB||null, img_db: IMG_DB||null }); }
    else res.json({ status: 'ok', database: 'not configured', version: VER, db2: pool2 ? 'connected' : 'not configured', ads_db: ADS_DB||null, img_db: IMG_DB||null });
  } catch (e) { res.json({ status: 'ok', database: 'error: ' + e.message, version: VER, db2: pool2 ? 'connected' : 'not configured', ads_db: ADS_DB||null, img_db: IMG_DB||null }); }
});

/* ═══════════ AUTH: USERS TABLE + SEED ═══════════ */
async function ensureUsersTable() {
  if (!pool) return;
  try {
    await q(`CREATE TABLE IF NOT EXISTS dashboard_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      name VARCHAR(255) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      password_salt VARCHAR(64) NOT NULL,
      role ENUM('admin','viewer') NOT NULL DEFAULT 'viewer',
      active TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP NULL
    )`, [], 10000);
    console.log('✅ dashboard_users table ready');

    // Invites table
    await q(`CREATE TABLE IF NOT EXISTS dashboard_invites (
      id INT AUTO_INCREMENT PRIMARY KEY,
      token VARCHAR(64) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL,
      name VARCHAR(255) DEFAULT '',
      role ENUM('admin','viewer') NOT NULL DEFAULT 'viewer',
      invited_by INT,
      expires_at TIMESTAMP NOT NULL,
      accepted_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, [], 10000);
    console.log('✅ dashboard_invites table ready');

    // Seed default admin if table is empty
    const count = await q('SELECT COUNT(*) as c FROM dashboard_users');
    if (count[0]?.c === 0) {
      const defaultEmail = process.env.ADMIN_EMAIL || 'admin@expeditee.com';
      const defaultPass = process.env.ADMIN_PASSWORD || 'Expeditee@2026';
      const { hash, salt } = hashPassword(defaultPass);
      await q('INSERT INTO dashboard_users (email, name, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)',
        [defaultEmail, 'Admin', hash, salt, 'admin']);
      console.log(`✅ Default admin created: ${defaultEmail} / ${defaultPass}`);
      console.log('⚠️ CHANGE DEFAULT PASSWORD! Set ADMIN_EMAIL + ADMIN_PASSWORD in env vars, or login and update.');
    }
  } catch (e) { console.warn('⚠️ ensureUsersTable failed:', e.message); }
}
setTimeout(() => ensureUsersTable(), 3000);

/* ═══════════ AUTH ENDPOINTS ═══════════ */
// Login — public, no token needed
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const rows = await q('SELECT * FROM dashboard_users WHERE email = ? AND active = 1', [email.trim().toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password' });
    const user = rows[0];
    if (!verifyPassword(password, user.password_hash, user.password_salt)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    // Update last_login
    q('UPDATE dashboard_users SET last_login = NOW() WHERE id = ?', [user.id]).catch(() => {});
    const token = signToken({ id: user.id, email: user.email, role: user.role, name: user.name });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Verify token — needs valid token
app.get('/api/auth/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
  res.json({ user: { id: payload.id, email: payload.email, name: payload.name, role: payload.role } });
});

// Change password — authenticated user
app.post('/api/auth/change-password', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  (async () => {
    try {
      const { currentPassword, newPassword } = req.body;
      if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
      const rows = await q('SELECT * FROM dashboard_users WHERE id = ?', [payload.id]);
      if (!rows.length) return res.status(404).json({ error: 'User not found' });
      if (!verifyPassword(currentPassword, rows[0].password_hash, rows[0].password_salt)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      const { hash, salt } = hashPassword(newPassword);
      await q('UPDATE dashboard_users SET password_hash = ?, password_salt = ? WHERE id = ?', [hash, salt, payload.id]);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  })();
});

// Admin: list users
app.get('/api/auth/users', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  q('SELECT id, email, name, role, active, created_at, last_login FROM dashboard_users ORDER BY created_at DESC')
    .then(rows => res.json(rows))
    .catch(e => res.status(500).json({ error: e.message }));
});

// Admin: create user
app.post('/api/auth/users', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  (async () => {
    try {
      const { email, name, password, role } = req.body;
      if (!email || !password || !name) return res.status(400).json({ error: 'Email, name, and password required' });
      if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      const validRole = (role === 'admin' || role === 'viewer') ? role : 'viewer';
      const { hash, salt } = hashPassword(password);
      await q('INSERT INTO dashboard_users (email, name, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)',
        [email.trim().toLowerCase(), name.trim(), hash, salt, validRole]);
      res.json({ ok: true });
    } catch (e) {
      if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already exists' });
      res.status(500).json({ error: e.message });
    }
  })();
});

// Admin: toggle active / change role
app.put('/api/auth/users/:id', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  (async () => {
    try {
      const uid = parseInt(req.params.id);
      if (uid === payload.id) return res.status(400).json({ error: 'Cannot modify your own account here' });
      const { active, role, resetPassword } = req.body;
      if (active !== undefined) await q('UPDATE dashboard_users SET active = ? WHERE id = ?', [active ? 1 : 0, uid]);
      if (role && (role === 'admin' || role === 'viewer')) await q('UPDATE dashboard_users SET role = ? WHERE id = ?', [role, uid]);
      if (resetPassword && resetPassword.length >= 6) {
        const { hash, salt } = hashPassword(resetPassword);
        await q('UPDATE dashboard_users SET password_hash = ?, password_salt = ? WHERE id = ?', [hash, salt, uid]);
      }
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  })();
});

// Admin: delete user
app.delete('/api/auth/users/:id', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  const uid = parseInt(req.params.id);
  if (uid === payload.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  q('DELETE FROM dashboard_users WHERE id = ?', [uid])
    .then(() => res.json({ ok: true }))
    .catch(e => res.status(500).json({ error: e.message }));
});

/* ═══════════ INVITE FLOW ═══════════ */
// Admin: create invite
app.post('/api/auth/invite', async (req, res) => {
  const authToken = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(authToken);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  try {
    const { email, role } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    // Check if user already exists
    const existing = await q('SELECT id FROM dashboard_users WHERE email = ?', [email.trim().toLowerCase()]);
    if (existing.length) return res.status(409).json({ error: 'User with this email already exists' });
    // Check if pending invite exists — return existing link instead of error
    const pendingInv = await q('SELECT token FROM dashboard_invites WHERE email = ? AND accepted_at IS NULL AND expires_at > NOW()', [email.trim().toLowerCase()]);
    if (pendingInv.length) {
      const baseUrl = process.env.APP_URL || req.headers.origin || `${req.protocol}://${req.get('host')}`;
      return res.json({ ok: true, inviteUrl: `${baseUrl}?invite=${pendingInv[0].token}`, token: pendingInv[0].token, reused: true });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const validRole = (role === 'admin' || role === 'viewer') ? role : 'viewer';
    await q('INSERT INTO dashboard_invites (token, email, role, invited_by, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))',
      [token, email.trim().toLowerCase(), validRole, payload.id]);

    // Build invite URL
    const baseUrl = process.env.APP_URL || req.headers.origin || `${req.protocol}://${req.get('host')}`;
    const inviteUrl = `${baseUrl}?invite=${token}`;

    res.json({ ok: true, inviteUrl, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Public: verify invite token
app.get('/api/auth/invite/:token', async (req, res) => {
  try {
    const rows = await q('SELECT * FROM dashboard_invites WHERE token = ? AND accepted_at IS NULL AND expires_at > NOW()', [req.params.token]);
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired invite' });
    const inv = rows[0];
    res.json({ email: inv.email, role: inv.role, expires_at: inv.expires_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Public: accept invite — user sets password + name
app.post('/api/auth/invite/:token/accept', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Name and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const rows = await q('SELECT * FROM dashboard_invites WHERE token = ? AND accepted_at IS NULL AND expires_at > NOW()', [req.params.token]);
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired invite' });
    const inv = rows[0];
    // Check if user was already created
    const existing = await q('SELECT id FROM dashboard_users WHERE email = ?', [inv.email]);
    if (existing.length) return res.status(409).json({ error: 'Account already exists. Please login.' });
    // Create user
    const { hash, salt } = hashPassword(password);
    await q('INSERT INTO dashboard_users (email, name, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)',
      [inv.email, name.trim(), hash, salt, inv.role]);
    // Mark invite as accepted
    await q('UPDATE dashboard_invites SET accepted_at = NOW() WHERE id = ?', [inv.id]);
    // Auto-login: return token
    const user = (await q('SELECT * FROM dashboard_users WHERE email = ?', [inv.email]))[0];
    const authTk = signToken({ id: user.id, email: user.email, role: user.role, name: user.name });
    await q('UPDATE dashboard_users SET last_login = NOW() WHERE id = ?', [user.id]).catch(() => {});
    res.json({ token: authTk, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Account already exists' });
    res.status(500).json({ error: e.message });
  }
});

// Admin: list pending invites
app.get('/api/auth/invites', (req, res) => {
  const authToken = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(authToken);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  q('SELECT id, email, role, expires_at, accepted_at, created_at FROM dashboard_invites ORDER BY created_at DESC LIMIT 50')
    .then(rows => res.json(rows))
    .catch(e => res.status(500).json({ error: e.message }));
});

// Admin: revoke invite
app.delete('/api/auth/invite/:id', (req, res) => {
  const authToken = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(authToken);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  q('DELETE FROM dashboard_invites WHERE id = ? AND accepted_at IS NULL', [parseInt(req.params.id)])
    .then(() => res.json({ ok: true }))
    .catch(e => res.status(500).json({ error: e.message }));
});

/* ═══════════ AUTH MIDDLEWARE — protects all /api/* below ═══════════ */
app.use('/api', (req, res, next) => {
  // Skip auth for public endpoints (already handled above)
  if (req.path === '/auth/login' || req.path === '/health') return next();
  if (req.path.match(/^\/auth\/invite\/[a-f0-9]+$/)) return next(); // GET verify invite
  if (req.path.match(/^\/auth\/invite\/[a-f0-9]+\/accept$/)) return next(); // POST accept invite
  if (req.path.startsWith('/debug/')) return next(); // debug endpoints — no auth needed
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Authentication required' });
  req.user = payload;
  next();
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
    try { R.steps.traffiecCols = (await q('SHOW COLUMNS FROM analytics_sale_traffiec_by_asin_date')).map(c=>c.Field); } catch(e) { R.steps.traffiecCols = e.message; }
    // Check indexes
    try {
      const idxRows = await q(`SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('seller_board_sales','seller_board_product')
        AND INDEX_NAME != 'PRIMARY' ORDER BY TABLE_NAME, INDEX_NAME`, [], 10000);
      R.steps.indexes = idxRows.map(r=>`${r.TABLE_NAME}.${r.INDEX_NAME}(${r.COLUMN_NAME})`);
    } catch(e) { R.steps.indexes = e.message; }
    // Quick query timing test
    try {
      const t0=Date.now();
      const ed=new Date().toISOString().slice(0,10);
      const sd=new Date(Date.now()-7*86400000).toISOString().slice(0,10);
      await q(`SELECT SUM(COALESCE(salesOrganic,0)+COALESCE(salesPPC,0)) as s FROM seller_board_sales WHERE date BETWEEN ? AND ?`,[sd,ed],20000);
      R.steps.queryMs = Date.now()-t0;
    } catch(e) { R.steps.queryMs = 'error:'+e.message; }
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
    // today = ngày mới nhất trong DB (không dùng đồng hồ server vì Railway chạy UTC, data lag 1-3 ngày)
    const today = maxDate || new Date().toISOString().slice(0,10);
    const todayMs = new Date(today+'T00:00:00').getTime();
    let defaultStart = new Date(todayMs-29*86400000).toISOString().slice(0,10);
    if (minDate && defaultStart < minDate) defaultStart = minDate;
    res.json({ minDate, maxDate, defaultStart, defaultEnd: today, today });
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
    const { start, end, store, seller, asin: af, productType } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccIds(store);
    let rows, cogsVal = 0;

    if (useProduct(seller, af) || (productType && productType !== 'All')) {
      const f = pWhere(s, e, accId, seller, af, productType);
      const sql = `SELECT SUM(${P_SALES}) as sales, SUM(${P_UNITS}) as units, 0 as orders,
        SUM(COALESCE(p.refunds,0)) as refunds, SUM(${P_ADS}) as advCost,
        0 as shippingCost, 0 as refundCost,
        SUM(COALESCE(p.amazonFees,0)) as amazonFees, SUM(COALESCE(p.costOfGoods,0)) as cogs,
        SUM(COALESCE(p.netProfit,0)) as netProfit, SUM(COALESCE(p.estimatedPayout,0)) as estPayout,
        SUM(COALESCE(p.sessions,0)) as sessions, SUM(COALESCE(p.grossProfit,0)) as grossProfit,
        SUM(COALESCE(p.salesOrganic,0)) as salesOrganic,
        SUM(COALESCE(p.salesSponsoredProducts,0)) as salesSP,
        SUM(COALESCE(p.salesSponsoredDisplay,0)) as salesSD,
        SUM(COALESCE(p.unitsOrganic,0)) as unitsOrganic,
        SUM(COALESCE(p.unitsSponsoredProducts,0)) as unitsSP,
        SUM(COALESCE(p.unitsSponsoredDisplay,0)) as unitsSD,
        SUM(COALESCE(p.sponsoredProducts,0)) as adsSP,
        SUM(COALESCE(p.sponsoredDisplay,0)) as adsSD,
        SUM(COALESCE(p.sponsoredBrands,0)) as adsSB,
        SUM(COALESCE(p.sponsoredBrandsVideo,0)) as adsSBV
        FROM seller_board_product p ${f.w}`;
      rows = await summaryLimiter(()=>qc(sql, f.p, 55000));
      try {
        const scf = scWhere(s, e, accId);
        const scRows = await qc(`SELECT SUM(COALESCE(sc.orders,0)) as orders,
          SUM(COALESCE(sc.shipping,0)) as shippingCost, SUM(COALESCE(sc.refundCost,0)) as refundCost
          FROM ${salesFrom()} ${scf.w}`, scf.p, 30000);
        if (scRows[0] && rows[0]) {
          rows[0].orders = scRows[0].orders || 0;
          rows[0].shippingCost = scRows[0].shippingCost || 0;
          rows[0].refundCost = scRows[0].refundCost || 0;
        }
      } catch(oe) { console.warn('orders sub-query failed:', oe.message); }
    } else {
      const f = scWhere(s, e, accId);
      const sql = `SELECT SUM(${SC_SALES}) as sales, SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders,
        SUM(COALESCE(sc.refunds,0)) as refunds, SUM(${SC_ADS}) as advCost,
        SUM(COALESCE(sc.shipping,0)) as shippingCost, SUM(COALESCE(sc.refundCost,0)) as refundCost,
        SUM(COALESCE(sc.amazonFees,0)) as amazonFees,
        SUM(COALESCE(sc.netProfit,0)) as netProfit, SUM(COALESCE(sc.estimatedPayout,0)) as estPayout,
        SUM(COALESCE(sc.sessions,0)) as sessions, SUM(COALESCE(sc.grossProfit,0)) as grossProfit
        FROM ${salesFrom()} ${f.w}`;
      rows = await summaryLimiter(()=>qc(sql, f.p, 55000));
      // Also fetch SP/SD/SB breakdown from seller_board_product
      try {
        let pw = 'WHERE p.date BETWEEN ? AND ?'; const pp = [s, e];
        { const _ac=accIdClause('p',accId); pw+=_ac.w; pp.push(..._ac.p); }
        const pbRows = await qc(`SELECT
          SUM(COALESCE(p.salesOrganic,0)) as salesOrganic,
          SUM(COALESCE(p.salesSponsoredProducts,0)) as salesSP,
          SUM(COALESCE(p.salesSponsoredDisplay,0)) as salesSD,
          SUM(COALESCE(p.unitsOrganic,0)) as unitsOrganic,
          SUM(COALESCE(p.unitsSponsoredProducts,0)) as unitsSP,
          SUM(COALESCE(p.unitsSponsoredDisplay,0)) as unitsSD,
          SUM(COALESCE(p.sponsoredProducts,0)) as adsSP,
          SUM(COALESCE(p.sponsoredDisplay,0)) as adsSD,
          SUM(COALESCE(p.sponsoredBrands,0)) as adsSB,
          SUM(COALESCE(p.sponsoredBrandsVideo,0)) as adsSBV,
          SUM(COALESCE(p.costOfGoods,0)) as cogs
          FROM seller_board_product p ${pw}`, pp, 30000);
        if (pbRows[0] && rows[0]) {
          Object.assign(rows[0], pbRows[0]);
          cogsVal = parseFloat(pbRows[0].cogs)||0;
        }
      } catch(pe) {}
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
      // SP/SD/SB breakdown
      salesOrganic: parseFloat(r.salesOrganic)||0,
      salesSP: parseFloat(r.salesSP)||0,
      salesSD: parseFloat(r.salesSD)||0,
      unitsOrganic: parseInt(r.unitsOrganic)||0,
      unitsSP: parseInt(r.unitsSP)||0,
      unitsSD: parseInt(r.unitsSD)||0,
      adsSP: Math.abs(parseFloat(r.adsSP)||0),
      adsSD: Math.abs(parseFloat(r.adsSD)||0),
      adsSB: Math.abs(parseFloat(r.adsSB)||0),
      adsSBV: Math.abs(parseFloat(r.adsSBV)||0),
    });
  } catch (e) { console.error('exec/summary:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC DAILY ═══════════ */
app.get('/api/exec/daily', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af, productType } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccIds(store);
    let rows;
    if (useProduct(seller, af) || (productType && productType !== 'All')) {
      const f = pWhere(s, e, accId, seller, af, productType);
      rows = await qc(`SELECT p.date,
        SUM(${P_SALES}) as revenue,
        SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(${P_UNITS}) as units,
        SUM(ABS(COALESCE(p.sponsoredProducts,0))+ABS(COALESCE(p.sponsoredBrands,0))+ABS(COALESCE(p.sponsoredBrandsVideo,0))+ABS(COALESCE(p.sponsoredDisplay,0))) as advCost,
        SUM(COALESCE(p.sessions,0)) as sessions
        FROM seller_board_product p ${f.w} GROUP BY p.date ORDER BY p.date`, f.p, 45000);
    } else {
      const f = scWhere(s, e, accId);
      rows = await qc(`SELECT sc.date,
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
    const { start, end, store, seller, asin: af, productType, niche } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccIds(store);
    const shopMap = await getShopMap();
    let w = 'WHERE p.date BETWEEN ? AND ?'; const params = [s, e];
    const ac = accIdClause('p', accId); w += ac.w; params.push(...ac.p);
    if (seller && seller !== 'All') { w += ' AND p.seller = ?'; params.push(seller); }
    if (af && af !== 'All') { w += ' AND p.asin = ?'; params.push(af); }
    if (productType && productType !== 'All') { w += ' AND a.productType = ?'; params.push(productType); }
    if (niche && niche !== 'All') { w += ' AND a.seasonAndNiche = ?'; params.push(niche); }
    const rows = await qc(`SELECT p.asin, p.accountId, p.seller,
      MAX(a.productType) as productType, MAX(a.seasonAndNiche) as seasonAndNiche,
      SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
      SUM(${P_UNITS}) as units, AVG(COALESCE(p.realACOS,0)) as acos,
      SUM(ABS(${P_ADS})) as advCost,
      SUM(COALESCE(p.sessions,0)) as sessions,
      AVG(CASE WHEN p.unitSessionPercentage > 0 THEN p.unitSessionPercentage END) as cr,
      CASE WHEN SUM(${P_UNITS}) > 0 THEN SUM(${P_SALES}) / SUM(${P_UNITS}) ELSE 0 END as avgPrice
      FROM seller_board_product p
      LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci = a.asin
      ${w} GROUP BY p.asin, p.accountId, p.seller ORDER BY revenue DESC`, params, 60000);
    // Fetch images + ads metrics from DB2 in parallel (non-blocking, fail gracefully)
    const asinList = rows.map(r => r.asin);
    const [imgMap, adsMap] = await Promise.all([
      getImageMap(asinList),
      getAdsMetrics(asinList, s, e),
    ]);
    res.json(rows.map(r => {
      const rev = parseFloat(r.revenue)||0, np = parseFloat(r.netProfit)||0;
      const acos = Math.round((parseFloat(r.acos)||0)*100)/100;
      const cr = Math.round((parseFloat(r.cr)||0)*100)/100;
      const advCost = parseFloat(r.advCost)||0;
      const units = parseInt(r.units)||0;
      const ads = adsMap[r.asin] || {};
      return { asin: r.asin, shop: shopMap[r.accountId]||'', seller: r.seller||'',
        productType: r.productType||'', niche: r.seasonAndNiche||'',
        revenue: rev, netProfit: np, units,
        margin: rev>0?Math.round(np/rev*1000)/10:0,
        acos, roas: acos>0?Math.round(100/acos*100)/100:0,
        cr, sessions: parseInt(r.sessions)||0,
        advCost, tacos: rev>0?Math.round(advCost/rev*10000)/100:0,
        avgPrice: Math.round((parseFloat(r.avgPrice)||0)*100)/100,
        imageUrl: imgMap[r.asin] || null,
        ctr: ads.ctr ?? null,
        cpc: ads.cpc ?? null,
        impressions: ads.impressions || 0,
        clicks: ads.clicks || 0,
      };
    }));
  } catch (e) { console.error('product/asins:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ PRODUCT ASIN DAILY (drill-down) ═══════════ */
app.get('/api/product/filter-options', async (req, res) => {
  try {
    const { store } = req.query;
    const accId = await storeToAccIds(store);
    let w = 'WHERE p.productType IS NOT NULL AND p.productType != ""'; const p = [];
    { const _ac=accIdClause('p',accId); w+=_ac.w; p.push(..._ac.p); }
    const [ptRows, nicheRows] = await Promise.all([
      qc(`SELECT DISTINCT p.productType FROM seller_board_product p ${w} ORDER BY p.productType`, p, 10000),
      qc(`SELECT DISTINCT a.seasonAndNiche FROM asin a WHERE a.seasonAndNiche IS NOT NULL AND a.seasonAndNiche != '' ORDER BY a.seasonAndNiche`, [], 10000),
    ]);
    res.json({
      productTypes: ptRows.map(r=>r.productType).filter(Boolean),
      niches: nicheRows.map(r=>r.seasonAndNiche).filter(Boolean),
    });
  } catch(e) { res.json({ productTypes:[], niches:[] }); }
});

app.get('/api/product/asin-daily', async (req, res) => {
  try {
    const { start, end, asin } = req.query;
    if (!asin) return res.json([]);
    const { s, e } = defDates(start, end);
    const rows = await q(
      `SELECT p.date,
         SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
         SUM(${P_UNITS}) as units,
         SUM(ABS(${P_ADS})) as advCost,
         SUM(COALESCE(t.sessions,0)) as sessions,
         AVG(CASE WHEN t.unitSessionPercentage>0 THEN t.unitSessionPercentage END) as cr,
         AVG(CASE WHEN t.buyBoxPercentage>0 THEN t.buyBoxPercentage END) as buyBox
       FROM seller_board_product p
       LEFT JOIN analytics_sale_traffiec_by_asin_date t ON t.asin=p.asin AND t.date=p.date AND t.typeDate='DAY'
       WHERE p.date BETWEEN ? AND ? AND p.asin=?
       GROUP BY p.date ORDER BY p.date`, [s, e, asin]);
    const MS2=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    res.json(rows.map(r=>{
      const ds=String(r.date).slice(0,10);
      const dt=new Date(ds+'T12:00:00');
      return{
        date:ds,
        label:isNaN(dt)?ds:MS2[dt.getMonth()]+' '+dt.getDate(),
        revenue:parseFloat(r.revenue)||0,
        netProfit:parseFloat(r.netProfit)||0,
        advCost:parseFloat(r.advCost)||0,
        units:parseInt(r.units)||0,
        sessions:parseInt(r.sessions)||0,
        cr:Math.round((parseFloat(r.cr)||0)*100)/100,
        buyBox:Math.round((parseFloat(r.buyBox)||0)*100)/100,
      };
    }));
  } catch(e){ res.status(500).json({error:e.message}); }
});

/* ═══════════ SHOPS ═══════════ */
app.get('/api/shops', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const shopMap = await getShopMap();
    const { s, e } = defDates(start, end);
    const accId = await storeToAccIds(store);

    // ── Q1: main revenue (run in parallel with Q2 stock, Q3 ads, Q4 plan) ──
    const q1 = useProduct(seller, af)
      ? (()=>{ const f=pWhere(s,e,accId,seller,af);
          return qc(`SELECT p.accountId, SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
            SUM(${P_UNITS}) as units, 0 as orders
            FROM seller_board_product p ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p); })()
      : (()=>{ const f=scWhere(s,e,accId);
          return qc(`SELECT sc.accountId, SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.netProfit,0)) as netProfit,
            SUM(${SC_UNITS}) as units, SUM(COALESCE(sc.orders,0)) as orders
            FROM ${salesFrom()} ${f.w} GROUP BY sc.accountId ORDER BY revenue DESC`, f.p, 45000); })();

    // ── Q2: stock (no date filter needed) ──
    const q2 = qc('SELECT accountId, SUM(FBAStock) as fba, SUM(COALESCE(stockValue,0)) as sv FROM seller_board_stock GROUP BY accountId', [], 20000)
      .catch(()=>qc('SELECT f.accountId, SUM(CAST(f.available AS SIGNED)) as fba FROM fba_iventory_planning f JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest ON f.accountId = latest.aid AND f.date = latest.maxDate GROUP BY f.accountId', [], 30000).catch(()=>[]));

    // ── Q3: ads+GP from seller_board_product — NO asin JOIN needed ──
    const pF2 = pWhere(s, e, accId, null, null);
    // Remove LEFT JOIN asin — not needed unless filtering by seller
    const adsSQL = seller && seller!=='All'
      ? `SELECT p.accountId, SUM(ABS(${P_ADS})) as ads, SUM(COALESCE(p.grossProfit,0)) as gp
         FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin ${pF2.w} GROUP BY p.accountId`
      : `SELECT p.accountId, SUM(ABS(${P_ADS})) as ads, SUM(COALESCE(p.grossProfit,0)) as gp
         FROM seller_board_product p ${pF2.w} GROUP BY p.accountId`;
    const q3 = qc(adsSQL, pF2.p, 35000).catch(()=>[]);

    // ── Q4: plan — use date range not YEAR() for index ──
    const yr = new Date(s).getFullYear();
    const q4 = qc(`SELECT p.accountId, ap.metrics, SUM(ap.value) as val
      FROM asin_plan ap
      JOIN (SELECT DISTINCT asin, accountId FROM seller_board_product WHERE date BETWEEN ? AND ?) p
        ON ap.asin COLLATE utf8mb4_0900_ai_ci = p.asin
      WHERE ap.year = ?
      GROUP BY p.accountId, ap.metrics`, [s, e, yr], 35000).catch(()=>[]);

    // ── Q5: sessions per shop ──
    const sessSQL2 = `SELECT p.accountId, SUM(COALESCE(p.sessions,0)) as sessions, SUM(${P_UNITS}) as sessUnits
      FROM seller_board_product p ${pF2.w} GROUP BY p.accountId`;
    const q5 = qc(sessSQL2, pF2.p, 35000).catch(()=>[]);

    // Run all in parallel
    const [rows, stockRows, adsRows, planRows, sessRows2] = await Promise.all([q1, q2, q3, q4, q5]);

    const stockMap = {};
    (stockRows||[]).forEach(s=>{ stockMap[s.accountId]={ fba:parseInt(s.fba)||0, sv:parseFloat(s.sv)||0 }; });

    const adsMap = {};
    (adsRows||[]).forEach(r=>{ adsMap[r.accountId]={ ads:parseFloat(r.ads)||0, gp:parseFloat(r.gp)||0 }; });

    const sessMap2 = {};
    (sessRows2||[]).forEach(r=>{ sessMap2[r.accountId]={ sessions:parseInt(r.sessions)||0, units:parseInt(r.sessUnits)||0 }; });

    const planMap = {};
    (planRows||[]).forEach(r=>{
      if(!planMap[r.accountId])planMap[r.accountId]={ gp:0, rv:0, ad:0, un:0 };
      const pm=planMap[r.accountId], mk=mapMetric(r.metrics), v=parseFloat(r.val)||0;
      if(mk==='gp')pm.gp+=v; else if(mk==='rv')pm.rv+=v; else if(mk==='ad')pm.ad+=v; else if(mk==='un')pm.un+=v;
    });

    res.json(rows.map(r=>{
      const rev=parseFloat(r.revenue)||0, np=parseFloat(r.netProfit)||0;
      const stk=stockMap[r.accountId]||{fba:0,sv:0};
      const plan=planMap[r.accountId]||{gp:0,rv:0,ad:0,un:0};
      const ad=adsMap[r.accountId]||{ads:0,gp:0};
      const gp=ad.gp||np;
      const sess=sessMap2[r.accountId]||{sessions:0,units:0};
      const units=parseInt(r.units)||0, orders=parseInt(r.orders)||0;
      const cr=sess.sessions>0?(units/sess.sessions*100):0;
      return{ shop:shopMap[r.accountId]||`Account ${r.accountId}`, accountId:r.accountId,
        revenue:rev, grossProfit:gp, netProfit:np, ads:ad.ads,
        units, orders, sessions:sess.sessions, cr:Math.round(cr*100)/100,
        margin:rev>0?(gp/rev*100):0, fbaStock:stk.fba, stockValue:stk.sv,
        gpPlan:plan.gp, rvPlan:plan.rv, adPlan:plan.ad, unPlan:plan.un };
    }));
  } catch(e){ res.status(500).json({ error: e.message }); }
});

/* ═══════════ TEAM ═══════════ */
app.get('/api/team', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accId = await storeToAccIds(store);
    let w = 'WHERE p.date BETWEEN ? AND ?'; const params = [s, e];
    if (af && af !== 'All') { w += ' AND p.asin = ?'; params.push(af); }
    { const _ac=accIdClause('p',accId); w+=_ac.w; params.push(..._ac.p); }
    if (seller && seller !== 'All') { w += " AND COALESCE(NULLIF(a.seller,''),'Unassigned') = ?"; params.push(seller); }
    const rows = await qc(`SELECT COALESCE(NULLIF(a.seller,''),'Unassigned') as seller,
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
    const { store } = req.query;
    const accId = await storeToAccIds(store);
    let extra = ''; const params = [];
    { const _ac=accIdClause('f',accId); extra=_ac.w; params.push(..._ac.p); }

    // FBA Stock from seller_board_stock (snapshot table, no date column)
    let fbaFromStock = 0;
    try {
      let sw = 'WHERE 1=1';
      const sp = [];
      { const _ac=accIdClauseRaw(accId); sw+=_ac.w; sp.push(..._ac.p); }
      const sr = await qc(`SELECT SUM(FBAStock) as fba FROM seller_board_stock ${sw}`, sp);
      fbaFromStock = parseInt(sr[0]?.fba) || 0;
    } catch (e) { /* seller_board_stock may not exist */ }

    const rows = await qc(`SELECT
      MAX(f.date) as snapshotDate,
      MIN(f.date) as oldestDate,
      SUM(GREATEST(CAST(f.available AS SIGNED), 0)) as availableInv,
      SUM(COALESCE(f.totalReservedQuantity,0)) as reserved, SUM(COALESCE(f.inboundQuantity,0)) as inbound,
      COUNT(DISTINCT CASE WHEN f.daysOfSupply<=30 THEN f.sku END) as criticalSkus,
      AVG(CASE WHEN f.daysOfSupply > 0 THEN f.daysOfSupply ELSE NULL END) as avgDaysOfSupply,
      SUM(COALESCE(f.invAge0To90Days,0)) as a0,
      SUM(COALESCE(f.invAge91To180Days,0)) as a91, SUM(COALESCE(f.invAge181To270Days,0)) as a181,
      SUM(COALESCE(f.invAge271To365Days,0)) as a271, SUM(COALESCE(f.invAge365PlusDays,0)) as a365,
      COUNT(DISTINCT CASE WHEN COALESCE(f.invAge0To90Days,0)>0 THEN f.asin END) as cnt0,
      COUNT(DISTINCT CASE WHEN COALESCE(f.invAge91To180Days,0)>0 THEN f.asin END) as cnt91,
      COUNT(DISTINCT CASE WHEN COALESCE(f.invAge181To270Days,0)>0 THEN f.asin END) as cnt181,
      COUNT(DISTINCT CASE WHEN COALESCE(f.invAge271To365Days,0)>0 THEN f.asin END) as cnt271,
      COUNT(DISTINCT CASE WHEN COALESCE(f.invAge365PlusDays,0)>0 THEN f.asin END) as cnt365,
      AVG(COALESCE(f.sellThrough,0)) as avgSellThrough
      FROM fba_iventory_planning f
      JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest
        ON f.accountId = latest.aid AND f.date = latest.maxDate
      WHERE 1=1${extra}`, params);

    // Storage fee: reuse EXACT same logic as /api/inventory/storage-monthly
    // → pick rows where date = MAX(date) per month, then take the latest month
    // This guarantees KPI matches the history table below
    let storageFee = 0;
    try {
      let sfExtra = ''; const sfParams = [];
      { const _ac=accIdClauseRaw(accId); sfExtra=_ac.w; sfParams.push(..._ac.p); }
      const sfRows = await qc(`
        SELECT SUM(COALESCE(estimatedStorageCostNextMonth,0)) as fee
        FROM fba_iventory_planning
        WHERE date IN (
          SELECT MAX(date) FROM fba_iventory_planning GROUP BY DATE_FORMAT(date,'%Y-%m')
        )
        AND DATE_FORMAT(date,'%Y-%m') = (
          SELECT DATE_FORMAT(MAX(date),'%Y-%m') FROM fba_iventory_planning
        )${sfExtra}`, sfParams, 15000);
      storageFee = parseFloat(sfRows[0]?.fee) || 0;
    } catch(e) { /* fallback to 0 */ }

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
      ageCnt0: parseInt(r.cnt0)||0, ageCnt91: parseInt(r.cnt91)||0, ageCnt181: parseInt(r.cnt181)||0,
      ageCnt271: parseInt(r.cnt271)||0, ageCnt365: parseInt(r.cnt365)||0,
      storageFee: storageFee, avgSellThrough: parseFloat(r.avgSellThrough)||0
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/stock-trend', async (req, res) => {
  try {
    const accId = await storeToAccIds(req.query.store);
    let extra = ''; const params = [];
    { const _ac=accIdClauseRaw(accId); extra=_ac.w; params.push(..._ac.p); }
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
    const accId = await storeToAccIds(req.query.store);
    let extra = ''; const params = [];
    { const _ac=accIdClause('p',accId); extra=_ac.w; params.push(..._ac.p); }
    // seller_board_product.fbaStorageFee: negative values = costs. Use MAX(date) per ASIN per month to avoid double-counting
    const rows = await q(`
      SELECT DATE_FORMAT(p.date,'%Y-%m') as ym,
        ABS(SUM(p.fbaStorageFee)) as fee
      FROM seller_board_product p
      JOIN (
        SELECT asin, accountId, DATE_FORMAT(date,'%Y-%m') as ym2, MAX(date) as maxDate
        FROM seller_board_product
        WHERE fbaStorageFee < 0
        GROUP BY asin, accountId, DATE_FORMAT(date,'%Y-%m')
      ) latest ON p.asin=latest.asin AND p.accountId=latest.accountId AND p.date=latest.maxDate
      WHERE p.fbaStorageFee < 0 ${extra}
      GROUP BY DATE_FORMAT(p.date,'%Y-%m')
      ORDER BY ym
    `, params);
    res.json((rows||[]).map(r => ({ month: r.ym, fee: Math.round((parseFloat(r.fee)||0)*100)/100 })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory/by-shop', async (req, res) => {
  try {
    const shopMap = await getShopMap();
    const accId = await storeToAccIds(req.query.store);
    let accFilter = ''; const accParams = [];
    { const _ac=accIdClauseRaw(accId); accFilter=_ac.w; accParams.push(..._ac.p); }
    // Separate qualified filter for JOIN queries on fba_iventory_planning (alias f)
    const { w: invFilter, p: invParams } = accIdClause('f', accId);

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
    const accId = await storeToAccIds(store);

    let accW = ''; const accP = [];
    { const _ac=accIdClauseRaw(accId); accW=_ac.w; accP.push(..._ac.p); }

    // Seller pre-filter
    let sellerAsinWhere = '';
    if (seller && seller !== 'All') {
      try {
        const slP2 = [seller, ...accP];
        const slAsins = await q(`SELECT DISTINCT asin FROM seller_board_product WHERE seller = ? ${accW}`, slP2, 15000);
        if (slAsins.length > 0) {
          const asinList = slAsins.map(r => `'${r.asin.replace(/'/g,"''")}'`).join(',');
          sellerAsinWhere = ` AND s.asin IN (${asinList})`;
        } else {
          return res.json([]);
        }
      } catch(e) { console.warn('seller pre-filter:', e.message); }
    }

    // Run stock + plan + seller map in parallel
    const stockSQL = `SELECT s.asin, s.name, s.sku, s.accountId,
      SUM(s.FBAStock) as fba, SUM(COALESCE(s.reserved,0)) as reserved,
      SUM(COALESCE(s.sentToFBA,0)) as sentToFBA, SUM(COALESCE(s.stockValue,0)) as stockValue,
      AVG(COALESCE(s.estimatedSalesVelocity,0)) as velocity,
      MIN(NULLIF(s.daysOfStockLeft,0)) as daysLeft
      FROM seller_board_stock s
      WHERE 1=1${accW}${sellerAsinWhere}
      GROUP BY s.asin, s.name, s.sku, s.accountId ORDER BY fba DESC`;

    const planSQL = `SELECT f.asin, f.accountId,
      SUM(CAST(f.available AS SIGNED)) as available,
      SUM(COALESCE(f.inboundQuantity,0)) as inbound,
      SUM(COALESCE(f.totalReservedQuantity,0)) as planReserved,
      SUM(COALESCE(f.estimatedStorageCostNextMonth,0)) as storageFee,
      SUM(COALESCE(f.unfulfillableQuantity,0)) as unfulfillable,
      AVG(COALESCE(f.daysOfSupply,0)) as daysOfSupply,
      SUM(COALESCE(f.invAge0To90Days,0)) as age0_90,
      SUM(COALESCE(f.invAge91To180Days,0)) as age91_180,
      SUM(COALESCE(f.invAge181To270Days,0)) as age181_270,
      SUM(COALESCE(f.invAge271To365Days,0)) as age271_365,
      SUM(COALESCE(f.invAge365PlusDays,0)) as age365plus
      FROM fba_iventory_planning f
      JOIN (SELECT accountId AS aid, MAX(date) as maxDate FROM fba_iventory_planning GROUP BY accountId) latest
        ON f.accountId = latest.aid AND f.date = latest.maxDate
      WHERE 1=1${accW} GROUP BY f.asin, f.accountId`;

    const sellerSQL = `SELECT p.asin, p.seller, MAX(p.date) as lastDate
      FROM seller_board_product p
      WHERE p.seller IS NOT NULL AND p.seller != ''${accW}
      GROUP BY p.asin, p.seller`;

    const [stockRows, planRows, sellerRows] = await Promise.all([
      q(stockSQL, accP, 60000).catch(()=>[]),
      q(planSQL, accP, 60000).catch(()=>[]),
      q(sellerSQL, accP, 20000).catch(()=>[]),
    ]);

    const planMap = {};
    planRows.forEach(r => { planMap[r.asin+'_'+r.accountId] = r; });

    const sellerMap = {};
    sellerRows.forEach(r => { if(!sellerMap[r.asin]) sellerMap[r.asin] = r.seller; });

    // Fetch images from DB2 (non-blocking, fails gracefully)
    const imgMap = await getImageMap(stockRows.map(r => r.asin));

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
        asin: r.asin, name: (r.name||'').substring(0,60), sku: r.sku||'',
        shop: shopMap[r.accountId]||`Account ${r.accountId}`,
        seller: sellerMap[r.asin]||'', accountId: r.accountId,
        imageUrl: imgMap[r.asin] || null,
        fba, available, reserved, inbound,
        stockValue: parseFloat(r.stockValue)||0,
        velocity: Math.round((parseFloat(r.velocity)||0)*100)/100,
        daysLeft, storageFee, longTermFee: 0,
        unfulfillable: parseInt(plan.unfulfillable)||0,
        age0_90: parseInt(plan.age0_90)||0, age91_180: parseInt(plan.age91_180)||0,
        age181_270: parseInt(plan.age181_270)||0, age271_365: parseInt(plan.age271_365)||0,
        age365plus: parseInt(plan.age365plus)||0, aged,
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

app.get('/api/debug/db2', async (req, res) => {
  const R = { pool2: !!pool2, ADS_DB, IMG_DB, tests: {} };
  if (pool2) {
    try {
      const conn = await pool2.getConnection();
      try {
        const [cnt] = await conn.execute('SELECT COUNT(*) as cnt FROM product_ads WHERE asin IS NOT NULL');
        R.tests.product_ads_count = cnt[0];
        const [sample] = await conn.execute(`
          SELECT pa.asin, r.date,
            ROUND(AVG(NULLIF(r.clickThroughRate,0))*100,4) AS ctr,
            ROUND(AVG(NULLIF(r.costPerClick,0)),2) AS cpc,
            SUM(r.impressions) AS impressions, SUM(r.clicks) AS clicks
          FROM product_ads pa
          JOIN report_sp_advertised_product r ON r.campaignId=pa.campaignId AND r.adGroupId=pa.adGroupId
          WHERE pa.asin IS NOT NULL AND r.date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
          GROUP BY pa.asin, r.date
          ORDER BY r.date DESC LIMIT 3`);
        R.tests.join_sample = sample;
        R.tests.join_note = sample.length > 0 ? '✅ JOIN works! CTR/CPC data available' : '❌ JOIN returned 0 rows';
      } finally { conn.release(); }
    } catch(e) { R.tests.error = e.message; }
  }
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

/* ═══════════ DEBUG: FORMULA CHECK ═══════════ */
// Dùng để tìm nguyên nhân chênh lệch với Sellerboard
// Gọi: /api/debug/formula-check?start=2026-03-01&end=2026-03-31
app.get('/api/debug/formula-check', async (req, res) => {
  try {
    const { start, end } = req.query;
    const { s, e } = defDates(start, end);
    const R = { period: { s, e }, sbs: {}, sbp: {} };

    // seller_board_sales: so sanh cac cong thuc
    const sbsRows = await q(`
      SELECT
        SUM(COALESCE(salesOrganic,0) + COALESCE(salesPPC,0)) AS formula_current,
        SUM(COALESCE(salesOrganic,0) + COALESCE(salesPPC,0) + COALESCE(salesSP,0) + COALESCE(salesSD,0)) AS formula_plus_sp_sd,
        SUM(COALESCE(salesOrganic,0)) AS col_organic,
        SUM(COALESCE(salesPPC,0))     AS col_ppc,
        SUM(COALESCE(salesSP,0))      AS col_sp,
        SUM(COALESCE(salesSD,0))      AS col_sd,
        SUM(COALESCE(unitsOrganic,0) + COALESCE(unitsPPC,0)) AS units_current,
        SUM(COALESCE(unitsOrganic,0) + COALESCE(unitsPPC,0) + COALESCE(unitsSP,0) + COALESCE(unitsSD,0)) AS units_plus_sp_sd,
        SUM(COALESCE(unitsSP,0))      AS col_units_sp,
        SUM(COALESCE(unitsSD,0))      AS col_units_sd,
        COUNT(*) AS row_count
      FROM seller_board_sales WHERE date BETWEEN ? AND ?`, [s, e], 30000);
    R.sbs = sbsRows[0] || {};
    R.sbs._ppc_vs_sp_plus_sd = (parseFloat(R.sbs.col_ppc)||0) - ((parseFloat(R.sbs.col_sp)||0) + (parseFloat(R.sbs.col_sd)||0));
    R.sbs._note = "Neu _ppc_vs_sp_plus_sd gan = 0 -> salesPPC da bao gom SP+SD, cong thuc hien tai dung";
    R.sbs._extra_if_add_sp_sd = (parseFloat(R.sbs.formula_plus_sp_sd)||0) - (parseFloat(R.sbs.formula_current)||0);

    // seller_board_product: tuong tu
    const sbpRows = await q(`
      SELECT
        SUM(COALESCE(salesOrganic,0) + COALESCE(salesPPC,0)) AS formula_current,
        SUM(COALESCE(salesOrganic,0) + COALESCE(salesPPC,0) + COALESCE(salesSponsoredProducts,0) + COALESCE(salesSponsoredDisplay,0)) AS formula_plus_sp_sd,
        SUM(COALESCE(salesOrganic,0))              AS col_organic,
        SUM(COALESCE(salesPPC,0))                  AS col_ppc,
        SUM(COALESCE(salesSponsoredProducts,0))    AS col_sp,
        SUM(COALESCE(salesSponsoredDisplay,0))     AS col_sd,
        SUM(COALESCE(unitsOrganic,0) + COALESCE(unitsPPC,0)) AS units_current,
        SUM(COALESCE(unitsSponsoredProducts,0))    AS col_units_sp,
        SUM(COALESCE(unitsSponsoredDisplay,0))     AS col_units_sd,
        COUNT(DISTINCT asin) AS asin_count,
        COUNT(*) AS row_count
      FROM seller_board_product WHERE date BETWEEN ? AND ?`, [s, e], 30000);
    R.sbp = sbpRows[0] || {};
    R.sbp._extra_if_add_sp_sd = (parseFloat(R.sbp.formula_plus_sp_sd)||0) - (parseFloat(R.sbp.formula_current)||0);

    R._comparison = {
      sbs_current:      parseFloat(R.sbs.formula_current)      || 0,
      sbs_plus_sp_sd:   parseFloat(R.sbs.formula_plus_sp_sd)   || 0,
      sbp_current:      parseFloat(R.sbp.formula_current)      || 0,
      sbp_plus_sp_sd:   parseFloat(R.sbp.formula_plus_sp_sd)   || 0,
      diff_sbs_vs_sbp:  (parseFloat(R.sbs.formula_current)||0) - (parseFloat(R.sbp.formula_current)||0),
    };
    R._howToRead = [
      "So sanh sbs_current voi so Sellerboard hien thi",
      "Neu sbs_plus_sp_sd gan hon -> can fix cong thuc",
      "Neu ca 2 van thap hon SB -> data trong DB bi thieu (loi import)",
      "diff_sbs_vs_sbp # 0 -> 2 bang khong khop nhau",
    ];
    res.json(R);
  } catch (e) {
    console.error('debug/formula-check:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ DEBUG: FORMULA CHECK DETAIL ═══════════ */
app.get('/api/debug/formula-check-detail', async (req, res) => {
  try {
    const { start, end } = req.query;
    const { s, e } = defDates(start, end);
    const R = { period: { s, e } };

    // 1. Breakdown theo accountId -- xem store nao bi thieu
    R.by_account = await q(`
      SELECT
        sc.accountId,
        a.shop,
        COUNT(DISTINCT sc.date) AS days_in_sbs,
        SUM(COALESCE(sc.salesOrganic,0) + COALESCE(sc.salesPPC,0)) AS sbs_sales,
        SUM(COALESCE(sc.orders,0)) AS sbs_orders,
        SUM(COALESCE(sc.unitsOrganic,0) + COALESCE(sc.unitsPPC,0)) AS sbs_units
      FROM seller_board_sales sc
      LEFT JOIN accounts a ON a.id = sc.accountId
      WHERE sc.date BETWEEN ? AND ?
      GROUP BY sc.accountId, a.shop
      ORDER BY sbs_sales DESC`, [s, e], 20000);

    // 2. Kiem tra ngay nao bi missing trong thang
    R.missing_dates = await q(`
      SELECT sc.accountId, a.shop, COUNT(DISTINCT sc.date) AS days_present,
        MIN(sc.date) AS min_date, MAX(sc.date) AS max_date,
        DATEDIFF(MAX(sc.date), MIN(sc.date)) + 1 AS expected_days,
        DATEDIFF(MAX(sc.date), MIN(sc.date)) + 1 - COUNT(DISTINCT sc.date) AS missing_days
      FROM seller_board_sales sc
      LEFT JOIN accounts a ON a.id = sc.accountId
      WHERE sc.date BETWEEN ? AND ?
      GROUP BY sc.accountId, a.shop
      HAVING missing_days > 0`, [s, e], 20000);

    // 3. So sanh tong seller_board_sales vs seller_board_day (neu co)
    try {
      R.seller_board_day_total = await q(`
        SELECT
          SUM(COALESCE(salesOrganic,0) + COALESCE(salesPPC,0)) AS total_sales,
          SUM(COALESCE(orders,0)) AS total_orders,
          SUM(COALESCE(unitsOrganic,0) + COALESCE(unitsPPC,0)) AS total_units,
          COUNT(*) AS row_count
        FROM seller_board_day
        WHERE date BETWEEN ? AND ?`, [s, e], 20000);
    } catch(e) { R.seller_board_day_total = 'table not found or error: ' + e.message; }

    // 4. Kiem tra co don nao trong orders_by_date_general ma khong co trong SBS khong
    try {
      R.orders_rt_total = await q(`
        SELECT
          SUM(COALESCE(item_price,0)) AS total_sales,
          COUNT(DISTINCT amazon_order_id) AS total_orders,
          SUM(CAST(COALESCE(quantity,'0') AS SIGNED)) AS total_units
        FROM orders_by_date_general
        WHERE DATE(purchase_date) BETWEEN ? AND ?
        AND order_status NOT IN ('Cancelled','Pending','PendingAvailability')`, [s, e], 30000);
    } catch(e) { R.orders_rt_total = 'error: ' + e.message; }

    res.json(R);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
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
      const accIds2 = await storeToAccIds(store);
      if (accIds2 && accIds2.length) {
        // Pre-fetch ASINs for this store (faster than subquery)
        const ph2 = accIds2.map(()=>'?').join(',');
        const storeAsins = (await q(`SELECT DISTINCT asin FROM seller_board_product WHERE accountId IN (${ph2}) AND date >= DATE_SUB(CURDATE(), INTERVAL 365 DAY) LIMIT 2000`, accIds2, 15000).catch(()=>[])).map(r=>r.asin);
        if (storeAsins.length) {
          const placeholders = storeAsins.map(()=>'?').join(',');
          where += ` AND ap.asin IN (${placeholders})`;
          params.push(...storeAsins);
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
    const accId = await storeToAccIds(store);
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
      { const _ac=accIdClause(prefix,accId); iw+=_ac.w; ip.push(..._ac.p); }
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
        { const _ac=accIdClause('s',accId); ucw+=_ac.w; ucp.push(..._ac.p); }
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
    const accId = await storeToAccIds(store);
    let rows;
    if (useProduct(seller, af)) {
      const f = pWhere(s, e, accId, seller, af);
      rows = await q(`SELECT p.date, SUM(${P_SALES}) as revenue, SUM(COALESCE(p.netProfit,0)) as netProfit,
        SUM(${P_UNITS}) as units, 0 as orders, SUM(${P_ADS}) as adSpend
        FROM seller_board_product p ${f.w} GROUP BY p.date ORDER BY p.date DESC LIMIT 60`, f.p);
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
    const accId = await storeToAccIds(store);
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
      0 as storageFee
      FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
      ${f.w} GROUP BY p.accountId ORDER BY revenue DESC`, f.p, 45000);
    // FBA Stock from snapshot
    let stockMap = {};
    try {
      const { w: _spw, p: _spp } = accIdClauseRaw(accId); const sp = ['WHERE 1=1'+_spw, _spp];
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
    const accId = await storeToAccIds(store);
    const fp = pWhere(s, e, accId, seller, af);

    // Single query — all detail columns in one pass over seller_board_product
    const mainQ = qc(`SELECT
        ABS(SUM(COALESCE(p.sponsoredProducts,0)))      as sp,
        ABS(SUM(COALESCE(p.sponsoredBrands,0)))        as sb,
        ABS(SUM(COALESCE(p.sponsoredBrandsVideo,0)))   as sbv,
        ABS(SUM(COALESCE(p.sponsoredDisplay,0)))       as sd,
        SUM(COALESCE(p.unitsOrganic,0))                as uo,
        SUM(COALESCE(p.unitsPPC,0))                    as up,
        ABS(SUM(COALESCE(p.FBAPerUnitFulfillmentFee,0))) as fba,
        ABS(SUM(COALESCE(p.commission,0)))             as comm,
        SUM(COALESCE(p.promoValue,0))                  as pv,
        SUM(COALESCE(p.salesOrganic,0))                as so,
        SUM(COALESCE(p.salesPPC,0))                    as spc
        FROM seller_board_product p
        LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
        ${fp.w}`, fp.p, 55000);

    // Sessions query (separate table, may not exist)
    let tw='WHERE date BETWEEN ? AND ?'; const tp=[s,e];
    { const _ac=accIdClauseRaw(accId); tw+=_ac.w; tp.push(..._ac.p); }
    const sessQ = qc(`SELECT SUM(COALESCE(browserSessions,0)) as bs, SUM(COALESCE(mobileAppSessions,0)) as ms
        FROM analytics_sale_traffic_by_date ${tw}`, tp, 20000).catch(()=>[{bs:0,ms:0}]);

    const [mainRes, sessRes] = await Promise.all([
      detailLimiter(()=>mainQ),
      sessQ,
    ]);

    const m = mainRes?.[0] || {};
    const sess = Array.isArray(sessRes) ? (sessRes[0]||{}) : {};

    res.json({
      sp:     parseFloat(m.sp)||0,
      sb:     parseFloat(m.sb)||0,
      sbv:    parseFloat(m.sbv)||0,
      sd:     parseFloat(m.sd)||0,
      unitsOrganic:   parseInt(m.uo)||0,
      unitsSP:        parseInt(m.up)||0,
      fbaFulfillment: parseFloat(m.fba)||0,
      commission:     parseFloat(m.comm)||0,
      promo:          parseFloat(m.pv)||0,
      salesOrganic:   parseFloat(m.so)||0,
      salesPPC:       parseFloat(m.spc)||0,
      browserSessions:  parseFloat(sess.bs)||0,
      mobileSessions:   parseFloat(sess.ms)||0,
    });
  } catch (e) { console.error('exec/detail:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════ EXEC MONTHLY LAST YEAR ═══════════ */
/* Returns monthly revenue/GP/units/ads for the previous year (same filter logic as plan/actuals) */
app.get('/api/exec/monthly-ly', async (req, res) => {
  try {
    const { store, seller, asin: af } = req.query;
    const lyYear = new Date().getFullYear() - 1;
    const accId = await storeToAccIds(store);
    const sd = `${lyYear}-01-01`, ed = `${lyYear}-12-31`;
    let rows;

    if (useProduct(seller, af)) {
      const f = pWhere(sd, ed, accId, seller, af);
      rows = await qc(`SELECT MONTH(p.date) as mn,
        SUM(${P_SALES}) as revenue, SUM(COALESCE(p.grossProfit,0)) as gp,
        SUM(COALESCE(p.netProfit,0)) as np, SUM(${P_UNITS}) as units,
        SUM(ABS(${P_ADS})) as ads, SUM(COALESCE(p.sessions,0)) as sessions
        FROM seller_board_product p LEFT JOIN asin a ON p.asin COLLATE utf8mb4_0900_ai_ci=a.asin
        ${f.w} GROUP BY MONTH(p.date) ORDER BY mn`, f.p, 45000);
    } else {
      const f = scWhere(sd, ed, accId);
      rows = await qc(`SELECT MONTH(sc.date) as mn,
        SUM(${SC_SALES}) as revenue, SUM(COALESCE(sc.grossProfit,0)) as gp,
        SUM(COALESCE(sc.netProfit,0)) as np, SUM(${SC_UNITS}) as units,
        SUM(ABS(${SC_ADS})) as ads, SUM(COALESCE(sc.sessions,0)) as sessions
        FROM ${salesFrom()} ${f.w} GROUP BY MONTH(sc.date) ORDER BY mn`, f.p, 45000);
    }
    const MS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    res.json((rows || []).map(r => ({
      mn: parseInt(r.mn),
      m: MS[(parseInt(r.mn)||1)-1],
      revenue: parseFloat(r.revenue)||0,
      gp: parseFloat(r.gp)||0,
      np: parseFloat(r.np)||0,
      units: parseInt(r.units)||0,
      ads: parseFloat(r.ads)||0,
      sessions: parseFloat(r.sessions)||0,
    })));
  } catch (e) { console.error('exec/monthly-ly:', e.message); res.status(500).json({ error: e.message }); }
});

/* ═══════════════════════════════════════════════════════════════
   REALTIME ENDPOINTS (Giai đoạn 1)
   Source: orders_by_date_general + analytics_sale_traffiec_by_asin_date
   Không đụng vào các endpoint cũ bên trên.
   Frontend dùng suffix "-rt" để phân biệt với endpoint Sellerboard.
═══════════════════════════════════════════════════════════════ */

/* ── Helper: lấy revenue từ orders_by_date_general ──
   orderedProductSales trong analytics là JSON {amount, currencyCode}
   item_price trong orders_by_date_general là decimal thông thường       */
function rtOrdersWhere(sd, ed, accIds) {
  // purchase_date da duoc luu theo PST roi (khop voi Sellerboard)
  let w = `WHERE DATE(o.purchase_date) BETWEEN ? AND ?
    AND o.order_status NOT IN ('Cancelled','Pending','PendingAvailability')`;
  const p = [sd, ed];
  const ac = accIdClause('o', accIds);
  w += ac.w;
  p.push(...ac.p);
  return { w, p };
}

/* ─────────────────────────────────────────────────────────────
   GET /api/exec/summary-rt
   Tương đương /api/exec/summary nhưng dùng data SP-API realtime
   Trả về: sales, units, orders, sessions, CVR, buyBox, advCost
───────────────────────────────────────────────────────────── */
app.get('/api/exec/summary-rt', async (req, res) => {
  try {
    const { start, end, store } = req.query;
    const { s, e } = defDates(start, end);
    const accIds = await storeToAccIds(store);
    const { w, p } = rtOrdersWhere(s, e, accIds);

    // Q1: Revenue + Units + Orders từ orders_by_date_general
    const ordersQ = qc(`
      SELECT
        SUM(COALESCE(o.item_price, 0))          AS sales,
        SUM(CAST(COALESCE(o.quantity,'0') AS SIGNED)) AS units,
        COUNT(DISTINCT o.amazon_order_id)        AS orders,
        SUM(COALESCE(o.item_promotion_discount, 0)) AS promoDiscount
      FROM orders_by_date_general o ${w}`, p, 45000);

    // Q2: Sessions + CVR + BuyBox từ analytics (typeDate='DAY')
    let tw = `WHERE t.date BETWEEN ? AND ? AND t.typeDate = 'DAY'`;
    const tp = [s, e];
    const tac = accIdClause('t', accIds); tw += tac.w; tp.push(...tac.p);
    const trafficQ = qc(`
      SELECT
        SUM(COALESCE(t.sessions, 0))                            AS sessions,
        SUM(COALESCE(t.pageViews, 0))                           AS pageViews,
        AVG(CASE WHEN t.unitSessionPercentage > 0
              THEN t.unitSessionPercentage END)                  AS cvr,
        AVG(CASE WHEN t.buyBoxPercentage > 0
              THEN t.buyBoxPercentage END)                       AS buyBox
      FROM analytics_sale_traffiec_by_asin_date t ${tw}`, tp, 30000);

    // Q3: Ad Spend từ ads DB (pool2) — dùng lại logic getAdsMetrics
    // Lấy tổng spend toàn bộ, không filter ASIN
    let adSpend = 0;
    if (pool2) {
      try {
        const conn = await pool2.getConnection();
        try {
          const [adRows] = await conn.execute(
            `SELECT SUM(cost) AS spend
             FROM report_sp_advertised_product
             WHERE date BETWEEN ? AND ?`, [s, e]);
          adSpend = parseFloat(adRows[0]?.spend) || 0;
        } finally { conn.release(); }
      } catch (e) { console.warn('[summary-rt] adSpend failed:', e.message); }
    }

    // Fallback: netProfit + advCost từ Sellerboard cũ (delay nhưng vẫn hiện để dễ so sánh)
    const scF = scWhere(s, e, accIds);
    const sbQ = qc(`
      SELECT
        SUM(COALESCE(sc.netProfit, 0))   AS netProfit,
        SUM(COALESCE(sc.grossProfit, 0)) AS grossProfit,
        SUM(${SC_ADS})                   AS advCost
      FROM ${salesFrom()} ${scF.w}`, scF.p, 30000).catch(() => [{}]);

    const [ordersRes, trafficRes, sbRes] = await Promise.all([ordersQ, trafficQ, sbQ]);
    const o  = ordersRes[0] || {};
    const t  = trafficRes[0] || {};
    const sb = sbRes[0] || {};

    const sales       = parseFloat(o.sales)        || 0;
    const units       = parseInt(o.units)           || 0;
    const orders      = parseInt(o.orders)          || 0;
    const sessions    = parseInt(t.sessions)        || 0;
    const cvr         = Math.round((parseFloat(t.cvr)    || 0) * 100) / 100;
    const buyBox      = Math.round((parseFloat(t.buyBox) || 0) * 100) / 100;
    const netProfit   = parseFloat(sb.netProfit)    || 0;
    const grossProfit = parseFloat(sb.grossProfit)  || 0;
    // advCost: ưu tiên ads DB nếu có, fallback về Sellerboard
    const advCostFinal = adSpend > 0 ? adSpend : (parseFloat(sb.advCost) || 0);

    res.json({
      dataSource:   'realtime',      // frontend hiển thị badge "RT"
      profitSource: 'sellerboard',   // tooltip giải thích profit vẫn từ SB
      sales, units, orders,
      sessions, cvr, buyBox,
      adSpend:      advCostFinal,
      advCost:      advCostFinal,
      realAcos:     sales > 0 ? (advCostFinal / sales * 100) : 0,
      netProfit,
      grossProfit,
      margin:       sales > 0 ? (netProfit / sales * 100) : 0,
    });
  } catch (e) {
    console.error('exec/summary-rt:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ─────────────────────────────────────────────────────────────
   GET /api/exec/daily-rt
   Tương đương /api/exec/daily nhưng dùng SP-API realtime
   Trả về mảng: [{ date, revenue, units, orders, sessions, cvr, buyBox }]
───────────────────────────────────────────────────────────── */
app.get('/api/exec/daily-rt', async (req, res) => {
  try {
    const { start, end, store } = req.query;
    const { s, e } = defDates(start, end);
    const accIds = await storeToAccIds(store);
    const { w, p } = rtOrdersWhere(s, e, accIds);

    // Q1: Daily revenue + units + orders
    const ordersQ = qc(`
      SELECT
        DATE(o.purchase_date)                              AS date,
        SUM(COALESCE(o.item_price, 0))                    AS revenue,
        SUM(CAST(COALESCE(o.quantity, '0') AS SIGNED))    AS units,
        COUNT(DISTINCT o.amazon_order_id)                 AS orders
      FROM orders_by_date_general o ${w}
      GROUP BY DATE(o.purchase_date)
      ORDER BY date`, p, 45000);

    // Q2: Daily sessions + CVR + BuyBox
    let tw = `WHERE t.date BETWEEN ? AND ? AND t.typeDate = 'DAY'`;
    const tp = [s, e];
    const tac = accIdClause('t', accIds); tw += tac.w; tp.push(...tac.p);
    const trafficQ = qc(`
      SELECT
        t.date,
        SUM(COALESCE(t.sessions, 0))                      AS sessions,
        AVG(CASE WHEN t.unitSessionPercentage > 0
              THEN t.unitSessionPercentage END)             AS cvr,
        AVG(CASE WHEN t.buyBoxPercentage > 0
              THEN t.buyBoxPercentage END)                  AS buyBox
      FROM analytics_sale_traffiec_by_asin_date t ${tw}
      GROUP BY t.date
      ORDER BY t.date`, tp, 30000);

    // Q3 fallback: netProfit + advCost theo ngay tu Sellerboard cu
    const scFd = scWhere(s, e, accIds);
    const sbDailyQ = qc(`
      SELECT sc.date,
        SUM(COALESCE(sc.netProfit, 0)) AS netProfit,
        SUM(${SC_ADS})                 AS advCost
      FROM ${salesFrom()} ${scFd.w}
      GROUP BY sc.date ORDER BY sc.date`, scFd.p, 30000).catch(() => []);

    const [ordersRows, trafficRows, sbDailyRows] = await Promise.all([ordersQ, trafficQ, sbDailyQ]);

    // Merge ca 3 nguon theo date
    const trafficMap = {};
    trafficRows.forEach(r => { trafficMap[String(r.date).slice(0, 10)] = r; });

    const sbDailyMap = {};
    sbDailyRows.forEach(r => { sbDailyMap[String(r.date).slice(0, 10)] = r; });

    const MS2 = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    res.json(ordersRows.map(r => {
      const ds  = String(r.date).slice(0, 10);
      const dt  = new Date(ds + 'T12:00:00');
      const trk = trafficMap[ds]  || {};
      const sb  = sbDailyMap[ds]  || {};
      return {
        date:         ds,
        label:        isNaN(dt) ? ds : MS2[dt.getMonth()] + ' ' + dt.getDate(),
        revenue:      parseFloat(r.revenue)  || 0,
        units:        parseInt(r.units)      || 0,
        orders:       parseInt(r.orders)     || 0,
        sessions:     parseInt(trk.sessions) || 0,
        cvr:          Math.round((parseFloat(trk.cvr)    || 0) * 100) / 100,
        buyBox:       Math.round((parseFloat(trk.buyBox) || 0) * 100) / 100,
        netProfit:    parseFloat(sb.netProfit) || 0,
        advCost:      Math.abs(parseFloat(sb.advCost) || 0),
        dataSource:   'realtime',
        profitSource: 'sellerboard',
      };
    }));
  } catch (e) {
    console.error('exec/daily-rt:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ─────────────────────────────────────────────────────────────
   GET /api/product/asins-rt
   Tương đương /api/product/asins nhưng dùng SP-API realtime
   Trả về per-ASIN: sessions, pageViews, CVR, buyBox, units, revenue
───────────────────────────────────────────────────────────── */
app.get('/api/product/asins-rt', async (req, res) => {
  try {
    const { start, end, store, seller, asin: af } = req.query;
    const { s, e } = defDates(start, end);
    const accIds = await storeToAccIds(store);
    const shopMap = await getShopMap();

    // Q1: Traffic per ASIN từ analytics
    let tw = `WHERE t.date BETWEEN ? AND ? AND t.typeDate = 'DAY'`;
    const tp = [s, e];
    const tac = accIdClause('t', accIds); tw += tac.w; tp.push(...tac.p);
    if (af && af !== 'All') { tw += ' AND t.asin = ?'; tp.push(af); }

    const trafficQ = qc(`
      SELECT
        t.asin,
        t.accountId,
        SUM(COALESCE(t.sessions, 0))                       AS sessions,
        SUM(COALESCE(t.pageViews, 0))                      AS pageViews,
        SUM(COALESCE(t.unitsOrdered, 0))                   AS unitsOrdered,
        AVG(CASE WHEN t.unitSessionPercentage > 0
              THEN t.unitSessionPercentage END)              AS cvr,
        AVG(CASE WHEN t.buyBoxPercentage > 0
              THEN t.buyBoxPercentage END)                   AS buyBox,
        -- orderedProductSales là JSON {amount, currencyCode}
        SUM(COALESCE(
          JSON_UNQUOTE(JSON_EXTRACT(t.orderedProductSales, '$.amount')),
          0
        ))                                                  AS revenue
      FROM analytics_sale_traffiec_by_asin_date t ${tw}
      GROUP BY t.asin, t.accountId
      ORDER BY revenue DESC`, tp, 60000);

    // Q2: Seller per ASIN từ seller_board_product (bảng nhỏ, query nhanh)
    let sw = 'WHERE p.date BETWEEN ? AND ?'; const sp = [s, e];
    const sac = accIdClause('p', accIds); sw += sac.w; sp.push(...sac.p);
    if (seller && seller !== 'All') { sw += ' AND p.seller = ?'; sp.push(seller); }
    const sellerQ = qc(`
      SELECT p.asin, MAX(p.seller) AS seller
      FROM seller_board_product p ${sw}
      GROUP BY p.asin`, sp, 20000).catch(() => []);

    // Q3: netProfit + margin per ASIN tu Sellerboard cu (fallback)
    let sbaw = 'WHERE p.date BETWEEN ? AND ?'; const sbap = [s, e];
    const sbac = accIdClause('p', accIds); sbaw += sbac.w; sbap.push(...sbac.p);
    const sbAsinQ = qc(`
      SELECT p.asin,
        SUM(COALESCE(p.netProfit, 0))   AS netProfit,
        SUM(COALESCE(p.grossProfit, 0)) AS grossProfit
      FROM seller_board_product p ${sbaw}
      GROUP BY p.asin`, sbap, 30000).catch(() => []);

    const [trafficRows, sellerRows, sbAsinRows] = await Promise.all([trafficQ, sellerQ, sbAsinQ]);

    // Build maps
    const sellerMap = {};
    sellerRows.forEach(r => { sellerMap[r.asin] = r.seller || ''; });

    const sbAsinMap = {};
    sbAsinRows.forEach(r => { sbAsinMap[r.asin] = r; });

    let rows = trafficRows;
    if (seller && seller !== 'All') {
      rows = rows.filter(r => sellerMap[r.asin] === seller);
    }

    // Ads metrics (CTR, CPC, impressions) tu pool2
    const asinList = rows.map(r => r.asin);
    const [imgMap, adsMap] = await Promise.all([
      getImageMap(asinList),
      getAdsMetrics(asinList, s, e),
    ]);

    res.json(rows.map(r => {
      const rev      = parseFloat(r.revenue)       || 0;
      const units    = parseInt(r.unitsOrdered)     || 0;
      const sess     = parseInt(r.sessions)         || 0;
      const cvr      = Math.round((parseFloat(r.cvr)    || 0) * 100) / 100;
      const buyBox   = Math.round((parseFloat(r.buyBox) || 0) * 100) / 100;
      const ads      = adsMap[r.asin] || {};
      const sbA      = sbAsinMap[r.asin] || {};
      const np       = parseFloat(sbA.netProfit) || 0;
      return {
        asin:         r.asin,
        shop:         shopMap[r.accountId] || '',
        seller:       sellerMap[r.asin]    || '',
        revenue:      rev,
        units,
        sessions:     sess,
        pageViews:    parseInt(r.pageViews) || 0,
        cvr,
        buyBox,
        // Profit tu Sellerboard cu (hien tam de so sanh)
        netProfit:    np,
        margin:       rev > 0 ? Math.round(np / rev * 1000) / 10 : 0,
        profitSource: 'sellerboard',
        // Ads tu Advertising API
        ctr:          ads.ctr        ?? null,
        cpc:          ads.cpc        ?? null,
        impressions:  ads.impressions || 0,
        clicks:       ads.clicks     || 0,
        imageUrl:     imgMap[r.asin] || null,
        dataSource:   'realtime',
      };
    }));
  } catch (e) {
    console.error('product/asins-rt:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ PRODUCT CR PERFORMANCE ═══════════ */
// date/week/month all derived from analytics_sale_traffiec_by_asin_date.date
// (Amazon report date — NOT created_at)
app.get('/api/product/cr-performance', async (req, res) => {
  try {
    const { period = 'monthly', year, start, end, store } = req.query;
    const yr      = parseInt(year) || new Date().getFullYear();
    const accIds  = await storeToAccIds(store);
    const shopMap = await getShopMap();

    let sd, ed, groupExpr, labelExpr, orderExpr;
    if (period === 'daily') {
      const { s, e } = defDates(start, end);
      sd = s; ed = e;
      groupExpr = `DATE(t.date)`;
      labelExpr = `DATE_FORMAT(t.date, '%Y-%m-%d')`;
      orderExpr = `DATE(t.date) ASC`;
    } else if (period === 'weekly') {
      sd = `${yr}-01-01`; ed = `${yr}-12-31`;
      groupExpr = `YEARWEEK(t.date, 1)`;
      labelExpr = `CONCAT('W', LPAD(WEEK(t.date,1),2,'0'))`;
      orderExpr = `YEARWEEK(t.date, 1) ASC`;
    } else {
      sd = `${yr}-01-01`; ed = `${yr}-12-31`;
      groupExpr = `MONTH(t.date)`;
      labelExpr = `CONCAT('T', MONTH(t.date))`;
      orderExpr = `MONTH(t.date) ASC`;
    }

    let accFilter = ''; const accParams = [];
    if (accIds && accIds.length) {
      accFilter = ` AND t.accountId IN (${accIds.map(() => '?').join(',')})`;
      accParams.push(...accIds);
    }

    // Q1: Analytics — CR + CTR per ASIN per period
    const analyticsRows = await q(`
      SELECT
        t.asin,
        t.accountId,
        MIN(${labelExpr})                              AS periodLabel,
        ${groupExpr}                                   AS periodGroup,
        ROUND(AVG(t.unitSessionPercentage), 2)         AS cr,
        ROUND(AVG(scp.clickRate) * 100, 2)             AS ctr,
        SUM(t.sessions)                                AS sessions,
        SUM(t.unitsOrdered)                            AS units
      FROM analytics_sale_traffiec_by_asin_date t
      LEFT JOIN analytics_search_catalog_performance scp
        ON  scp.asin      = t.asin
        AND scp.accountId = t.accountId
        AND scp.startDate = t.date
      WHERE t.typeDate = 'DAY'
        AND t.date BETWEEN ? AND ?
        ${accFilter}
      GROUP BY t.asin, t.accountId, ${groupExpr}
      ORDER BY t.asin, ${orderExpr}
    `, [sd, ed, ...accParams], 90000);

    if (analyticsRows.length === 0) return res.json({ periodLabels: [], rows: [] });

    const asinSet    = [...new Set(analyticsRows.map(r => r.asin))];
    const asinAccMap = {};
    analyticsRows.forEach(r => { if (!asinAccMap[r.asin]) asinAccMap[r.asin] = r.accountId; });
    const ph = asinSet.map(() => '?').join(',');

    // Q2: ASIN master — contenters (1/2/3), imagers, seller, tier
    let asinMaster = [];
    try {
      const cols    = (await q('SHOW COLUMNS FROM asin', [], 5000)).map(c => c.Field);
      const has2    = cols.includes('contenters2');
      const has3    = cols.includes('contenters3');
      const hasTier = cols.includes('tier');
      asinMaster = await q(`
        SELECT a.asin, a.seller,
          a.contenters                                 AS content1,
          ${has2 ? 'a.contenters2' : 'NULL'}           AS content2,
          ${has3 ? 'a.contenters3' : 'NULL'}           AS content3,
          a.imagers                                    AS image,
          ${hasTier ? 'a.tier' : 'NULL'}               AS tier
        FROM asin a WHERE a.asin IN (${ph})
      `, asinSet, 15000);
    } catch(e) { console.warn('[cr-performance] asin master:', e.message); }

    // Q3: productType + niche — try asin table first, fallback to seller_board_product
    let sbpRows = [];
    try {
      // Try getting from asin table if columns exist
      const asinCols = (await q('SHOW COLUMNS FROM asin', [], 5000)).map(c => c.Field);
      const hasPT    = asinCols.includes('productType');
      const hasNiche = asinCols.includes('seasonAndNiche');
      if (hasPT || hasNiche) {
        sbpRows = await q(`
          SELECT a.asin,
            ${hasPT    ? 'a.productType'    : 'NULL'} AS productType,
            ${hasNiche ? 'a.seasonAndNiche' : 'NULL'} AS niche
          FROM asin a WHERE a.asin IN (${ph})
        `, asinSet, 10000);
      }
    } catch(e) { console.warn('[cr-performance] asin ptNiche:', e.message); }
    // Fallback: seller_board_product (last 365 days — wider range to catch sparse data)
    if (!sbpRows.length || sbpRows.every(r => !r.productType && !r.niche)) {
      try {
        sbpRows = await q(`
          SELECT p.asin,
            MAX(p.productType)    AS productType,
            MAX(p.seasonAndNiche) AS niche
          FROM seller_board_product p
          WHERE p.asin IN (${ph}) AND p.date >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)
          GROUP BY p.asin
        `, asinSet, 20000);
      } catch(e) { console.warn('[cr-performance] sbp:', e.message); }
    }

    // Q4: SKU + FBA stock snapshot
    let stockRows = [];
    try {
      stockRows = await q(`
        SELECT s.asin, MIN(s.sku) AS sku, SUM(s.FBAStock) AS stock
        FROM seller_board_stock s WHERE s.asin IN (${ph})
        GROUP BY s.asin
      `, asinSet, 10000);
    } catch(e) { console.warn('[cr-performance] stock:', e.message); }

    // Q5: Available from fba_iventory_planning (latest snapshot)
    let availRows = [];
    try {
      availRows = await q(`
        SELECT f.asin,
          SUM(GREATEST(CAST(f.available AS SIGNED), 0)) AS avail
        FROM fba_iventory_planning f
        JOIN (SELECT accountId AS aid, MAX(date) AS maxDate FROM fba_iventory_planning GROUP BY accountId) latest
          ON f.accountId = latest.aid AND f.date = latest.maxDate
        WHERE f.asin IN (${ph})
        GROUP BY f.asin
      `, asinSet, 15000);
    } catch(e) { console.warn('[cr-performance] avail:', e.message); }

    // Q6: Ads CTR from pool2 — date from report_sp_advertised_product.date (NOT created_at)
    const adsCtrMap = {};
    if (pool2) {
      try {
        const conn = await pool2.getConnection();
        try {
          let adsGrp;
          if (period === 'daily')       adsGrp = `DATE(r.date)`;
          else if (period === 'weekly') adsGrp = `YEARWEEK(r.date, 1)`;
          else                          adsGrp = `MONTH(r.date)`;
          const [adsRows] = await conn.execute(`
            SELECT pa.asin, ${adsGrp} AS periodGroup,
              ROUND(SUM(r.clicks)/NULLIF(SUM(r.impressions),0)*100, 4) AS adsCtr
            FROM (
              SELECT campaignId, adGroupId, ${adsGrp} AS pg,
                SUM(clicks) AS clicks, SUM(impressions) AS impressions
              FROM report_sp_advertised_product WHERE date BETWEEN ? AND ?
              GROUP BY campaignId, adGroupId, ${adsGrp}
            ) r
            JOIN product_ads pa ON pa.campaignId=r.campaignId AND pa.adGroupId=r.adGroupId
            WHERE pa.asin IS NOT NULL AND pa.asin != ''
            GROUP BY pa.asin, ${adsGrp}
          `, [sd, ed]);
          adsRows.forEach(r => {
            if (!adsCtrMap[r.asin]) adsCtrMap[r.asin] = {};
            adsCtrMap[r.asin][String(r.periodGroup)] = parseFloat(r.adsCtr) || 0;
          });
        } finally { conn.release(); }
      } catch(e) { console.warn('[cr-performance] adsCtr:', e.message); }
    }

    // Build maps
    const masterMap = {}; asinMaster.forEach(r => { masterMap[r.asin] = r; });
    const sbpMap    = {}; sbpRows.forEach(r => { sbpMap[r.asin] = r; });
    const stockMap  = {}; stockRows.forEach(r => { stockMap[r.asin] = r; });
    const availMap  = {}; availRows.forEach(r => { availMap[r.asin] = r; });

    // Period label ordering
    const periodMap = {};
    analyticsRows.forEach(r => { periodMap[String(r.periodGroup)] = r.periodLabel; });
    const periodLabels = Object.entries(periodMap)
      .sort(([a], [b]) => String(a).localeCompare(String(b)))
      .map(([, label]) => label);

    // Pivot analytics per ASIN
    const asinPeriods = {};
    analyticsRows.forEach(r => {
      if (!asinPeriods[r.asin]) asinPeriods[r.asin] = {};
      const lbl = periodMap[String(r.periodGroup)];
      asinPeriods[r.asin][lbl] = {
        cr:     r.cr  != null ? parseFloat(r.cr)  : null,
        ctr:    r.ctr != null ? parseFloat(r.ctr) : null,
        adsCtr: adsCtrMap[r.asin]?.[String(r.periodGroup)] ?? null,
      };
    });

    const rows = asinSet.map(asin => {
      const m  = masterMap[asin] || {};
      const sb = sbpMap[asin]    || {};
      const st = stockMap[asin]  || {};
      const av = availMap[asin]  || {};
      return {
        asin,
        sku:         st.sku  || '',
        store:       shopMap[asinAccMap[asin]] || '',
        sellers:     m.seller     || '',
        content1:    m.content1   || '',
        content2:    m.content2   || '',
        content3:    m.content3   || '',
        image:       m.image      || '',
        tier:        m.tier       || '',
        productType: sb.productType || '',
        niche:       sb.niche      || '',
        stock:       parseInt(st.stock) || 0,
        avail:       parseInt(av.avail) || 0,
        periods:     asinPeriods[asin] || {},
      };
    });

    res.json({ periodLabels, rows });
  } catch(e) {
    console.error('[cr-performance]', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ═══════════ SERVE FRONTEND ═══════════ */
const distPath = join(__dirname, 'dist');
app.use(express.static(distPath));
app.get('*', (req, res) => { res.sendFile(join(distPath, 'index.html')); });
app.listen(PORT, '0.0.0.0', () => { console.log(`\n🚀 Dashboard ${VER} on :${PORT} | DB: ${process.env.DB_HOST||'none'}\n`); });
