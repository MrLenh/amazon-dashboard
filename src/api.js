// api.js — API helpers with auth token support
const BASE = (import.meta.env.VITE_API_URL || '') + '/api';

// Token storage
let _token = localStorage.getItem('dashboard_token') || null;
export function setToken(t) { _token = t; if (t) localStorage.setItem('dashboard_token', t); else localStorage.removeItem('dashboard_token'); }
export function getToken() { return _token; }
export function clearAuth() { _token = null; localStorage.removeItem('dashboard_token'); localStorage.removeItem('dashboard_user'); }

function authHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (_token) h['Authorization'] = 'Bearer ' + _token;
  return h;
}

export async function checkBackend() {
  try {
    const r = await fetch(BASE + '/health', { signal: AbortSignal.timeout(8000) });
    return r.ok;
  } catch { return false; }
}

export async function api(endpoint, params = {}, timeout = 30000) {
  const qs = Object.entries(params).filter(([, v]) => v != null && v !== '' && v !== 'All').map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const url = `${BASE}/${endpoint}${qs ? '?' + qs : ''}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { headers: authHeaders(), signal: ctrl.signal });
    clearTimeout(timer);
    if (r.status === 401) { clearAuth(); window.location.reload(); throw new Error('Session expired'); }
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || `HTTP ${r.status}`); }
    return r.json();
  } catch (e) { clearTimeout(timer); throw e; }
}

export async function apiPost(endpoint, body = {}, timeout = 30000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(`${BASE}/${endpoint}`, {
      method: 'POST', headers: authHeaders(), body: JSON.stringify(body), signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (r.status === 401) { clearAuth(); window.location.reload(); throw new Error('Session expired'); }
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || `HTTP ${r.status}`); }
    return r.json();
  } catch (e) { clearTimeout(timer); throw e; }
}

// Auth-specific API calls
export async function authLogin(email, password) {
  const r = await fetch(`${BASE}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || 'Login failed');
  setToken(data.token);
  localStorage.setItem('dashboard_user', JSON.stringify(data.user));
  return data;
}

export async function authMe() {
  if (!_token) return null;
  try {
    const r = await fetch(`${BASE}/auth/me`, { headers: authHeaders() });
    if (!r.ok) { clearAuth(); return null; }
    const data = await r.json();
    return data.user;
  } catch { clearAuth(); return null; }
}

export async function authChangePassword(currentPassword, newPassword) {
  return apiPost('auth/change-password', { currentPassword, newPassword });
}

export async function authGetUsers() { return api('auth/users'); }
export async function authCreateUser(email, name, password, role) {
  return apiPost('auth/users', { email, name, password, role });
}
export async function authUpdateUser(id, data) {
  const r = await fetch(`${BASE}/auth/users/${id}`, {
    method: 'PUT', headers: authHeaders(), body: JSON.stringify(data),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Update failed');
  return d;
}
export async function authDeleteUser(id) {
  const r = await fetch(`${BASE}/auth/users/${id}`, {
    method: 'DELETE', headers: authHeaders(),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Delete failed');
  return d;
}

// Invite flow
export async function authSendInvite(email, role) {
  return apiPost('auth/invite', { email, role });
}
export async function authVerifyInvite(token) {
  const r = await fetch(`${BASE}/auth/invite/${token}`);
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Invalid invite');
  return d;
}
export async function authAcceptInvite(token, name, password) {
  const r = await fetch(`${BASE}/auth/invite/${token}/accept`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, password }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Failed to accept invite');
  if (d.token) { setToken(d.token); localStorage.setItem('dashboard_user', JSON.stringify(d.user)); }
  return d;
}
export async function authGetInvites() { return api('auth/invites'); }
export async function authRevokeInvite(id) {
  const r = await fetch(`${BASE}/auth/invite/${id}`, {
    method: 'DELETE', headers: authHeaders(),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Revoke failed');
  return d;
}
