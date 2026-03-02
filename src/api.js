const BASE = window.location.origin;

export async function checkBackend() {
  try {
    const r = await fetch(`${BASE}/api/health`, { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    return d.status === 'ok' && d.database === 'connected';
  } catch { return false; }
}

export async function api(path, params = {}) {
  const qs = Object.entries(params).filter(([,v]) => v != null && v !== '' && v !== 'All').map(([k,v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const url = `${BASE}/api/${path}${qs ? '?' + qs : ''}`;
  const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

export async function apiPost(path, body) {
  const r = await fetch(`${BASE}/api/${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(30000),
  });
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

export const isLive = false; // will be determined at runtime
