// Strip credentials from the URL to avoid "Request cannot be constructed from a URL that includes credentials" errors
const BASE = `${window.location.protocol}//${window.location.host}`;

function authHeaders() {
  const token = localStorage.getItem("token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function authFetch(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { ...authHeaders(), ...opts.headers },
  });
  if (res.status === 401) {
    localStorage.removeItem("token");
    window.dispatchEvent(new Event("auth:logout"));
  }
  return res.json();
}

export async function login(username, password) {
  const res = await fetch(`${BASE}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (data.ok) {
    localStorage.setItem("token", data.token);
  }
  return data;
}

export function logout() {
  localStorage.removeItem("token");
}

export function isLoggedIn() {
  return !!localStorage.getItem("token");
}

export async function fetchResults() {
  return authFetch(`${BASE}/api/results`);
}

export async function fetchImages() {
  return authFetch(`${BASE}/api/images`);
}

export async function fetchHistory(image) {
  return authFetch(`${BASE}/api/history/${image}`);
}

export async function fetchDetail(image, file) {
  return authFetch(`${BASE}/api/detail/${image}/${file}`);
}

export async function fetchStatus() {
  return authFetch(`${BASE}/api/status`);
}

export async function triggerScan() {
  return authFetch(`${BASE}/api/scan`, { method: "POST" });
}
