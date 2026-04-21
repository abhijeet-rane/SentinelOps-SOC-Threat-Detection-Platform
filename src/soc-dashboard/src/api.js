// ── SOC Platform API Client – Connected to Real Backend ──
// VITE_API_BASE_URL is baked in at build time (Vite envs are static).
// Dev: unset → falls back to localhost:5101. Prod: set to "/api/v1" so the
// browser hits the same origin and Caddy reverse-proxies to the API.
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5101/api/v1';

let authToken = localStorage.getItem('soc_token') || null;

export const setToken = (token) => {
  authToken = token;
  if (token) localStorage.setItem('soc_token', token);
  else localStorage.removeItem('soc_token');
};

export const getToken = () => authToken;
export const isAuthenticated = () => !!authToken;

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

  try {
    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
    // Don't intercept 401 on login/auth endpoints — let the caller handle it
    if (res.status === 401 && !path.startsWith('/auth/')) {
      setToken(null);
      window.location.href = '/login';
      throw new Error('Unauthorized');
    }
    const data = await res.json();
    return data;
  } catch (err) {
    if (err.message === 'Unauthorized') throw err;
    console.error(`API Error [${path}]:`, err);
    return { success: false, message: err.message || 'Network error' };
  }
}

export const api = {
  // ── Auth ──
  login: (username, password) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  forgotPassword: (email) =>
    request('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token, newPassword) =>
    request('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, newPassword }) }),

  // ── Alerts ──
  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/alerts?${qs}`);
  },
  getAlert: (id) => request(`/alerts/${id}`),
  getAlertStats: () => request(`/alerts/stats`),
  updateAlertStatus: (id, newStatus) =>
    request(`/alerts/${id}/status`, { method: 'PATCH', body: JSON.stringify({ newStatus }) }),
  assignAlert: (id, analystId) =>
    request(`/alerts/${id}/assign`, { method: 'PATCH', body: JSON.stringify({ analystId }) }),
  escalateAlert: (id) =>
    request(`/alerts/${id}/escalate`, { method: 'PATCH' }),

  // ── Incidents ──
  getIncidents: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/incidents?${qs}`);
  },
  getIncident: (id) => request(`/incidents/${id}`),
  createIncident: (data) =>
    request('/incidents', { method: 'POST', body: JSON.stringify(data) }),
  updateIncident: (id, data) =>
    request(`/incidents/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  addNote: (id, content) =>
    request(`/incidents/${id}/notes`, { method: 'POST', body: JSON.stringify({ content }) }),
  getTimeline: (id) => request(`/incidents/${id}/timeline`),

  // ── Detection Rules ──
  getRules: () => request('/detectionrules'),
  getRule: (id) => request(`/detectionrules/${id}`),
  toggleRule: (id) => request(`/detectionrules/${id}/toggle`, { method: 'PATCH' }),
  deleteRule: (id) => request(`/detectionrules/${id}`, { method: 'DELETE' }),

  // ── Playbooks ──
  getPlaybooks: () => request('/playbooks'),
  getPendingExecutions: () => request('/playbooks/executions/pending'),
  approveExecution: (id) =>
    request(`/playbooks/executions/${id}/approve`, { method: 'POST' }),
  rejectExecution: (id, reason) =>
    request(`/playbooks/executions/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
  getExecutionHistory: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/playbooks/executions/history?${qs}`);
  },

  // ── Threat Intelligence ──
  getThreatIntel: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/threatintel?${qs}`);
  },
  getThreatIntelById: (id) => request(`/threatintel/${id}`),
  createThreatIntel: (data) =>
    request('/threatintel', { method: 'POST', body: JSON.stringify(data) }),
  updateThreatIntel: (id, data) =>
    request(`/threatintel/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  toggleThreatIntel: (id) =>
    request(`/threatintel/${id}/toggle`, { method: 'PATCH' }),
  deleteThreatIntel: (id) =>
    request(`/threatintel/${id}`, { method: 'DELETE' }),
  importThreatIntel: (data) =>
    request('/threatintel/import', { method: 'POST', body: JSON.stringify(data) }),
  seedThreatIntel: () =>
    request('/threatintel/seed', { method: 'POST' }),
  enrichValue: (value, type) =>
    request('/threatintel/enrich', { method: 'POST', body: JSON.stringify({ value, type }) }),
  enrichLog: (data) =>
    request('/threatintel/enrich/log', { method: 'POST', body: JSON.stringify(data) }),
  autoEscalateAlert: (alertId) =>
    request(`/threatintel/escalate/${alertId}`, { method: 'POST' }),
  getThreatIntelStats: () => request('/threatintel/stats'),

  // ── Audit Logs ──
  getAuditLogs: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/auditlog?${qs}`);
  },
  verifyAuditIntegrity: () => request('/auditlog/integrity'),

  // ── Dashboard / Analytics ──
  getAnalytics: () => request('/dashboard/analytics'),
  getMitreCoverage: () => request('/dashboard/mitre'),
  getAlertTrend: () => request('/dashboard/trend'),

  // ── Users ──
  getUsers: () => request('/auth/users'),
  updateUser: (id, data) =>
    request(`/auth/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deactivateUser: (id) =>
    request(`/auth/users/${id}/deactivate`, { method: 'PATCH' }),

  // ── Roles ──
  getRoles: () => request('/auth/roles'),

  // ── Reports ──
  getDailyReport: (from, to) =>
    request(`/reports/daily?from=${from}&to=${to}`),
  getIncidentReport: (from, to) =>
    request(`/reports/incidents?from=${from}&to=${to}`),
  getAnalystReport: (from, to) =>
    request(`/reports/analysts?from=${from}&to=${to}`),
  getComplianceReport: (from, to, framework = 'NIST') =>
    request(`/reports/compliance?from=${from}&to=${to}&framework=${framework}`),
  exportReport: async (type, format, from, to, framework = 'NIST') => {
    const url = `${API_BASE}/reports/export?type=${type}&format=${format}&from=${from}&to=${to}&framework=${framework}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    if (!res.ok) throw new Error('Export failed');
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `soc-${type}-report.${format === 'excel' ? 'xlsx' : 'pdf'}`;
    a.click();
    URL.revokeObjectURL(a.href);
  },

  // ── ML Detection ──
  getMlStatus: () => request('/ml/status'),
  mlAnalyze: (data) =>
    request('/ml/analyze', { method: 'POST', body: JSON.stringify(data) }),
  mlTrain: (model = 'all') =>
    request('/ml/train', { method: 'POST', body: JSON.stringify({ model }) }),
};
