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

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch (err) {
    // Fetch itself failed — the API is unreachable, CORS preflight was denied,
    // or the network dropped. fetch() throws TypeError "Failed to fetch" here.
    console.error(`API Error [${path}]: network`, err);
    return {
      success: false,
      message: 'Cannot reach the API server. Check that it is running and try again.',
    };
  }

  // Don't intercept 401 on login/auth endpoints — let the caller handle it.
  if (res.status === 401 && !path.startsWith('/auth/')) {
    // Attempt token refresh before giving up
    const refreshToken = localStorage.getItem('soc_refresh_token');
    if (refreshToken) {
      try {
        const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken }),
        });
        if (refreshRes.ok) {
          const refreshData = await refreshRes.json();
          if (refreshData.success && refreshData.data?.accessToken) {
            setToken(refreshData.data.accessToken);
            if (refreshData.data.refreshToken) {
              localStorage.setItem('soc_refresh_token', refreshData.data.refreshToken);
            }
            // Retry the original request with new token
            headers['Authorization'] = `Bearer ${refreshData.data.accessToken}`;
            const retryRes = await fetch(`${API_BASE}${path}`, { ...options, headers });
            const retryText = await retryRes.text();
            if (!retryText) return retryRes.ok ? { success: true, data: null } : { success: false, message: `HTTP ${retryRes.status}` };
            try { return JSON.parse(retryText); } catch { return { success: false, message: `HTTP ${retryRes.status}` }; }
          }
        }
      } catch { /* refresh failed, fall through to logout */ }
    }
    // Refresh failed or no refresh token — clear session and redirect
    setToken(null);
    localStorage.removeItem('soc_user');
    localStorage.removeItem('soc_refresh_token');
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  // 429 is special — show it to the user with the Retry-After hint if set.
  if (res.status === 429) {
    const retryAfter = parseInt(res.headers.get('Retry-After') || '0', 10);
    const minutes = retryAfter ? Math.ceil(retryAfter / 60) : null;
    return {
      success: false,
      errors: ['Too many attempts. Please wait'
              + (minutes ? ` about ${minutes} minute(s)` : ' a few minutes')
              + ' and try again.'],
    };
  }

  // Empty body (204, or rejects with no content) → synthesize a success/fail.
  const text = await res.text();
  if (!text) {
    return res.ok
      ? { success: true, data: null }
      : { success: false, message: `HTTP ${res.status}` };
  }

  try {
    const json = JSON.parse(text);
    // If the response is a success (2xx) or already has our `success` field, return as-is.
    if (res.ok || json.success !== undefined) return json;
    // Non-2xx JSON without `success` field — likely ASP.NET ProblemDetails.
    // Normalize into our standard shape so callers always see { success, message }.
    return {
      success: false,
      message: json.detail || json.title || json.message || `HTTP ${res.status}: ${JSON.stringify(json).slice(0, 200)}`,
      errors: json.errors ? (Array.isArray(json.errors) ? json.errors : Object.values(json.errors).flat()) : [],
    };
  } catch {
    // Non-JSON response (HTML error page, plain text) — surface it rather than
    // crashing. Happens on 500 when the global exception handler misses.
    console.error(`API Error [${path}]: non-JSON response`, text.slice(0, 200));
    return {
      success: false,
      message: `Server returned a non-JSON response (HTTP ${res.status}).`,
    };
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
  register: (data) =>
    request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  logout: () =>
    request('/auth/logout', { method: 'POST' }),
  refreshToken: (refreshToken) =>
    request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refreshToken }) }),
  getProfile: () => request('/auth/profile'),

  // ── MFA (TOTP, RFC 6238) ──
  // The login flow:
  //   1. api.login(u, p) → if res.data.mfaRequired, hold the mfaToken.
  //   2. api.mfaVerify(mfaToken, code)  OR  api.mfaBackup(mfaToken, backupCode)
  //      → returns a normal login response with accessToken+refreshToken.
  mfaSetup:    ()                 => request('/auth/mfa/setup',   { method: 'POST' }),
  mfaEnable:   (code)             => request('/auth/mfa/enable',  { method: 'POST', body: JSON.stringify({ code }) }),
  mfaDisable:  (currentPassword, code) =>
                                     request('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ currentPassword, code }) }),
  mfaStatus:   ()                 => request('/auth/mfa/status'),
  mfaVerify:   (mfaToken, code)   => request('/auth/mfa/verify',  { method: 'POST', body: JSON.stringify({ mfaToken, code }) }),
  mfaBackup:   (mfaToken, backupCode) =>
                                     request('/auth/mfa/backup',  { method: 'POST', body: JSON.stringify({ mfaToken, backupCode }) }),

  // First-time enrollment during login (for privileged roles that haven't
  // enrolled yet). Uses the mfaToken in place of an access token.
  mfaEnrollSetup:    (mfaToken)        => request('/auth/mfa/enroll-setup',    { method: 'POST', body: JSON.stringify({ mfaToken }) }),
  mfaEnrollComplete: (mfaToken, code)  => request('/auth/mfa/enroll-complete', { method: 'POST', body: JSON.stringify({ mfaToken, code }) }),

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
  addEvidence: (id, data) =>
    request(`/incidents/${id}/evidence`, { method: 'POST', body: JSON.stringify(data) }),
  linkAlerts: (id, alertIds) =>
    request(`/incidents/${id}/alerts`, { method: 'POST', body: JSON.stringify(alertIds) }),
  getTimeline: (id) => request(`/incidents/${id}/timeline`),

  // ── Detection Rules ──
  getRules: () => request('/detectionrules'),
  getRule: (id) => request(`/detectionrules/${id}`),
  createRule: (data) =>
    request('/detectionrules', { method: 'POST', body: JSON.stringify(data) }),
  updateRule: (id, data) =>
    request(`/detectionrules/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  toggleRule: (id) => request(`/detectionrules/${id}/toggle`, { method: 'PATCH' }),
  deleteRule: (id) => request(`/detectionrules/${id}`, { method: 'DELETE' }),

  // ── Playbooks ──
  getPlaybooks: () => request('/playbooks'),
  getPlaybook: (id) => request(`/playbooks/${id}`),
  createPlaybook: (data) =>
    request('/playbooks', { method: 'POST', body: JSON.stringify(data) }),
  updatePlaybook: (id, data) =>
    request(`/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  togglePlaybook: (id) =>
    request(`/playbooks/${id}/toggle`, { method: 'PATCH' }),
  triggerPlaybook: (id, alertId) =>
    request(`/playbooks/${id}/trigger`, { method: 'POST', body: JSON.stringify({ alertId }) }),
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
  getThreatFeedSources: () => request('/threatintel/sources'),
  syncThreatFeeds: () =>
    request('/threatintel/sync', { method: 'POST' }),

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
