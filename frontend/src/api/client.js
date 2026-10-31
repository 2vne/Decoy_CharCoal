const BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');

/**
 * Backend Endpoint Authentication Analysis:
 *
 * Requiring X-API-Key authentication:
 *  - POST  /api/events (Collector ingestion - honeypots only)
 *  - POST  /api/attackers/{id}/block
 *  - POST  /api/attackers/{id}/unblock
 *  - PATCH /api/incidents/{id}
 *  - POST  /api/incidents/{id}/notes
 *
 * Public / Unauthenticated endpoints:
 *  - POST /api/simulate/start
 *  - GET  /api/overview
 *  - GET  /api/events
 *  - GET  /api/attackers
 *  - GET  /api/attackers/{id}
 *  - GET  /api/attackers/{id}/timeline
 *  - GET  /api/attackers/{id}/replay
 *  - GET  /api/relationships
 *  - GET  /api/incidents
 *  - GET  /api/incidents/{id}
 *  - GET  /api/incidents/{id}/investigation
 *  - POST /api/incidents/{id}/investigate
 *  - GET  /api/incidents/{id}/report
 *  - GET  /api/actions
 *  - POST /api/actions/{id}/approve
 *  - POST /api/actions/{id}/reject
 *  - GET  /api/blocks
 *  - GET  /api/metrics
 *  - GET  /api/honeypots/health
 *  - GET  /api/reports/summary
 *  - GET  /api/adaptive-deception
 *  - GET  /api/ioc
 *  - GET  /api/audit
 *  - GET  /api/events/{id}/integrity
 *  - POST /api/whatif
 *  - GET  /api/attackers/{id}/prediction
 *  - GET  /api/exposure
 *  - PUT  /api/exposure
 *  - GET  /api/health-correlation
 *  - WS   /ws/live
 */

const jsonHeaders = {
  'Content-Type': 'application/json',
};

// Returns auth headers if configured in browser session (never hardcodes collector key)
function getAuthHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (typeof window !== 'undefined') {
    const sessionKey = sessionStorage.getItem('sentinel_auth_key') || localStorage.getItem('sentinel_auth_key');
    if (sessionKey) {
      headers['X-API-Key'] = sessionKey;
    }
  }
  return headers;
}

export function setSessionAuthKey(key) {
  if (typeof window !== 'undefined') {
    if (key) {
      sessionStorage.setItem('sentinel_auth_key', key);
    } else {
      sessionStorage.removeItem('sentinel_auth_key');
      localStorage.removeItem('sentinel_auth_key');
    }
  }
}

async function handleResponse(res) {
  if (!res.ok) {
    const errorText = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${errorText || res.statusText}`);
  }
  return res.json();
}

export const api = {
  getBaseUrl() {
    return BASE_URL;
  },

  async getOverview() {
    const res = await fetch(`${BASE_URL}/api/overview`);
    return handleResponse(res);
  },

  async getEvents(params = {}) {
    const query = new URLSearchParams();
    if (params.severity) query.append('severity', params.severity);
    if (params.honeypot) query.append('honeypot', params.honeypot);
    if (params.q) query.append('q', params.q);
    if (params.limit) query.append('limit', params.limit);
    if (params.cursor) query.append('cursor', params.cursor);

    const res = await fetch(`${BASE_URL}/api/events?${query.toString()}`);
    return handleResponse(res);
  },

  async getAttackers() {
    const res = await fetch(`${BASE_URL}/api/attackers`);
    return handleResponse(res);
  },

  async getAttacker(id) {
    const res = await fetch(`${BASE_URL}/api/attackers/${id}`);
    return handleResponse(res);
  },

  async getAttackerTimeline(id) {
    const res = await fetch(`${BASE_URL}/api/attackers/${id}/timeline`);
    return handleResponse(res);
  },

  async getAttackerReplay(id) {
    const res = await fetch(`${BASE_URL}/api/attackers/${id}/replay`);
    return handleResponse(res);
  },

  async blockAttacker(id) {
    const res = await fetch(`${BASE_URL}/api/attackers/${id}/block`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse(res);
  },

  async unblockAttacker(id) {
    const res = await fetch(`${BASE_URL}/api/attackers/${id}/unblock`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse(res);
  },

  async getRelationships() {
    const res = await fetch(`${BASE_URL}/api/relationships`);
    return handleResponse(res);
  },

  async getIncidents() {
    const res = await fetch(`${BASE_URL}/api/incidents`);
    return handleResponse(res);
  },

  async getIncident(id) {
    const res = await fetch(`${BASE_URL}/api/incidents/${id}`);
    return handleResponse(res);
  },

  async patchIncident(id, data) {
    const res = await fetch(`${BASE_URL}/api/incidents/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  async addIncidentNote(id, noteData) {
    const res = await fetch(`${BASE_URL}/api/incidents/${id}/notes`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(noteData),
    });
    return handleResponse(res);
  },

  async getBlocks() {
    const res = await fetch(`${BASE_URL}/api/blocks`);
    return handleResponse(res);
  },

  async getMetrics() {
    const res = await fetch(`${BASE_URL}/api/metrics`);
    return handleResponse(res);
  },

  async getHoneypotHealth() {
    const res = await fetch(`${BASE_URL}/api/honeypots/health`);
    return handleResponse(res);
  },

  async startSimulation(scenario = 'full_chain', speed = 1.0) {
    const res = await fetch(`${BASE_URL}/api/simulate/start`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ scenario, speed }),
    });
    return handleResponse(res);
  },

  async getActions(status = null) {
    const query = status ? `?status=${status}` : '';
    const res = await fetch(`${BASE_URL}/api/actions${query}`);
    return handleResponse(res);
  },

  async approveAction(id, approver = 'analyst', durationSeconds = 600) {
    const res = await fetch(`${BASE_URL}/api/actions/${id}/approve`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ approver, duration_seconds: durationSeconds }),
    });
    return handleResponse(res);
  },

  async rejectAction(id, approver = 'analyst', reason = 'Declined by analyst') {
    const res = await fetch(`${BASE_URL}/api/actions/${id}/reject`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ approver, reason }),
    });
    return handleResponse(res);
  },

  async getIncidentInvestigation(incidentId) {
    const res = await fetch(`${BASE_URL}/api/incidents/${incidentId}/investigation`);
    return handleResponse(res);
  },

  async triggerIncidentInvestigate(incidentId) {
    const res = await fetch(`${BASE_URL}/api/incidents/${incidentId}/investigate`, {
      method: 'POST',
      headers: jsonHeaders,
    });
    return handleResponse(res);
  },

  getIncidentReportUrl(incidentId) {
    return `${BASE_URL}/api/incidents/${incidentId}/report`;
  },

  async getReportsSummary() {
    const res = await fetch(`${BASE_URL}/api/reports/summary`);
    return handleResponse(res);
  },

  async getAdaptiveDeception() {
    const res = await fetch(`${BASE_URL}/api/adaptive-deception`);
    return handleResponse(res);
  },

  async getIocs(format = 'json') {
    const res = await fetch(`${BASE_URL}/api/ioc?format=${format}`);
    if (format === 'csv') return res.text();
    return handleResponse(res);
  },

  getIocDownloadUrl(format = 'csv') {
    return `${BASE_URL}/api/ioc?format=${format}`;
  },

  async getAuditLogs(entityType = null, limit = 50) {
    const query = new URLSearchParams();
    if (entityType) query.append('entity_type', entityType);
    if (limit) query.append('limit', limit);
    const res = await fetch(`${BASE_URL}/api/audit?${query.toString()}`);
    return handleResponse(res);
  },

  async getEventIntegrity(eventId) {
    const res = await fetch(`${BASE_URL}/api/events/${eventId}/integrity`);
    return handleResponse(res);
  },

  async runWhatIf(attackerId, action = 'block', atStage = 'recon') {
    const res = await fetch(`${BASE_URL}/api/whatif`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ attacker_id: attackerId, action, at_stage: atStage }),
    });
    return handleResponse(res);
  },

  async getAttackerPrediction(attackerId) {
    const res = await fetch(`${BASE_URL}/api/attackers/${attackerId}/prediction`);
    return handleResponse(res);
  },

  async getExposureBudget() {
    const res = await fetch(`${BASE_URL}/api/exposure`);
    return handleResponse(res);
  },

  async updateExposureBudget(assets) {
    const res = await fetch(`${BASE_URL}/api/exposure`, {
      method: 'PUT',
      headers: jsonHeaders,
      body: JSON.stringify({ assets }),
    });
    return handleResponse(res);
  },

  async getHealthCorrelation() {
    const res = await fetch(`${BASE_URL}/api/health-correlation`);
    return handleResponse(res);
  },
};
