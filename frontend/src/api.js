const API_BASE = 'http://localhost:8000/api/v1';

export function getAuthHeaders() {
  const role = localStorage.getItem('user_role') || 'analyst';
  const userId = localStorage.getItem('user_id') || 'analyst_alice';
  return {
    'Content-Type': 'application/json',
    'X-User-Role': role,
    'X-User-ID': userId,
  };
}

export async function fetchCases(status = '', severityTier = '') {
  const params = new URLSearchParams();
  if (status) params.append('status', status);
  if (severityTier) params.append('severity_tier', severityTier);

  const res = await fetch(`${API_BASE}/cases/?${params.toString()}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch cases (${res.status} ${res.statusText})`);
  }
  return res.json();
}

export async function fetchCaseDetail(caseId) {
  const res = await fetch(`${API_BASE}/cases/${caseId}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Failed to fetch case #${caseId}`);
  }
  return res.json();
}

export async function approveAction(actionId) {
  const res = await fetch(`${API_BASE}/actions/${actionId}/approve`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(data.detail || `Approval failed with status ${res.status}`);
    err.status = res.status;
    err.detail = data.detail;
    throw err;
  }
  return data;
}

export async function denyAction(actionId, denialReason) {
  const res = await fetch(`${API_BASE}/actions/${actionId}/deny`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ denial_reason: denialReason }),
  });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(data.detail || `Denial failed with status ${res.status}`);
    err.status = res.status;
    err.detail = data.detail;
    throw err;
  }
  return data;
}

export async function ingestTestAlert(payload) {
  const res = await fetch(`${API_BASE}/alerts/`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Ingestion failed (${res.status})`);
  }
  return data;
}
