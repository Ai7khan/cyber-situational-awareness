const BASE = "/api";

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

export const api = {
  health: () => req("/health"),
  ingestDemo: () => req("/ingest/demo", { method: "POST" }),
  upload: (files, replace) => {
    const fd = new FormData();
    for (const f of files) fd.append("files", f);
    return req(`/ingest/upload?replace=${replace ? "true" : "false"}`, { method: "POST", body: fd });
  },
  analyze: () => req("/analyze", { method: "POST" }),
  clear: () => req("/events", { method: "DELETE" }),
  stats: () => req("/stats"),
  events: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return req("/events?" + q);
  },
  event: (id) => req("/events/" + id),
  correlations: () => req("/correlations"),
  anomalies: (limit = 50) => req("/anomalies?limit=" + limit),
  journal: (limit = 200) => req("/journal?limit=" + limit),
  getConfig: () => req("/config"),
  patchConfig: (patch) =>
    req("/config", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) }),
  resetConfig: () => req("/config/reset", { method: "POST" }),
  reportUrl: () => BASE + "/report",
};
