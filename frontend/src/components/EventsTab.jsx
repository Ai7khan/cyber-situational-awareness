import React, { useEffect, useState } from "react";
import { api } from "../api";
import { CAT_RU, PRI_RU, fmtTime } from "../constants";

export default function EventsTab({ onSelect, refreshKey }) {
  const [data, setData] = useState({ events: [], total: 0 });
  const [filters, setFilters] = useState({ category: "", priority: "", is_anomaly: "" });
  const [orderBy, setOrderBy] = useState("event_time");
  const [loading, setLoading] = useState(false);

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filters, orderBy, refreshKey]);

  async function load() {
    setLoading(true);
    const params = { limit: 300, order_by: orderBy, order_dir: "DESC" };
    if (filters.category) params.category = filters.category;
    if (filters.priority) params.priority = filters.priority;
    if (filters.is_anomaly) params.is_anomaly = filters.is_anomaly;
    try { setData(await api.events(params)); } finally { setLoading(false); }
  }

  const set = (k) => (e) => setFilters({ ...filters, [k]: e.target.value });

  return (
    <div className="card">
      <div className="toolbar">
        <select className="select" value={filters.category} onChange={set("category")}>
          <option value="">Все категории</option>
          {Object.entries(CAT_RU).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="select" value={filters.priority} onChange={set("priority")}>
          <option value="">Все приоритеты</option>
          {Object.entries(PRI_RU).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="select" value={filters.is_anomaly} onChange={set("is_anomaly")}>
          <option value="">Все события</option>
          <option value="true">Только аномалии</option>
        </select>
        <select className="select" value={orderBy} onChange={(e) => setOrderBy(e.target.value)}>
          <option value="event_time">Сортировка: время</option>
          <option value="priority_score">Сортировка: приоритет</option>
          <option value="anomaly_score">Сортировка: аномальность</option>
        </select>
        <span className="muted" style={{ fontSize: 12 }}>
          {loading ? "Загрузка…" : `Показано ${data.events.length} из ${data.total}`}
        </span>
      </div>

      <div style={{ maxHeight: "66vh", overflow: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Время</th><th>Тип</th><th>Источник → Цель</th><th>Категория</th>
              <th>Приоритет</th><th>Аном.</th><th>Группа</th>
            </tr>
          </thead>
          <tbody>
            {data.events.map((e) => (
              <tr key={e.id} onClick={() => onSelect(e.id)}>
                <td className="mono">{fmtTime(e.event_time)}</td>
                <td>{e.raw_type}</td>
                <td className="mono">{e.src_ip || "—"} → {e.dst_ip || e.host || "—"}</td>
                <td>{CAT_RU[e.category] || e.category}</td>
                <td><span className={`pill ${e.priority}`}>{PRI_RU[e.priority] || e.priority}</span></td>
                <td>{e.is_anomaly ? <span className="pill anom">{e.anomaly_score?.toFixed(2)}</span> : ""}</td>
                <td>{e.correlation_group_id ? `#${e.correlation_group_id}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.events.length === 0 && !loading && <div className="empty">Нет событий.</div>}
      </div>
    </div>
  );
}
