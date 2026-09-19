import React, { useEffect, useState } from "react";
import { api } from "../api";
import { fmtDate } from "../constants";

const ACTION_RU = {
  ingest_demo: "Загрузка демо-данных",
  ingest_upload: "Загрузка файла",
  pipeline_run: "Запуск анализа",
  config_update: "Изменение параметров",
  config_reset: "Сброс параметров",
  clear_events: "Очистка событий",
  report_generated: "Формирование отчёта",
};

export default function JournalPanel({ refreshKey }) {
  const [entries, setEntries] = useState([]);
  useEffect(() => { api.journal(300).then((d) => setEntries(d.entries)); }, [refreshKey]);

  return (
    <div className="card">
      <h3>Журнал событий и действий</h3>
      <div style={{ maxHeight: "70vh", overflow: "auto" }}>
        <table className="table">
          <thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Детали</th></tr></thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="mono">{fmtDate(e.ts)}</td>
                <td>{e.actor === "user" ? "Оператор" : "Система"}</td>
                <td>{ACTION_RU[e.action] || e.action}</td>
                <td className="muted mono" style={{ fontSize: 11 }}>{summarize(e.details)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {entries.length === 0 && <div className="empty">Журнал пуст.</div>}
      </div>
    </div>
  );
}

function summarize(d) {
  if (!d || typeof d !== "object") return "";
  if (d.events != null && d.elapsed_ms != null)
    return `событий: ${d.events}, аномалий: ${d.anomalies}, групп: ${d.correlation_groups}, ${d.elapsed_ms} мс`;
  if (d.file) return `${d.file} (+${d.inserted ?? 0})`;
  if (d.patch) return JSON.stringify(d.patch);
  return Object.keys(d).length ? JSON.stringify(d).slice(0, 80) : "";
}
