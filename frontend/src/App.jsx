import React, { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { CAT_RU, PRI_RU, fmtTime } from "./constants";
import { TimelineChart, CategoryChart, PriorityChart } from "./components/Charts";
import CorrelationGraph from "./components/CorrelationGraph";
import EventDrawer from "./components/EventDrawer";
import EventsTab from "./components/EventsTab";
import ConfigPanel from "./components/ConfigPanel";
import JournalPanel from "./components/JournalPanel";

const TABS = [
  ["dashboard", "Обзор"],
  ["events", "События"],
  ["correlations", "Корреляции"],
  ["anomalies", "Аномалии"],
  ["journal", "Журнал"],
  ["config", "Настройки"],
];

export default function App() {
  const [tab, setTab] = useState("dashboard");
  const [stats, setStats] = useState(null);
  const [groups, setGroups] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [selId, setSelId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("cyber-theme") || "dark"; } catch { return "dark"; }
  });
  const fileRef = useRef();

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("cyber-theme", theme); } catch {}
  }, [theme]);
  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

  const notify = (m) => { setToast(m); setTimeout(() => setToast(null), 2600); };

  async function refresh() {
    const [s, c, a] = await Promise.all([api.stats(), api.correlations(), api.anomalies(60)]);
    setStats(s); setGroups(c.groups); setAnomalies(a.anomalies);
    setRefreshKey((k) => k + 1);
  }

  useEffect(() => { refresh().catch(() => {}); }, []);

  const guard = async (fn, msg) => {
    setBusy(true);
    try { await fn(); await refresh(); if (msg) notify(msg); }
    catch (e) { notify("Ошибка: " + e.message); }
    finally { setBusy(false); }
  };

  const loadDemo = () => guard(() => api.ingestDemo(), "Демо-данные загружены и проанализированы");
  const analyze = () => guard(() => api.analyze(), "Анализ выполнен");
  const clear = () => guard(() => api.clear(), "События очищены");
  const onUpload = (e) => {
    const files = e.target.files;
    if (files?.length) guard(() => api.upload(files, true), "Файлы загружены и проанализированы");
    e.target.value = "";
  };

  const total = stats?.total ?? 0;
  const sit = stats?.situation || { label: "—", color: "#888", code: "stable" };

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <span className="dot" />
          <div>Мониторинг киберобстановки
            <small>Интеллектуальная система анализа · DefenceTech</small></div>
        </div>
        <div className="spacer" />
        <button className="btn primary" onClick={loadDemo} disabled={busy}>▷ Демо-данные</button>
        <button className="btn" onClick={() => fileRef.current.click()} disabled={busy}>⭱ Загрузить</button>
        <input ref={fileRef} type="file" multiple hidden onChange={onUpload}
               accept=".csv,.json,.log,.syslog,.txt" />
        <button className="btn" onClick={analyze} disabled={busy || !total}>⟳ Анализ</button>
        <a className="btn" href={api.reportUrl()} target="_blank" rel="noreferrer"
           style={total ? {} : { pointerEvents: "none", opacity: 0.5 }}>▤ Отчёт</a>
        <button className="btn" onClick={toggleTheme}
                title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}>
          {theme === "dark" ? "☀" : "☾"}</button>
        <button className="btn" onClick={clear} disabled={busy || !total}>🗑</button>
      </div>

      <div className="tabs">
        {TABS.map(([k, label]) => (
          <div key={k} className={"tab" + (tab === k ? " active" : "")} onClick={() => setTab(k)}>{label}</div>
        ))}
      </div>

      <div className="main">
        {total === 0 && tab !== "config" && (
          <div className="notice">
            Данных нет. Нажмите <b>«Демо-данные»</b> для загрузки синтетического учебного
            набора (три формата: CSV, JSON, syslog) или <b>«Загрузить»</b> собственные файлы.
          </div>
        )}

        {tab === "dashboard" && stats && (
          <>
            <div className="banner" style={{ background: `linear-gradient(90deg, ${sit.color}22, transparent)`, borderColor: sit.color }}>
              <div className="pulse" style={{ background: sit.color }} />
              <div>
                <div className="muted" style={{ fontSize: 12 }}>Оценка информационной обстановки</div>
                <div className="lvl" style={{ color: sit.color }}>{sit.label}</div>
              </div>
              <div className="spacer" />
              {stats.last_run && (
                <div className="desc">
                  Обработка: <b>{stats.last_run.elapsed_ms} мс</b> · {stats.last_run.throughput_eps} соб/с
                </div>
              )}
            </div>

            <div className="grid kpis">
              <Kpi n={total} l="Всего событий" />
              <Kpi n={stats.anomalies} l="Аномалий" cls="crit" />
              <Kpi n={stats.correlation_groups} l="Взаимосвязанных групп" cls="acc" />
              <Kpi n={stats.critical} l="Критических" cls="crit" />
              <Kpi n={stats.high} l="Высокий приоритет" cls="warn" />
            </div>

            <div className="grid cols-2">
              <div className="card">
                <h3>Динамика событий во времени</h3>
                <TimelineChart data={stats.timeseries} />
              </div>
              <div className="card">
                <h3>Распределение по категориям</h3>
                <CategoryChart categories={stats.categories} />
              </div>
            </div>

            <div className="grid cols-2" style={{ marginTop: 14 }}>
              <div className="card">
                <h3>Наиболее значимые события</h3>
                <table className="table">
                  <thead><tr><th>Время</th><th>Тип</th><th>Источник</th><th>Приоритет</th><th>Обоснование</th></tr></thead>
                  <tbody>
                    {stats.top_events.map((e) => (
                      <tr key={e.id} onClick={() => setSelId(e.id)}>
                        <td className="mono">{fmtTime(e.event_time)}</td>
                        <td>{e.raw_type}</td>
                        <td className="mono">{e.src_ip || e.host || "—"}</td>
                        <td><span className={`pill ${e.priority}`}>{PRI_RU[e.priority]}</span></td>
                        <td className="muted" style={{ fontSize: 11.5 }}>{e.priority_reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="card">
                <h3>Приоритеты</h3>
                <PriorityChart priorities={stats.priorities} />
              </div>
            </div>
          </>
        )}

        {tab === "events" && <EventsTab onSelect={setSelId} refreshKey={refreshKey} />}

        {tab === "correlations" && <CorrelationGraph groups={groups} onSelect={setSelId} />}

        {tab === "anomalies" && (
          <div className="card">
            <h3>Выявленные аномалии — рекомендации интеллектуального анализа</h3>
            <div className="notice">Результаты носят рекомендательный характер. Итоговое решение принимает оператор.</div>
            <table className="table">
              <thead><tr><th>Время</th><th>Тип</th><th>Источник</th><th>Оценка</th><th>Обоснование</th></tr></thead>
              <tbody>
                {anomalies.map((e) => (
                  <tr key={e.id} onClick={() => setSelId(e.id)}>
                    <td className="mono">{fmtTime(e.event_time)}</td>
                    <td>{e.raw_type}</td>
                    <td className="mono">{e.src_ip || e.host || "—"}</td>
                    <td><span className="pill anom">{e.anomaly_score?.toFixed(2)}</span></td>
                    <td className="muted" style={{ fontSize: 11.5 }}>
                      {(e.explain?.anomaly?.factors || []).join("; ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {anomalies.length === 0 && <div className="empty">Аномалии не обнаружены.</div>}
          </div>
        )}

        {tab === "journal" && <JournalPanel refreshKey={refreshKey} />}

        {tab === "config" && <ConfigPanel onChanged={refresh} notify={notify} />}
      </div>

      {selId != null && <EventDrawer id={selId} onClose={() => setSelId(null)} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function Kpi({ n, l, cls }) {
  return (
    <div className="card kpi">
      <div className={"n " + (cls || "")}>{n}</div>
      <div className="l">{l}</div>
    </div>
  );
}
