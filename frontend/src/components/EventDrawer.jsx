import React, { useEffect, useState } from "react";
import { api } from "../api";
import { CAT_RU, PRI_RU, PRI_COLOR, STAGE_RU, fmtDate } from "../constants";

function Bar({ frac, color }) {
  return <div className="bar"><span style={{ width: `${Math.min(frac * 100, 100)}%`, background: color }} /></div>;
}

export default function EventDrawer({ id, onClose }) {
  const [ev, setEv] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (id == null) return;
    setEv(null); setErr(null);
    api.event(id).then(setEv).catch((e) => setErr(e.message));
  }, [id]);

  if (id == null) return null;

  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <div className="drawer">
        <span className="close-x" onClick={onClose}>×</span>
        {err && <div className="empty">{err}</div>}
        {!ev && !err && <div className="empty">Загрузка…</div>}
        {ev && <Body ev={ev} />}
      </div>
    </>
  );
}

function Body({ ev }) {
  const ex = ev.explain || {};
  const pr = ex.priority || {};
  const comps = pr.components || {};
  const maxComp = Math.max(0.001, ...Object.values(comps));

  return (
    <div>
      <h2>{ev.raw_type}</h2>
      <div className="muted" style={{ fontSize: 12 }}>{fmtDate(ev.event_time)} · {ev.source_name}</div>

      <div style={{ display: "flex", gap: 8, margin: "12px 0", flexWrap: "wrap" }}>
        <span className={`pill ${ev.priority}`}>Приоритет: {PRI_RU[ev.priority] || ev.priority}</span>
        <span className="tag">{CAT_RU[ev.category] || ev.category}</span>
        {ev.is_anomaly && <span className="pill anom">Аномалия {ev.anomaly_score?.toFixed(2)}</span>}
        {ev.correlation_group_id && <span className="tag">Группа #{ev.correlation_group_id}</span>}
        {ev.kill_chain_stage && <span className="tag">{STAGE_RU[ev.kill_chain_stage] || ev.kill_chain_stage}</span>}
      </div>

      <div className="kv">
        <div className="k">Источник (IP)</div><div className="mono">{ev.src_ip || "—"}</div>
        <div className="k">Цель (IP)</div><div className="mono">{ev.dst_ip || "—"}</div>
        <div className="k">Узел</div><div>{ev.host || "—"}</div>
        <div className="k">Учётная запись</div><div>{ev.user || "—"}</div>
        <div className="k">Действие</div><div>{ev.action || "—"}</div>
        <div className="k">Протокол/порт</div><div>{ev.protocol || "—"} / {ev.port ?? "—"}</div>
        <div className="k">Статус</div><div>{ev.status || "—"}</div>
        <div className="k">Исх. важность</div><div>{ev.raw_severity}</div>
      </div>
      {ev.message && <div className="notice" style={{ marginBottom: 14 }}>{ev.message}</div>}

      {/* --- WHY: priority --- */}
      <div className="explain-box">
        <h4>Почему такой приоритет?</h4>
        <div style={{ fontSize: 13, marginBottom: 4 }}>
          Итоговая оценка: <b style={{ color: PRI_COLOR[ev.priority] }}>{(pr.score ?? ev.priority_score)?.toFixed(3)}</b>
          {" "}→ {PRI_RU[ev.priority]}
        </div>
        {Object.entries(comps).map(([k, v]) => (
          <div key={k}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
              <span className="muted">{LBL[k] || k}</span><span>+{v.toFixed(3)}</span>
            </div>
            <Bar frac={v / maxComp} color="#5b8fd0" />
          </div>
        ))}
        <div className="muted" style={{ fontSize: 11.5 }}>{ev.priority_reason}</div>
      </div>

      {/* --- WHY: anomaly --- */}
      {ex.anomaly && (
        <div className="explain-box">
          <h4>Интеллектуальный анализ</h4>
          <div style={{ fontSize: 12, marginBottom: 4 }} className="muted">{ex.anomaly.method}</div>
          <ul className="factors">
            {(ex.anomaly.factors || []).map((f, i) => <li key={i}>{f}</li>)}
          </ul>
        </div>
      )}

      {/* --- WHY: correlation --- */}
      {ex.correlation && (
        <div className="explain-box">
          <h4>Взаимосвязь</h4>
          <div style={{ fontSize: 12.5 }}>
            Группа #{ex.correlation.group_id}, событий: {ex.correlation.group_size}
          </div>
          {ex.correlation.kill_chain?.length > 0 && (
            <div className="mono" style={{ fontSize: 12, color: "#9a93cc", margin: "4px 0" }}>
              {ex.correlation.kill_chain.map((s) => STAGE_RU[s] || s).join(" → ")}
            </div>
          )}
          <ul className="factors">
            {(ex.correlation.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      {/* --- WHY: classification --- */}
      {ex.classification && (
        <div className="explain-box">
          <h4>Классификация</h4>
          <ul className="factors">
            {(ex.classification.reasons || []).map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      {ev.tags?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Доп. поля источника</div>
          {ev.tags.map((t, i) => <span key={i} className="tag" style={{ marginRight: 6 }}>{t}</span>)}
        </div>
      )}
    </div>
  );
}

const LBL = {
  raw_severity: "Исходная важность", anomaly: "Аномальность",
  correlation: "Взаимосвязанность", repetition: "Повторяемость", kill_chain: "Этап атаки",
};
