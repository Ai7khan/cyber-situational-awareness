import React from "react";
import { PRI_COLOR, STAGE_RU, fmtTime } from "../constants";

const W = 900, PAD = 60, ROW_H = 92, R = 9;

function ts(iso) { return new Date(iso).getTime(); }

/** Sample down to `max` nodes keeping first & last, for very large groups. */
function sample(nodes, max = 40) {
  if (nodes.length <= max) return { nodes, omitted: 0 };
  const step = (nodes.length - 1) / (max - 1);
  const out = [];
  for (let i = 0; i < max; i++) out.push(nodes[Math.round(i * step)]);
  return { nodes: out, omitted: nodes.length - out.length };
}

function GroupRow({ group, onSelect }) {
  const meta = group.meta;
  const { nodes, omitted } = sample(group.nodes);
  const times = nodes.map((n) => ts(n.time));
  const t0 = Math.min(...times), t1 = Math.max(...times);
  const span = Math.max(t1 - t0, 1);
  const x = (t) => PAD + ((t - t0) / span) * (W - 2 * PAD);
  const isChain = (meta.kill_chain || []).length >= 2;

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <div>
          <b>Группа #{meta.id}</b> · {meta.size} событий · источник{" "}
          <span className="mono">{(meta.src_ips || []).join(", ") || "—"}</span>
          {isChain && <span className="pill critical" style={{ marginLeft: 8 }}>многоэтапная атака</span>}
        </div>
        <div className="muted" style={{ fontSize: 12 }}>
          {Math.round(meta.span_sec / 60)} мин · аномалий: {meta.anomalies}
        </div>
      </div>

      {isChain && (
        <div className="mono" style={{ fontSize: 12, color: "#9a93cc", margin: "6px 0 2px" }}>
          {meta.kill_chain.map((s) => STAGE_RU[s] || s).join("  →  ")}
        </div>
      )}

      <svg viewBox={`0 0 ${W} ${ROW_H}`} width="100%" height={ROW_H} style={{ marginTop: 6 }}>
        <line x1={PAD} y1={ROW_H / 2} x2={W - PAD} y2={ROW_H / 2} stroke="var(--line)" strokeWidth="1" />
        {nodes.slice(0, -1).map((n, i) => {
          const a = x(ts(n.time)), b = x(ts(nodes[i + 1].time));
          return <line key={"e" + i} x1={a} y1={ROW_H / 2} x2={b} y2={ROW_H / 2}
                       stroke="var(--edge)" strokeWidth="2" />;
        })}
        {nodes.map((n, i) => {
          const cx = x(ts(n.time));
          const yOff = i % 2 === 0 ? -1 : 1;         // alternate label side
          const r = R + Math.min((n.severity || 0) / 18, 7);
          return (
            <g key={n.id} style={{ cursor: "pointer" }} onClick={() => onSelect(n.id)}>
              <circle cx={cx} cy={ROW_H / 2} r={r} fill={PRI_COLOR[n.priority] || "#5aa9ff"}
                      stroke={n.is_anomaly ? "var(--node-ring-anom)" : "var(--node-ring)"}
                      strokeWidth={n.is_anomaly ? 2 : 1.5}>
                <title>{n.label} · {fmtTime(n.time)} · {n.priority}</title>
              </circle>
              {n.stage && (
                <text x={cx} y={ROW_H / 2 + (yOff < 0 ? -r - 6 : r + 14)} fill="#8b97ad"
                      fontSize="10" textAnchor="middle">{STAGE_RU[n.stage] || n.stage}</text>
              )}
            </g>
          );
        })}
        <text x={PAD} y={ROW_H - 4} fill="#5b6577" fontSize="10">{fmtTime(nodes[0].time)}</text>
        <text x={W - PAD} y={ROW_H - 4} fill="#5b6577" fontSize="10" textAnchor="end">
          {fmtTime(nodes[nodes.length - 1].time)}
        </text>
      </svg>

      {omitted > 0 && <div className="muted" style={{ fontSize: 11 }}>+{omitted} событий скрыто (показана выборка)</div>}
      <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>
        Основания: {(meta.reasons || []).join("; ")}
      </div>
    </div>
  );
}

export default function CorrelationGraph({ groups, onSelect }) {
  if (!groups || groups.length === 0)
    return <div className="empty">Взаимосвязанные группы не обнаружены. Загрузите данные и выполните анализ.</div>;
  return (
    <div>
      <div className="legend" style={{ marginBottom: 12 }}>
        <span><i style={{ background: PRI_COLOR.critical }} />Критический</span>
        <span><i style={{ background: PRI_COLOR.high }} />Высокий</span>
        <span><i style={{ background: PRI_COLOR.medium }} />Средний</span>
        <span><i style={{ background: PRI_COLOR.low }} />Низкий</span>
        <span><i style={{ background: "var(--node-ring-anom)", border: "1px solid var(--muted)", borderRadius: "50%" }} />контрастная обводка = аномалия</span>
      </div>
      {groups.map((g) => <GroupRow key={g.meta.id} group={g} onSelect={onSelect} />)}
    </div>
  );
}
