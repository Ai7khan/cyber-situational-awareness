import React, { useEffect, useState } from "react";
import { api } from "../api";

const SLIDERS = [
  { key: "repeat_min_count", label: "Порог повторов", min: 3, max: 40, step: 1 },
  { key: "correlation_window_sec", label: "Окно корреляции (сек)", min: 30, max: 600, step: 10 },
  { key: "campaign_window_sec", label: "Окно кампании (сек)", min: 300, max: 7200, step: 60 },
  { key: "anomaly_contamination", label: "Доля аномалий (IF)", min: 0.01, max: 0.3, step: 0.01 },
  { key: "anomaly_threshold", label: "Порог аномалии", min: 0.3, max: 0.95, step: 0.05 },
];
const WEIGHTS = [
  { key: "raw_severity", label: "Исходная важность" },
  { key: "anomaly", label: "Аномальность" },
  { key: "correlation", label: "Взаимосвязанность" },
  { key: "repetition", label: "Повторяемость" },
  { key: "kill_chain", label: "Этап атаки" },
];

export default function ConfigPanel({ onChanged, notify }) {
  const [cfg, setCfg] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.getConfig().then(setCfg); }, []);
  if (!cfg) return <div className="empty">Загрузка конфигурации…</div>;

  const apply = async (patch) => {
    setBusy(true);
    try {
      const r = await api.patchConfig(patch);
      setCfg(r.config);
      notify?.("Параметры обновлены, анализ пересчитан");
      onChanged?.();
    } finally { setBusy(false); }
  };

  const reset = async () => {
    setBusy(true);
    try { const r = await api.resetConfig(); setCfg(r.config); notify?.("Сброшено к значениям по умолчанию"); onChanged?.(); }
    finally { setBusy(false); }
  };

  return (
    <div className="grid cols-2">
      <div className="card">
        <h3>Параметры анализа</h3>
        <div className="notice">
          Критерии прозрачны и настраиваются. Любое изменение немедленно
          пересчитывает классификацию, корреляцию, аномалии и приоритеты.
        </div>
        {SLIDERS.map((s) => (
          <div className="slider-row" key={s.key}>
            <span>{s.label}</span>
            <input type="range" min={s.min} max={s.max} step={s.step} value={cfg[s.key]}
                   disabled={busy}
                   onChange={(e) => setCfg({ ...cfg, [s.key]: Number(e.target.value) })}
                   onMouseUp={(e) => apply({ [s.key]: Number(e.target.value) })} />
            <span className="mono">{cfg[s.key]}</span>
          </div>
        ))}
      </div>

      <div className="card">
        <h3>Веса приоритизации</h3>
        <div className="notice">Формула: сумма (вес × нормализованный фактор) → уровень приоритета.</div>
        {WEIGHTS.map((w) => (
          <div className="slider-row" key={w.key}>
            <span>{w.label}</span>
            <input type="range" min={0} max={1} step={0.05} value={cfg.weights[w.key]}
                   disabled={busy}
                   onChange={(e) => setCfg({ ...cfg, weights: { ...cfg.weights, [w.key]: Number(e.target.value) } })}
                   onMouseUp={(e) => apply({ weights: { [w.key]: Number(e.target.value) } })} />
            <span className="mono">{Number(cfg.weights[w.key]).toFixed(2)}</span>
          </div>
        ))}
        <button className="btn" style={{ marginTop: 12 }} onClick={reset} disabled={busy}>
          Сбросить к значениям по умолчанию
        </button>
      </div>
    </div>
  );
}
