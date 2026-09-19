import React from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import { CAT_RU, CAT_COLOR, PRI_RU, PRI_COLOR } from "../constants";

const axis = { stroke: "var(--chart-axis)", fontSize: 11 };
const GRID = "var(--chart-grid)";
const tooltipStyle = {
  background: "var(--tooltip-bg)", border: "1px solid var(--tooltip-border)", borderRadius: 8,
  fontSize: 12, color: "var(--ink)",
};

export function TimelineChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={230}>
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#5b8fd0" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#5b8fd0" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
        <XAxis dataKey="t" {...axis} minTickGap={28} />
        <YAxis {...axis} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Area type="monotone" dataKey="total" name="Всего" stroke="#5b8fd0" fill="url(#gTotal)" strokeWidth={2} />
        <Area type="monotone" dataKey="high" name="Высокий" stroke="#cf8a3c" fill="none" strokeWidth={1.6} />
        <Area type="monotone" dataKey="critical" name="Критич." stroke="#d1495b" fill="none" strokeWidth={1.8} />
        <Area type="monotone" dataKey="anomaly" name="Аномалии" stroke="#7e77b3" fill="none" strokeWidth={1.6} strokeDasharray="4 2" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function CategoryChart({ categories }) {
  const data = Object.entries(categories || {}).map(([k, v]) => ({
    name: CAT_RU[k] || k, value: v, key: k,
  }));
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%"
             innerRadius={52} outerRadius={82} paddingAngle={2}>
          {data.map((d) => <Cell key={d.key} fill={CAT_COLOR[d.key] || "#888"} />)}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function PriorityChart({ priorities }) {
  const order = ["critical", "high", "medium", "low"];
  const data = order.filter((k) => priorities?.[k]).map((k) => ({
    name: PRI_RU[k], value: priorities[k], key: k,
  }));
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={data} margin={{ top: 5, right: 10, left: -18, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={GRID} />
        <XAxis dataKey="name" {...axis} />
        <YAxis {...axis} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--panel2)" }} />
        <Bar dataKey="value" radius={[6, 6, 0, 0]}>
          {data.map((d) => <Cell key={d.key} fill={PRI_COLOR[d.key]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
