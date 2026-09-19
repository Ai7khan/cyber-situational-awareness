export const CAT_RU = {
  informational: "Информационные",
  needs_analysis: "Требуют анализа",
  anomalous: "Аномальные",
  repeating: "Повторяющиеся",
  correlated: "Взаимосвязанные",
};

export const PRI_RU = {
  low: "Низкий",
  medium: "Средний",
  high: "Высокий",
  critical: "Критический",
};

export const CAT_COLOR = {
  informational: "#5b8fd0",
  needs_analysis: "#c2a24a",
  anomalous: "#d1495b",
  repeating: "#4a9a8f",
  correlated: "#7e77b3",
};

export const PRI_COLOR = {
  low: "#4f9d7f",
  medium: "#c2a24a",
  high: "#cf8a3c",
  critical: "#d1495b",
};

export const STAGE_RU = {
  recon: "Разведка",
  delivery: "Доставка",
  exploitation: "Эксплуатация",
  installation: "Закрепление",
  command_control: "Управление",
  lateral_movement: "Латер. движение",
  exfiltration: "Утечка данных",
};

export const fmtTime = (iso) => (iso ? iso.slice(11, 19) : "—");
export const fmtDate = (iso) => (iso ? iso.slice(0, 19).replace("T", " ") : "—");
