// Блоки страницы анализа
import { useState } from "react";

import type { Indicator, Prediction, Section, Task } from "../api/types";
import { ALGO_TITLE, Card, Empty, SeverityBadge, TASK_TITLE, pct } from "./ui";

const LABEL_RU: Record<string, string> = { benign: "безопасный", malware: "вредоносный" };
const ALGO_ORDER = ["rf", "lgbm", "mlp", "ensemble"];

export function ModelComparison({ predictions, disagreement }: {
  predictions: Prediction[];
  disagreement: Partial<Record<Task, boolean>> | null;
}) {
  const tasks = (["detection", "family", "category"] as Task[]).filter((t) => predictions.some((p) => p.task === t));
  if (!tasks.length) return null;
  return (
    <Card title="Ответ каждой модели">
      <div className="space-y-6">
        {tasks.map((task) => (
          <div key={task}>
            <div className="mb-2 flex items-center gap-3">
              <h3 className="text-sm font-semibold">{TASK_TITLE[task]}</h3>
              {disagreement?.[task] && (
                <span className="rounded bg-amber-50 px-2 py-0.5 text-xs text-amber-800 ring-1 ring-amber-600/20">
                  Модели расходятся во мнении
                </span>
              )}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="th">Модель</th>
                    <th className="th">Ответ</th>
                    <th className="th">Уверенность</th>
                    <th className="th">Топ-3 вероятностей</th>
                    <th className="th text-right">Время</th>
                  </tr>
                </thead>
                <tbody>
                  {predictions
                    .filter((p) => p.task === task)
                    .sort((a, b) => ALGO_ORDER.indexOf(a.algorithm) - ALGO_ORDER.indexOf(b.algorithm))
                    .map((p) => (
                      <tr key={p.algorithm} className={p.is_final ? "bg-slate-50" : ""}>
                        <td className="td">
                          {ALGO_TITLE[p.algorithm]}
                          {p.is_final && (
                            <span className="ml-2 rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium text-white">
                              итоговая
                            </span>
                          )}
                          <div className="mono text-slate-400">v{p.model_version}</div>
                        </td>
                        <td className="td font-medium">{LABEL_RU[p.predicted_label] ?? p.predicted_label}</td>
                        <td className="td">{pct(p.confidence)}</td>
                        <td className="td">
                          <div className="space-y-1">
                            {p.top_k.map((k) => (
                              <div key={k.label} className="flex items-center gap-2">
                                <div className="h-1.5 w-24 rounded bg-slate-100">
                                  <div className="h-1.5 rounded bg-slate-500" style={{ width: `${k.probability * 100}%` }} />
                                </div>
                                <span className="text-xs text-slate-600">
                                  {LABEL_RU[k.label] ?? k.label} {pct(k.probability)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </td>
                        <td className="td text-right text-xs text-slate-500">{p.latency_ms.toFixed(1)} мс</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-slate-500">
        «Итоговая» — модель, выбранная по validation; её ответ и пороги дают вердикт. Для семейства и категории модели
        запускаются, только если файл не признан безопасным.
      </p>
    </Card>
  );
}

export function IndicatorList({ items, available, reason }: { items: Indicator[]; available: boolean; reason: string | null }) {
  return (
    <Card title={`Подозрительные индикаторы${available ? ` (${items.length})` : ""}`}>
      {!available ? (
        <Empty>{reason}</Empty>
      ) : items.length === 0 ? (
        <Empty>Ни одно правило не сработало.</Empty>
      ) : (
        <ul className="divide-y divide-slate-100">
          {items.map((i) => (
            <li key={i.code} className="py-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={i.severity} />
                <span className="font-medium">{i.title}</span>
                <span className="mono text-slate-400">{i.code}</span>
              </div>
              <p className="mt-1 text-sm text-slate-700">{i.description}</p>
              <p className="mt-1 text-xs text-slate-500">Не доказательство: {i.caveat}</p>
              <Evidence evidence={i.evidence} />
            </li>
          ))}
        </ul>
      )}
      {available && (
        <p className="mt-3 text-xs text-slate-500">Индикаторы объясняют, на что обратить внимание, и не влияют на вердикт моделей.</p>
      )}
    </Card>
  );
}

function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  const parts = Object.entries(evidence).filter(([, v]) => !(Array.isArray(v) && v.length === 0));
  return (
    <div className="mt-2 rounded bg-slate-50 p-2 text-xs text-slate-700">
      {parts.map(([k, v]) => (
        <div key={k}>
          <span className="text-slate-500">{k}: </span>
          <span className="mono">
            {Array.isArray(v) ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") : String(v)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function SectionsTable({ sections }: { sections: Section[] }) {
  if (!sections.length) return null;
  return (
    <Card title="Секции">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr>
              {["Имя", "Вирт. адрес", "Вирт. размер", "Размер на диске", "Энтропия", "Права"].map((h) => (
                <th key={h} className="th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sections.map((s, i) => (
              <tr key={i}>
                <td className="td mono">{s.name || "(без имени)"}</td>
                <td className="td mono">0x{s.virtual_address.toString(16)}</td>
                <td className="td">{s.virtual_size}</td>
                <td className="td">{s.raw_size}</td>
                <td className={`td ${s.entropy > 7.2 ? "font-semibold text-red-700" : ""}`}>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 rounded bg-slate-100">
                      <div className={`h-1.5 rounded ${s.entropy > 7.2 ? "bg-red-500" : "bg-slate-500"}`} style={{ width: `${(s.entropy / 8) * 100}%` }} />
                    </div>
                    {s.entropy.toFixed(2)}
                  </div>
                </td>
                <td className={`td mono ${s.is_write && s.is_exec ? "font-semibold text-red-700" : ""}`}>
                  {s.is_read ? "R" : "-"}
                  {s.is_write ? "W" : "-"}
                  {s.is_exec ? "X" : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function ImportsList({ imports }: { imports: Record<string, string[]> }) {
  const [open, setOpen] = useState(false);
  const dlls = Object.entries(imports);
  const total = dlls.reduce((n, [, f]) => n + f.length, 0);
  if (!dlls.length) return null;
  return (
    <Card
      title={`Импорты: ${dlls.length} DLL, ${total} функций`}
      right={<button className="btn-secondary" onClick={() => setOpen(!open)}>{open ? "Свернуть" : "Показать"}</button>}
    >
      {open && (
        <div className="grid gap-4 md:grid-cols-2">
          {dlls.map(([dll, funcs]) => (
            <div key={dll}>
              <div className="text-sm font-semibold">{dll}</div>
              <div className="mono mt-1 text-slate-600">{funcs.join(", ")}</div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export function StaticSummary({ info }: { info: Record<string, any> }) {
  const rows: [string, React.ReactNode][] = [
    ["Формат", `${info.format ?? "—"} ${info.kind ?? ""}`],
    ["Архитектура", info.machine],
    ["Подсистема", info.subsystem],
    ["Время компиляции", info.compile_time ?? "0 (не указано)"],
    ["Точка входа", `0x${(info.entry_point_rva ?? 0).toString(16)} в секции ${info.entry_point_section ?? "—"}`],
    ["Энтропия файла", info.entropy?.toFixed(3)],
    ["Цифровая подпись", info.has_signature ? "есть (цепочка не проверяется)" : "нет"],
    ["Overlay", info.overlay_size ? `${info.overlay_size} байт` : "нет"],
    ["Ресурсы", info.resources?.length ?? 0],
    ["Экспорты", info.exports?.length ?? 0],
  ];
  const urls: string[] = info.strings?.urls ?? [];
  const ips: string[] = info.strings?.ips ?? [];
  return (
    <Card title="Сведения о файле">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        {rows.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-4 border-b border-slate-100 py-1">
            <dt className="text-slate-500">{k}</dt>
            <dd className="text-right">{v}</dd>
          </div>
        ))}
      </dl>
      {(urls.length > 0 || ips.length > 0) && (
        <div className="mt-4 text-sm">
          <div className="font-medium">Адреса в строках</div>
          <div className="mono mt-1 text-slate-600">{[...urls, ...ips].slice(0, 30).join("  ")}</div>
        </div>
      )}
    </Card>
  );
}
