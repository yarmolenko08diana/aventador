import { useQueries, useQuery } from "@tanstack/react-query";
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LineElement,
  LinearScale,
  LogarithmicScale,
  PointElement,
  Tooltip,
} from "chart.js";
import { useState } from "react";
import { Bar, Scatter } from "react-chartjs-2";

import { api } from "../api/client";
import type { Algorithm, Comparison, ConfusionMatrix, Task } from "../api/types";
import { ALGO_TITLE, Card, Empty, ErrorBox, TASK_TITLE, dt, pct } from "../components/ui";

ChartJS.register(BarElement, CategoryScale, LineElement, LinearScale, LogarithmicScale, PointElement, Tooltip, Legend);

const TASKS: Task[] = ["detection", "family", "category"];
const ALGO_COLOR: Record<Algorithm, string> = { rf: "#0ea5e9", lgbm: "#10b981", mlp: "#a855f7", ensemble: "#0f172a" };

type Row = Comparison["models"][number];
type Metric = { label: string; hint: string; test: (r: Row) => number | null | undefined; val: (r: Row) => number | null | undefined; lowerBetter?: boolean };

// Какие метрики показывать для каждой задачи. Значения берутся только из ответа API (evaluation.json / manifest.json).
const METRICS: Record<Task, Metric[]> = {
  detection: [
    { label: "TPR при FPR ≤ 1%", hint: "главная метрика: доля пойманных вредоносных при 1% ложных тревог",
      test: (r) => r.test?.tpr_at_fpr_1pct, val: (r) => r.validation.tpr_at_fpr_1pct },
    { label: "TPR при FPR ≤ 0.1%", hint: "то же при 0.1% ложных тревог",
      test: (r) => r.test?.metrics.tpr_at_fpr_0_1pct, val: (r) => r.validation.tpr_at_fpr_0_1pct },
    { label: "ROC-AUC", hint: "качество ранжирования по всем порогам", test: (r) => r.test?.roc_auc, val: (r) => r.validation.roc_auc },
    { label: "FPR вердикта «вредоносный»", hint: "доля безопасных, получивших «вредоносный» (порог выбран на validation)",
      test: (r) => r.test?.metrics.malicious_fpr, val: (r) => r.validation.malicious_fpr, lowerBetter: true },
    { label: "ECE", hint: "ошибка калибровки: насколько вероятность совпадает с частотой", test: (r) => r.test?.metrics.ece,
      val: (r) => r.validation.ece, lowerBetter: true },
  ],
  family: [
    { label: "Macro-F1", hint: "главная метрика: средний F1 по семействам, каждое семейство с равным весом",
      test: (r) => r.test?.f1_macro, val: (r) => r.validation.macro_f1 },
    { label: "Accuracy", hint: "доля верных ответов", test: (r) => r.test?.accuracy, val: (r) => r.validation.accuracy },
    { label: "Open-set macro-F1", hint: "с учётом семейств, которых нет среди классов (правильный ответ — «не определено»)",
      test: (r) => r.test?.metrics.open_set?.open_set_macro_f1, val: (r) => r.validation.open_set?.open_set_macro_f1 },
    { label: "Неизвестных отвергнуто", hint: "доля незнакомых семейств, получивших «не определено»",
      test: (r) => r.test?.metrics.open_set?.unknown_rejected, val: (r) => r.validation.open_set?.unknown_rejected },
    { label: "Известных отвергнуто", hint: "доля знакомых семейств, ошибочно получивших «не определено»",
      test: (r) => r.test?.metrics.open_set?.known_rejected, val: (r) => r.validation.open_set?.known_rejected, lowerBetter: true },
    { label: "ECE", hint: "ошибка калибровки", test: (r) => r.test?.metrics.ece, val: (r) => r.validation.ece, lowerBetter: true },
  ],
  category: [
    { label: "Macro-F1", hint: "главная метрика", test: (r) => r.test?.f1_macro, val: (r) => r.validation.macro_f1 },
    { label: "Accuracy", hint: "доля верных ответов", test: (r) => r.test?.accuracy, val: (r) => r.validation.accuracy },
    { label: "Precision (macro)", hint: "", test: (r) => r.test?.precision_macro, val: () => undefined },
    { label: "Recall (macro)", hint: "", test: (r) => r.test?.recall_macro, val: () => undefined },
    { label: "ECE", hint: "ошибка калибровки", test: (r) => r.test?.metrics.ece, val: (r) => r.validation.ece, lowerBetter: true },
  ],
};

export default function Models() {
  const [task, setTask] = useState<Task>("detection");
  const [picked, setPicked] = useState<number | null>(null);
  const cmp = useQuery({ queryKey: ["comparison", task], queryFn: () => api.comparison(task) });
  const models = useQuery({ queryKey: ["models"], queryFn: api.models });

  const rows = cmp.data?.models ?? [];
  const selectedId = picked !== null && rows.some((r) => r.model_id === picked) ? picked : rows.find((r) => r.is_final)?.model_id ?? null;
  const selected = rows.find((r) => r.model_id === selectedId);
  const info = models.data?.find((m) => m.id === selectedId);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Модели</h1>
        <div className="flex gap-1 rounded-lg bg-slate-200 p-1">
          {TASKS.map((t) => (
            <button
              key={t}
              onClick={() => {
                setTask(t);
                setPicked(null);
              }}
              className={`rounded-md px-3 py-1.5 text-sm font-medium ${t === task ? "bg-white shadow-sm" : "text-slate-600"}`}
            >
              {TASK_TITLE[t]}
            </button>
          ))}
        </div>
      </div>

      {cmp.isError && <ErrorBox error={cmp.error} />}
      {cmp.data && <MetricsTable task={task} rows={rows} selectedId={selectedId} onPick={setPicked} />}

      {task === "detection" && rows.length > 0 && <RocChart rows={rows} />}

      {selected && (
        <div className="grid gap-6 lg:grid-cols-2">
          <ConfusionCard modelId={selected.model_id} />
          <ReliabilityCard modelId={selected.model_id} title={ALGO_TITLE[selected.algorithm]} />
        </div>
      )}
      {selected?.test?.per_class && task !== "detection" && <PerClass row={selected} />}

      {info && (
        <Card title={`Версия модели: ${ALGO_TITLE[info.algorithm]}`}>
          <dl className="grid gap-x-8 gap-y-1 text-sm md:grid-cols-2">
            <div>Версия: <span className="mono">{info.version}</span></div>
            <div>Обучена: {dt(info.trained_at)}</div>
            <div>Данные: {info.dataset}, разбиение {info.split_strategy}</div>
            <div>Признаки: {info.feature_version}</div>
            {Object.entries(info.thresholds).map(([k, v]) => (
              <div key={k}>Порог {k}: <b>{v.toFixed(4)}</b> (выбран на validation)</div>
            ))}
          </dl>
          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-slate-600">Гиперпараметры</summary>
            <pre className="mt-2 overflow-x-auto rounded bg-slate-50 p-3 text-xs">{JSON.stringify(info.hyperparameters, null, 2)}</pre>
          </details>
        </Card>
      )}
    </div>
  );
}

function MetricsTable({ task, rows, selectedId, onPick }: { task: Task; rows: Row[]; selectedId: number | null; onPick: (id: number) => void }) {
  const metrics = METRICS[task];
  const best = metrics.map((m) => {
    const vals = rows.map((r) => m.test(r)).filter((v): v is number => typeof v === "number");
    return vals.length ? (m.lowerBetter ? Math.min(...vals) : Math.max(...vals)) : null;
  });
  const nTest = rows[0]?.test?.metrics.n_test;
  return (
    <Card title={`Сравнение алгоритмов: ${TASK_TITLE[task]}`}>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Модель</th>
              {metrics.map((m) => (
                <th key={m.label} className="th" title={m.hint}>{m.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.model_id}
                onClick={() => onPick(r.model_id)}
                className={`cursor-pointer ${r.model_id === selectedId ? "bg-slate-100" : "hover:bg-slate-50"}`}
              >
                <td className="td">
                  <span className="font-medium">{ALGO_TITLE[r.algorithm]}</span>
                  {r.is_final && <span className="ml-2 rounded bg-slate-900 px-1.5 py-0.5 text-[10px] text-white">итоговая</span>}
                </td>
                {metrics.map((m, i) => {
                  const t = m.test(r);
                  const v = m.val(r);
                  return (
                    <td key={m.label} className="td">
                      <span className={t !== null && t !== undefined && t === best[i] ? "font-semibold" : ""}>
                        {r.test ? fmt(t) : "нет оценки"}
                      </span>
                      {typeof v === "number" && <div className="text-xs text-slate-400">val {fmt(v)}</div>}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-slate-500">
        Крупно — тестовая выборка (самые поздние по времени файлы{nTest ? `, ${nTest} шт.` : ""}), мелко — validation.
        Итоговая модель и пороги выбраны по validation; тест использован один раз для честной оценки.
        Жирным — лучшее значение на тесте. Нажмите на строку, чтобы посмотреть матрицу ошибок этой модели.
      </p>
    </Card>
  );
}

const fmt = (x: number | null | undefined) => (typeof x === "number" ? (x <= 1 ? x.toFixed(4) : String(x)) : "—");

function RocChart({ rows }: { rows: Row[] }) {
  const curves = useQueries({
    queries: rows.map((r) => ({ queryKey: ["curves", r.model_id], queryFn: () => api.curves(r.model_id), enabled: !!r.test })),
  });
  const ready = curves.filter((c) => c.data?.roc);
  if (!ready.length) return null;
  return (
    <Card title="ROC-кривые на тесте">
      <div className="h-80">
        <Scatter
          data={{
            datasets: ready.map((c) => {
              const row = rows.find((r) => r.model_id === c.data!.model_id)!;
              const roc = c.data!.roc!;
              return {
                label: `${ALGO_TITLE[row.algorithm]} (AUC ${c.data!.roc_auc?.toFixed(4)})`,
                data: roc.fpr.map((x, i) => ({ x, y: roc.tpr[i] })),
                showLine: true,
                pointRadius: 0,
                borderWidth: 2,
                borderColor: ALGO_COLOR[row.algorithm],
                backgroundColor: ALGO_COLOR[row.algorithm],
              };
            }),
          }}
          options={{
            maintainAspectRatio: false,
            plugins: { legend: { position: "bottom" } },
            scales: {
              x: {
                type: "logarithmic",
                min: 1e-4,
                max: 1,
                title: { display: true, text: "FPR (доля ложных тревог), лог. шкала" },
                // подписываем только степени десяти: 0.01%, 0.1%, 1%, 10%, 100%
                ticks: {
                  autoSkip: false,
                  maxRotation: 0,
                  callback: (v) => {
                    const lg = Math.log10(Number(v));
                    return Math.abs(lg - Math.round(lg)) < 1e-9 ? `${+(Number(v) * 100).toPrecision(1)}%` : "";
                  },
                },
              },
              y: { min: 0, max: 1, title: { display: true, text: "TPR (доля обнаруженных)" } },
            },
          }}
        />
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Ось FPR логарифмическая: на практике важна левая часть, где ложных тревог меньше 1%. Точки с FPR = 0 на ней не видны.
      </p>
    </Card>
  );
}

function ConfusionCard({ modelId }: { modelId: number }) {
  const cm = useQuery({ queryKey: ["confusion", modelId], queryFn: () => api.confusion(modelId) });
  return (
    <Card title={cm.data ? `Матрица ошибок: ${ALGO_TITLE[cm.data.algorithm]}` : "Матрица ошибок"}>
      {cm.isError && <ErrorBox error={cm.error} />}
      {cm.data && <Matrix cm={cm.data} />}
    </Card>
  );
}

function Matrix({ cm }: { cm: ConfusionMatrix }) {
  const labels = cm.task === "detection" ? ["безопасный", "вредоносный"] : cm.classes;
  const small = labels.length > 10;
  return (
    <div>
      <div className="overflow-x-auto">
        <table className={small ? "text-[10px]" : "text-sm"}>
          <thead>
            <tr>
              <th className="p-1 text-left text-xs font-normal text-slate-500">истина ↓ прогноз →</th>
              {labels.map((l) => (
                <th key={l} className="p-1 font-medium text-slate-600">
                  <div className={small ? "h-20 w-4 whitespace-nowrap [writing-mode:vertical-rl] rotate-180" : ""}>{l}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cm.matrix.map((row, i) => {
              const sum = row.reduce((a, b) => a + b, 0) || 1;
              return (
                <tr key={i}>
                  <th className="whitespace-nowrap p-1 pr-2 text-left font-medium text-slate-600">{labels[i]}</th>
                  {row.map((v, j) => {
                    const share = v / sum; // цвет — доля строки (recall по классу), число — сколько файлов
                    const bg = i === j ? `rgba(16,185,129,${share})` : `rgba(239,68,68,${Math.min(1, share * 2)})`;
                    return (
                      <td
                        key={j}
                        title={`${labels[i]} → ${labels[j]}: ${v} (${pct(share)} строки)`}
                        className={`border border-white text-center ${small ? "h-5 w-5" : "h-12 w-16"}`}
                        style={{ background: v ? bg : "#f8fafc", color: share > 0.6 ? "white" : undefined }}
                      >
                        {small ? "" : v}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-slate-500">
        {cm.note}. Цвет — доля строки: зелёный на диагонали — верно, красный вне её — ошибки.
        {small && " Число файлов — во всплывающей подсказке."}
      </p>
    </div>
  );
}

function ReliabilityCard({ modelId, title }: { modelId: number; title: string }) {
  const c = useQuery({ queryKey: ["curves", modelId], queryFn: () => api.curves(modelId) });
  return (
    <Card title={`Калибровка: ${title}`}>
      {c.isError && <ErrorBox error={c.error} />}
      {c.data && c.data.reliability.length === 0 && <Empty>Нет данных.</Empty>}
      {c.data && c.data.reliability.length > 0 && (
        <>
          <div className="h-64">
            <Bar
              data={{
                labels: c.data.reliability.map((b) => `${b.bin * 10}–${b.bin * 10 + 10}%`),
                datasets: [
                  { label: "Средняя уверенность", data: c.data.reliability.map((b) => b.mean_confidence), backgroundColor: "#cbd5e1" },
                  { label: "Доля верных на деле", data: c.data.reliability.map((b) => b.observed), backgroundColor: "#475569" },
                ],
              }}
              options={{
                maintainAspectRatio: false,
                plugins: {
                  legend: { position: "bottom" },
                  tooltip: { callbacks: { afterBody: (items) => `файлов: ${c.data!.reliability[items[0].dataIndex].count}` } },
                },
                scales: { y: { min: 0, max: 1 } },
              }}
            />
          </div>
          <p className="mt-2 text-xs text-slate-500">
            Хорошо откалиброванная модель: столбцы в каждой группе одной высоты. ECE = {c.data.ece?.toFixed(4) ?? "—"}.
          </p>
        </>
      )}
    </Card>
  );
}

function PerClass({ row }: { row: Row }) {
  const pc = row.test!.per_class!;
  const classes = Object.entries(pc)
    .filter(([k]) => !["accuracy", "macro avg", "weighted avg"].includes(k))
    .sort((a, b) => a[1]["f1-score"] - b[1]["f1-score"]);
  return (
    <Card title={`По классам: ${ALGO_TITLE[row.algorithm]} (от худших к лучшим)`}>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr>
              <th className="th">Класс</th>
              <th className="th">Precision</th>
              <th className="th">Recall</th>
              <th className="th">F1</th>
              <th className="th">Файлов в тесте</th>
            </tr>
          </thead>
          <tbody>
            {classes.map(([name, m]) => (
              <tr key={name}>
                <td className="td font-medium">{name}</td>
                <td className="td">{m.precision.toFixed(3)}</td>
                <td className="td">{m.recall.toFixed(3)}</td>
                <td className="td">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-24 rounded bg-slate-100">
                      <div className="h-1.5 rounded bg-slate-600" style={{ width: `${m["f1-score"] * 100}%` }} />
                    </div>
                    {m["f1-score"].toFixed(3)}
                  </div>
                </td>
                <td className="td">{m.support}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
