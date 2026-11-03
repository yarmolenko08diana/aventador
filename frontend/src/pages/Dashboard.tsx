import { useQuery } from "@tanstack/react-query";
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip,
} from "chart.js";
import { Bar, Doughnut } from "react-chartjs-2";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { Card, Empty, ErrorBox, StatusBadge, VerdictBadge, dt } from "../components/ui";

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const COLORS = { clean: "#10b981", suspicious: "#f59e0b", malicious: "#ef4444" };

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="card">
      <div className="text-sm text-slate-500">{label}</div>
      <div className="mt-1 text-3xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export default function Dashboard() {
  const stats = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard, refetchInterval: 5000 });
  const recent = useQuery({ queryKey: ["recent"], queryFn: () => api.analyses({ limit: 8 }), refetchInterval: 5000 });

  if (stats.isError) return <ErrorBox error={stats.error} />;
  const s = stats.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Панель</h1>
        <Link to="/upload" className="btn">Загрузить файл</Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Анализов всего" value={s?.total_analyses ?? "…"} hint={s ? `файлов: ${s.total_samples}` : undefined} />
        <Stat label="Вредоносных" value={s?.by_verdict.malicious ?? "…"} hint={s ? `подозрительных: ${s.by_verdict.suspicious}` : undefined} />
        <Stat label="Семейств обнаружено" value={s?.families_detected ?? "…"} hint={s ? `не определено: ${s.family_unknown}` : undefined} />
        <Stat
          label="Среднее время анализа"
          value={s?.avg_duration_ms ? `${(s.avg_duration_ms / 1000).toFixed(1)} с` : "—"}
          hint={s?.by_status.failed ? `с ошибкой: ${s.by_status.failed}` : undefined}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Вердикты">
          {s && s.total_analyses > 0 ? (
            <Doughnut
              data={{
                labels: ["Безопасные", "Подозрительные", "Вредоносные"],
                datasets: [{
                  data: [s.by_verdict.clean, s.by_verdict.suspicious, s.by_verdict.malicious],
                  backgroundColor: [COLORS.clean, COLORS.suspicious, COLORS.malicious],
                }],
              }}
              options={{ plugins: { legend: { position: "bottom" } } }}
            />
          ) : <Empty>Пока нет анализов.</Empty>}
        </Card>
        <Card title="Семейства">
          {s && s.top_families.length > 0 ? (
            <Bar
              data={{
                labels: s.top_families.map((f) => f.family),
                datasets: [{ label: "Анализов", data: s.top_families.map((f) => f.count), backgroundColor: "#475569" }],
              }}
              options={{ indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { ticks: { precision: 0 } } } }}
            />
          ) : <Empty>Семейства появятся после анализа вредоносных образцов.</Empty>}
        </Card>
        <Card title="По дням">
          {s && s.timeline.length > 0 ? (
            <Bar
              data={{
                labels: s.timeline.map((d) => new Date(d.date).toLocaleDateString("ru-RU")),
                datasets: (["clean", "suspicious", "malicious"] as const).map((v) => ({
                  label: { clean: "Безопасные", suspicious: "Подозрительные", malicious: "Вредоносные" }[v],
                  data: s.timeline.map((d) => d[v] ?? 0),
                  backgroundColor: COLORS[v],
                })),
              }}
              options={{ plugins: { legend: { position: "bottom" } }, scales: { x: { stacked: true }, y: { stacked: true, ticks: { precision: 0 } } } }}
            />
          ) : <Empty>Нет данных.</Empty>}
        </Card>
      </div>

      <Card title="Последние анализы" right={<Link to="/history" className="text-sm text-slate-600 hover:underline">Вся история →</Link>}>
        {recent.data && recent.data.items.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr>
                <th className="th">Файл</th>
                <th className="th">Статус</th>
                <th className="th">Вердикт</th>
                <th className="th">Семейство</th>
                <th className="th">Время</th>
              </tr>
            </thead>
            <tbody>
              {recent.data.items.map((a) => (
                <tr key={a.id} className="hover:bg-slate-50">
                  <td className="td">
                    <Link to={`/analyses/${a.id}`} className="font-medium text-slate-900 hover:underline">
                      {a.sample.original_name ?? `${a.sample.sha256.slice(0, 16)}…`}
                    </Link>
                    {a.sample.source === "dataset" && <span className="ml-2 text-xs text-slate-500">из теста</span>}
                  </td>
                  <td className="td"><StatusBadge status={a.status} /></td>
                  <td className="td"><VerdictBadge verdict={a.verdict} /></td>
                  <td className="td text-sm">
                    {a.final_family ?? (a.family_status === "unknown" ? <span className="text-amber-700">не определено</span> : "—")}
                  </td>
                  <td className="td text-xs text-slate-500">{dt(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty>Загрузите первый файл.</Empty>}
      </Card>
    </div>
  );
}
