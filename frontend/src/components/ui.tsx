// Небольшие общие элементы интерфейса
import type { ReactNode } from "react";
import type { Status, Verdict } from "../api/types";

const VERDICT: Record<Verdict, { text: string; cls: string }> = {
  clean: { text: "Безопасный", cls: "bg-emerald-100 text-emerald-800 ring-emerald-600/20" },
  suspicious: { text: "Подозрительный", cls: "bg-amber-100 text-amber-800 ring-amber-600/20" },
  malicious: { text: "Вредоносный", cls: "bg-red-100 text-red-800 ring-red-600/20" },
};

const STATUS: Record<Status, string> = {
  queued: "В очереди",
  processing: "Анализируется",
  done: "Готово",
  failed: "Ошибка",
};

export function VerdictBadge({ verdict, large }: { verdict: Verdict | null; large?: boolean }) {
  if (!verdict) return <span className="text-slate-400">—</span>;
  const v = VERDICT[verdict];
  return (
    <span className={`inline-flex rounded-full font-medium ring-1 ring-inset ${v.cls} ${large ? "px-4 py-1.5 text-base" : "px-2.5 py-0.5 text-xs"}`}>
      {v.text}
    </span>
  );
}

export function StatusBadge({ status }: { status: Status }) {
  const cls =
    status === "failed" ? "text-red-700" : status === "done" ? "text-slate-600" : "text-blue-700 animate-pulse";
  return <span className={`text-xs font-medium ${cls}`}>{STATUS[status]}</span>;
}

export function SeverityBadge({ severity }: { severity: "low" | "medium" | "high" }) {
  const map = {
    high: ["Высокая", "bg-red-50 text-red-700 ring-red-600/20"],
    medium: ["Средняя", "bg-amber-50 text-amber-700 ring-amber-600/20"],
    low: ["Низкая", "bg-slate-100 text-slate-600 ring-slate-500/20"],
  } as const;
  const [text, cls] = map[severity];
  return <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}>{text}</span>;
}

export function Card({ title, children, right }: { title?: ReactNode; children: ReactNode; right?: ReactNode }) {
  return (
    <section className="card">
      {(title || right) && (
        <div className="mb-3 flex items-center justify-between gap-4">
          {title && <h2 className="card-title mb-0">{title}</h2>}
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">Ошибка: {msg}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-slate-500">{children}</p>;
}

export const pct = (x: number | null | undefined, digits = 1) =>
  x === null || x === undefined ? "—" : `${(x * 100).toFixed(digits)}%`;

// Вероятность или порог: у LightGBM они бывают очень малы, и 0.0000 скрыл бы разницу с порогом
export const prob = (x: number | null | undefined) =>
  x === null || x === undefined ? "—" : x === 0 || x >= 0.001 ? x.toFixed(4) : x.toExponential(2);

export const dt = (iso: string | null) => (iso ? new Date(iso).toLocaleString("ru-RU") : "—");

export const bytes = (n: number | null) => {
  if (n === null) return "—";
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
  return `${(n / 1024 / 1024).toFixed(1)} МБ`;
};

export const TASK_TITLE = { detection: "Обнаружение", family: "Семейство", category: "Категория" } as const;
export const ALGO_TITLE = { rf: "Random Forest", lgbm: "LightGBM", mlp: "MLP", ensemble: "Ансамбль" } as const;
