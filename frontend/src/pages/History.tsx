import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api/client";
import { Card, Empty, ErrorBox, StatusBadge, VerdictBadge, dt, pct } from "../components/ui";

const PAGE = 25;
const FILTERS = ["q", "verdict", "family", "status", "date_from", "date_to"] as const;

export default function History() {
  // Фильтры живут в адресе страницы: ссылкой можно поделиться, «Назад» возвращает к той же выборке
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const page = Number(params.get("page") ?? 0);
  const [search, setSearch] = useState(get("q"));

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    next.delete("page");
    setParams(next);
  };
  const filters = Object.fromEntries(FILTERS.map((k) => [k, get(k) || undefined]));

  const list = useQuery({
    queryKey: ["history", filters, page],
    queryFn: () => api.analyses({ ...filters, limit: PAGE, offset: page * PAGE }),
    placeholderData: keepPreviousData,
    refetchInterval: 5000,
  });
  // Список семейств — классы итоговой модели семейств, а не выдуманный справочник
  const models = useQuery({ queryKey: ["models"], queryFn: api.models });
  const families = models.data?.find((m) => m.task === "family" && m.is_final)?.classes ?? [];

  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));
  const hasFilters = FILTERS.some((k) => params.get(k));

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">История анализов</h1>

      <Card>
        <form
          className="grid gap-3 md:grid-cols-6"
          onSubmit={(e) => {
            e.preventDefault();
            set("q", search.trim());
          }}
        >
          <input
            className="input md:col-span-2"
            placeholder="Имя файла, SHA-256, SHA-1 или MD5"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onBlur={() => search.trim() !== get("q") && set("q", search.trim())}
          />
          <select className="input" value={get("verdict")} onChange={(e) => set("verdict", e.target.value)}>
            <option value="">Любой вердикт</option>
            <option value="clean">Безопасный</option>
            <option value="suspicious">Подозрительный</option>
            <option value="malicious">Вредоносный</option>
          </select>
          <select className="input" value={get("family")} onChange={(e) => set("family", e.target.value)}>
            <option value="">Любое семейство</option>
            {families.map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
          <input className="input" type="date" title="С даты" value={get("date_from")} onChange={(e) => set("date_from", e.target.value)} />
          <input className="input" type="date" title="По дату" value={get("date_to")} onChange={(e) => set("date_to", e.target.value)} />
        </form>
        <div className="mt-3 flex items-center gap-4 text-sm text-slate-500">
          <span>Найдено: {list.data ? total : "…"}</span>
          {get("status") === "failed" && <span>только с ошибкой</span>}
          {hasFilters && (
            <button
              className="text-slate-700 underline"
              onClick={() => {
                setSearch("");
                setParams(new URLSearchParams());
              }}
            >
              Сбросить фильтры
            </button>
          )}
        </div>
      </Card>

      <Card>
        {list.isError && <ErrorBox error={list.error} />}
        {list.data && list.data.items.length === 0 && (
          <Empty>{hasFilters ? "Под фильтры ничего не подходит." : "Анализов пока нет."}</Empty>
        )}
        {list.data && list.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">#</th>
                  <th className="th">Файл</th>
                  <th className="th">Статус</th>
                  <th className="th">Вердикт</th>
                  <th className="th">Вероятность</th>
                  <th className="th">Семейство</th>
                  <th className="th">Категория</th>
                  <th className="th">Дата</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50">
                    <td className="td text-xs text-slate-500">{a.id}</td>
                    <td className="td max-w-xs">
                      <Link to={`/analyses/${a.id}`} className="font-medium text-slate-900 hover:underline">
                        {a.sample.original_name ?? `${a.sample.sha256.slice(0, 16)}…`}
                      </Link>
                      {a.sample.source === "dataset" && <span className="ml-2 text-xs text-slate-500">из теста</span>}
                      <div className="mono text-slate-400">{a.sample.sha256.slice(0, 32)}…</div>
                    </td>
                    <td className="td"><StatusBadge status={a.status} /></td>
                    <td className="td"><VerdictBadge verdict={a.verdict} /></td>
                    <td className="td text-sm">{a.detector_score === null ? "—" : a.detector_score.toFixed(3)}</td>
                    <td className="td text-sm">
                      {a.final_family ?? (a.family_status === "unknown" ? <span className="text-amber-700">не определено</span> : "—")}
                      {a.final_family && <span className="ml-1 text-xs text-slate-500">{pct(a.family_confidence, 0)}</span>}
                    </td>
                    <td className="td text-sm">{a.final_category ?? "—"}</td>
                    <td className="td whitespace-nowrap text-xs text-slate-500">{dt(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {pages > 1 && (
          <div className="mt-4 flex items-center justify-end gap-3 text-sm">
            <button
              className="btn-secondary"
              disabled={page === 0}
              onClick={() => setParams((p) => (p.set("page", String(page - 1)), p))}
            >
              Назад
            </button>
            <span>
              {page + 1} из {pages}
            </span>
            <button
              className="btn-secondary"
              disabled={page + 1 >= pages}
              onClick={() => setParams((p) => (p.set("page", String(page + 1)), p))}
            >
              Вперёд
            </button>
          </div>
        )}
      </Card>
    </div>
  );
}
