import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";

import { api } from "../api/client";
import ErrorBoundary from "./ErrorBoundary";

const links = [
  { to: "/", label: "Панель", end: true },
  { to: "/upload", label: "Загрузка" },
  { to: "/history", label: "История" },
  { to: "/models", label: "Модели" },
];

function Bell() {
  // Счётчик непрочитанных обновляется каждые 5 секунд
  const unread = useQuery({ queryKey: ["unread"], queryFn: api.unreadAlerts, refetchInterval: 5000 });
  const n = unread.data?.unread ?? 0;
  return (
    <NavLink
      to="/alerts"
      title={n ? `Непрочитанных оповещений: ${n}` : "Оповещения"}
      className={({ isActive }) => `relative rounded-md p-2 ${isActive ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-100"}`}
    >
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={1.8} aria-hidden>
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
      </svg>
      <span className="sr-only">Оповещения</span>
      {n > 0 && (
        <span className="absolute -right-1 -top-1 min-w-[1.25rem] rounded-full bg-red-600 px-1 text-center text-[11px] font-semibold leading-5 text-white">
          {n > 99 ? "99+" : n}
        </span>
      )}
    </NavLink>
  );
}

export default function Layout() {
  const { pathname } = useLocation();
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-8 gap-y-2 px-4 py-3">
          <Link to="/" className="text-lg font-semibold tracking-tight">Malscan</Link>
          <nav className="flex flex-wrap gap-1">
            {links.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.end}
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 text-sm font-medium ${isActive ? "bg-slate-900 text-white" : "text-slate-600 hover:bg-slate-100"}`
                }
              >
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <span className="hidden text-xs text-slate-500 lg:block">Статический анализ: файлы не запускаются</span>
            <Bell />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <ErrorBoundary key={pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
