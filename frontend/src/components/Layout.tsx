import { NavLink, Outlet } from "react-router-dom";

const links = [
  { to: "/", label: "Панель", end: true },
  { to: "/upload", label: "Загрузка" },
];

export default function Layout() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center gap-8 px-4 py-3">
          <span className="text-lg font-semibold tracking-tight">Malscan</span>
          <nav className="flex gap-1">
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
          <span className="ml-auto hidden text-xs text-slate-500 sm:block">
            Статический анализ: файлы не запускаются
          </span>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
