import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import { Card, Empty, ErrorBox, SeverityBadge, dt } from "../components/ui";

export default function Alerts() {
  const qc = useQueryClient();
  const [onlyUnread, setOnlyUnread] = useState(false);
  const alerts = useQuery({ queryKey: ["alerts", onlyUnread], queryFn: () => api.alerts(onlyUnread), refetchInterval: 5000 });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["alerts"] });
    qc.invalidateQueries({ queryKey: ["unread"] });
  };
  const mark = useMutation({ mutationFn: ({ id, read }: { id: number; read: boolean }) => api.markAlert(id, read), onSuccess: refresh });
  const markAll = useMutation({ mutationFn: api.markAllAlerts, onSuccess: refresh });
  const unread = alerts.data?.filter((a) => !a.is_read).length ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Оповещения</h1>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-600">
            <input type="checkbox" checked={onlyUnread} onChange={(e) => setOnlyUnread(e.target.checked)} />
            только непрочитанные
          </label>
          <button className="btn-secondary" disabled={markAll.isPending || unread === 0} onClick={() => markAll.mutate()}>
            Прочитать все
          </button>
        </div>
      </div>
      <p className="text-sm text-slate-500">
        Оповещение создаётся автоматически, когда итоговый детектор признаёт файл подозрительным или вредоносным.
      </p>

      <Card>
        {alerts.isError && <ErrorBox error={alerts.error} />}
        {alerts.data && alerts.data.length === 0 && (
          <Empty>{onlyUnread ? "Непрочитанных оповещений нет." : "Оповещений пока нет: подозрительных файлов не было."}</Empty>
        )}
        <ul className="divide-y divide-slate-100">
          {alerts.data?.map((a) => (
            <li key={a.id} className={`flex items-start gap-4 py-3 ${a.is_read ? "opacity-60" : ""}`}>
              <span className={`mt-2 h-2 w-2 shrink-0 rounded-full ${a.is_read ? "bg-transparent" : "bg-blue-600"}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <Link
                    to={`/analyses/${a.analysis_id}`}
                    className="font-medium text-slate-900 hover:underline"
                    onClick={() => !a.is_read && mark.mutate({ id: a.id, read: true })}
                  >
                    {a.title}
                  </Link>
                </div>
                <p className="mt-1 text-sm text-slate-600">{a.message}</p>
                <p className="mt-1 text-xs text-slate-400">{dt(a.created_at)}</p>
              </div>
              <button
                className="shrink-0 text-xs text-slate-500 hover:text-slate-900"
                onClick={() => mark.mutate({ id: a.id, read: !a.is_read })}
              >
                {a.is_read ? "Сделать непрочитанным" : "Прочитано"}
              </button>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
