import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import type { Analysis } from "../api/types";
import { ImportsList, IndicatorList, ModelComparison, SectionsTable, StaticSummary } from "../components/AnalysisParts";
import { Card, ErrorBox, StatusBadge, VerdictBadge, bytes, dt, pct } from "../components/ui";

const finished = (a?: Analysis) => a?.status === "done" || a?.status === "failed";

export default function AnalysisDetail() {
  const id = Number(useParams().id);
  const navigate = useNavigate();
  // Опрашиваем статус раз в секунду, пока worker не закончит
  const analysis = useQuery({
    queryKey: ["analysis", id],
    queryFn: () => api.analysis(id),
    refetchInterval: (q) => (finished(q.state.data) ? false : 1000),
  });
  const done = analysis.data?.status === "done";
  const predictions = useQuery({ queryKey: ["predictions", id], queryFn: () => api.predictions(id), enabled: done });
  const indicators = useQuery({ queryKey: ["indicators", id], queryFn: () => api.indicators(id), enabled: done });
  const staticInfo = useQuery({ queryKey: ["static", id], queryFn: () => api.staticInfo(id), enabled: done });
  const rerun = useMutation({ mutationFn: api.rerun, onSuccess: (r) => navigate(`/analyses/${r.analysis_id}`) });

  if (analysis.isError) return <ErrorBox error={analysis.error} />;
  const a = analysis.data;
  if (!a) return <p className="text-sm text-slate-500">Загрузка…</p>;
  const s = a.sample;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">{s.original_name ?? (s.source === "dataset" ? "Образец из тестовой выборки" : s.sha256)}</h1>
          <p className="mono mt-1 text-slate-500">SHA-256 {s.sha256}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={a.status} />
          {finished(a) && (
            <button className="btn-secondary" disabled={rerun.isPending} onClick={() => rerun.mutate(a.id)}>
              Повторить анализ
            </button>
          )}
        </div>
      </div>

      {!finished(a) && (
        <Card>
          <p className="text-sm text-slate-600">
            {a.status === "queued" ? "Файл в очереди. Убедитесь, что worker запущен (make worker)." : "Worker разбирает файл в изолированном процессе…"}
          </p>
        </Card>
      )}
      {a.status === "failed" && (
        <Card title="Анализ не выполнен">
          <pre className="whitespace-pre-wrap text-sm text-red-800">{a.error_message}</pre>
        </Card>
      )}

      {done && (
        <div className="grid gap-6 md:grid-cols-3">
          <Card title="Вердикт">
            <VerdictBadge verdict={a.verdict} large />
            <p className="mt-3 text-sm text-slate-600">
              Вероятность вредоносности (итоговый детектор): <b>{a.detector_score?.toFixed(4)}</b>
            </p>
          </Card>
          <Card title="Семейство и категория">
            {a.family_status === "not_applicable" ? (
              <p className="text-sm text-slate-600">Не определялись: файл признан безопасным.</p>
            ) : (
              <div className="space-y-2 text-sm">
                <div>
                  Семейство:{" "}
                  {a.family_status === "identified" ? (
                    <b>{a.final_family}</b>
                  ) : (
                    <b className="text-amber-700">не определено</b>
                  )}{" "}
                  <span className="text-slate-500">(уверенность {pct(a.family_confidence)})</span>
                </div>
                {a.family_status === "unknown" && (
                  <p className="text-xs text-slate-500">
                    Уверенность ниже порога, выбранного на validation: вероятно, семейство не из тех, на которых училась модель.
                  </p>
                )}
                <div>
                  Категория: <b>{a.final_category}</b> <span className="text-slate-500">({pct(a.category_confidence)})</span>
                </div>
              </div>
            )}
          </Card>
          <Card title="Файл">
            <dl className="space-y-1 text-sm">
              <div>Источник: {s.source === "upload" ? "загрузка" : "тестовая выборка BODMAS"}</div>
              {s.size_bytes !== null && <div>Размер: {bytes(s.size_bytes)}</div>}
              {s.md5 && <div className="mono text-slate-500">MD5 {s.md5}</div>}
              <div>Время анализа: {a.duration_ms?.toFixed(0)} мс</div>
              <div className="text-slate-500">{dt(a.finished_at)}</div>
            </dl>
          </Card>
        </div>
      )}

      {done && s.dataset_truth && <TruthCard a={a} />}

      {done && predictions.data && <ModelComparison predictions={predictions.data} disagreement={a.disagreement} />}
      {done && indicators.data && <IndicatorList {...indicators.data} />}
      {done && staticInfo.data?.available && staticInfo.data.static_info && (
        <>
          <StaticSummary info={staticInfo.data.static_info} />
          <SectionsTable sections={staticInfo.data.sections} />
          <ImportsList imports={staticInfo.data.imports} />
        </>
      )}
    </div>
  );
}

function TruthCard({ a }: { a: Analysis }) {
  const t = a.sample.dataset_truth!;
  const predictedMalware = a.verdict !== "clean";
  const detectionOk = predictedMalware === (t.label === "malware");
  const familyOk = t.family && a.final_family ? t.family === a.final_family : null;
  return (
    <Card title="Сравнение с правильным ответом (BODMAS)">
      <table className="w-full max-w-xl text-sm">
        <thead>
          <tr><th className="th"></th><th className="th">Правда</th><th className="th">Прогноз</th><th className="th"></th></tr>
        </thead>
        <tbody>
          <tr>
            <td className="td">Класс</td>
            <td className="td">{t.label === "malware" ? "вредоносный" : "безопасный"}</td>
            <td className="td"><VerdictBadge verdict={a.verdict} /></td>
            <td className="td">{detectionOk ? "✓" : "✗"}</td>
          </tr>
          {t.label === "malware" && (
            <tr>
              <td className="td">Семейство</td>
              <td className="td">
                {t.family}
                {!t.family_in_classifier && <div className="text-xs text-slate-500">нет среди классов модели</div>}
              </td>
              <td className="td">{a.final_family ?? (a.family_status === "unknown" ? "не определено" : "—")}</td>
              <td className="td">
                {familyOk === null ? (!t.family_in_classifier && a.family_status === "unknown" ? "✓" : "—") : familyOk ? "✓" : "✗"}
              </td>
            </tr>
          )}
          {t.label === "malware" && (
            <tr>
              <td className="td">Категория</td>
              <td className="td">
                {t.category}
                {t.category_target && t.category_target !== t.category && (
                  <div className="text-xs text-slate-500">для модели: {t.category_target}</div>
                )}
              </td>
              <td className="td">{a.final_category ?? "—"}</td>
              <td className="td">{a.final_category ? (a.final_category === (t.category_target ?? t.category) ? "✓" : "✗") : "—"}</td>
            </tr>
          )}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-slate-500">
        Для семейства, которого нет среди классов модели, правильный ответ системы — «не определено».
        Редкие категории модель знает только как «other».
      </p>
    </Card>
  );
}
