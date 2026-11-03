import { useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { UploadResult } from "../api/types";
import { Card, ErrorBox } from "../components/ui";

const GROUP_TITLE = {
  benign: "Безопасные",
  known_family: "Известное семейство",
  unknown_family: "Семейство, которого нет в классификаторе",
} as const;

export default function Upload() {
  const navigate = useNavigate();
  const [duplicate, setDuplicate] = useState<UploadResult | null>(null);

  const upload = useMutation({
    mutationFn: api.upload,
    onSuccess: (res) => (res.duplicate ? setDuplicate(res) : navigate(`/analyses/${res.analysis_id}`)),
  });
  const fromDataset = useMutation({
    mutationFn: api.fromDataset,
    onSuccess: (res) => navigate(`/analyses/${res.analysis_id}`),
  });
  const rerun = useMutation({
    mutationFn: api.rerun,
    onSuccess: (res) => navigate(`/analyses/${res.analysis_id}`),
  });
  const examples = useQuery({ queryKey: ["examples"], queryFn: () => api.datasetExamples(4) });

  const onDrop = useCallback(
    (files: File[]) => {
      setDuplicate(null);
      if (files[0]) upload.mutate(files[0]);
    },
    [upload],
  );
  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, multiple: false, maxSize: 50 * 1024 * 1024 });

  return (
    <div className="space-y-6">
      <Card title="Загрузить PE-файл (.exe, .dll)">
        <div
          {...getRootProps()}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-14 text-center transition ${
            isDragActive ? "border-slate-900 bg-slate-100" : "border-slate-300 hover:border-slate-500"
          }`}
        >
          <input {...getInputProps()} />
          <p className="text-base font-medium">
            {upload.isPending ? "Загрузка…" : "Перетащите файл сюда или нажмите, чтобы выбрать"}
          </p>
          <p className="mt-2 text-sm text-slate-500">
            До 50 МБ. Тип проверяется по содержимому (MZ/PE), а не по расширению. Файл сохраняется в карантин и
            никогда не запускается.
          </p>
        </div>
        {upload.isError && <div className="mt-4"><ErrorBox error={upload.error} /></div>}
        {duplicate && (
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900">
            Этот файл (SHA-256 {duplicate.sha256.slice(0, 16)}…) уже анализировался.
            <button className="btn-secondary" onClick={() => navigate(`/analyses/${duplicate.analysis_id}`)}>
              Открыть прошлый анализ
            </button>
            <button className="btn" disabled={rerun.isPending} onClick={() => rerun.mutate(duplicate.analysis_id)}>
              Проанализировать заново
            </button>
          </div>
        )}
      </Card>

      <Card title="Образец из тестовой выборки BODMAS">
        <p className="mb-4 text-sm text-slate-600">
          Готовый вектор признаков из тестовой части датасета, которую модели не видели при обучении. Самого файла нет,
          поэтому индикаторы не строятся, зато известен правильный ответ и его можно сравнить с прогнозом.
        </p>
        {examples.isError && <ErrorBox error={examples.error} />}
        {fromDataset.isError && <div className="mb-3"><ErrorBox error={fromDataset.error} /></div>}
        <div className="grid gap-4 md:grid-cols-3">
          {(["benign", "known_family", "unknown_family"] as const).map((group) => (
            <div key={group}>
              <h3 className="mb-2 text-sm font-semibold text-slate-700">{GROUP_TITLE[group]}</h3>
              <ul className="space-y-1">
                {examples.data
                  ?.filter((e) => e.group === group)
                  .map((e) => (
                    <li key={e.sha256}>
                      <button
                        className="w-full rounded border border-slate-200 px-2 py-1.5 text-left hover:bg-slate-50 disabled:opacity-50"
                        disabled={fromDataset.isPending}
                        onClick={() => fromDataset.mutate(e.sha256)}
                      >
                        <span className="mono block text-slate-500">{e.sha256.slice(0, 24)}…</span>
                        {e.family && <span className="text-xs text-slate-700">{e.family}</span>}
                      </button>
                    </li>
                  ))}
                {examples.data && !examples.data.some((e) => e.group === group) && (
                  <li className="text-sm text-slate-500">В тестовой выборке таких нет.</li>
                )}
              </ul>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
