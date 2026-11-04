import { useMutation } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import type { UploadResult } from "../api/types";
import { Card, ErrorBox } from "../components/ui";

export default function Upload() {
  const navigate = useNavigate();
  const [duplicate, setDuplicate] = useState<UploadResult | null>(null);

  const upload = useMutation({
    mutationFn: api.upload,
    onSuccess: (res) => (res.duplicate ? setDuplicate(res) : navigate(`/analyses/${res.analysis_id}`)),
  });
  const rerun = useMutation({
    mutationFn: api.rerun,
    onSuccess: (res) => navigate(`/analyses/${res.analysis_id}`),
  });

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
    </div>
  );
}
