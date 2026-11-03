// Тонкий клиент к FastAPI. Все данные на страницах приходят отсюда — ничего не выдумывается на фронтенде.
import type {
  Alert,
  Analysis,
  Comparison,
  ConfusionMatrix,
  Curves,
  ModelInfo,
  AnalysisList,
  DashboardStats,
  DatasetExample,
  Indicators,
  Prediction,
  StaticInfo,
  UploadResult,
} from "./types";

const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* тело не JSON — оставляем statusText */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  upload(file: File): Promise<UploadResult> {
    const form = new FormData();
    form.append("file", file);
    return request("/samples", { method: "POST", body: form });
  },
  fromDataset: (sha256: string) => request<UploadResult>("/analyses/from-dataset", json({ sha256 })),
  datasetExamples: (perGroup = 4) => request<DatasetExample[]>(`/dataset/examples?per_group=${perGroup}`),
  analysis: (id: number) => request<Analysis>(`/analyses/${id}`),
  analyses: (params: Record<string, string | number | undefined> = {}) => {
    const q = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && q.set(k, String(v)));
    return request<AnalysisList>(`/analyses?${q}`);
  },
  staticInfo: (id: number) => request<StaticInfo>(`/analyses/${id}/static`),
  indicators: (id: number) => request<Indicators>(`/analyses/${id}/indicators`),
  predictions: (id: number) => request<Prediction[]>(`/analyses/${id}/predictions`),
  reportUrl: (id: number) => `${BASE}/analyses/${id}/report.pdf`,
  rerun: (id: number) => request<UploadResult>(`/analyses/${id}/rerun`, { method: "POST" }),
  dashboard: () => request<DashboardStats>("/dashboard/stats"),
  models: () => request<ModelInfo[]>("/models"),
  comparison: (task: string) => request<Comparison>(`/models/comparison?task=${task}`),
  confusion: (modelId: number) => request<ConfusionMatrix>(`/models/${modelId}/confusion-matrix`),
  curves: (modelId: number) => request<Curves>(`/models/${modelId}/curves`),
  alerts: (unread = false) => request<Alert[]>(`/alerts?limit=200${unread ? "&unread=true" : ""}`),
  unreadAlerts: () => request<{ unread: number }>("/alerts/unread-count"),
  markAlert: (id: number, isRead: boolean) =>
    request<Alert>(`/alerts/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ is_read: isRead }),
    }),
  markAllAlerts: () => request<{ marked: number }>("/alerts/read-all", { method: "POST" }),
};
