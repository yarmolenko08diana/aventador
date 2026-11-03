// Типы ответов API (соответствуют backend/app/schemas/api.py)

export type Status = "queued" | "processing" | "done" | "failed";
export type Verdict = "clean" | "suspicious" | "malicious";
export type Task = "detection" | "family" | "category";
export type Algorithm = "rf" | "lgbm" | "mlp" | "ensemble";

export interface Sample {
  id: number;
  sha256: string;
  md5: string | null;
  sha1: string | null;
  size_bytes: number | null;
  original_name: string | null;
  source: "upload" | "dataset";
  dataset_truth: {
    label: "benign" | "malware";
    family: string | null;
    category: string | null;
    category_target: string | null;
    family_in_classifier: boolean;
    timestamp: string;
  } | null;
  first_seen_at: string;
}

export interface Analysis {
  id: number;
  status: Status;
  verdict: Verdict | null;
  detector_score: number | null;
  final_family: string | null;
  family_confidence: number | null;
  family_status: "identified" | "unknown" | "not_applicable" | null;
  final_category: string | null;
  category_confidence: number | null;
  disagreement: Partial<Record<Task, boolean>> | null;
  feature_version: string | null;
  error_message: string | null;
  duration_ms: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  sample: Sample;
}

export interface AnalysisList {
  total: number;
  items: Analysis[];
}

export interface UploadResult {
  analysis_id: number;
  sha256: string;
  duplicate: boolean;
  status: Status;
}

export interface Section {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  is_read: boolean;
  is_write: boolean;
  is_exec: boolean;
}

export interface StaticInfo {
  available: boolean;
  reason: string | null;
  static_info: Record<string, any> | null;
  sections: Section[];
  imports: Record<string, string[]>;
}

export interface Indicator {
  code: string;
  title: string;
  severity: "low" | "medium" | "high";
  category: string;
  description: string;
  caveat: string;
  evidence: Record<string, unknown>;
}

export interface Indicators {
  available: boolean;
  reason: string | null;
  items: Indicator[];
}

export interface Prediction {
  task: Task;
  algorithm: Algorithm;
  model_version: string;
  predicted_label: string;
  confidence: number;
  top_k: { label: string; probability: number }[];
  latency_ms: number;
  is_final: boolean;
}

export interface DashboardStats {
  total_analyses: number;
  total_samples: number;
  by_status: Partial<Record<Status, number>>;
  by_verdict: Record<Verdict, number>;
  families_detected: number;
  family_unknown: number;
  top_families: { family: string; count: number }[];
  timeline: ({ date: string } & Partial<Record<Verdict, number>>)[];
  avg_duration_ms: number | null;
}

export interface DatasetExample {
  group: "benign" | "known_family" | "unknown_family";
  sha256: string;
  label: string;
  family: string | null;
}
