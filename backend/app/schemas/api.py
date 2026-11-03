"""Схемы ответов API (Pydantic). Документация Swagger строится по ним."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UploadOut(BaseModel):
    analysis_id: int
    sha256: str
    duplicate: bool
    status: str


class DatasetRequest(BaseModel):
    sha256: str


class SampleOut(ORM):
    id: int
    sha256: str
    md5: str | None
    sha1: str | None
    size_bytes: int | None
    original_name: str | None
    source: str
    dataset_truth: dict | None
    first_seen_at: datetime


class AnalysisOut(ORM):
    id: int
    status: str
    verdict: str | None
    detector_score: float | None
    final_family: str | None
    family_confidence: float | None
    family_status: str | None
    final_category: str | None
    category_confidence: float | None
    disagreement: dict | None
    feature_version: str | None
    error_message: str | None
    duration_ms: float | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    sample: SampleOut


class AnalysisList(BaseModel):
    total: int
    items: list[AnalysisOut]


class SectionOut(ORM):
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    is_read: bool
    is_write: bool
    is_exec: bool


class StaticOut(BaseModel):
    available: bool
    reason: str | None = None
    static_info: dict | None = None
    sections: list[SectionOut] = []
    imports: dict[str, list[str]] = {}


class IndicatorOut(BaseModel):
    code: str
    title: str
    severity: str
    category: str
    description: str
    caveat: str
    evidence: dict


class IndicatorsOut(BaseModel):
    available: bool
    reason: str | None = None
    items: list[IndicatorOut] = []


class PredictionOut(BaseModel):
    task: str
    algorithm: str
    model_version: str
    predicted_label: str
    confidence: float
    top_k: list[dict]
    latency_ms: float
    is_final: bool


class ModelOut(ORM):
    id: int
    task: str
    algorithm: str
    version: str
    feature_version: str
    dataset: str
    split_strategy: str
    classes: list
    thresholds: dict
    hyperparameters: dict
    validation: dict
    trained_at: datetime
    is_active: bool
    is_final: bool


class AlertOut(ORM):
    id: int
    analysis_id: int
    severity: str
    title: str
    message: str
    is_read: bool
    created_at: datetime
    read_at: datetime | None


class AlertPatch(BaseModel):
    is_read: bool
