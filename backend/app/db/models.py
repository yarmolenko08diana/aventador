"""Таблицы БД (раздел 8 ТЗ). Центр схемы — analyses: всё остальное привязано к конкретному анализу."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    REAL,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

STATUSES = ("queued", "processing", "done", "failed")
VERDICTS = ("clean", "suspicious", "malicious")
SOURCES = ("upload", "dataset")


class Base(DeclarativeBase):
    pass


def _now():
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    original_name: Mapped[str | None] = mapped_column(Text)  # только как текст, на диске имя <sha256>.bin
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    storage_path: Mapped[str | None] = mapped_column(Text)  # None у образцов из датасета: файла нет
    dataset_truth: Mapped[dict | None] = mapped_column(JSONB)  # истинные метки BODMAS для режима «из теста»
    first_seen_at: Mapped[datetime] = _now()

    analyses: Mapped[list[Analysis]] = relationship(back_populates="sample")
    __table_args__ = (CheckConstraint(f"source in {SOURCES}", name="ck_samples_source"),)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id", ondelete="CASCADE"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", index=True)
    verdict: Mapped[str | None] = mapped_column(String(16), index=True)
    detector_score: Mapped[float | None] = mapped_column(Float)
    final_family: Mapped[str | None] = mapped_column(Text, index=True)
    family_confidence: Mapped[float | None] = mapped_column(Float)
    family_status: Mapped[str | None] = mapped_column(String(16))  # identified / unknown / not_applicable
    final_category: Mapped[str | None] = mapped_column(Text)
    category_confidence: Mapped[float | None] = mapped_column(Float)
    disagreement: Mapped[dict | None] = mapped_column(JSONB)
    feature_version: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = _now()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sample: Mapped[Sample] = relationship(back_populates="analyses")
    features: Mapped[AnalysisFeatures | None] = relationship(cascade="all, delete-orphan", uselist=False)
    sections: Mapped[list[PeSection]] = relationship(cascade="all, delete-orphan", order_by="PeSection.id")
    imports: Mapped[list[PeImport]] = relationship(cascade="all, delete-orphan", order_by="PeImport.id")
    indicator_hits: Mapped[list[IndicatorHit]] = relationship(cascade="all, delete-orphan", order_by="IndicatorHit.id")
    predictions: Mapped[list[ModelPrediction]] = relationship(cascade="all, delete-orphan", order_by="ModelPrediction.id")
    alerts: Mapped[list[Alert]] = relationship(cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(f"status in {STATUSES}", name="ck_analyses_status"),
        CheckConstraint(f"verdict is null or verdict in {VERDICTS}", name="ck_analyses_verdict"),
    )


class AnalysisFeatures(Base):
    __tablename__ = "analysis_features"

    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True)
    vector: Mapped[list[float] | None] = mapped_column(ARRAY(REAL))
    static_info: Mapped[dict | None] = mapped_column(JSONB)


class PeSection(Base):
    __tablename__ = "pe_sections"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(Text)
    virtual_address: Mapped[int] = mapped_column(BigInteger)
    virtual_size: Mapped[int] = mapped_column(BigInteger)
    raw_size: Mapped[int] = mapped_column(BigInteger)
    entropy: Mapped[float] = mapped_column(Float)
    is_read: Mapped[bool] = mapped_column(Boolean)
    is_write: Mapped[bool] = mapped_column(Boolean)
    is_exec: Mapped[bool] = mapped_column(Boolean)


class PeImport(Base):
    __tablename__ = "pe_imports"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    dll: Mapped[str] = mapped_column(Text)
    function: Mapped[str] = mapped_column(Text)


class IndicatorRule(Base):
    __tablename__ = "indicator_rules"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    caveat: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(32))


class IndicatorHit(Base):
    __tablename__ = "indicator_hits"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    rule_code: Mapped[str] = mapped_column(ForeignKey("indicator_rules.code"))
    severity: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict] = mapped_column(JSONB)

    rule: Mapped[IndicatorRule] = relationship(lazy="joined")


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    task: Mapped[str] = mapped_column(String(16), index=True)
    algorithm: Mapped[str] = mapped_column(String(16))
    version: Mapped[str] = mapped_column(String(32))  # первые 12 символов sha256 manifest.json
    feature_version: Mapped[str] = mapped_column(String(32))
    dataset: Mapped[str] = mapped_column(String(32))
    split_strategy: Mapped[str] = mapped_column(String(32))
    classes: Mapped[list] = mapped_column(JSONB)
    thresholds: Mapped[dict] = mapped_column(JSONB)
    hyperparameters: Mapped[dict] = mapped_column(JSONB)
    validation: Mapped[dict] = mapped_column(JSONB)
    artifact_path: Mapped[str] = mapped_column(Text)
    artifact_sha256: Mapped[str] = mapped_column(String(64))  # sha256 manifest.json (в нём sha256 файлов модели)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[datetime] = _now()
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)  # даёт итоговый ответ своей задачи

    evaluations: Mapped[list[ModelEvaluation]] = relationship(cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint("task", "algorithm", "artifact_sha256", name="uq_model_version"),)


class ModelPrediction(Base):
    __tablename__ = "model_predictions"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"))
    task: Mapped[str] = mapped_column(String(16))
    predicted_label: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    top_k: Mapped[list] = mapped_column(JSONB)
    latency_ms: Mapped[float] = mapped_column(Float)
    is_final: Mapped[bool] = mapped_column(Boolean)

    model_version: Mapped[ModelVersion] = relationship(lazy="joined")


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id: Mapped[int] = mapped_column(primary_key=True)
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id", ondelete="CASCADE"), index=True)
    split_name: Mapped[str] = mapped_column(String(32))  # test_temporal
    accuracy: Mapped[float | None] = mapped_column(Float)
    precision_macro: Mapped[float | None] = mapped_column(Float)
    recall_macro: Mapped[float | None] = mapped_column(Float)
    f1_macro: Mapped[float | None] = mapped_column(Float)
    roc_auc: Mapped[float | None] = mapped_column(Float)
    tpr_at_fpr_1pct: Mapped[float | None] = mapped_column(Float)
    confusion_matrix: Mapped[list] = mapped_column(JSONB)
    per_class: Mapped[dict | None] = mapped_column(JSONB)
    metrics: Mapped[dict] = mapped_column(JSONB)  # весь evaluation.json без кривых
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = _now()
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = [
    "Base", "Sample", "Analysis", "AnalysisFeatures", "PeSection", "PeImport", "IndicatorRule",
    "IndicatorHit", "ModelVersion", "ModelPrediction", "ModelEvaluation", "Alert",
]
