"""Этап 1: подготовка данных BODMAS.

Запуск из корня репозитория:
    python -m mltrain.data.prepare

Результат:
    data/splits/detection.csv, family.csv, category.csv
        колонки: row (номер строки в bodmas.npz), sha256, timestamp, split, target
    data/processed/data_report.md — отчёт для текста практики

Сам массив признаков не копируется: обучение читает строки X из bodmas.npz по номеру row.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import yaml

from mltrain.data.load_bodmas import ROOT, load_bodmas
from mltrain.data.splits import (
    SPLITS,
    UNKNOWN,
    class_table,
    find_duplicate_rows,
    split_category,
    split_detection,
    split_family,
)

CONFIG = ROOT / "ml" / "configs" / "data.yaml"
SPLITS_DIR = ROOT / "data" / "splits"
REPORT = ROOT / "data" / "processed" / "data_report.md"


def time_ranges(frame) -> list[str]:
    rows = ["| Выборка | Образцов | С | По |", "| --- | --- | --- | --- |"]
    for name in SPLITS:
        part = frame[frame["split"] == name]
        rows.append(
            f"| {name} | {len(part)} | {part['timestamp'].min():%Y-%m-%d} | {part['timestamp'].max():%Y-%m-%d} |"
        )
    return rows


def main() -> int:
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    ratios = cfg["ratios"]

    print("Загрузка BODMAS...")
    data = load_bodmas()
    meta = data.meta
    print(f"  образцов: {len(meta)}, вредоносных: {int(meta['label'].sum())}")

    print("Поиск одинаковых векторов признаков...")
    dup_mask = find_duplicate_rows(data.X, meta)
    dup_by_label = meta.loc[dup_mask, "label"].value_counts().to_dict()
    meta = meta[~dup_mask].copy()
    print(f"  удалено дубликатов: {int(dup_mask.sum())} (по классам 0/1: {dup_by_label})")

    detection = split_detection(meta, ratios)
    family = split_family(meta, ratios, cfg["family"])
    category = split_category(meta, ratios, cfg["category"]["min_train"])

    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    for name, frame in (("detection", detection), ("family", family), ("category", category)):
        frame.to_csv(SPLITS_DIR / f"{name}.csv", index=False)
        print(f"  сохранено: data/splits/{name}.csv ({len(frame)} строк)")

    known = family[family["target"] != UNKNOWN]
    n_classes = known["target"].nunique()
    unknown_by_split = family[family["target"] == UNKNOWN]["split"].value_counts().reindex(SPLITS, fill_value=0)

    lines = [
        "# Подготовка данных BODMAS",
        "",
        f"Исходно образцов: {len(data.meta)}. Удалено одинаковых векторов признаков: {int(dup_mask.sum())} "
        f"(безопасных {dup_by_label.get(0, 0)}, вредоносных {dup_by_label.get(1, 0)}). Осталось: {len(meta)}.",
        f"Доли выборок: train {ratios['train']}, val {ratios['val']}, test {ratios['test']}; разбиение по времени.",
        "",
        "## Обнаружение (benign / malware)",
        "",
        "Разбиение по времени внутри каждого класса.",
        "",
        class_table(detection).to_markdown(),
        "",
        "Время по выборкам, безопасные:",
        "",
        *time_ranges(detection[detection["target"] == "benign"]),
        "",
        "Время по выборкам, вредоносные:",
        "",
        *time_ranges(detection[detection["target"] == "malware"]),
        "",
        "## Семейства",
        "",
        f"Порог: не меньше {cfg['family']['min_train']} в train, {cfg['family']['min_val']} в val, "
        f"{cfg['family']['min_test']} в test. Прошло семейств: {n_classes} из {family_total(meta)}.",
        f"Образцов вне этих семейств (unknown, только для оценки ответа «не определено»): "
        f"train {unknown_by_split['train']}, val {unknown_by_split['val']}, test {unknown_by_split['test']}.",
        "",
        class_table(known).to_markdown(),
        "",
        "## Категории",
        "",
        f"Категории, у которых меньше {cfg['category']['min_train']} образцов в train, объединены в other.",
        "",
        class_table(category).to_markdown(),
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nСемейств в классификаторе: {n_classes}; категорий: {category['target'].nunique()}")
    print(f"Отчёт: {REPORT.relative_to(ROOT)}")
    return 0


def family_total(meta) -> int:
    return int(meta.loc[meta["label"] == 1, "family"].nunique())


if __name__ == "__main__":
    np.set_printoptions(linewidth=120)
    sys.exit(main())
