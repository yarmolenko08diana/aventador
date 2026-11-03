"""Этап 5, дополнительные эксперименты для отчёта (запускать после mltrain.evaluate).

    python -m mltrain.experiments

1. Важность признаков LightGBM (gain): какие группы признаков EMBER решают.
2. Проверка «шортката» по дате компиляции. Безопасные файлы BODMAS датированы с 2007 года,
   вредоносные — 2019–2020, поэтому модель могла выучить «старый файл = безопасный».
   Обучаем LightGBM обнаружения с теми же гиперпараметрами, но с обнулённым признаком
   header.coff.timestamp, и сравниваем на том же тесте с исходной моделью.
3. Случайное разбиение вместо разбиения по времени: тот же LightGBM на случайном
   стратифицированном разбиении 70/10/20. Разница с тестом по времени показывает, насколько
   случайное разбиение завышает качество.

Это анализ, а не выбор модели: модели из этих экспериментов в сервис не попадают.
Результат: artifacts/reports/experiments.json и experiments.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from malcore.features.names import feature_names, group_of, index_of
from mltrain import metrics
from mltrain.data.load_bodmas import ROOT
from mltrain.datasets import SPLITS_DIR, TASKS, balanced_weights, load_features, read_split
from mltrain.evaluate import MODELS_DIR, REPORTS_DIR

TIMESTAMP = "header.coff.timestamp"


def lgbm_params(manifest: dict, n_classes: int, n_jobs: int) -> tuple[dict, int]:
    hp = dict(manifest["hyperparameters"])
    rounds = int(hp.pop("best_iteration"))
    params = {**hp, "verbosity": -1, "seed": manifest["seed"], "num_threads": n_jobs,
              "deterministic": True, "force_col_wise": True}
    if n_classes == 2:
        params["objective"] = "binary"
    else:
        params.update(objective="multiclass", num_class=n_classes)
    return params, rounds


def fit_predict(params: dict, rounds: int, Xtr, ytr, Xte, n_classes: int) -> np.ndarray:
    w = balanced_weights(ytr, n_classes)
    booster = lgb.train(params, lgb.Dataset(Xtr, label=ytr, weight=w[ytr]), num_boost_round=rounds)
    p = booster.predict(Xte)
    return np.column_stack([1 - p, p]) if p.ndim == 1 else p


def score(task: str, y, proba) -> dict:
    if task == "detection":
        m = metrics.detection_metrics(y, proba[:, 1])
        return {k: m[k] for k in ("roc_auc", "tpr_at_fpr_1pct", "tpr_at_fpr_0_1pct")}
    return metrics.multiclass_metrics(y, proba)


def labelled(task: str, split: pd.DataFrame, classes: list[str]) -> pd.DataFrame:
    frame = split[split["target"] != metrics.UNKNOWN] if task == "family" else split
    return frame.assign(y=frame["target"].map({c: i for i, c in enumerate(classes)}))


# --- 1. важность признаков ----------------------------------------------------------------


def importance(models_dir: Path, task: str, top: int = 20) -> dict:
    booster = lgb.Booster(model_file=str(models_dir / task / "lgbm" / "model.txt"))
    gain = booster.feature_importance(importance_type="gain")
    share = gain / gain.sum()
    names = feature_names()
    order = np.argsort(-share)
    groups: dict[str, float] = {}
    for i, s in enumerate(share):
        groups[group_of(i)] = groups.get(group_of(i), 0.0) + float(s)
    ts = index_of(TIMESTAMP)
    return {
        "top": [{"feature": names[i], "group": group_of(i), "gain_share": float(share[i])} for i in order[:top]],
        "groups": dict(sorted(groups.items(), key=lambda kv: -kv[1])),
        "timestamp_rank": int(np.where(order == ts)[0][0]) + 1,
        "timestamp_gain_share": float(share[ts]),
    }


# --- 2. дата компиляции -------------------------------------------------------------------


def timestamp_years(X: np.ndarray, frame: pd.DataFrame) -> dict:
    """Медиана и доля «до 2015 года» по признаку времени компиляции, по классам и выборкам."""
    ts = X[frame["row"].to_numpy(), index_of(TIMESTAMP)].astype(np.int64)
    years = pd.to_datetime(ts.clip(0, 4_102_444_800), unit="s").year
    df = pd.DataFrame({"split": frame["split"].to_numpy(), "target": frame["target"].to_numpy(), "year": years})
    out = {}
    for (sp, tg), g in df.groupby(["split", "target"]):
        out[f"{sp}/{tg}"] = {"median_year": int(g["year"].median()), "share_before_2015": float((g["year"] < 2015).mean()),
                             "share_zero_or_1970": float((g["year"] <= 1970).mean()), "n": int(len(g))}
    return out


def timestamp_ablation(X, split, models_dir: Path, n_jobs: int) -> dict:
    man = json.loads((models_dir / "detection" / "lgbm" / "manifest.json").read_text(encoding="utf-8"))
    original = json.loads((models_dir / "detection" / "lgbm" / "evaluation.json").read_text(encoding="utf-8"))
    frame = labelled("detection", split, man["classes"])
    tr, te = frame[frame["split"] == "train"], frame[frame["split"] == "test"]
    ts = index_of(TIMESTAMP)
    Xtr, Xte = X[tr["row"].to_numpy()], X[te["row"].to_numpy()]
    Xtr[:, ts] = 0  # копии, исходный X не меняется
    Xte[:, ts] = 0
    params, rounds = lgbm_params(man, 2, n_jobs)
    start = time.time()
    proba = fit_predict(params, rounds, Xtr, tr["y"].to_numpy(), Xte, 2)
    without = score("detection", te["y"].to_numpy(), proba)
    return {
        "with_timestamp": {k: original[k] for k in without},
        "without_timestamp": without,
        "seconds": round(time.time() - start, 1),
        "years": timestamp_years(X, frame),
    }


# --- 3. случайное разбиение ---------------------------------------------------------------


def random_split(task: str, X, split, models_dir: Path, n_jobs: int, seed: int) -> dict:
    man = json.loads((models_dir / task / "lgbm" / "manifest.json").read_text(encoding="utf-8"))
    temporal = json.loads((models_dir / task / "lgbm" / "evaluation.json").read_text(encoding="utf-8"))
    frame = labelled(task, split, man["classes"])
    n_test = int((frame["split"] == "test").sum())
    n_train = int((frame["split"] == "train").sum())
    # Те же объёмы train и test, что во временном разбиении; validation тут не нужна:
    # число итераций берём из модели этапа 4
    rest, test = train_test_split(frame, test_size=n_test, stratify=frame["y"], random_state=seed)
    train, _ = train_test_split(rest, train_size=n_train, stratify=rest["y"], random_state=seed)
    n_classes = len(man["classes"])
    params, rounds = lgbm_params(man, n_classes, n_jobs)
    start = time.time()
    proba = fit_predict(params, rounds, X[train["row"].to_numpy()], train["y"].to_numpy(),
                        X[test["row"].to_numpy()], n_classes)
    rnd = score(task, test["y"].to_numpy(), proba)
    return {"temporal_test": {k: temporal[k] for k in rnd}, "random_test": rnd,
            "n_train": int(len(train)), "n_test": int(len(test)), "seconds": round(time.time() - start, 1)}


# --- отчёт --------------------------------------------------------------------------------


def report(res: dict) -> str:
    lines = ["# Дополнительные эксперименты (этап 5)", ""]
    lines += ["## Случайное разбиение против разбиения по времени (LightGBM)", "",
              "| Задача | Метрика | Тест по времени | Случайный тест | Завышение |", "| --- | --- | --- | --- | --- |"]
    for task, r in res["random_split"].items():
        for k in r["random_test"]:
            t, rn = r["temporal_test"][k], r["random_test"][k]
            lines.append(f"| {task} | {k} | {t:.4f} | {rn:.4f} | {rn - t:+.4f} |")
    a = res["timestamp"]
    lines += ["", "## Зависит ли обнаружение от даты компиляции", "",
              f"Признак {TIMESTAMP}: место по важности {res['importance']['detection']['timestamp_rank']} из 2381, "
              f"доля gain {res['importance']['detection']['timestamp_gain_share']:.4f}.", "",
              "| Метрика | С признаком | Без признака |", "| --- | --- | --- |"]
    for k in a["without_timestamp"]:
        lines.append(f"| {k} | {a['with_timestamp'][k]:.5f} | {a['without_timestamp'][k]:.5f} |")
    lines += ["", "Год компиляции по признаку timestamp (медиана, доля до 2015):", "",
              "| Выборка/класс | Медиана года | До 2015 | 0 или 1970 | n |", "| --- | --- | --- | --- | --- |"]
    for k, v in sorted(a["years"].items()):
        lines.append(f"| {k} | {v['median_year']} | {v['share_before_2015']:.3f} | {v['share_zero_or_1970']:.3f} | {v['n']} |")
    for task, imp in res["importance"].items():
        lines += ["", f"## Важность признаков LightGBM: {task}", "", "Доля gain по группам: " + ", ".join(
            f"{g} {s:.3f}" for g, s in imp["groups"].items()) + ".", "", "| # | Признак | Группа | Доля gain |", "| --- | --- | --- | --- |"]
        for i, t in enumerate(imp["top"][:10], 1):
            lines.append(f"| {i} | {t['feature']} | {t['group']} | {t['gain_share']:.4f} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--splits-dir", type=Path, default=SPLITS_DIR)
    ap.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    ap.add_argument("--reports-dir", type=Path, default=REPORTS_DIR)
    ap.add_argument("--features", type=Path, default=None)
    ap.add_argument("--n-jobs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    for task in TASKS:
        if not (args.models_dir / task / "lgbm" / "evaluation.json").exists():
            sys.exit(f"нет {task}/lgbm/evaluation.json: сначала запусти python -m mltrain.evaluate --all")

    print("Загрузка признаков...", flush=True)
    X = load_features(args.features) if args.features else load_features()
    res = {"importance": {}, "random_split": {}}
    for task in TASKS:
        res["importance"][task] = importance(args.models_dir, task)
    print("Проверка даты компиляции (LightGBM без признака timestamp)...", flush=True)
    res["timestamp"] = timestamp_ablation(X, read_split("detection", args.splits_dir)[0], args.models_dir, args.n_jobs)
    print(f"  {res['timestamp']['with_timestamp']} -> {res['timestamp']['without_timestamp']}")
    for task in TASKS:
        print(f"Случайное разбиение: {task}...", flush=True)
        res["random_split"][task] = random_split(task, X, read_split(task, args.splits_dir)[0], args.models_dir,
                                                 args.n_jobs, args.seed)
        r = res["random_split"][task]
        print(f"  по времени {r['temporal_test']} -> случайно {r['random_test']}")
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    (args.reports_dir / "experiments.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.reports_dir / "experiments.md").write_text(report(res), encoding="utf-8")
    print(f"Отчёт: {args.reports_dir / 'experiments.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
