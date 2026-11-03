"""Этап 4: обучение моделей на векторах BODMAS.

Запуск из корня репозитория:
    python -m mltrain.train --task detection --model lgbm     # одна модель
    python -m mltrain.train --task family                     # три модели + ансамбль задачи
    python -m mltrain.train --all                             # все 9 моделей + 3 ансамбля
    python -m mltrain.train --task detection --model lgbm --verify   # проверка воспроизводимости

Результат: artifacts/models/<task>/<rf|lgbm|mlp|ensemble>/
    файл модели, manifest.json, train.log, val_proba.npy (вероятности на validation для ансамбля)

Тестовая выборка не загружается: её один раз использует этап 5.
"""

from __future__ import annotations

import argparse
import copy
import json
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

import numpy as np
import yaml

from malcore.features.vector import FEATURE_VERSION, VECTOR_SIZE
from malcore.inference.registry import load_predictor, sha256_file
from mltrain import metrics
from mltrain.data.load_bodmas import ROOT
from mltrain.datasets import SPLITS_DIR, TASKS, TaskData, build_task, load_features, read_split
from mltrain.models import lightgbm_model, mlp, random_forest

CONFIG = ROOT / "ml" / "configs" / "train.yaml"
MODELS_DIR = ROOT / "artifacts" / "models"
ALGORITHMS = {"rf": random_forest, "lgbm": lightgbm_model, "mlp": mlp}
VAL_PROBA = "val_proba.npy"


# --- конфигурация и окружение ------------------------------------------------------------


def algo_config(cfg: dict, task: str, algo: str) -> dict:
    out = copy.deepcopy(cfg[algo])
    for key, value in cfg.get("overrides", {}).get(task, {}).get(algo, {}).items():
        out[key] = {**out.get(key, {}), **value} if isinstance(value, dict) else value
    return out


def versions() -> dict:
    names = ["numpy", "scikit-learn", "lightgbm", "torch", "lief", "pefile", "malcore", "mltrain"]
    out = {"python": platform.python_version()}
    for n in names:
        try:
            out[n] = metadata.version(n)
        except metadata.PackageNotFoundError:
            out[n] = None
    return out


def git_commit() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


# --- метрики validation и пороги ----------------------------------------------------------


def selector(task: str):
    """Чем выбираем лучший вариант гиперпараметров на validation."""
    if task == "detection":
        # TPR при 1% ложных тревог различает модели лучше, чем ROC-AUC (у всех ~0.99)
        return lambda y, p: metrics.detection_metrics(y, p[:, 1])["tpr_at_fpr_1pct"]
    return lambda y, p: metrics.multiclass_metrics(y, p)["macro_f1"]


def validation_summary(task: str, data: TaskData, proba: np.ndarray, cfg: dict,
                       unknown_proba: np.ndarray | None) -> tuple[dict, dict]:
    """Метрики на validation и пороги, выбранные на validation."""
    conf, pred = proba.max(axis=1), proba.argmax(axis=1)
    ece = metrics.expected_calibration_error((pred == data.y_val).astype(float), conf)
    if task == "detection":
        score = proba[:, 1]
        thresholds = {
            name: metrics.threshold_at_fpr(data.y_val, score, fpr)
            for name, fpr in cfg["detection_verdict_fpr"].items()
        }
        val = metrics.detection_metrics(data.y_val, score, thresholds)
    else:
        thresholds = {}
        val = metrics.multiclass_metrics(data.y_val, proba)
        if task == "family" and unknown_proba is not None and len(unknown_proba):
            open_set = metrics.choose_unknown_threshold(data.y_val, proba, unknown_proba)
            thresholds["unknown_confidence"] = open_set["threshold"]
            val["open_set"] = open_set
    val["ece"] = ece
    return val, thresholds


# --- запись артефактов --------------------------------------------------------------------


class Logger:
    def __init__(self, path: Path):
        self.file = open(path, "w", encoding="utf-8")

    def __call__(self, msg: str) -> None:
        print(msg, flush=True)
        self.file.write(msg + "\n")
        self.file.flush()

    def close(self):
        self.file.close()


def write_manifest(out_dir: Path, manifest: dict, files: list[str]) -> None:
    manifest["files"] = {name: sha256_file(out_dir / name) for name in files}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def base_manifest(task: str, algo: str, data: TaskData, cfg: dict) -> dict:
    return {
        "task": task,
        "algorithm": algo,
        "feature_version": FEATURE_VERSION,
        "n_features": VECTOR_SIZE,
        "classes": data.classes,
        "seed": cfg["seed"],
        "data": {
            "dataset": "BODMAS",
            "split_file": f"data/splits/{task}.csv",
            "split_file_sha256": data.split_file_sha256,
            "split": "temporal",
            **data.counts,
        },
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": git_commit(),
        "versions": versions(),
        "evaluated_on_test": False,  # заполнит этап 5
    }


# --- обучение -----------------------------------------------------------------------------


def train_model(task: str, algo: str, data: TaskData, cfg: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    log = Logger(out_dir / "train.log")
    try:
        module = ALGORITHMS[algo]
        log(f"[{task}/{algo}] train {data.counts['train']}, val {data.counts['val']}, классов {len(data.classes)}")
        start = time.time()
        fitted = module.fit(data, algo_config(cfg, task, algo), cfg["seed"], cfg["n_jobs"], selector(task), log)
        seconds = round(time.time() - start, 1)

        files = module.save(fitted, out_dir)
        unknown_proba = None
        np.save(out_dir / VAL_PROBA, fitted.val_proba.astype(np.float32))

        manifest = base_manifest(task, algo, data, cfg)
        manifest.update(hyperparameters=fitted.hyperparameters, search=fitted.search, training_seconds=seconds)
        write_manifest(out_dir, manifest, files)

        # Проверка: модель, загруженная с диска через malcore (как в сервисе), даёт те же вероятности
        predictor = load_predictor(out_dir)
        reloaded = predictor.predict_proba(data.X_val)
        max_diff = float(np.abs(reloaded - fitted.val_proba).max())
        if max_diff > 1e-4:
            raise RuntimeError(f"после загрузки с диска вероятности отличаются на {max_diff}")
        if data.X_val_unknown is not None and len(data.X_val_unknown):
            unknown_proba = predictor.predict_proba(data.X_val_unknown)
            np.save(out_dir / "val_unknown_proba.npy", unknown_proba)

        val, thresholds = validation_summary(task, data, fitted.val_proba, cfg, unknown_proba)
        manifest.update(validation=val, thresholds=thresholds, reload_check={"max_abs_diff": max_diff, "passed": True})
        write_manifest(out_dir, manifest, files)
        log(f"[{task}/{algo}] validation: {json.dumps(val, ensure_ascii=False)}")
        log(f"[{task}/{algo}] пороги: {thresholds}; время {seconds} с; сохранено в {out_dir}")
        return manifest
    finally:
        log.close()


def build_ensemble(task: str, data: TaskData, cfg: dict, task_dir: Path, members: list[str]) -> dict:
    """Ансамбль = среднее вероятностей участников; пороги тоже выбираются на validation."""
    out_dir = task_dir / "ensemble"
    out_dir.mkdir(parents=True, exist_ok=True)
    probas, unknowns = [], []
    for m in members:
        man = json.loads((task_dir / m / "manifest.json").read_text(encoding="utf-8"))
        if man["classes"] != data.classes or man["data"]["split_file_sha256"] != data.split_file_sha256:
            raise RuntimeError(f"{m}: обучен на другом разбиении или с другими классами, переобучите его")
        probas.append(np.load(task_dir / m / VAL_PROBA))
        if (task_dir / m / "val_unknown_proba.npy").exists():
            unknowns.append(np.load(task_dir / m / "val_unknown_proba.npy"))
    proba = np.mean(probas, axis=0)
    unknown = np.mean(unknowns, axis=0) if len(unknowns) == len(members) and unknowns else None
    val, thresholds = validation_summary(task, data, proba, cfg, unknown)
    manifest = base_manifest(task, "ensemble", data, cfg)
    manifest.update(members=members, validation=val, thresholds=thresholds, hyperparameters={"combine": "mean_proba"})
    np.save(out_dir / VAL_PROBA, proba.astype(np.float32))
    write_manifest(out_dir, manifest, [])
    print(f"[{task}/ensemble] validation: {json.dumps(val, ensure_ascii=False)}")
    return manifest


def compare_validation(a: dict, b: dict, tol: float = 1e-9) -> list[str]:
    """Различия метрик validation двух запусков (пустой список = совпадают)."""
    diffs = []
    for key, va in a.items():
        vb = b.get(key)
        if isinstance(va, dict):
            diffs += [f"{key}.{d}" for d in compare_validation(va, vb or {}, tol)]
        elif isinstance(va, float) and isinstance(vb, float):
            if abs(va - vb) > tol:
                diffs.append(f"{key}: {va} != {vb}")
        elif va != vb:
            diffs.append(f"{key}: {va} != {vb}")
    return diffs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task", choices=TASKS)
    ap.add_argument("--model", choices=sorted(ALGORITHMS))
    ap.add_argument("--all", action="store_true", help="все задачи и все модели")
    ap.add_argument("--verify", action="store_true", help="обучить заново во временную папку и сравнить метрики")
    ap.add_argument("--config", type=Path, default=CONFIG)
    ap.add_argument("--splits-dir", type=Path, default=SPLITS_DIR)
    ap.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    ap.add_argument("--features", type=Path, default=None, help="npz с массивом X (по умолчанию bodmas.npz)")
    args = ap.parse_args(argv)
    if not args.all and not args.task:
        ap.error("укажи --task или --all")

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    tasks = TASKS if args.all else (args.task,)
    algos = [args.model] if args.model else list(ALGORITHMS)

    print("Загрузка признаков...", flush=True)
    X = load_features(args.features) if args.features else load_features()
    for task in tasks:
        split, sha = read_split(task, args.splits_dir)
        data = build_task(task, X, split, sha)
        task_dir = args.models_dir / task
        for algo in algos:
            if args.verify:
                saved = json.loads((task_dir / algo / "manifest.json").read_text(encoding="utf-8"))
                tmp = task_dir / f"_verify_{algo}"
                try:
                    again = train_model(task, algo, data, cfg, tmp)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
                diffs = compare_validation(saved["validation"], again["validation"])
                if diffs:
                    print(f"[{task}/{algo}] ВОСПРОИЗВОДИМОСТЬ НЕ ПОДТВЕРЖДЕНА:\n  " + "\n  ".join(diffs))
                    return 1
                print(f"[{task}/{algo}] повторный запуск дал те же метрики validation")
                continue
            train_model(task, algo, data, cfg, task_dir / algo)
        if not args.verify and all((task_dir / a / "manifest.json").exists() for a in ALGORITHMS):
            build_ensemble(task, data, cfg, task_dir, list(ALGORITHMS))
        del data
    return 0


if __name__ == "__main__":
    sys.exit(main())
