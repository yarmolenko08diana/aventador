"""Этап 5: единственный прогон моделей на тестовой выборке.

Запуск из корня репозитория:
    python -m mltrain.evaluate --all

Что делает:
- считает вероятности RF, LightGBM, MLP и ансамбля на test (разбиение по времени);
- применяет пороги, выбранные на validation на этапе 4 (на тесте ничего не подбирается);
- пишет evaluation.json рядом с каждой моделью, artifacts/reports/evaluation.md и рисунки
  в artifacts/reports/figures/.

Тест используется один раз: после прогона в artifacts/models/<task>/test_evaluated.json
записывается отметка, и повторный запуск отказывается работать без флага --again
(повтор тоже фиксируется в отметке, чтобы это было видно в отчёте).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_curve

from malcore.inference.registry import load_predictor, read_manifest, sha256_file
from mltrain import metrics
from mltrain.data.load_bodmas import ROOT
from mltrain.datasets import SPLITS_DIR, TASKS, load_features, read_split
from mltrain.train import git_commit

MODELS_DIR = ROOT / "artifacts" / "models"
REPORTS_DIR = ROOT / "artifacts" / "reports"
MEMBERS = ["rf", "lgbm", "mlp", "ensemble"]
TITLES = {"rf": "Random Forest", "lgbm": "LightGBM", "mlp": "MLP", "ensemble": "Ансамбль"}


# --- данные теста -------------------------------------------------------------------------


def test_data(task: str, X: np.ndarray, split, classes: list[str]):
    test = split[split["split"] == "test"]
    unknown = None
    if task == "family":
        unknown = test[test["target"] == metrics.UNKNOWN]
        test = test[test["target"] != metrics.UNKNOWN]
    index = {c: i for i, c in enumerate(classes)}
    missing = set(test["target"]) - set(index)
    if missing:
        raise ValueError(f"в test есть классы, которых модель не знает: {sorted(missing)}")
    y = test["target"].map(index).to_numpy(np.int64)
    X_unknown = X[unknown["row"].to_numpy()] if unknown is not None else None
    return X[test["row"].to_numpy()], y, X_unknown


# --- метрики одной модели -----------------------------------------------------------------


def evaluate_detection(man: dict, proba: np.ndarray, y: np.ndarray) -> dict:
    score = proba[:, 1]
    thr = man["thresholds"]
    res = metrics.detection_metrics(y, score, thr)
    verdict = np.where(score >= thr["malicious"], 2, np.where(score >= thr["suspicious"], 1, 0))
    res["verdicts"] = {
        cls: {v: int(((verdict == i) & (y == k)).sum()) for i, v in enumerate(["clean", "suspicious", "malicious"])}
        for k, cls in enumerate(man["classes"])
    }
    # Матрица ошибок при пороге malicious: строки — истина (benign, malware), столбцы — прогноз
    res["confusion_matrix"] = confusion_matrix(y, (score >= thr["malicious"]).astype(int), labels=[0, 1]).tolist()
    res["ece"] = metrics.expected_calibration_error(((score >= 0.5) == y).astype(float), np.maximum(score, 1 - score))
    res["reliability"] = metrics.reliability(y.astype(float), score)
    fpr, tpr, _ = roc_curve(y, score)
    keep = np.unique(np.linspace(0, len(fpr) - 1, min(len(fpr), 400)).astype(int))
    res["roc_curve"] = {"fpr": fpr[keep].tolist(), "tpr": tpr[keep].tolist()}
    return res


def evaluate_multiclass(task: str, man: dict, proba: np.ndarray, y: np.ndarray, proba_unknown) -> dict:
    res = metrics.multiclass_metrics(y, proba)
    pred = proba.argmax(axis=1)
    labels = np.arange(len(man["classes"]))
    res["per_class"] = classification_report(
        y, pred, labels=labels, target_names=man["classes"], output_dict=True, zero_division=0
    )
    res["confusion_matrix"] = confusion_matrix(y, pred, labels=labels).tolist()
    conf = proba.max(axis=1)
    res["ece"] = metrics.expected_calibration_error((pred == y).astype(float), conf)
    res["reliability"] = metrics.reliability((pred == y).astype(float), conf)
    if task == "family" and proba_unknown is not None:
        res["open_set"] = metrics.open_set_metrics(y, proba, proba_unknown, man["thresholds"]["unknown_confidence"])
    return res


def main_metric(task: str, res: dict) -> float:
    return res["tpr_at_fpr_1pct"] if task == "detection" else res["macro_f1"]


def select_on_validation(task: str, manifests: dict[str, dict]) -> str:
    """Модель для итогового вердикта выбирается по validation, а не по тесту.

    Detection: TPR при FPR 1%, при равенстве — TPR при FPR 0,1% и ROC-AUC.
    Family и category: macro-F1.
    """
    def key(name):
        v = manifests[name]["validation"]
        if task == "detection":
            return (v["tpr_at_fpr_1pct"], v["tpr_at_fpr_0_1pct"], v["roc_auc"])
        return (v["macro_f1"],)

    return max(MEMBERS, key=key)


# --- рисунки ------------------------------------------------------------------------------


def plot_task(task: str, results: dict[str, dict], classes: list[str], selected: str, fig_dir: Path) -> list[str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    files = []
    fig_dir.mkdir(parents=True, exist_ok=True)

    if task == "detection":
        fig, ax = plt.subplots(figsize=(6, 4.5))
        for name in MEMBERS:
            c = results[name]["roc_curve"]
            ax.plot(np.maximum(c["fpr"], 1e-5), c["tpr"], label=f"{TITLES[name]} (AUC {results[name]['roc_auc']:.5f})")
        ax.set_xscale("log")
        ax.set_xlim(1e-4, 1)
        ax.axvline(0.01, color="grey", ls=":", lw=1)
        ax.set_xlabel("Доля ложных тревог (FPR, лог. шкала)")
        ax.set_ylabel("Доля обнаруженных (TPR)")
        ax.set_title("ROC на тестовой выборке (разбиение по времени)")
        ax.legend(loc="lower right", fontsize=8)
        fig.tight_layout()
        files.append(_save(fig, fig_dir / "detection_roc.png"))

    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], color="grey", ls=":", lw=1)
    for name in MEMBERS:
        pts = results[name]["reliability"]
        ax.plot([p["mean_confidence"] for p in pts], [p["observed"] for p in pts], marker="o", ms=3,
                label=f"{TITLES[name]} (ECE {results[name]['ece']:.3f})")
    ax.set_xlabel("Вероятность вредоносности" if task == "detection" else "Уверенность модели")
    ax.set_ylabel("Реальная доля вредоносных" if task == "detection" else "Доля верных ответов")
    ax.set_title(f"Диаграмма надёжности: {task}")
    ax.legend(fontsize=8)
    fig.tight_layout()
    files.append(_save(fig, fig_dir / f"{task}_reliability.png"))

    cm = np.asarray(results[selected]["confusion_matrix"], dtype=float)
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    size = max(4.5, 0.38 * len(classes) + 2)
    fig, ax = plt.subplots(figsize=(size, size))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=90, fontsize=7)
    ax.set_yticks(range(len(classes)), classes, fontsize=7)
    if len(classes) <= 10:
        for i in range(len(classes)):
            for j in range(len(classes)):
                ax.text(j, i, int(cm[i, j]), ha="center", va="center", fontsize=7,
                        color="white" if norm[i, j] > 0.5 else "black")
    ax.set_xlabel("Прогноз")
    ax.set_ylabel("Истина")
    ax.set_title(f"Матрица ошибок ({TITLES[selected]}, {task}), доли по строкам", fontsize=9)
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    files.append(_save(fig, fig_dir / f"{task}_confusion.png"))
    return files


def _save(fig, path: Path) -> str:
    import matplotlib.pyplot as plt

    fig.savefig(path, dpi=150)
    plt.close(fig)
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


# --- отчёт --------------------------------------------------------------------------------


def task_section(task: str, results: dict, manifests: dict, selected: str) -> list[str]:
    lines = [f"## {task}", ""]
    if task == "detection":
        lines += ["| Модель | ROC-AUC | TPR при FPR 1% | TPR при FPR 0,1% | FPR при пороге malicious | TPR при пороге malicious | ECE |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        for n in MEMBERS:
            r = results[n]
            lines.append(f"| {TITLES[n]}{' ✓' if n == selected else ''} | {r['roc_auc']:.5f} | {r['tpr_at_fpr_1pct']:.4f} | "
                         f"{r['tpr_at_fpr_0_1pct']:.4f} | {r['malicious_fpr']:.4f} | {r['malicious_tpr']:.4f} | {r['ece']:.4f} |")
        lines += ["", "Пороги выбраны на validation так, чтобы FPR был не больше 1% (malicious) и 5% (suspicious). "
                  "Столбец «FPR при пороге malicious» показывает, сколько ложных тревог этот порог даёт на новых, более поздних файлах."]
    else:
        head = "| Модель | macro-F1 | accuracy | ECE |"
        sep = "| --- | --- | --- | --- |"
        if task == "family":
            head += " Неизвестные отвергнуты | Известные отвергнуты зря | open-set macro-F1 |"
            sep += " --- | --- | --- |"
        lines += [head, sep]
        for n in MEMBERS:
            r = results[n]
            row = f"| {TITLES[n]}{' ✓' if n == selected else ''} | {r['macro_f1']:.4f} | {r['accuracy']:.4f} | {r['ece']:.4f} |"
            if task == "family":
                o = r["open_set"]
                row += f" {o['unknown_rejected']:.3f} | {o['known_rejected']:.3f} | {o['open_set_macro_f1']:.4f} |"
            lines.append(row)
        worst = sorted(
            ((c, v["f1-score"], v["support"]) for c, v in results[selected]["per_class"].items()
             if isinstance(v, dict) and c not in ("macro avg", "weighted avg")),
            key=lambda t: t[1],
        )[:5]
        lines += ["", f"Хуже всего ({TITLES[selected]}): " + ", ".join(f"{c} F1={f:.2f} (n={int(s)})" for c, f, s in worst) + "."]
    val_key = "tpr_at_fpr_1pct" if task == "detection" else "macro_f1"
    lines += ["", "Сравнение с validation (главная метрика): " + ", ".join(
        f"{TITLES[n]} {manifests[n]['validation'][val_key]:.4f} → {main_metric(task, results[n]):.4f}" for n in MEMBERS) + ".",
        f"✓ — модель итогового вердикта, выбрана по validation: {TITLES[selected]}.", ""]
    return lines


# --- запуск -------------------------------------------------------------------------------


def evaluate_task(task: str, X: np.ndarray, splits_dir: Path, models_dir: Path, again: bool, fig_dir: Path) -> list[str]:
    task_dir = models_dir / task
    marker = task_dir / "test_evaluated.json"
    previous = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else None
    if previous and not again:
        raise SystemExit(
            f"{task}: тест уже использован {previous['runs'][0]['at']}. Повторный прогон искажает оценку; "
            "если он действительно нужен (например, после исправления ошибки в коде), запусти с --again."
        )

    manifests = {n: read_manifest(task_dir / n) for n in MEMBERS}
    classes = manifests["rf"]["classes"]
    split, sha = read_split(task, splits_dir)
    for n, man in manifests.items():
        if man["data"]["split_file_sha256"] != sha or man["classes"] != classes:
            raise SystemExit(f"{task}/{n}: обучен на другом разбиении, переобучи модели этапа 4")

    X_test, y_test, X_unknown = test_data(task, X, split, classes)
    print(f"[{task}] test: {len(y_test)} образцов" + (f", неизвестных семейств {len(X_unknown)}" if X_unknown is not None else ""))

    results = {}
    for n in MEMBERS:
        predictor = load_predictor(task_dir / n)
        proba = predictor.predict_proba(X_test)
        if task == "detection":
            res = evaluate_detection(manifests[n], proba, y_test)
        else:
            unk = predictor.predict_proba(X_unknown) if X_unknown is not None else None
            res = evaluate_multiclass(task, manifests[n], proba, y_test, unk)
        res.update(task=task, algorithm=n, n_test=int(len(y_test)), split="temporal",
                   evaluated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   manifest_sha256=sha256_file(task_dir / n / "manifest.json"))
        (task_dir / n / "evaluation.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        results[n] = res
        print(f"  {TITLES[n]}: {main_metric(task, res):.4f}")

    selected = select_on_validation(task, manifests)
    (task_dir / "selection.json").write_text(json.dumps(
        {"task": task, "selected": selected, "rule": "лучшая главная метрика на validation"},
        ensure_ascii=False, indent=2), encoding="utf-8")

    runs = (previous or {"runs": []})["runs"] + [{"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                                   "git_commit": git_commit()}]
    marker.write_text(json.dumps({"task": task, "runs": runs}, ensure_ascii=False, indent=2), encoding="utf-8")

    figures = plot_task(task, results, classes, selected, fig_dir)
    lines = task_section(task, results, manifests, selected)
    if len(runs) > 1:
        lines.insert(2, f"**Внимание: тест для этой задачи прогонялся {len(runs)} раз(а).**\n")
    lines += [f"![{Path(f).stem}](figures/{Path(f).name})" for f in figures] + [""]
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task", choices=TASKS)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--again", action="store_true", help="разрешить повторный прогон на тесте (фиксируется)")
    ap.add_argument("--splits-dir", type=Path, default=SPLITS_DIR)
    ap.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    ap.add_argument("--reports-dir", type=Path, default=REPORTS_DIR)
    ap.add_argument("--features", type=Path, default=None)
    args = ap.parse_args(argv)
    if not args.all and not args.task:
        ap.error("укажи --task или --all")
    tasks = TASKS if args.all else (args.task,)

    print("Загрузка признаков...", flush=True)
    X = load_features(args.features) if args.features else load_features()
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Оценка на тестовой выборке (этап 5)", "",
             "Тест — самые поздние 20% образцов (разбиение по времени). Пороги и выбор модели сделаны на validation, "
             "на тесте ничего не подбиралось.", ""]
    for task in tasks:
        lines += evaluate_task(task, X, args.splits_dir, args.models_dir, args.again, args.reports_dir / "figures")
    name = "evaluation.md" if args.all else f"evaluation_{args.task}.md"
    (args.reports_dir / name).write_text("\n".join(lines), encoding="utf-8")
    print(f"Отчёт: {args.reports_dir / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
