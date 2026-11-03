"""Оценка ложных срабатываний правил на заведомо безопасных файлах.

Файлы только читаются и разбираются статически, ничего не запускается.

    python -m malcore.indicators.fp_report /mnt/c/Windows/System32 --limit 1000

Печатает для каждого правила долю безопасных PE, на которых оно сработало.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from malcore.features.static_info import analyze
from malcore.indicators.engine import catalog, evaluate

EXTENSIONS = {".exe", ".dll", ".sys", ".pyd", ".ocx", ".cpl", ".scr"}
MAX_BYTES = 50 * 1024 * 1024


def collect(root: Path, limit: int, seed: int) -> list[Path]:
    files = []
    for p in root.rglob("*"):
        try:
            if p.suffix.lower() in EXTENSIONS and p.is_file() and 0 < p.stat().st_size <= MAX_BYTES:
                files.append(p)
        except OSError:
            continue
    files.sort()
    random.Random(seed).shuffle(files)
    return files[:limit] if limit else files


def evidence_items(evidence: dict) -> list[str]:
    """Что именно нашло правило: функции, секции, домены URL, причины."""
    items = []
    for key, value in evidence.items():
        if isinstance(value, list):
            for v in value:
                if isinstance(v, dict):
                    items.append(str(v.get("section", v)))
                elif key == "urls":
                    try:
                        items.append("url:" + (urlparse(v).hostname or v))
                    except ValueError:
                        items.append("url:" + v)
                else:
                    items.append(f"{key[:-1] if key.endswith('s') else key}:{v}")
        elif key == "reason":
            items.append(str(value))
    return items


def run(paths: list[Path]) -> tuple[int, int, Counter, list[str], dict[str, Counter]]:
    parsed, failed, counts, errors = 0, 0, Counter(), []
    details: dict[str, Counter] = {}
    for i, path in enumerate(paths, 1):
        try:
            info = analyze(path.read_bytes())
        except OSError:
            failed += 1
            continue
        if "parse_error" in info:
            failed += 1
            continue
        parsed += 1
        try:
            for hit in evaluate(info):
                counts[hit["code"]] += 1
                details.setdefault(hit["code"], Counter()).update(set(evidence_items(hit["evidence"])))
        except Exception as exc:  # ошибка в правиле: не прячем, а печатаем файл и продолжаем
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
        if i % 200 == 0:
            print(f"  обработано {i}/{len(paths)}", file=sys.stderr)
    return parsed, failed, counts, errors, details


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path, help="папка с безопасными PE (например, /mnt/c/Windows/System32)")
    ap.add_argument("--limit", type=int, default=1000, help="сколько файлов взять (0 = все)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--top", type=int, default=0, help="показать N самых частых находок для правил с долей >= 1%%")
    args = ap.parse_args(argv)

    paths = collect(args.root, args.limit, args.seed)
    print(f"Найдено файлов: {len(paths)}", file=sys.stderr)
    parsed, failed, counts, errors, details = run(paths)
    if not parsed:
        sys.exit("Ни один файл не разобран как PE")

    print(f"\nРазобрано PE: {parsed}, не разобрано: {failed}\n")
    print(f"{'правило':<20} {'важность':<8} {'файлов':>7} {'доля':>7}")
    for rule in catalog():
        n = counts.get(rule["code"], 0)
        print(f"{rule['code']:<20} {rule['severity']:<8} {n:>7} {n / parsed:>7.1%}")
    if args.top:
        for code, found in details.items():
            if counts[code] / parsed < 0.01 or not found:
                continue
            print(f"\n{code}: самые частые находки (в скольких файлах)")
            for item, n in found.most_common(args.top):
                print(f"  {n:>5}  {item}")
    if errors:
        print(f"\nОшибки правил ({len(errors)}), это баги, пришли их разработчику:")
        print("\n".join(errors[:20]))


if __name__ == "__main__":
    main()
