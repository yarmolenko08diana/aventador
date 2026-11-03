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


def run(paths: list[Path]) -> tuple[int, int, Counter]:
    parsed, failed, counts = 0, 0, Counter()
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
        counts.update({h["code"] for h in evaluate(info)})
        if i % 200 == 0:
            print(f"  обработано {i}/{len(paths)}", file=sys.stderr)
    return parsed, failed, counts


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path, help="папка с безопасными PE (например, /mnt/c/Windows/System32)")
    ap.add_argument("--limit", type=int, default=1000, help="сколько файлов взять (0 = все)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    paths = collect(args.root, args.limit, args.seed)
    print(f"Найдено файлов: {len(paths)}", file=sys.stderr)
    parsed, failed, counts = run(paths)
    if not parsed:
        sys.exit("Ни один файл не разобран как PE")

    print(f"\nРазобрано PE: {parsed}, не разобрано: {failed}\n")
    print(f"{'правило':<20} {'важность':<8} {'файлов':>7} {'доля':>7}")
    for rule in catalog():
        n = counts.get(rule["code"], 0)
        print(f"{rule['code']:<20} {rule['severity']:<8} {n:>7} {n / parsed:>7.1%}")


if __name__ == "__main__":
    main()
