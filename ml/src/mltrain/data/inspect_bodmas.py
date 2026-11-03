"""Этап 1, шаг 1: проверка структуры исходных файлов BODMAS.

Ничего не обучает и не изменяет. Печатает, что реально лежит в файлах:
ключи и размеры массивов в bodmas.npz, колонки и первые строки CSV,
совпадение числа строк. По этому выводу пишется загрузчик (шаг 2),
чтобы не опираться на догадки о формате.

Запуск из корня репозитория:
    python -m mltrain.data.inspect_bodmas
Отчёт также сохраняется в data/processed/inspect_report.txt
"""

from __future__ import annotations

import sys
import warnings
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[4]
RAW = ROOT / "data" / "raw" / "bodmas"
REPORT = ROOT / "data" / "processed" / "inspect_report.txt"

FILES = {
    "npz": RAW / "bodmas.npz",
    "metadata": RAW / "bodmas_metadata.csv",
    "category": RAW / "bodmas_malware_category.csv",
}


def describe_npz(path: Path, out: list[str]) -> dict[str, tuple]:
    """Читает только заголовки массивов внутри .npz, не загружая данные в память."""
    shapes: dict[str, tuple] = {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            with zf.open(name) as fh:
                version = np.lib.format.read_magic(fh)
                if version == (1, 0):
                    shape, fortran, dtype = np.lib.format.read_array_header_1_0(fh)
                else:
                    shape, fortran, dtype = np.lib.format.read_array_header_2_0(fh)
            key = name.removesuffix(".npy")
            shapes[key] = shape
            out.append(f"  {key}: shape={shape}, dtype={dtype}")
    # Метки небольшие — их можно загрузить целиком, чтобы увидеть значения
    with np.load(path, allow_pickle=False) as data:
        for key, shape in shapes.items():
            if len(shape) == 1:
                values, counts = np.unique(data[key], return_counts=True)
                if len(values) <= 20:
                    pairs = ", ".join(f"{v}: {c}" for v, c in zip(values, counts))
                    out.append(f"  {key}: значения -> {pairs}")
    return shapes


def describe_csv(path: Path, out: list[str]) -> pd.DataFrame:
    df = pd.read_csv(path)
    out.append(f"  строк: {len(df)}, колонок: {df.shape[1]}")
    out.append(f"  колонки: {list(df.columns)}")
    out.append("  первые 3 строки:")
    out.extend("    " + line for line in df.head(3).to_string().splitlines())
    out.append("  уникальных значений и пропусков по колонкам:")
    for col in df.columns:
        out.append(f"    {col}: unique={df[col].nunique()}, null={int(df[col].isna().sum())}")
    return df


def main() -> int:
    warnings.filterwarnings("ignore", message="Could not infer format")
    out: list[str] = []
    missing = [str(p) for p in FILES.values() if not p.exists()]
    if missing:
        print("Не найдены файлы:\n  " + "\n  ".join(missing))
        print(f"Положите их в {RAW}")
        return 1

    for key, path in FILES.items():
        out.append(f"== {path.name} ({path.stat().st_size / 2**20:.1f} МБ)")
        if key == "npz":
            shapes = describe_npz(path, out)
        else:
            df = describe_csv(path, out)
            if key == "metadata":
                meta = df
            else:
                cat = df

    out.append("== Согласованность")
    n_rows = {k: v[0] for k, v in shapes.items()}
    out.append(f"  строк в массивах npz: {n_rows}")
    out.append(f"  строк в metadata: {len(meta)}, в category: {len(cat)}")

    # Временные метки и семейства — ищем колонки по содержимому, а не по догадке об имени
    for col in meta.columns:
        if not pd.api.types.is_numeric_dtype(meta[col]):
            parsed = pd.to_datetime(meta[col], errors="coerce", utc=True)
            if parsed.notna().mean() > 0.9:
                out.append(f"  колонка времени: {col}, от {parsed.min()} до {parsed.max()}")
    for col in meta.columns:
        if not pd.api.types.is_numeric_dtype(meta[col]) and 10 < meta[col].nunique() < min(5000, len(meta) // 2):
            top = meta[col].value_counts().head(15)
            out.append(f"  топ-15 значений колонки {col}:")
            out.extend(f"    {idx}: {cnt}" for idx, cnt in top.items())

    text = "\n".join(out)
    print(text)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(text + "\n", encoding="utf-8")
    print(f"\nОтчёт сохранён: {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
