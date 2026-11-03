"""Этап 2: наш экстрактор даёт те же векторы EMBER v2, что и оригинальный код ember.

Эталоны и происхождение файлов описаны в fixtures/README.md.
"""

from pathlib import Path

import numpy as np
import pytest

from malcore.features.vector import VECTOR_SIZE, extract_vector

FIX = Path(__file__).parent / "fixtures"

GROUPS = [
    ("ByteHistogram", 256), ("ByteEntropyHistogram", 256), ("StringExtractor", 104),
    ("GeneralFileInfo", 10), ("HeaderFileInfo", 62), ("SectionInfo", 255),
    ("ImportsInfo", 1280), ("ExportsInfo", 128), ("DataDirectories", 30),
]

CASES = [
    ("benign_lief0123.npz", "benign"),
    ("benign_lief0101.npz", "benign"),
    ("crafted_lief0123.npz", "crafted"),
]


def test_group_sizes_sum_to_vector_size():
    assert sum(dim for _, dim in GROUPS) == VECTOR_SIZE == 2381


@pytest.mark.parametrize("reference,folder", CASES)
def test_matches_original_ember(reference, folder):
    ref = np.load(FIX / "reference" / reference)
    ours = np.array([extract_vector((FIX / "pe" / folder / n).read_bytes()) for n in ref["names"]])
    mismatches = []
    start = 0
    for name, dim in GROUPS:
        diff = ~np.isclose(ours[:, start:start + dim], ref["X"][:, start:start + dim], rtol=1e-5, atol=1e-6)
        for i in np.where(diff.any(axis=1))[0]:
            mismatches.append(f"{ref['names'][i]}: {name}")
        start += dim
    assert not mismatches, f"расхождения с LIEF {ref['lief']}: {mismatches}"


def test_deterministic():
    data = (FIX / "pe" / "benign" / "pip_t64.exe").read_bytes()
    assert np.array_equal(extract_vector(data), extract_vector(data))


def test_not_pe_still_gives_vector():
    # Как в оригинале: если LIEF не разобрал файл, PE-группы нулевые, а байтовые считаются
    vec = extract_vector((FIX / "pe" / "crafted" / "not_pe.bin").read_bytes())
    assert vec.shape == (VECTOR_SIZE,)
    assert vec[:256].sum() == pytest.approx(1.0)
