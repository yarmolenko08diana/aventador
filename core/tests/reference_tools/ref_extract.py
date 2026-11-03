"""Эталонные векторы: оригинальный features.py из elastic/ember, без изменений.
Запуск: python ref_extract.py <папка_с_pe> <out.npz>
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from features import PEFeatureExtractor  # noqa: E402

src, out = sys.argv[1], sys.argv[2]
ext = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
names, vecs = [], []
for name in sorted(os.listdir(src)):
    with open(os.path.join(src, name), "rb") as fh:
        vecs.append(ext.feature_vector(fh.read()))
    names.append(name)
import lief  # noqa: E402

np.savez(out, names=np.array(names), X=np.array(vecs, dtype=np.float32), lief=lief.__version__)
print(out, len(names), lief.__version__)
