import sys

import numpy as np

GROUPS = [("ByteHistogram", 256), ("ByteEntropyHistogram", 256), ("StringExtractor", 104),
          ("GeneralFileInfo", 10), ("HeaderFileInfo", 62), ("SectionInfo", 255),
          ("ImportsInfo", 1280), ("ExportsInfo", 128), ("DataDirectories", 30)]

a, b = np.load(sys.argv[1]), np.load(sys.argv[2])
assert list(a["names"]) == list(b["names"])
print(f"{a['lief']} vs {b['lief']}, файлов: {len(a['names'])}")
start = 0
for name, dim in GROUPS:
    xa, xb = a["X"][:, start:start + dim], b["X"][:, start:start + dim]
    diff = ~np.isclose(xa, xb, rtol=1e-5, atol=1e-6)
    files = int(diff.any(axis=1).sum())
    cols = np.where(diff.any(axis=0))[0]
    print(f"  {name:22s} различий: файлов {files:2d}, позиций {len(cols):3d} {list(cols[:8] + start) if len(cols) else ''}")
    start += dim
