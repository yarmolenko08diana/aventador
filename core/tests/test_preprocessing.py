import numpy as np

from malcore.preprocessing import CLIP, Standardizer


def test_fit_uses_log_for_nonnegative_and_standardizes(tmp_path):
    rng = np.random.default_rng(0)
    X = np.column_stack([rng.exponential(1000, 500), rng.normal(0, 5, 500), np.full(500, 3.0)]).astype(np.float32)
    s = Standardizer.fit(X, chunk=128)
    assert s.log_mask.tolist() == [True, False, True]
    Z = s.transform(X)
    assert np.allclose(Z[:, :2].mean(axis=0), 0, atol=1e-3)
    assert np.allclose(Z[:, :2].std(axis=0), 1, atol=1e-3)
    assert np.all(Z[:, 2] == 0)  # постоянный признак

    s.save(tmp_path / "s.npz")
    s2 = Standardizer.load(tmp_path / "s.npz")
    assert np.array_equal(s2.transform(X), Z)


def test_outliers_are_clipped():
    X = np.array([[0.0], [1.0], [2.0]], dtype=np.float32)
    s = Standardizer.fit(X)
    assert s.transform(np.array([[1e12]], dtype=np.float32))[0, 0] == CLIP
    assert s.transform(np.array([[-5.0]], dtype=np.float32))[0, 0] <= 0  # отрицательное в log-столбце -> как 0
