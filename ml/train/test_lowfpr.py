"""Tests for ml/train/lowfpr.py. Run: python3 -m unittest ml.train.test_lowfpr"""

import unittest

import numpy as np

from ml.train.lowfpr import (
    cluster_bootstrap_detection,
    detection_at_fpr,
    resolvable,
    threshold_for_fpr,
    wilson_interval,
)


class WilsonInterval(unittest.TestCase):
    def test_zero_flags_still_has_an_upper_bound(self):
        lo, hi = wilson_interval(0, 1000)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 0.0038, places=3)  # about 3 in 1,000

    def test_widens_with_fewer_documents(self):
        small = wilson_interval(1, 100)
        large = wilson_interval(10, 1000)
        self.assertGreater(small[1] - small[0], large[1] - large[0])

    def test_empty_sample_is_everything(self):
        self.assertEqual(wilson_interval(0, 0), (0.0, 1.0))


class Thresholds(unittest.TestCase):
    def test_one_percent_of_a_thousand_lets_ten_documents_through(self):
        honest = np.arange(1000) / 1000.0  # 0.000 .. 0.999
        t = threshold_for_fpr(honest, 0.01)
        self.assertEqual(int((honest > t).sum()), 10)

    def test_zero_allowed_puts_threshold_on_the_highest_document(self):
        honest = np.array([0.1, 0.9, 0.5])
        self.assertEqual(threshold_for_fpr(honest, 0.0), 0.9)
        self.assertEqual(int((honest > 0.9).sum()), 0)

    def test_resolvable_needs_one_document_of_room(self):
        self.assertTrue(resolvable(1000, 0.001))
        self.assertFalse(resolvable(999, 0.001))
        self.assertFalse(resolvable(105, 0.001))
        self.assertTrue(resolvable(105, 0.01))


class Detection(unittest.TestCase):
    def test_counts_attacks_above_the_threshold(self):
        honest = np.linspace(0, 0.5, 1000)
        attacks = np.array([0.4, 0.6, 0.7, 0.9])
        r = detection_at_fpr(honest, attacks, 0.01)
        self.assertEqual(r["detected"], 3)
        self.assertTrue(r["resolvable"])

    def test_flags_unresolvable_rates(self):
        r = detection_at_fpr(np.linspace(0, 0.5, 100), np.array([0.9]), 0.001)
        self.assertFalse(r["resolvable"])


class ClusterBootstrap(unittest.TestCase):
    def test_interval_brackets_the_point_estimate_and_widens_with_few_repositories(self):
        rng = np.random.default_rng(1)
        honest = rng.random(600) * 0.4
        attacks = 0.3 + rng.random(100) * 0.7
        many = np.repeat(np.arange(60), 10)
        few = np.repeat(np.arange(3), 200)
        point = detection_at_fpr(honest, attacks, 0.01)["detection_rate"]
        lo_m, hi_m = cluster_bootstrap_detection(honest, many, attacks, 0.01, rounds=300)
        lo_f, hi_f = cluster_bootstrap_detection(honest, few, attacks, 0.01, rounds=300)
        self.assertLessEqual(lo_m, point)
        self.assertGreaterEqual(hi_m, point)
        self.assertGreater(hi_f - lo_f, hi_m - lo_m)


if __name__ == "__main__":
    unittest.main()
