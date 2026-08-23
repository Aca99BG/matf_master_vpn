import unittest

from matf_vpn.final_analysis import holm_adjust, round_aggregates


class HolmCorrectionTest(unittest.TestCase):
    def test_adjustment_is_monotonic_in_sorted_order(self) -> None:
        raw = [0.01, 0.04, 0.03, 0.20]

        adjusted = holm_adjust(raw)

        self.assertEqual(adjusted, [0.04, 0.09, 0.09, 0.20])
        sorted_pairs = sorted(zip(raw, adjusted))
        self.assertEqual(
            [value for _, value in sorted_pairs],
            sorted([value for _, value in sorted_pairs]),
        )

    def test_round_aggregates_use_five_run_medians(self) -> None:
        values = list(range(30))

        self.assertEqual(round_aggregates(values), [2, 7, 12, 17, 22, 27])


if __name__ == "__main__":
    unittest.main()