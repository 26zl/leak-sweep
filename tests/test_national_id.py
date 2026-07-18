import os
import unittest
from unittest import mock

import national_id


class ValidateTests(unittest.TestCase):
    def test_validate_accepts_valid_national_id(self):
        self.assertTrue(national_id.validate("15108695088", "NO"))
        self.assertTrue(national_id.validate("8803200016", "SE"))

    def test_validate_rejects_noise_and_unknown_region(self):
        self.assertFalse(national_id.validate("12345678901", "NO"))
        self.assertFalse(national_id.validate("15108695088", "ZZ"))

    def test_classify_returns_first_matching_country_and_type(self):
        self.assertEqual(national_id.classify("15108695088", ["NO", "SE"]), ("NO", "fødselsnummer"))
        self.assertIsNone(national_id.classify("12345678901", ["NO", "SE"]))

    def test_available_is_true_when_stdnum_present(self):
        self.assertTrue(national_id.available())


class ResolveRegionsTests(unittest.TestCase):
    def test_auto_uses_locale_country(self):
        with mock.patch.dict(os.environ, {"LC_ALL": "", "LC_CTYPE": "", "LANG": "nb_NO.UTF-8"}, clear=True):
            self.assertEqual(national_id.resolve_id_regions("auto", "GB"), (["NO"], []))

    def test_auto_falls_back_to_phone_region_when_locale_unknown(self):
        with mock.patch.dict(os.environ, {"LC_ALL": "", "LC_CTYPE": "", "LANG": "C"}, clear=True):
            self.assertEqual(national_id.resolve_id_regions("auto", "SE"), (["SE"], []))

    def test_none_and_all(self):
        self.assertEqual(national_id.resolve_id_regions("none", "NO"), ([], []))
        regions, unknown = national_id.resolve_id_regions("all", "NO")
        self.assertIn("NO", regions)
        self.assertEqual(unknown, [])

    def test_csv_reports_unknown_codes(self):
        regions, unknown = national_id.resolve_id_regions("SE, dk, ZZ", "NO")
        self.assertEqual(regions, ["SE", "DK"])
        self.assertEqual(unknown, ["ZZ"])

    def test_duplicate_codes_are_deduped(self):
        self.assertEqual(national_id.resolve_id_regions("NO,no,SE", "NO")[0], ["NO", "SE"])


class ScanTextTests(unittest.TestCase):
    def test_finds_validated_id_with_country_and_type(self):
        hits = list(national_id.scan_text("id: 15108695088 end", ["NO"]))
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0].value, hits[0].country, hits[0].type),
                         ("15108695088", "NO", "fødselsnummer"))

    def test_matches_separated_and_alphanumeric_forms(self):
        self.assertTrue(list(national_id.scan_text("x 151086 95088 y", ["NO"])))
        self.assertTrue(list(national_id.scan_text("hetu 131052A308T", ["FI"])))

    def test_rejects_noise_and_respects_empty_regions(self):
        self.assertEqual(list(national_id.scan_text("num 12345678901", ["NO"])), [])
        self.assertEqual(list(national_id.scan_text("15108695088", [])), [])

    def test_covers_wide_valid_forms(self):
        self.assertTrue(list(national_id.scan_text("p 198803200016", ["SE"])))  # 12-digit SE
        self.assertTrue(list(national_id.scan_text("h 131052Y308T", ["FI"])))   # FI letter marker


class GitleaksRulesTests(unittest.TestCase):
    def test_emits_one_rule_per_region_no_lookbehind(self):
        rules = national_id.gitleaks_rules(["NO", "US"])
        ids = [rid for rid, _ in rules]
        self.assertEqual(ids, ["national-id-NO", "national-id-US"])
        for _, regex in rules:
            self.assertNotIn("(?<", regex)  # RE2 has no look-behind

    def test_empty_for_no_regions(self):
        self.assertEqual(national_id.gitleaks_rules([]), [])


if __name__ == "__main__":
    unittest.main()
