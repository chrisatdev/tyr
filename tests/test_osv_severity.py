"""Severity in the OSV plugin, from the data OSV actually returns.

Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plugins.osv import OSVPlugin, cvss3_base_score  # noqa: E402


class Cvss3BaseScoreTest(unittest.TestCase):
    # Expected scores are NVD's published base scores for these vectors
    # (e.g. 3.4 is CVE-2014-3566's).
    def test_known_vectors(self):
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N": 8.6,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N": 5.4,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N": 3.4,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            self.assertEqual(cvss3_base_score(vector), expected, vector)

    def test_temporal_metrics_after_the_base_ones_are_ignored(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O"), 9.8)

    def test_anything_else_is_not_a_cvss3_score(self):
        for value in ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                      "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      "", None, 7.5]:
            self.assertIsNone(cvss3_base_score(value), value)


def _osv_response(vulns):
    response = mock.Mock(status_code=200)
    response.json.return_value = {"vulns": vulns}
    response.raise_for_status.return_value = None
    return response


def _query(vulns):
    plugin = OSVPlugin()
    plugin.delay = 0
    with mock.patch("plugins.osv.requests.post", return_value=_osv_response(vulns)):
        return plugin.query_vulnerabilities("jinja2", "2.10", "pypi")


class OsvSeverityTest(unittest.TestCase):
    def test_a_cvss_vector_is_scored_instead_of_dropping_the_package(self):
        # Shape of the PYSEC entries OSV returns for jinja2 2.10: a CVSS vector string,
        # no database_specific.severity. It used to raise TypeError and lose all 12.
        found = _query([
            {"id": "PYSEC-2019-217", "summary": "sandbox escape",
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
            {"id": "GHSA-462w-v97r-4m45", "database_specific": {"severity": "HIGH"}},
        ])
        self.assertEqual([v["id"] for v in found], ["PYSEC-2019-217", "GHSA-462w-v97r-4m45"])
        self.assertEqual((found[0]["cvss_score"], found[0]["severity"]), (9.8, "CRITICAL"))
        self.assertEqual(found[1]["severity"], "HIGH")

    def test_an_unreadable_severity_still_reports_the_advisory(self):
        found = _query([
            {"id": "OSV-1", "summary": "remote code execution",
             "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]},
            {"id": "OSV-2", "database_specific": {"cvss": {"score": "?"}}},
            {"id": "OSV-3", "database_specific": {"cvss": "7.5"}},
        ])
        self.assertEqual([v["id"] for v in found], ["OSV-1", "OSV-2", "OSV-3"])
        self.assertEqual(found[0]["severity"], "CRITICAL")  # from the text, as before
        self.assertEqual(found[2]["cvss_score"], 7.5)
        for v in found:
            self.assertIsInstance(v["cvss_score"], float)


if __name__ == "__main__":
    unittest.main()
