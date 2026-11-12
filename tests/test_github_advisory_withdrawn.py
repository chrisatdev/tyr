"""Withdrawn GitHub advisories are not vulnerabilities.

Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plugins.github_advisory import GitHubAdvisoryPlugin  # noqa: E402


def _node(ghsa, withdrawn_at=None):
    return {
        "advisory": {
            "ghsaId": ghsa,
            "summary": ghsa,
            "description": ghsa,
            "severity": "HIGH",
            "publishedAt": "2026-01-01T00:00:00Z",
            "withdrawnAt": withdrawn_at,
            "references": [],
            "cvss": {"score": 7.5},
            "cwes": {"nodes": []},
        },
        "vulnerableVersionRange": ">= 0.17.0, < 0.28.1",
        "firstPatchedVersion": {"identifier": "0.28.1"},
    }


class WithdrawnAdvisoryTest(unittest.TestCase):
    def test_a_withdrawn_advisory_is_not_reported(self):
        # GHSA-gv7w-rqvm-qjhr (esbuild) was withdrawn; the API still returns it.
        payload = {"data": {"securityVulnerabilities": {"nodes": [
            _node("GHSA-gv7w-rqvm-qjhr", withdrawn_at="2026-06-01T00:00:00Z"),
            _node("GHSA-real-real-real"),
        ]}}}
        response = mock.Mock(status_code=200)
        response.json.return_value = payload
        response.raise_for_status.return_value = None
        plugin = GitHubAdvisoryPlugin()
        plugin.delay = 0
        with mock.patch("plugins.github_advisory.requests.post", return_value=response) as post:
            found = plugin.query_vulnerabilities("esbuild", "0.25.12", "npm")
        self.assertEqual([v["id"] for v in found], ["GHSA-real-real-real"])
        self.assertIn("withdrawnAt", post.call_args.kwargs["json"]["query"])


if __name__ == "__main__":
    unittest.main()
