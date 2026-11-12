"""Version filtering in the GitHub Advisory plugin.

The ranges below are real ones returned by the GitHub Advisory API.
Run with: python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plugins.github_advisory import GitHubAdvisoryPlugin  # noqa: E402


class VersionAffectedTest(unittest.TestCase):
    def setUp(self):
        self.affected = GitHubAdvisoryPlugin()._version_affected

    def test_version_inside_a_bounded_range_is_affected(self):
        self.assertTrue(self.affected("7.3.6", ">= 7.0.0, <= 7.3.6"))
        self.assertTrue(self.affected("1.55.0", "< 1.55.1"))

    def test_version_outside_the_range_is_not_affected(self):
        # vite 7.3.8 against GHSA-587h-7wmj-h5pm's 7.x range (fixed in 7.3.7)
        self.assertFalse(self.affected("7.3.8", ">= 7.0.0, <= 7.3.6"))
        # playwright 1.65.0 against GHSA-7mvr-c777-76hp
        self.assertFalse(self.affected("1.65.0", "< 1.55.1"))
        # vitest 4.1.12 against GHSA-9crc-q9x8-hgqq's 3.x range
        self.assertFalse(self.affected("4.1.12", ">= 3.0.0, < 3.0.5"))

    def test_exact_match_ranges(self):
        self.assertTrue(self.affected("6.4.4", "= 6.4.4"))
        self.assertFalse(self.affected("7.3.8", "= 6.4.4"))

    def test_bounds_are_inclusive_or_exclusive_as_written(self):
        self.assertFalse(self.affected("4.1.12", ">= 4.1.11, < 4.1.12"))
        self.assertTrue(self.affected("4.1.11", ">= 4.1.11, < 4.1.12"))
        self.assertTrue(self.affected("0.0.125", "<= 0.0.125"))
        self.assertFalse(self.affected("0.0.126", "<= 0.0.125"))
        self.assertTrue(self.affected("2.0.1", "> 2.0.0"))

    def test_prereleases_sort_before_their_release(self):
        npm = {"ecosystem": "NPM"}
        self.assertTrue(self.affected("5.0.0-beta.1", ">= 5.0.0-beta.1, < 5.0.3", **npm))
        self.assertTrue(self.affected("5.0.0-rc.1", ">= 5.0.0-beta.1, < 5.0.0-rc.2", **npm))
        self.assertFalse(self.affected("5.0.0", ">= 5.0.0-beta.1, < 5.0.0-rc.2", **npm))
        self.assertFalse(self.affected("2.1.0-beta.6", ">= 2.1.0-beta.7, < 4.1.12", **npm))

    def test_versions_with_fewer_parts_compare_as_zero_padded_in_bounds(self):
        self.assertTrue(self.affected("2.0.0", ">= 2.0.0, < 2.1"))
        self.assertFalse(self.affected("2.1.0", ">= 2.0.0, < 2.1"))

    def test_a_spec_with_fewer_than_three_parts_is_a_range_not_a_version(self):
        # npm reads "4.17" as 4.17.x, which includes 4.17.5.
        self.assertTrue(self.affected("4.17", ">= 4.17.1, < 4.17.9"))
        self.assertTrue(self.affected("18", ">= 18.2.0, < 18.3.1"))
        self.assertTrue(self.affected("1.2", ">= 1.2.3, < 1.2.9"))
        self.assertTrue(self.affected("2", ">= 2.0.0, < 2.1"))

    def test_a_short_version_marked_exact_is_compared_as_written(self):
        self.assertFalse(self.affected("4.17", ">= 4.17.1, < 4.17.9", exact=True))
        self.assertTrue(self.affected("4.17", ">= 4.17.0, < 4.17.9", exact=True))
        self.assertFalse(self.affected("2.1", ">= 2.0.0, < 2.1.0", exact=True))

    def test_non_semver_qualifiers_keep_the_advisory(self):
        # Maven "-RELEASE"/"-SP1", PyPI post-release "-1": not semver prereleases,
        # so they must not be sorted below their release.
        self.assertTrue(self.affected("1.0.0-RELEASE", ">= 1.0.0, < 1.0.5"))
        self.assertTrue(self.affected("1.0.0-SP1", ">= 1.0.0, < 1.0.5"))
        self.assertTrue(self.affected("1.0-1", ">= 1.0.0, < 1.0.5"))
        self.assertTrue(self.affected("1.0.0", ">= 1.0.0-RELEASE, < 1.0.5"))

    def test_semver_prerelease_qualifiers_are_still_ordered(self):
        for ecosystem in ["NPM", "RUST", "GO", "NUGET"]:
            for tag in ["alpha", "alpha.1", "beta.2", "rc.1", "pre.3", "dev.4", "rc1", "0", "1.2"]:
                self.assertFalse(
                    self.affected(f"1.0.0-{tag}", ">= 1.0.0, < 1.0.5", ecosystem=ecosystem),
                    f"{ecosystem} {tag}",
                )

    def test_suffixes_outside_semver_ecosystems_keep_the_advisory(self):
        # PyPI "2.0.0-1" is the post-release 2.0.0.post1, which sorts AFTER 2.0.0 and
        # is inside this range; semver would sort it before 2.0.0 and drop it.
        self.assertTrue(self.affected("2.0.0-1", ">= 2.0.0, < 2.0.1", ecosystem="PIP"))
        for ecosystem in ["PIP", "MAVEN", "RUBYGEMS", "COMPOSER", None]:
            self.assertTrue(
                self.affected("1.0.0-beta.1", ">= 1.0.0, < 1.0.5", ecosystem=ecosystem), ecosystem
            )
            self.assertTrue(
                self.affected("1.0.0", ">= 1.0.0-rc.1, < 1.0.5", ecosystem=ecosystem), ecosystem
            )
        # Plain releases still compare in every ecosystem.
        self.assertFalse(self.affected("2.0.2", ">= 2.0.0, < 2.0.1", ecosystem="PIP"))

    def test_leading_v_is_ignored(self):
        self.assertFalse(self.affected("v7.3.8", ">= 7.0.0, <= 7.3.6"))

    def test_a_range_specifier_keeps_the_advisory(self):
        # "^1.2.0" may resolve to 1.4.0, which this range includes: never filter on a
        # range's lower bound, only on an exact version.
        for spec in ["^1.2.0", "~1.2.0", ">=1.0.0 <2.0.0", "1.x", "*", "1.2.0 || 2.0.0"]:
            self.assertTrue(self.affected(spec, ">= 1.3.0, < 1.5.0"), spec)

    def test_the_plugin_asks_for_the_raw_specifier(self):
        self.assertTrue(GitHubAdvisoryPlugin().accepts_raw_version)

    def test_unknown_input_keeps_the_advisory(self):
        # Better a false positive than a hidden vulnerability.
        self.assertTrue(self.affected("", ">= 1.0.0, < 2.0.0"))
        self.assertTrue(self.affected(None, "< 2.0.0"))
        self.assertTrue(self.affected("1.2.3", ""))
        self.assertTrue(self.affected("latest", "< 2.0.0"))
        self.assertTrue(self.affected("1.2.3", "~> 1.2"))
        self.assertTrue(self.affected("1.2.3", ">= banana"))


class ScanPassesVersionsTest(unittest.TestCase):
    """What TyrScanner hands each plugin: the raw specifier only to plugins that ask."""

    class FakePlugin:
        def __init__(self, name, raw):
            self.name, self.accepts_raw_version, self.seen = name, raw, []

        def query_vulnerabilities(self, package, version, package_type=None):
            self.seen.append(version)
            return []

    def test_raw_specifier_goes_only_to_plugins_that_accept_it(self):
        from tyr import TyrScanner

        scanner = TyrScanner(plugin_names=[], analyzer_names=[])
        raw, clean = self.FakePlugin("raw", True), self.FakePlugin("clean", False)
        scanner.enabled_plugins = [raw, clean]
        scanner.scan_vulnerabilities([
            {"name": "a", "version": "^1.2.0", "type": "npm"},
            {"name": "b", "version": "5.0.0-beta.1", "type": "npm"},
        ])
        self.assertEqual(raw.seen, ["^1.2.0", "5.0.0-beta.1"])
        self.assertEqual(clean.seen, ["1.2.0", "5.0.0"])


if __name__ == "__main__":
    unittest.main()
