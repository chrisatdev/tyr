"""How TyrScanner turns a project tree into the dependencies it looks up."""
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tyr import TyrScanner  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "lockfiles"


class CollectDependenciesTest(unittest.TestCase):
    def setUp(self):
        # Under a directory named "build" on purpose: skipping must be relative to the
        # project, or every project living below such a folder would scan nothing.
        self.base = Path(tempfile.mkdtemp())
        self.project = self.base / "build" / "project"
        self.project.mkdir(parents=True)
        self.scanner = TyrScanner(plugin_names=[], analyzer_names=[])

    def tearDown(self):
        shutil.rmtree(self.base)

    def write(self, relative, content):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return path

    def collect(self):
        with redirect_stdout(io.StringIO()) as out:
            deps = self.scanner.collect_dependencies(self.project)
        return {(d["type"], d["name"], d["version"]) for d in deps}, out.getvalue()

    def test_the_lockfile_replaces_the_manifest_ranges(self):
        self.write("package.json", {"dependencies": {"minimist": "^1.2.0"}, "devDependencies": {"is-number": "^7.0.0"}})
        shutil.copy(FIXTURES / "npm3" / "package-lock.json", self.project / "package-lock.json")
        deps, _ = self.collect()
        self.assertEqual(deps, {("npm", "minimist", "1.2.5"), ("npm", "is-number", "7.0.0")})

    def test_node_modules_and_other_vendored_trees_are_ignored(self):
        self.write("package.json", {"dependencies": {"minimist": "1.2.5"}})
        self.write("node_modules/minimist/package.json", {"devDependencies": {"tape": "^5.0.0"}})
        self.write("vendor/bundle/Gemfile.lock", "GEM\n  specs:\n    rack (1.0.0)\n")
        deps, _ = self.collect()
        self.assertEqual(deps, {("npm", "minimist", "1.2.5")})

    def test_a_broken_lockfile_falls_back_to_the_manifest_and_says_so(self):
        self.write("package.json", {"dependencies": {"minimist": "^1.2.0"}})
        self.write("package-lock.json", "{not json")
        deps, out = self.collect()
        self.assertEqual(deps, {("npm", "minimist", "^1.2.0")})
        self.assertIn("package-lock.json", out)

    def test_lockfiles_of_one_ecosystem_are_combined(self):
        shutil.copy(FIXTURES / "npm3" / "package-lock.json", self.project / "package-lock.json")
        shutil.copy(FIXTURES / "yarnberry" / "yarn.lock", self.project / "yarn.lock")
        deps, _ = self.collect()
        self.assertEqual(deps, {("npm", "minimist", "1.2.5"), ("npm", "is-number", "7.0.0")})

    def test_each_directory_and_ecosystem_is_resolved_on_its_own(self):
        shutil.copy(FIXTURES / "npm3" / "package-lock.json", self.project / "package-lock.json")
        self.write("api/Gemfile", 'gem "rack", "2.2.3"\n')
        shutil.copy(FIXTURES / "bundler" / "Gemfile.lock", self.project / "api" / "Gemfile.lock")
        self.write("tools/requirements.txt", "requests==2.25.0\n")
        deps, _ = self.collect()
        self.assertEqual(deps, {
            ("npm", "minimist", "1.2.5"), ("npm", "is-number", "7.0.0"),
            ("gem", "rack", "2.2.3"), ("gem", "rake", "13.0.6"),
            ("pypi", "requests", "2.25.0"),
        })

    def test_non_registry_entries_are_reported_not_looked_up(self):
        shutil.copy(FIXTURES / "npm3" / "package-lock.json", self.project / "package-lock.json")
        deps, out = self.collect()
        self.assertNotIn("local-lib", {name for _, name, _ in deps})
        self.assertIn("local-lib", out)


class ExactVersionsReachPluginsTest(unittest.TestCase):
    class FakePlugin:
        name = "fake"

        def __init__(self):
            self.seen = []

        def query_vulnerabilities(self, package, version, package_type=None):
            self.seen.append(version)
            return []

    def test_exact_versions_skip_clean_version(self):
        scanner = TyrScanner(plugin_names=[], analyzer_names=[])
        plugin = self.FakePlugin()
        scanner.enabled_plugins = [plugin]
        with redirect_stdout(io.StringIO()):
            scanner.scan_vulnerabilities([
                {"name": "a", "version": "5.0.0-beta.1", "type": "npm", "exact": True},
                {"name": "b", "version": "^1.2.0", "type": "npm"},
            ])
        self.assertEqual(plugin.seen, ["5.0.0-beta.1", "1.2.0"])


if __name__ == "__main__":
    unittest.main()
