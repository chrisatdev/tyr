"""The Docker image must ship every module the scanner imports."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class DockerfileTest(unittest.TestCase):
    def test_every_top_level_module_tyr_imports_is_copied_into_the_image(self):
        source = (ROOT / "tyr.py").read_text()
        imported = set(re.findall(r"^(?:from|import)\s+(\w+)", source, re.M))
        local = {name for name in imported if (ROOT / f"{name}.py").is_file() or (ROOT / name).is_dir()}
        self.assertIn("lockfiles", local)

        copied = set()
        for line in (ROOT / "Dockerfile").read_text().splitlines():
            if line.startswith("COPY "):
                copied.update(Path(part.rstrip("/")).name for part in line.split()[1:-1])
        for name in local:
            self.assertTrue({name, f"{name}.py"} & copied, f"Dockerfile does not COPY {name}")


if __name__ == "__main__":
    unittest.main()
