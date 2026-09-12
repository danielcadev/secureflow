"""Frozen public vectors and generated contracts must reproduce without network."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class TrustedCatalogVectors(unittest.TestCase):
    def test_independent_openssl_vectors_reproduce(self):
        fixture = ROOT / 'tests/fixtures/trusted-catalog'
        generator = module(fixture / 'generate.py', 'trust_vectors')
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            for name in ['catalog.manifest.json', 'catalog.sqlite3.zst']:
                shutil.copyfile(fixture / name, destination / name)
            generator.generate(destination)
            for name in json.loads((fixture / 'hashes.json').read_text()):
                self.assertEqual((fixture / name).read_bytes(), (destination / name).read_bytes(), name)
            self.assertEqual((fixture / 'hashes.json').read_bytes(), (destination / 'hashes.json').read_bytes())

    def test_schemas_reproduce_without_modifying_checkout(self):
        generator = module(ROOT / 'scripts/generate_trust_schemas.py', 'trust_schemas')
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            (destination / 'schemas').mkdir()
            generator.ROOT = destination
            generator.generate()
            for path in (destination / 'schemas').iterdir():
                self.assertEqual(path.read_bytes(), (ROOT / 'schemas' / path.name).read_bytes(), path.name)


if __name__ == '__main__':
    unittest.main()
