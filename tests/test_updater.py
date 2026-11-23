"""更新检查与多语言基础测试。"""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import updater  # noqa: E402


class _Response:
    def __init__(self, payload: object) -> None:
        self._data = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def fake_opener(*responses):
    calls: list[str] = []
    pending = list(responses)

    def opener(request, timeout=8.0):
        calls.append(request.full_url)
        if not pending:
            raise urllib.error.URLError("no response")
        response = pending.pop(0)
        if isinstance(response, Exception):
            raise response
        return _Response(response)

    opener.calls = calls  # type: ignore[attr-defined]
    return opener


class UpdaterTests(unittest.TestCase):
    def test_parse_versions(self):
        self.assertEqual(updater.parse_version("v2.4.1"), (2, 4, 1))
        self.assertEqual(updater.parse_version("2.4"), (2, 4, 0))
        self.assertEqual(updater.parse_version("v2.4.0-beta"), (2, 4, 0))
        self.assertIsNone(updater.parse_version("nightly"))

    def test_new_version_available(self):
        opener = fake_opener({"tag_name": "v9.9.0"})
        info = updater.check_for_update((2, 4, 0), opener=opener)
        self.assertTrue(info.available)
        self.assertEqual(info.latest, (9, 9, 0))
        self.assertEqual(info.tag, "v9.9.0")

    def test_current_version(self):
        opener = fake_opener({"tag_name": "v2.4.0"}, [])
        info = updater.check_for_update((2, 4, 0), opener=opener)
        self.assertFalse(info.available)
        self.assertEqual(info.status, "current")

    def test_v23_starts_update_check(self):
        opener = fake_opener({"tag_name": "v2.3.1"})
        info = updater.check_for_update((2, 3, 0), opener=opener)
        self.assertFalse(info.ignored)
        self.assertTrue(info.available)

    def test_versions_before_23_are_ignored(self):
        opener = fake_opener({"tag_name": "v9.9.0"})
        info = updater.check_for_update((2, 2, 0), opener=opener)
        self.assertTrue(info.ignored)
        self.assertEqual(opener.calls, [])
        self.assertFalse(info.available)

    def test_tags_fallback(self):
        opener = fake_opener(
            {}, [{"name": "v2.4"}, {"name": "v2.5.2"}, {"name": "bad"}])
        info = updater.check_for_update((2, 4, 0), opener=opener)
        self.assertEqual(info.latest, (2, 5, 2))
        self.assertTrue(info.available)

    def test_network_error(self):
        opener = fake_opener(urllib.error.URLError("offline"),
                             urllib.error.URLError("offline"))
        info = updater.check_for_update((2, 4, 0), opener=opener)
        self.assertFalse(info.available)
        self.assertEqual(info.status, "error")
        self.assertIn("GitHub", info.error)

    def test_release_older_than_tag(self):
        opener = fake_opener({"tag_name": "v2.3.9"}, [{"name": "v2.4.1"}])
        info = updater.check_for_update((2, 4, 0), opener=opener)
        self.assertEqual(info.latest, (2, 4, 1))
        self.assertTrue(info.available)


if __name__ == "__main__":
    unittest.main()
