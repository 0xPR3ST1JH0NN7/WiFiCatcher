"""Tests for the in-app save-location directory picker endpoint."""

import os

from fastapi.testclient import TestClient

from WiFiCatcher.server import app

client = TestClient(app)


def test_lists_directory_dirs_first(tmp_path):
    (tmp_path / "beta_dir").mkdir()
    (tmp_path / "alpha_dir").mkdir()
    (tmp_path / "note.txt").write_text("x")
    (tmp_path / ".hidden").write_text("x")   # dot-entries are hidden

    r = client.get("/api/fs/list", params={"path": str(tmp_path)})
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == str(tmp_path)
    assert body["parent"] == os.path.dirname(str(tmp_path))
    assert body["writable"] is True
    names = [e["name"] for e in body["entries"]]
    assert names == ["alpha_dir", "beta_dir", "note.txt"]   # dirs first, then files
    assert [e["is_dir"] for e in body["entries"]] == [True, True, False]


def test_root_has_no_parent():
    body = client.get("/api/fs/list", params={"path": "/"}).json()
    assert body["parent"] is None


def test_missing_directory_is_400():
    r = client.get("/api/fs/list", params={"path": "/no/such/dir/zzz"})
    assert r.status_code == 400


def test_default_is_home():
    body = client.get("/api/fs/list").json()
    assert body["path"] == os.path.abspath(os.path.expanduser("~"))
