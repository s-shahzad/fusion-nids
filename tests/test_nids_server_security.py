from __future__ import annotations

import importlib.util
import io
from pathlib import Path


def _load_server():
    path = Path(__file__).parents[1] / "nids_server.py"
    spec = importlib.util.spec_from_file_location("nids_server_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_file_drop_hides_validation_exception_details(monkeypatch) -> None:
    server = _load_server()

    def fail(*args, **kwargs):
        raise ValueError("/secret/internal/path: parser detail")

    monkeypatch.setattr(server, "build_file_response", fail)
    client = server.app.test_client()
    response = client.post(
        "/api/scan/file-drop",
        data={"file": (io.BytesIO(bytes([1, 2, 3])), "sample.bin")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Uploaded file could not be scanned."}
    assert b"/secret/internal/path" not in response.data
