import ast
import os
from pathlib import Path
from types import SimpleNamespace


def test_hosted_mode_off_by_default_and_enabled_by_env(monkeypatch):
    app_path = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"
    app_tree = ast.parse(app_path.read_text(encoding="utf-8"))
    helper = next(
        node for node in app_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_hosted_mode_enabled"
    )
    helper_module = ast.Module(body=[helper], type_ignores=[])
    namespace = {"os": os, "st": SimpleNamespace(secrets={})}
    exec(compile(helper_module, str(app_path), "exec"), namespace)
    hosted_mode_enabled = namespace["_hosted_mode_enabled"]

    monkeypatch.delenv("HOSTED_MODE", raising=False)
    assert hosted_mode_enabled() is False

    monkeypatch.setenv("HOSTED_MODE", "TrUe")
    assert hosted_mode_enabled() is True

    monkeypatch.delenv("HOSTED_MODE")
    namespace["st"].secrets["HOSTED_MODE"] = "TRUE"
    assert hosted_mode_enabled() is True
