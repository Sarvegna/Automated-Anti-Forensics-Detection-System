from types import SimpleNamespace

from core import hidden_file_detection


def test_normal_file_without_windows_attributes_is_not_hidden(tmp_path, monkeypatch):
    file_path = tmp_path / "normal.txt"
    file_path.write_text("test", encoding="utf-8")
    monkeypatch.setattr(hidden_file_detection.os, "stat", lambda _: SimpleNamespace())

    result = hidden_file_detection.check_hidden_file(str(file_path))

    assert result["is_hidden"] is False


def test_dotfile_without_windows_attributes_is_hidden(tmp_path, monkeypatch):
    file_path = tmp_path / ".secret"
    file_path.write_text("test", encoding="utf-8")
    monkeypatch.setattr(hidden_file_detection.os, "stat", lambda _: SimpleNamespace())

    result = hidden_file_detection.check_hidden_file(str(file_path))

    assert result["is_hidden"] is True


def test_windows_hidden_attribute_still_marks_file_hidden(tmp_path, monkeypatch):
    file_path = tmp_path / "windows-hidden.txt"
    file_path.write_text("test", encoding="utf-8")
    monkeypatch.setattr(
        hidden_file_detection.os,
        "stat",
        lambda _: SimpleNamespace(st_file_attributes=0x2),
    )

    result = hidden_file_detection.check_hidden_file(str(file_path))

    assert result["is_hidden"] is True
