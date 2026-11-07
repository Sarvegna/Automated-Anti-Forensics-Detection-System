from core import ntfs_analysis


def test_ntfs_scan_reports_truncation_at_record_limit(tmp_path, monkeypatch):
    image_path = tmp_path / "synthetic.img"
    image_path.write_bytes(b"x" * 12)
    monkeypatch.setattr(ntfs_analysis, "find_ntfs_volume", lambda _: {
        "is_ntfs": True,
        "mft_offset": 0,
        "mft_record_size": 4,
        "volume_info": {},
    })
    monkeypatch.setattr(ntfs_analysis, "parse_mft_entry", lambda *_: None)

    result = ntfs_analysis.enumerate_ntfs_files(str(image_path), max_records=2)

    assert result["scan_truncated"] is True
    assert result["scan_note"] == "Scan stopped after 2 MFT records. Later records were not checked."


def test_ntfs_scan_is_not_truncated_at_end_of_file(tmp_path, monkeypatch):
    image_path = tmp_path / "synthetic.img"
    image_path.write_bytes(b"x" * 8)
    monkeypatch.setattr(ntfs_analysis, "find_ntfs_volume", lambda _: {
        "is_ntfs": True,
        "mft_offset": 0,
        "mft_record_size": 4,
        "volume_info": {},
    })
    monkeypatch.setattr(ntfs_analysis, "parse_mft_entry", lambda *_: None)

    result = ntfs_analysis.enumerate_ntfs_files(str(image_path), max_records=2)

    assert result["scan_truncated"] is False
    assert result["scan_note"] == ""
