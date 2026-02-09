import sys
import pytest

from bad_chaos_magic import main


def test_no_arguments(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bad-chaos-magic"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Usage:" in captured.err


def test_nonexistent_file(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bad-chaos-magic", "/no/such/file.txt"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_skipped_file(monkeypatch, capsys, tmp_path):
    f = tmp_path / "fake.zip"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    monkeypatch.setattr(sys, "argv", ["bad-chaos-magic", str(f)])
    main()
    captured = capsys.readouterr()
    assert "Skipped:" in captured.err
    assert captured.out == ""


def test_valid_text_file(monkeypatch, capsys, tmp_path):
    f = tmp_path / "readme.txt"
    f.write_text(
        "The quick brown fox jumps over the lazy dog. "
        "This is a simple test of the entropy analysis system."
    )
    monkeypatch.setattr(sys, "argv", ["bad-chaos-magic", str(f)])
    main()
    captured = capsys.readouterr()
    assert "entropy" in captured.err.lower()
    assert "Language:" in captured.err
