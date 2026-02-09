import hashlib

from bad_chaos_magic import compute_hashes


def test_returns_correct_keys():
    result = compute_hashes(b"test")
    assert set(result.keys()) == {"md5", "sha1", "sha256"}


def test_values_are_hex_strings():
    result = compute_hashes(b"test")
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64
    for value in result.values():
        int(value, 16)  # raises if not valid hex


def test_known_input_matches_hashlib():
    data = b"bad chaos magic"
    result = compute_hashes(data)
    assert result["md5"] == hashlib.md5(data).hexdigest()
    assert result["sha1"] == hashlib.sha1(data).hexdigest()
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
