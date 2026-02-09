from bad_chaos_magic import measure_entropy


def test_empty_bytes():
    assert measure_entropy(b"") == 0.0


def test_single_repeated_byte():
    assert measure_entropy(b"\x00" * 100) == 0.0


def test_two_equally_distributed_bytes():
    data = b"\x00\x01" * 50
    assert measure_entropy(data) == 1.0


def test_all_256_values_equally_distributed():
    data = bytes(range(256)) * 4
    assert measure_entropy(data) == 8.0


def test_known_text_sane_range():
    data = b"The quick brown fox jumps over the lazy dog"
    entropy = measure_entropy(data)
    assert 0 < entropy < 8
