from bad_chaos_magic import ignore_filter


def test_empty_bytes():
    assert ignore_filter(b"") is None


def test_plain_text():
    assert ignore_filter(b"Hello, world! This is plain text.") is None


def test_zip_magic():
    data = b"PK\x03\x04" + b"\x00" * 100
    result = ignore_filter(data)
    assert result is not None
    assert "known file magic" in result


def test_elf_magic():
    data = b"\x7fELF" + b"\x00" * 100
    result = ignore_filter(data)
    assert result is not None
    assert "known file magic" in result


def test_pem_certificate():
    data = b"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----\n"
    result = ignore_filter(data)
    assert result == "certificate / PEM-encoded data"


def test_rfc2822_email_above_threshold():
    data = b"From: alice@example.com\nTo: bob@example.com\nSubject: Hi\nDate: Mon, 1 Jan 2024\n\nBody"
    result = ignore_filter(data)
    assert result is not None
    assert "RFC 2822 email" in result


def test_rfc2822_only_two_headers():
    data = b"From: alice@example.com\nTo: bob@example.com\n\nBody text only two headers"
    assert ignore_filter(data) is None
