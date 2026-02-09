from bad_chaos_magic import language_guesser


def test_english_prose(tmp_path):
    f = tmp_path / "english.txt"
    f.write_text(
        "The quick brown fox jumps over the lazy dog. "
        "This is a story about the world and the people in it. "
        "They have been to the store and they are with friends."
    )
    assert language_guesser(str(f)) == "English"


def test_python_source(tmp_path):
    f = tmp_path / "example.py"
    f.write_text(
        "import os\n"
        "from sys import argv\n"
        "def main():\n"
        "    class Foo:\n"
        "        def __init__(self):\n"
        "            self.x = None\n"
        "            pass\n"
        "    print(True, False)\n"
        "    yield lambda: None\n"
    )
    assert language_guesser(str(f)) == "Python"


def test_javascript_source(tmp_path):
    f = tmp_path / "example.js"
    f.write_text(
        "const express = require('express');\n"
        "let app = express();\n"
        "function handler(req, res) {\n"
        "    var result = typeof undefined;\n"
        "    console.log(result);\n"
        "    return null;\n"
        "    export async function foo() { await bar(); }\n"
        "}\n"
    )
    assert language_guesser(str(f)) == "JavaScript"


def test_binary_file(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert language_guesser(str(f)) is False


def test_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    assert language_guesser(str(f)) is False


def test_cyrillic_text(tmp_path):
    f = tmp_path / "russian.txt"
    f.write_text("Привет мир, это тестовый текст на русском языке для проверки.")
    assert language_guesser(str(f)) == "Russian/Cyrillic"


def test_latin_no_keyword_matches(tmp_path):
    f = tmp_path / "latin.txt"
    f.write_text("zyx wvu tsrq ponm lkji hgfe dcba zyxw vuts rqpo nmlk jihg fedc")
    assert language_guesser(str(f)) == "Unknown (Latin script)"
