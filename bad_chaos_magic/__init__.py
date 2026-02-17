#!/usr/bin/env python3
# bad_chaos_magic
# Ryan C. Moon (@moonbas3)
# 2026-02-09
#
# Detects bad chaos magic.
# Frequently attack code or phishing uses highly obfuscated code that no human would write. This tries to detect that.

import math
import sys
import os
import hashlib
import json
import unicodedata
from collections import Counter

__all__ = ["analyze_file", "measure_entropy", "language_guesser", "ignore_filter", "compute_hashes"]


def measure_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


LANGUAGE_WORDS = {
    "English": {"the", "and", "is", "of", "to", "in", "it", "that", "was", "for",
                "on", "are", "with", "this", "have", "from", "not", "but", "they"},
    "Spanish": {"de", "el", "la", "en", "que", "los", "del", "las", "por", "con",
                "una", "para", "como", "pero", "sus", "sobre", "este", "entre"},
    "French": {"le", "la", "de", "et", "les", "des", "est", "en", "que", "une",
               "dans", "pour", "pas", "sur", "sont", "avec", "plus", "tout"},
    "German": {"der", "die", "und", "den", "ist", "von", "das", "ein", "mit",
               "sich", "auf", "dem", "nicht", "eine", "als", "auch", "nach"},
    "Portuguese": {"de", "que", "do", "da", "em", "para", "com", "uma", "os",
                   "no", "na", "por", "mais", "como", "dos", "das", "foi"},
    "Italian": {"di", "che", "il", "la", "per", "non", "una", "del", "della",
                "sono", "con", "anche", "come", "dalla", "hanno", "questo"},
}

PROGRAMMING_KEYWORDS = {
    "JavaScript": {"function", "const", "let", "var", "return", "typeof", "undefined",
                   "console", "document", "require", "export", "async", "await",
                   "=>", "null", "===", "!==", "window", "prototype", "new", "this", 
                   "true", "false"},
    "PowerShell": {"param", "function", "foreach", "write-host", "get-childitem",
                   "set-item", "get-content", "set-content", "$_", "cmdletbinding",
                   "-eq", "-ne", "-gt", "-lt", "try", "catch", "invoke-expression",
                   "new-object", "out-null", "write-output"},
    "Python": {"def", "class", "import", "from", "elif", "except", "lambda",
               "yield", "self", "none", "true", "false", "print", "__init__",
               "__name__", "__main__", "async", "await", "nonlocal", "pass"},
}

MAX_ENTROPY = {
    "English":    4.50,
    "Spanish":    4.40,
    "French":     4.30,
    "German":     4.60,
    "Portuguese": 4.45,
    "Italian":    4.35,
    "JavaScript": 5.20,
    "PowerShell": 5.00,
    "Python":     4.80,
}

SCRIPT_LANGUAGES = {
    "CYRILLIC": "Russian/Cyrillic",
    "ARABIC": "Arabic",
    "CJK": "Chinese",
    "HIRAGANA": "Japanese",
    "KATAKANA": "Japanese",
    "HANGUL": "Korean",
    "DEVANAGARI": "Hindi",
    "THAI": "Thai",
    "GREEK": "Greek",
    "HEBREW": "Hebrew",
}


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return True
    non_text = sum(
        1 for b in data[:8192]
        if b < 8 or (13 < b < 32 and b != 27)
    )
    return non_text / min(len(data), 8192) > 0.30


def _detect_script(text: str) -> Counter:
    scripts = Counter()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch, "")
        except ValueError:
            continue
        for script_key in SCRIPT_LANGUAGES:
            if script_key in name:
                scripts[script_key] += 1
                break
        else:
            if ch.isascii():
                scripts["LATIN"] += 1
    return scripts


def _score_words(text: str) -> dict[str, int]:
    words = set(text.lower().split())
    return {
        lang: len(words & wordset)
        for lang, wordset in LANGUAGE_WORDS.items()
    }


def _score_programming(text: str) -> dict[str, int]:
    lower = text.lower()
    tokens = set(lower.split())
    scores = {}
    for lang, keywords in PROGRAMMING_KEYWORDS.items():
        score = len(tokens & keywords)
        for kw in keywords:
            if len(kw) > 2 and kw not in tokens and kw in lower:
                score += 1
        scores[lang] = score
    return scores


def language_guesser(file_path: str):
    with open(file_path, "rb") as f:
        data = f.read()

    if not data or _is_binary(data):
        return False

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("latin-1")
        except UnicodeDecodeError:
            return False

    scripts = _detect_script(text)
    if not scripts:
        return False

    dominant_script = scripts.most_common(1)[0][0]

    if dominant_script != "LATIN":
        return SCRIPT_LANGUAGES[dominant_script]

    prog_scores = _score_programming(text)
    best_prog = max(prog_scores, key=prog_scores.get)

    scores = _score_words(text)
    best_lang = max(scores, key=scores.get)

    if prog_scores[best_prog] > scores[best_lang]:
        return best_prog
    if scores[best_lang] == 0:
        if prog_scores[best_prog] > 0:
            return best_prog
        return "Unknown (Latin script)"
    return best_lang


KNOWN_MAGIC = (
    # Archives / compression
    b"PK\x03\x04",                          # ZIP (also DOCX, XLSX, PPTX, JAR, APK)
    b"PK\x05\x06",                          # ZIP empty archive
    b"PK\x07\x08",                          # ZIP spanned archive
    b"Rar!\x1a\x07",                        # RAR
    b"7z\xbc\xaf\x27\x1c",                 # 7-Zip
    b"\x1f\x8b",                            # GZIP
    b"BZh",                                 # BZIP2
    b"\xfd7zXZ\x00",                        # XZ
    b"\x28\xb5\x2f\xfd",                    # Zstandard
    b"\x04\x22\x4d\x18",                    # LZ4
    # Executables / object code
    b"MZ",                                  # PE32 / DOS executable
    b"\x7fELF",                             # ELF
    b"\xfe\xed\xfa\xce",                    # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",                    # Mach-O 64-bit
    b"\xca\xfe\xba\xbe",                    # Mach-O universal / Java class
    # Documents / media
    b"%PDF",                                # PDF
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",   # OLE2 (DOC, XLS, PPT, MSG)
    b"\x89PNG\r\n\x1a\n",                   # PNG
    b"\xff\xd8\xff",                         # JPEG
    b"GIF87a",                              # GIF87
    b"GIF89a",                              # GIF89
    b"RIFF",                                # RIFF (AVI, WAV, WebP)
    b"\x00\x00\x01\x00",                    # ICO
    b"ID3",                                 # MP3 with ID3
    b"\xff\xfb",                            # MP3
    b"OggS",                                # OGG
    b"fLaC",                                # FLAC
    b"\x1a\x45\xdf\xa3",                    # MKV / WebM (EBML)
    # Databases / misc binary
    b"SQLite format 3\x00",                 # SQLite
)

PEM_MARKERS = (
    b"-----BEGIN CERTIFICATE",
    b"-----BEGIN RSA PRIVATE KEY",
    b"-----BEGIN EC PRIVATE KEY",
    b"-----BEGIN PRIVATE KEY",
    b"-----BEGIN PUBLIC KEY",
    b"-----BEGIN ENCRYPTED PRIVATE KEY",
    b"-----BEGIN X509 CRL",
    b"-----BEGIN PKCS7",
    b"-----BEGIN PKCS12",
    b"-----BEGIN SSH2",
    b"-----BEGIN OPENSSH PRIVATE KEY",
    b"-----BEGIN PGP",
)

RFC2822_HEADERS = (
    b"Subject:",
    b"Sender:",
    b"To:",
    b"From:",
    b"Date:",
    b"Message-ID:",
    b"MIME-Version:",
    b"Content-Type:",
    b"Received:",
    b"Return-Path:",
    b"X-Mailer:",
)

RFC2822_THRESHOLD = 3


def ignore_filter(data: bytes) -> str | None:
    if not data:
        return None

    for magic in KNOWN_MAGIC:
        if data[:len(magic)] == magic:
            return f"known file magic ({data[:8]!r})"

    head = data[:4096]

    for marker in PEM_MARKERS:
        if marker in head:
            return "certificate / PEM-encoded data"

    matched = sum(1 for hdr in RFC2822_HEADERS if hdr in head)
    if matched >= RFC2822_THRESHOLD:
        return f"RFC 2822 email ({matched} headers matched)"

    return None


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def analyze_file(path: str) -> dict:
    """Analyze a file for obfuscated/malicious code via entropy and language detection.

    Returns a dict with keys:
        file_name  — basename of the file
        entropy    — Shannon entropy (bits per byte)
        language   — detected language/format, or False for binary
        skipped    — reason string if file was filtered out, else None
        alert      — True if entropy exceeds threshold, else False
        hashes     — {"md5", "sha1", "sha256"} dict (only when alert is True)
        message    — alert message string (only when alert is True)
    """
    with open(path, "rb") as f:
        data = f.read()

    result = {
        "file_name": os.path.basename(path),
        "entropy": 0.0,
        "language": False,
        "skipped": None,
        "alert": False,
    }

    ignored = ignore_filter(data)
    if ignored:
        result["skipped"] = ignored
        return result

    entropy = measure_entropy(data)
    result["entropy"] = entropy

    language = language_guesser(path)
    result["language"] = language

    if language and language in MAX_ENTROPY:
        threshold = MAX_ENTROPY[language] * 0.95
        if entropy >= threshold:
            result["alert"] = True
            result["hashes"] = compute_hashes(data)
            result["message"] = "highly obfuscated data observed, probable phishing or exploitation code detected."

    return result


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]

    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file or does not exist.", file=sys.stderr)
        sys.exit(1)

    if not os.access(path, os.R_OK):
        print(f"Error: '{path}' is not readable.", file=sys.stderr)
        sys.exit(1)

    result = analyze_file(path)

    if result["skipped"]:
        print(f"Skipped: {result['skipped']}", file=sys.stderr)
        return

    print(f"Shannon entropy: {result['entropy']:.4f} bits per byte", file=sys.stderr)

    if result["language"] is False:
        print("Language: Binary file (not text)", file=sys.stderr)
    else:
        print(f"Language: {result['language']}", file=sys.stderr)

    if result["alert"]:
        alert = {
            "alert": True,
            "entropy": f"{result['entropy']:.4f}",
            "language": result["language"],
            "message": result["message"],
            "file_name": result["file_name"],
            "md5": result["hashes"]["md5"],
            "sha1": result["hashes"]["sha1"],
            "sha256": result["hashes"]["sha256"],
        }
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
