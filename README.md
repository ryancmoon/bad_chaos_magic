# bad_chaos_magic

Detects bad chaos magic.

__description__ = 'Detects obfuscated and malicious code via entropy analysis and language detection. Attack code and phishing payloads often use heavy obfuscation that no human would write. This library measures the Shannon entropy of a file, identifies its language or script, and flags files whose entropy exceeds a per-language threshold. Known binary formats, certificates, and emails are automatically skipped.'    
__author__ = 'Ryan C. Moon'    
__version__ = '0.3.0'    
__date__ = '2026-02-09'  


## Installation

```
pip install .
```

Requires Python 3.10+. No external dependencies.

## CLI usage

```
bad-chaos-magic <file>
```

Diagnostic output (entropy, language) is printed to **stderr**. When an alert fires, a JSON object is printed to **stdout**, making it easy to pipe into other tools.

```
$ bad-chaos-magic suspicious.js
Shannon entropy: 5.3012 bits per byte        # stderr
Language: JavaScript                          # stderr
{                                             # stdout
  "alert": true,
  "entropy": "5.3012",
  "language": "JavaScript",
  "message": "highly obfuscated data observed, probable phishing or exploitation code detected.",
  "file_name": "suspicious.js",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

Exit codes: `0` on success, `1` on usage error or missing/unreadable file.

## Python API

```python
from bad_chaos_magic import (
    analyze_file,
    measure_entropy,
    language_guesser,
    ignore_filter,
    compute_hashes,
)
```

### `analyze_file(path: str) -> dict`

Top-level entry point. Reads the file, applies the ignore filter, measures entropy, detects language, and returns a result dict (schema below).

### `measure_entropy(data: bytes) -> float`

Returns Shannon entropy in bits per byte (0.0 -- 8.0). An empty input returns 0.0.

### `language_guesser(file_path: str) -> str | False`

Reads a file and guesses its natural or programming language. Returns a language name string, or `False` for binary/empty/undetectable files.

Detected natural languages: English, Spanish, French, German, Portuguese, Italian.
Detected programming languages: JavaScript, PowerShell, Python.
Detected scripts: Russian/Cyrillic, Arabic, Chinese, Japanese, Korean, Hindi, Thai, Greek, Hebrew.

### `ignore_filter(data: bytes) -> str | None`

Returns a reason string if the file should be skipped (known binary magic bytes, PEM-encoded data, RFC 2822 email), or `None` if it should be analyzed.

### `compute_hashes(data: bytes) -> dict[str, str]`

Returns `{"md5": ..., "sha1": ..., "sha256": ...}` hex digest strings.

## Output schema

`analyze_file()` returns a dict. The base keys are always present; `hashes` and `message` appear only when `alert` is `true`.

```jsonc
{
  // Always present
  "file_name": "example.js",        // os.path.basename of the input path
  "entropy":   5.3012,              // float, Shannon entropy (bits per byte)
  "language":  "JavaScript",        // string language name, or false
  "skipped":   null,                // string reason if skipped, or null
  "alert":     true,                // bool, true when entropy exceeds threshold

  // Present only when alert is true
  "hashes": {
    "md5":    "d41d8cd98f00b204e9800998ecf8427e",
    "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "message": "highly obfuscated data observed, probable phishing or exploitation code detected."
}
```

### Alert thresholds

An alert fires when a file's entropy reaches 95% of the expected maximum for its detected language:

| Language   | Max entropy | Alert threshold (95%) |
|------------|------------:|----------------------:|
| English    |        4.50 |                  4.28 |
| Spanish    |        4.40 |                  4.18 |
| French     |        4.30 |                  4.09 |
| German     |        4.60 |                  4.37 |
| Portuguese |        4.45 |                  4.23 |
| Italian    |        4.35 |                  4.13 |
| JavaScript |        5.20 |                  4.94 |
| PowerShell |        5.00 |                  4.75 |
| Python     |        4.80 |                  4.56 |

Files whose language is not in this table (e.g. binary, Cyrillic, unknown) never trigger an alert.

## Testing

```
pip install pytest
pytest tests/ -v
```

## License

MIT
