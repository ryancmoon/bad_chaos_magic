/*
 * bad_chaos_magic.yar
 * YARA implementation of bad_chaos_magic detection logic.
 *
 * Detects highly obfuscated code (probable phishing / exploitation payloads)
 * by combining language identification with per-language entropy thresholds.
 *
 * Original tool: bad_chaos_magic by Ryan C. Moon (@moonbas3)
 *
 * Differences from the Python implementation:
 *   - Language detection uses fixed keyword-count thresholds instead of
 *     competitive scoring between languages.  Multiple language rules
 *     may fire for the same file.
 *   - Non-Latin script languages (Cyrillic, Arabic, CJK, etc.) are not
 *     covered because the Python tool has no entropy thresholds for them
 *     and therefore never generates alerts for those scripts.
 *   - Binary detection via the "30 % non-text bytes" heuristic is not
 *     replicated; magic-byte filtering covers the vast majority of cases.
 */

import "math"

// ── Files to skip ─────────────────────────────────────────────────────

private rule IsKnownBinary
{
    strings:
        // Archives / compression
        $magic_zip1    = { 50 4B 03 04 }
        $magic_zip2    = { 50 4B 05 06 }
        $magic_zip3    = { 50 4B 07 08 }
        $magic_rar     = { 52 61 72 21 1A 07 }
        $magic_7z      = { 37 7A BC AF 27 1C }
        $magic_gzip    = { 1F 8B }
        $magic_bzip2   = { 42 5A 68 }
        $magic_xz      = { FD 37 7A 58 5A 00 }
        $magic_zstd    = { 28 B5 2F FD }
        $magic_lz4     = { 04 22 4D 18 }
        // Executables / object code
        $magic_pe      = { 4D 5A }
        $magic_elf     = { 7F 45 4C 46 }
        $magic_macho32 = { FE ED FA CE }
        $magic_macho64 = { FE ED FA CF }
        $magic_fat     = { CA FE BA BE }
        // Documents / media
        $magic_pdf     = { 25 50 44 46 }
        $magic_ole2    = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_png     = { 89 50 4E 47 0D 0A 1A 0A }
        $magic_jpeg    = { FF D8 FF }
        $magic_gif87   = { 47 49 46 38 37 61 }
        $magic_gif89   = { 47 49 46 38 39 61 }
        $magic_riff    = { 52 49 46 46 }
        $magic_ico     = { 00 00 01 00 }
        $magic_id3     = { 49 44 33 }
        $magic_mp3     = { FF FB }
        $magic_ogg     = { 4F 67 67 53 }
        $magic_flac    = { 66 4C 61 43 }
        $magic_ebml    = { 1A 45 DF A3 }
        // Databases
        $magic_sqlite  = "SQLite format 3\x00"

    condition:
        for any of ($magic_*) : (@ == 0)
}


private rule IsPEMData
{
    strings:
        $pem01 = "-----BEGIN CERTIFICATE"
        $pem02 = "-----BEGIN RSA PRIVATE KEY"
        $pem03 = "-----BEGIN EC PRIVATE KEY"
        $pem04 = "-----BEGIN PRIVATE KEY"
        $pem05 = "-----BEGIN PUBLIC KEY"
        $pem06 = "-----BEGIN ENCRYPTED PRIVATE KEY"
        $pem07 = "-----BEGIN X509 CRL"
        $pem08 = "-----BEGIN PKCS7"
        $pem09 = "-----BEGIN PKCS12"
        $pem10 = "-----BEGIN SSH2"
        $pem11 = "-----BEGIN OPENSSH PRIVATE KEY"
        $pem12 = "-----BEGIN PGP"

    condition:
        for any of ($pem*) : (@ < 4096)
}


private rule IsRFC2822Email
{
    strings:
        $hdr01 = "Subject:"
        $hdr02 = "Sender:"
        $hdr03 = "To:"
        $hdr04 = "From:"
        $hdr05 = "Date:"
        $hdr06 = "Message-ID:"
        $hdr07 = "MIME-Version:"
        $hdr08 = "Content-Type:"
        $hdr09 = "Received:"
        $hdr10 = "Return-Path:"
        $hdr11 = "X-Mailer:"

    condition:
        for 3 of ($hdr*) : (@ < 4096)
}


// ── Programming language alerts ───────────────────────────────────────

rule BadChaosMagic_JavaScript
{
    meta:
        author          = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description     = "Highly obfuscated JavaScript detected — probable phishing or exploitation payload"
        creation_date   = "2026-02-09"
        last_updated    = "2026-02-10"
        threshold       = "4.94"   // MAX_ENTROPY 5.20 * 0.95
        prod            = "true"
        family          = "generic"
    strings:
        $js01 = "function"  ascii nocase
        $js02 = "const"     ascii nocase
        $js03 = "var"       ascii nocase
        $js04 = "return"    ascii nocase
        $js05 = "typeof"    ascii nocase
        $js06 = "undefined" ascii nocase
        $js07 = "console"   ascii nocase
        $js08 = "document"  ascii nocase
        $js09 = "require"   ascii nocase
        $js10 = "export"    ascii nocase
        $js11 = "async"     ascii nocase
        $js12 = "await"     ascii nocase
        $js13 = "=>"        ascii
        $js14 = "null"      ascii nocase
        $js15 = "==="       ascii
        $js16 = "!=="       ascii
        $js17 = "window"    ascii nocase
        $js18 = "prototype" ascii nocase
        $js19 = "this"      ascii nocase 
        $js20 = "new"       ascii nocase
        $js21 = "true"      ascii nocase 
        $js22 = "false"     ascii nocase
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        3 of ($js*) and
        math.entropy(0, filesize) >= 4.94
}


rule BadChaosMagic_PowerShell
{
    meta:
        author          = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description     = "Highly obfuscated PowerShell detected — probable phishing or exploitation payload"
        threshold       = "4.75"   // MAX_ENTROPY 5.00 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = "generic"
    strings:
        $ps01 = "param"             ascii nocase
        $ps02 = "foreach"           ascii nocase
        $ps03 = "Write-Host"        ascii nocase
        $ps04 = "Get-ChildItem"     ascii nocase
        $ps05 = "Set-Item"          ascii nocase
        $ps06 = "Get-Content"       ascii nocase
        $ps07 = "Set-Content"       ascii nocase
        $ps08 = "$_"                ascii
        $ps09 = "CmdletBinding"     ascii nocase
        $ps10 = "-eq"               ascii nocase
        $ps11 = "-ne"               ascii nocase
        $ps12 = "-gt"               ascii nocase
        $ps13 = "-lt"               ascii nocase
        $ps14 = "Invoke-Expression" ascii nocase
        $ps15 = "New-Object"        ascii nocase
        $ps16 = "Out-Null"          ascii nocase
        $ps17 = "Write-Output"      ascii nocase
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        3 of ($ps*) and
        math.entropy(0, filesize) >= 4.75
}


rule BadChaosMagic_Python
{
    meta:
        author          = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description     = "Highly obfuscated Python detected — probable phishing or exploitation payload"
        threshold       = "4.56"   // MAX_ENTROPY 4.80 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = "generic"
    strings:
        $py01 = "def"       ascii nocase
        $py02 = "class"     ascii nocase
        $py03 = "import"    ascii nocase
        $py04 = "elif"      ascii nocase
        $py05 = "except"    ascii nocase
        $py06 = "lambda"    ascii nocase
        $py07 = "yield"     ascii nocase
        $py08 = "self"      ascii nocase
        $py09 = "__init__"  ascii
        $py10 = "__name__"  ascii
        $py11 = "__main__"  ascii
        $py12 = "nonlocal"  ascii nocase
        $py13 = "print("    ascii
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        3 of ($py*) and
        math.entropy(0, filesize) >= 4.56
}


// ── Natural language alerts ───────────────────────────────────────────
// fullword modifier prevents partial matches (e.g. "the" in "theorem")

rule BadChaosMagic_English
{
    meta:
        author          = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description     = "Highly obfuscated English-language content — probable phishing payload"
        threshold       = "4.275"  // MAX_ENTROPY 4.50 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $en01 = "the"   ascii nocase fullword
        $en02 = "and"   ascii nocase fullword
        $en03 = "that"  ascii nocase fullword
        $en04 = "was"   ascii nocase fullword
        $en05 = "for"   ascii nocase fullword
        $en06 = "are"   ascii nocase fullword
        $en07 = "with"  ascii nocase fullword
        $en08 = "this"  ascii nocase fullword
        $en09 = "have"  ascii nocase fullword
        $en10 = "from"  ascii nocase fullword
        $en11 = "not"   ascii nocase fullword
        $en12 = "but"   ascii nocase fullword
        $en13 = "they"  ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($en*) and
        math.entropy(0, filesize) >= 4.275
}


rule BadChaosMagic_Spanish
{
    meta:
        author      = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description = "Highly obfuscated Spanish-language content — probable phishing payload"
        threshold   = "4.18"   // MAX_ENTROPY 4.40 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $es01 = "que"   ascii nocase fullword
        $es02 = "los"   ascii nocase fullword
        $es03 = "del"   ascii nocase fullword
        $es04 = "las"   ascii nocase fullword
        $es05 = "por"   ascii nocase fullword
        $es06 = "con"   ascii nocase fullword
        $es07 = "una"   ascii nocase fullword
        $es08 = "para"  ascii nocase fullword
        $es09 = "como"  ascii nocase fullword
        $es10 = "pero"  ascii nocase fullword
        $es11 = "sus"   ascii nocase fullword
        $es12 = "sobre" ascii nocase fullword
        $es13 = "este"  ascii nocase fullword
        $es14 = "entre" ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($es*) and
        math.entropy(0, filesize) >= 4.18
}


rule BadChaosMagic_French
{
    meta:
        author      = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description = "Highly obfuscated French-language content — probable phishing payload"
        threshold   = "4.085"  // MAX_ENTROPY 4.30 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $fr01 = "les"   ascii nocase fullword
        $fr02 = "des"   ascii nocase fullword
        $fr03 = "est"   ascii nocase fullword
        $fr04 = "que"   ascii nocase fullword
        $fr05 = "une"   ascii nocase fullword
        $fr06 = "dans"  ascii nocase fullword
        $fr07 = "pour"  ascii nocase fullword
        $fr08 = "pas"   ascii nocase fullword
        $fr09 = "sur"   ascii nocase fullword
        $fr10 = "sont"  ascii nocase fullword
        $fr11 = "avec"  ascii nocase fullword
        $fr12 = "plus"  ascii nocase fullword
        $fr13 = "tout"  ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($fr*) and
        math.entropy(0, filesize) >= 4.085
}


rule BadChaosMagic_German
{
    meta:
        author      = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description = "Highly obfuscated German-language content — probable phishing payload"
        threshold   = "4.37"   // MAX_ENTROPY 4.60 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $de01 = "der"   ascii nocase fullword
        $de02 = "die"   ascii nocase fullword
        $de03 = "und"   ascii nocase fullword
        $de04 = "den"   ascii nocase fullword
        $de05 = "ist"   ascii nocase fullword
        $de06 = "von"   ascii nocase fullword
        $de07 = "das"   ascii nocase fullword
        $de08 = "ein"   ascii nocase fullword
        $de09 = "mit"   ascii nocase fullword
        $de10 = "sich"  ascii nocase fullword
        $de11 = "auf"   ascii nocase fullword
        $de12 = "dem"   ascii nocase fullword
        $de13 = "nicht" ascii nocase fullword
        $de14 = "eine"  ascii nocase fullword
        $de15 = "auch"  ascii nocase fullword
        $de16 = "nach"  ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($de*) and
        math.entropy(0, filesize) >= 4.37
}


rule BadChaosMagic_Portuguese
{
    meta:
        author      = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description = "Highly obfuscated Portuguese-language content — probable phishing payload"
        threshold   = "4.2275" // MAX_ENTROPY 4.45 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $pt01 = "que"   ascii nocase fullword
        $pt02 = "uma"   ascii nocase fullword
        $pt03 = "para"  ascii nocase fullword
        $pt04 = "com"   ascii nocase fullword
        $pt05 = "mais"  ascii nocase fullword
        $pt06 = "como"  ascii nocase fullword
        $pt07 = "dos"   ascii nocase fullword
        $pt08 = "das"   ascii nocase fullword
        $pt09 = "foi"   ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($pt*) and
        math.entropy(0, filesize) >= 4.2275
}


rule BadChaosMagic_Italian
{
    meta:
        author      = "Ryan C. Moon (@moonbas3)"
        attribution     = "SEI Incident Response and Countermeasures"
        description = "Highly obfuscated Italian-language content — probable phishing payload"
        threshold   = "4.1325" // MAX_ENTROPY 4.35 * 0.95
        creation_date   = "2026-02-09"
        last_updated    = ""
        prod            = "true"
        family          = ""
    strings:
        $it01 = "che"    ascii nocase fullword
        $it02 = "per"    ascii nocase fullword
        $it03 = "non"    ascii nocase fullword
        $it04 = "una"    ascii nocase fullword
        $it05 = "del"    ascii nocase fullword
        $it06 = "della"  ascii nocase fullword
        $it07 = "sono"   ascii nocase fullword
        $it08 = "con"    ascii nocase fullword
        $it09 = "anche"  ascii nocase fullword
        $it10 = "come"   ascii nocase fullword
        $it11 = "dalla"  ascii nocase fullword
        $it12 = "hanno"  ascii nocase fullword
        $it13 = "questo" ascii nocase fullword
    condition:
        not IsKnownBinary and
        not IsPEMData and
        not IsRFC2822Email and
        4 of ($it*) and
        math.entropy(0, filesize) >= 4.1325
}
