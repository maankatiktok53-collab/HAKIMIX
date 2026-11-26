#!/usr/bin/env python3
"""HASH module: offline hash identification and wordlist auditing.

Standalone:
    python3 06_HASH/hash.py localhost -y --hash 5d41402abc4b2a76b9719d911017c592
    python3 06_HASH/hash.py localhost -y --hashfile hashes.txt --wordlist /usr/share/wordlists/rockyou.txt

Importable:
    run(target, workspace, config, logger, options) -> dict
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cli import base_parser, prepare  # noqa: E402
from core.utils import ensure_logger, module_envelope, run_command, tool_available, truncate, utcnow, write_text  # noqa: E402

PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("sha512", re.compile(r"^[0-9a-fA-F]{128}$")),
    ("sha384", re.compile(r"^[0-9a-fA-F]{96}$")),
    ("sha256", re.compile(r"^[0-9a-fA-F]{64}$")),
    ("sha224", re.compile(r"^[0-9a-fA-F]{56}$")),
    ("sha1", re.compile(r"^[0-9a-fA-F]{40}$")),
    ("md5", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("md4", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("ntlm", re.compile(r"^[0-9a-fA-F]{32}$")),
    ("lm", re.compile(r"^[0-9a-fA-F]{16}$")),
]

ALIASES = {
    "md5": ("md5",), "sha1": ("sha1",), "sha256": ("sha256",), "sha512": ("sha512",),
    "sha224": ("sha224",), "sha384": ("sha384",), "ntlm": ("ntlm",), "bcrypt": ("bcrypt",),
    "md4": ("md4",), "lm": ("lm",),
}
JOHN_FORMATS = {"md5": "raw-md5", "sha1": "raw-sha1", "sha256": "raw-sha256", "sha512": "raw-sha512", "ntlm": "ntlm", "bcrypt": "bcrypt"}
HASHCAT_MODES = {"md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700, "ntlm": 1000, "bcrypt": 3200}


def identify(value: str, hint: str = "") -> Dict[str, Any]:
    candidate = value.strip()
    entry: Dict[str, Any] = {"hash": candidate, "length": len(candidate), "identified_types": [], "possible_user": ""}
    if ":" in candidate and not candidate.startswith("$"):
        user, _, remainder = candidate.rpartition(":")
        if user:
            entry["possible_user"] = user
            candidate = remainder.strip()
            entry["hash"] = candidate
            entry["length"] = len(candidate)
    if not candidate:
        entry["note"] = "empty hash"
        return entry

    matches = [name for name, pattern in PATTERNS if pattern.fullmatch(candidate)]
    if hint:
        wanted = [name for name in matches if name in ALIASES.get(hint.lower(), (hint.lower(),))]
        if wanted:
            matches = wanted
    entry["identified_types"] = matches
    if not matches:
        entry["note"] = "unrecognised format (may be salted, encoded or not a supported hash)"
    elif len(matches) > 1:
        entry["note"] = "several formats share this length; context/hint needed"
    return entry


def _read_hashes(options: Dict[str, Any], workspace: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    inline = options.get("hash", "")
    hashfile = options.get("hashfile", "")
    hint = str(options.get("hash_type", "") or "")
    analysis: Dict[str, Any] = {"source": "", "lines": 0, "empty_lines": 0, "format_counts": {}, "unrecognised": []}

    if inline:
        analysis["source"] = "command-line"
        return [identify(inline, hint)], analysis
    if not hashfile or not Path(hashfile).is_file():
        return [], {"source": "none", "note": "no --hashfile or --hash provided; identification only"}

    analysis["source"] = str(hashfile)
    try:
        lines = Path(hashfile).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        analysis["error"] = str(exc)
        return [], analysis
    analysis["lines"] = len(lines)
    entries: List[Dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for line in lines:
        if not line.strip():
            analysis["empty_lines"] += 1
            continue
        entry = identify(line, hint)
        if not entry["identified_types"]:
            analysis["unrecognised"].append(line.strip()[:120])
        for kind in entry["identified_types"]:
            counts[kind] += 1
        entry["line_number"] = len(entries) + 1
        entries.append(entry)
    analysis["format_counts"] = dict(counts)
    copied = workspace.file("hash", "hashes_copy.txt")
    write_text(copied, "\n".join(lines))
    analysis["copy"] = copied.name
    return entries, analysis


def _john(hashfile: str, wordlist: str, fmt: str, workspace: Any, timeout: int, logger: Any) -> Dict[str, Any]:
    pot = workspace.file("hash", "john.pot")
    session = workspace.file("hash", "john_session")
    result: Dict[str, Any] = {"tool": "john", "format": fmt, "wordlist": wordlist, "time_limit": timeout}
    run_result = run_command(
        ["john", f"--wordlist={wordlist}", f"--format={fmt}", f"--pot={pot}", f"--session={session}", hashfile],
        timeout=timeout,
    )
    result["returncode"] = run_result.get("returncode")
    result["timed_out"] = run_result.get("timed_out", False)
    result["error"] = run_result.get("error", "")
    write_text(workspace.file("hash", "john_output.txt"), truncate(run_result.get("stdout", "") + "\n" + run_result.get("stderr", ""), 30000))
    show = run_command(["john", "--show", f"--format={fmt}", f"--pot={pot}", hashfile], timeout=30)
    result["cracked"] = [line.strip()[:300] for line in show.get("stdout", "").splitlines() if ":" in line][:200]
    result["cracked_count"] = len(result["cracked"])
    logger.info("john finished: %d cracked", result["cracked_count"])
    return result


def _hashcat(hashfile: str, wordlist: str, mode: int, workspace: Any, timeout: int, logger: Any, cpu_only: bool) -> Dict[str, Any]:
    pot = workspace.file("hash", "hashcat.potfile")
    cmd = ["hashcat", "-m", str(mode), "-a", "0", hashfile, wordlist, "--potfile-path", str(pot), "--quiet", "--force"]
    if cpu_only:
        cmd.append("--backend-ignore-cuda")
    result: Dict[str, Any] = {"tool": "hashcat", "mode": mode, "wordlist": wordlist, "time_limit": timeout}
    run_result = run_command(cmd, timeout=timeout)
    result["returncode"] = run_result.get("returncode")
    result["timed_out"] = run_result.get("timed_out", False)
    result["error"] = run_result.get("error", "")
    result["note"] = "--force used: CPU/weak OpenCL backends allowed"
    write_text(workspace.file("hash", "hashcat_output.txt"), truncate(run_result.get("stdout", "") + "\n" + run_result.get("stderr", ""), 30000))
    show = run_command(["hashcat", "-m", str(mode), "--show", "--potfile-path", str(pot), hashfile], timeout=30)
    result["cracked"] = [line.strip()[:300] for line in show.get("stdout", "").splitlines() if ":" in line][:200]
    result["cracked_count"] = len(result["cracked"])
    logger.info("hashcat finished: %d cracked", result["cracked_count"])
    return result


def run(
    target: str,
    workspace: Any,
    config: Dict[str, Any],
    logger: Any,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Identify hashes and optionally audit them with a local wordlist."""
    options = options or {}
    logger = ensure_logger(logger, "hash")
    started = utcnow()
    cached = workspace.fresh_json(
        "hash", "hash.json",
        config.get("general", {}).get("max_result_age_hours", 24),
        options.get("reuse", False),
    )
    if isinstance(cached, dict) and cached.get("status") in ("success", "partial"):
        logger.info("reusing cached hash results")
        return cached
    hash_config = config.get("scan", {}).get("hash", {})
    timeout = int(options.get("timeout", config.get("general", {}).get("default_timeout", 120)))
    max_time = min(timeout, int(hash_config.get("max_crack_time", 300)))
    hashfile = str(options.get("hashfile", "") or "")
    wordlist = str(options.get("wordlist", "") or "")

    hashes, analysis = _read_hashes(options, workspace)
    results: Dict[str, Any] = {"offline_only": True, "performed": False, "cracks": [], "notes": []}
    if options.get("no_crack"):
        results["notes"].append("cracking disabled by --no-crack; identification only")
    elif not hashes:
        results["notes"].append("no hashes provided; no wordlist attack attempted")
    elif not hashfile or not Path(hashfile).is_file():
        results["notes"].append("inline hash only: supply --hashfile to run a wordlist audit")
    elif not wordlist or not Path(wordlist).is_file():
        results["notes"].append("no valid --wordlist supplied; no wordlist attack attempted")
    else:
        dominant = "md5"
        counts: Counter[str] = Counter()
        for entry in hashes:
            for kind in entry.get("identified_types", []):
                counts[kind] += 1
        if counts:
            dominant = counts.most_common(1)[0][0]
        hint = str(options.get("hash_type", "") or "").lower()
        if hint in JOHN_FORMATS:
            dominant = hint
        logger.info("offline audit with %s on %s", dominant, Path(hashfile).name)
        results["performed"] = True
        if tool_available("john") and dominant in JOHN_FORMATS:
            results["cracks"].append(_john(hashfile, wordlist, JOHN_FORMATS[dominant], workspace, max_time, logger))
        elif tool_available("hashcat") and dominant in HASHCAT_MODES:
            results["cracks"].append(_hashcat(hashfile, wordlist, HASHCAT_MODES[dominant], workspace, max_time, logger, bool(hash_config.get("hashcat_cpu_only", True))))
        else:
            results["notes"].append(f"no supported offline tool for type '{dominant}'")
            results["performed"] = False

    findings: List[Dict[str, Any]] = []
    for entry in hashes:
        types = entry.get("identified_types", [])
        if types:
            findings.append({
                "title": f"Hash identified as {', '.join(types)}",
                "severity": "info",
                "status": "confirmed",
                "evidence": f"length={entry['length']} value={entry['hash'][:24]}...",
                "recommendation": "Use only offline auditing with data you are authorized to process.",
                "source": "hash",
            })

    data: Dict[str, Any] = {
        "offline_only": True,
        "hashes": hashes,
        "file_analysis": analysis,
        "crack_results": results,
        "findings": findings,
        "supported_types": ["md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt", "md4", "lm", "sha224", "sha384"],
        "warning": "No online password attacks are performed by HAKIMIX.",
    }
    envelope = module_envelope("hash", target, data, "success", [], started)
    workspace.save("hash", "hash.json", envelope)
    logger.info("hash module complete: %d hash(es) analysed", len(hashes))
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = base_parser(
        "HAKIMIX HASH - offline hash identification and wordlist auditing",
        "examples:\n"
        "  python3 hash.py localhost -y --hash 5d41402abc4b2a76b9719d911017c592\n"
        "  python3 hash.py localhost -y --hashfile hashes.txt --wordlist rockyou.txt --hash-type ntlm",
    )
    parser.add_argument("--hash", help="single hash value to identify")
    parser.add_argument("--hashfile", help="file containing hashes (one per line, optional user:hash)")
    parser.add_argument("--wordlist", help="local wordlist for offline auditing")
    parser.add_argument("--hash-type", help="type hint: md5, sha1, sha256, sha512, ntlm, bcrypt")
    parser.add_argument("--no-crack", action="store_true", help="only identify hashes")
    args = parser.parse_args(argv)
    if not args.target:
        args.target = "localhost"
    target, workspace, config, logger, options = prepare(args, "hash")
    for key in ("hash", "hashfile", "wordlist", "hash_type", "no_crack"):
        options[key] = getattr(args, key)
    envelope = run(target, workspace, config, logger, options)
    print(f"[hash] status={envelope['status']} hashes={len(envelope['data']['hashes'])} output={workspace.dir('hash')}")
    for entry in envelope["data"]["hashes"][:10]:
        print(f"  {entry['hash'][:32]} -> {', '.join(entry['identified_types']) or 'unknown'}")
    for note in envelope["data"]["crack_results"]["notes"]:
        print(f"[note] {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
