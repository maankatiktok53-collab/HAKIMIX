#!/usr/bin/env python3
"""Shared helper functions used by every HAKIMIX module.

Only the Python standard library is used here so the toolkit stays
lightweight on Kali Linux with limited RAM.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent

BANNER = r"""
 _   _                 _      __  __ _   _
| | | |_   _ _ __ ___ | |__  |  \/  | | | |
| |_| | | | | '_ ` _ \| '_ \ | |\/| | | | |
|  _  | |_| | | | | | | | | || |  | | |_| |
|_| |_|\__,_|_| |_| |_|_| |_||_|  |_|\___/
        HTB / OSCP / CTF automation toolkit
"""

AUTHORIZATION_NOTICE = (
    "HAKIMIX is only for HTB labs, CTF challenges and systems you are "
    "explicitly authorized to test."
)


class WorkspaceError(Exception):
    """Raised when the output workspace cannot be prepared."""


def utcnow() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config(path: Optional[os.PathLike | str] = None) -> Dict[str, Any]:
    """Load config.json. Never raises: an empty config is usable."""
    config_path = Path(path) if path else ROOT / "config.json"
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        print(f"[warn] could not read {config_path}: {exc}", file=sys.stderr)
        return {}


def get_logger(
    name: str,
    log_file: Optional[os.PathLike | str] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Return a logger with stream + optional file handler (no duplicates)."""
    logger = logging.getLogger(f"hakimix.{name}")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("could not open log file %s: %s", log_file, exc)
    return logger


def validate_target(value: str) -> Dict[str, Any]:
    """Validate an IP address or hostname and normalise it.

    Returns ``{"valid", "value", "type", "error"}``. A URL is reduced to
    its host component so users can paste ``http://target/path`` safely.
    """
    result: Dict[str, Any] = {"valid": False, "value": "", "type": "", "error": ""}
    if not isinstance(value, str) or not value.strip():
        result["error"] = "empty target"
        return result

    target = value.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()

    if target.startswith("[") and "]" in target:
        target = target[1 : target.index("]")]
    else:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if target.count(":") == 1:
                target = target.rsplit(":", 1)[0]

    if not target or len(target) > 253:
        result["error"] = "invalid target length"
        return result

    try:
        ipaddress.ip_address(target)
        result.update(valid=True, value=target, type="ip")
        return result
    except ValueError:
        pass

    if (
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?", target)
        and re.search(r"[A-Za-z]", target)
    ):
        result.update(valid=True, value=target.lower(), type="domain")
        return result

    result["error"] = "not a valid IP address or hostname"
    return result


def safe_name(target: str) -> str:
    """Make a target safe to use as a directory name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target).strip()).strip("._-")
    return (cleaned or "target")[:120]


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def check_tools(names: Iterable[str]) -> Dict[str, bool]:
    return {name: tool_available(name) for name in names}


def run_command(
    cmd: Sequence[str],
    timeout: int = 60,
    cwd: Optional[os.PathLike | str] = None,
    stdin_data: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run a command without a shell and always return a structured result."""
    started = time.time()
    result: Dict[str, Any] = {
        "command": list(cmd),
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "error": "",
        "duration": 0.0,
    }
    try:
        proc = subprocess.run(
            list(cmd),
            stdin=subprocess.PIPE if stdin_data is not None else None,
            input=stdin_data.encode() if stdin_data is not None else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout)),
            cwd=str(cwd) if cwd else None,
            env=env,
            check=False,
        )
        result.update(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except FileNotFoundError:
        result["error"] = f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        result["stdout"] = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        result["stderr"] = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        result["error"] = f"timeout after {timeout}s"
    except OSError as exc:
        result["error"] = str(exc)
    result["duration"] = round(time.time() - started, 2)
    return result


def write_json(path: os.PathLike | str, data: Any) -> bool:
    """Atomically write JSON data. Returns True on success."""
    target = Path(path)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=False, default=str)
            handle.write("\n")
        os.replace(tmp, target)
        return True
    except (OSError, TypeError, ValueError) as exc:
        print(f"[warn] could not write {target}: {exc}", file=sys.stderr)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def read_json(path: os.PathLike | str, default: Any = None) -> Any:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_text(path: os.PathLike | str, content: str) -> bool:
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content or "", encoding="utf-8", errors="replace")
        return True
    except OSError as exc:
        print(f"[warn] could not write {path}: {exc}", file=sys.stderr)
        return False


def read_text(path: os.PathLike | str, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def parse_port_spec(spec: str) -> List[int]:
    """Parse ``80,443,8000-8010`` into a sorted list of unique ports."""
    ports: set[int] = set()
    for chunk in str(spec).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            bounds = chunk.split("-", 1)
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError:
                continue
            if 1 <= start <= end <= 65535 and end - start <= 65535:
                ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def dedupe(items: Iterable[Any]) -> List[Any]:
    seen: set[str] = set()
    output: List[Any] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output


def truncate(text: str, limit: int = 20000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def clean_lines(text: str, limit: Optional[int] = None) -> List[str]:
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    return lines[:limit] if limit else lines


def guess_scheme(port: int) -> str:
    return "https" if int(port) in (443, 8443, 9443) else "http"


def build_url(target: str, port: int, scheme: Optional[str] = None, is_ip: bool = True) -> str:
    host = str(target)
    if not is_ip and ":" not in host:
        host = host
    elif ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme or guess_scheme(port)}://{host}:{port}"


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    """Gate active scans behind an explicit authorisation confirmation."""
    if assume_yes:
        return True
    print("\n" + AUTHORIZATION_NOTICE)
    print(f"Target: {target}")
    try:
        answer = input("Confirm you are authorized to test this target [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def print_banner() -> None:
    print(BANNER)


def ensure_logger(logger: Any, name: str = "module") -> Any:
    """Return a usable logger even when a caller passes None."""
    if logger is not None:
        return logger
    fallback = logging.getLogger(f"hakimix.{name}.null")
    if not fallback.handlers:
        fallback.addHandler(logging.NullHandler())
    return fallback


def module_envelope(
    module: str,
    target: str,
    data: Dict[str, Any],
    status: str = "success",
    errors: Optional[List[str]] = None,
    started_at: str = "",
) -> Dict[str, Any]:
    """Build the standard result wrapper used by all modules."""
    return {
        "module": module,
        "target": target,
        "status": status,
        "started_at": started_at or utcnow(),
        "finished_at": utcnow(),
        "errors": errors or [],
        "data": data,
    }
