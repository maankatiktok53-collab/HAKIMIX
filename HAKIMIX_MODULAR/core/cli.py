#!/usr/bin/env python3
"""Shared CLI bootstrap used by every standalone HAKIMIX module."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Tuple

from .paths import Workspace
from .utils import (
    ROOT,
    confirm_authorization,
    get_logger,
    load_config,
    validate_target,
)


def base_parser(description: str, epilog: str = "") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog or "For authorized HTB / CTF / penetration testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="target IP address or hostname")
    parser.add_argument("--config", default=str(ROOT / "config.json"), help="path to config.json")
    parser.add_argument("--output-dir", help="override output directory")
    parser.add_argument("--timeout", type=int, default=0, help="override command timeout")
    parser.add_argument("--reuse", action="store_true", help="reuse fresh cached JSON results")
    parser.add_argument("-y", "--yes", action="store_true", help="skip authorization prompt")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    return parser


def prepare(args: argparse.Namespace, module: str) -> Tuple[str, Workspace, Dict[str, Any], Any, Dict[str, Any]]:
    """Validate CLI arguments and return the standard module context."""
    validation = validate_target(args.target or "")
    if not validation["valid"]:
        raise SystemExit(f"[!] invalid target: {validation['error']}")

    target = validation["value"]
    config = load_config(args.config)
    general = config.setdefault("general", {})
    if getattr(args, "output_dir", None):
        general["output_dir"] = args.output_dir
    if getattr(args, "timeout", 0) > 0:
        general["default_timeout"] = args.timeout
    if getattr(args, "reuse", False):
        general["reuse_existing"] = True
    if getattr(args, "verbose", False):
        general["verbose"] = True

    if general.get("confirm_authorization", True) and not confirm_authorization(target, getattr(args, "yes", False)):
        raise SystemExit("[!] authorization not confirmed - nothing was executed")

    workspace = Workspace(target, config=config).ensure()
    logger = get_logger(module, workspace.log_file, general.get("verbose", False))

    options = {
        "authorized": True,
        "reuse": bool(general.get("reuse_existing", False)),
        "timeout": int(general.get("default_timeout", 120)),
        "verbose": bool(general.get("verbose", False)),
        "target_type": validation["type"],
    }
    for key in ("wordlist", "hashfile", "hash_type", "user", "no_crack", "full_scan"):
        if hasattr(args, key):
            options[key] = getattr(args, key)
    return target, workspace, config, logger, options
