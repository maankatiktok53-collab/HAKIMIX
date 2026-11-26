#!/usr/bin/env python3
"""HAKIMIX main controller.

Orchestrates every module, stores each result as JSON, and builds the
final report. Every module can also be executed on its own.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import Workspace  # noqa: E402
from core.report import generate as generate_report  # noqa: E402
from core.utils import (  # noqa: E402
    ROOT,
    check_tools,
    confirm_authorization,
    get_logger,
    load_config,
    module_envelope,
    print_banner,
    utcnow,
    validate_target,
    write_json,
)

REGISTRY: "OrderedDict[str, List[Tuple[str, str]]]" = OrderedDict(
    [
        ("recon", [("recon", "01_RECON/recon.py")]),
        ("network", [("nmap", "03_NETWORK/nmap_scan.py"), ("dns", "03_NETWORK/dns_enum.py"), ("service", "03_NETWORK/service_enum.py")]),
        ("web", [("web", "02_WEB/web.py")]),
        ("analysis", [("analysis", "04_ANALYSIS/analysis.py")]),
        ("privesc", [("linux", "05_PRIVESC/linux_privesc.py"), ("windows", "05_PRIVESC/windows_privesc.py")]),
        ("hash", [("hash", "06_HASH/hash.py")]),
    ]
)

MODULE_HELP: Dict[str, str] = {
    "recon": "Target validation, DNS/WHOIS, subdomains and profiling",
    "network": "Nmap TCP scan, DNS records, service and banner enumeration",
    "web": "HTTP detection, headers, technologies, paths, TLS and vhosts",
    "analysis": "Correlates all results and prioritises next steps",
    "privesc": "Read-only Linux/Windows local privilege-escalation checks",
    "hash": "Offline hash identification and wordlist auditing",
    "all": "Run every module in dependency order",
}


def list_modules() -> None:
    print("\nAvailable modules:")
    for name, scripts in REGISTRY.items():
        print(f"  {name:<10} {MODULE_HELP[name]}")
        for key, script in scripts:
            print(f"             - {key}: {script}")


def show_tools(config: Dict[str, Any]) -> Dict[str, bool]:
    tools = config.get("tools", {})
    availability = check_tools(tools.keys())
    print("\nTool availability:")
    for name, available in availability.items():
        required = "required" if tools.get(name, {}).get("required") else "optional"
        print(f"  {name:<14} {'OK      ' if available else 'MISSING '} ({required})")
    return availability


def load_runner(script: str) -> Tuple[Optional[Callable[..., Any]], str]:
    path = ROOT / script
    if not path.is_file():
        return None, f"script missing: {script}"
    module_name = f"hakimix_dynamic_{script.replace('/', '_').replace('.', '_')}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            return None, f"cannot load {script}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        runner = getattr(module, "run", None)
        if not callable(runner):
            return None, f"no run() function in {script}"
        return runner, ""
    except Exception as exc:  # noqa: BLE001 - a broken module must not kill the controller
        return None, f"failed to load {script}: {type(exc).__name__}: {exc}"


def run_module(
    name: str,
    target: str,
    workspace: Workspace,
    config: Dict[str, Any],
    logger: Any,
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute all scripts of one module, saving partial results on failure."""
    started = utcnow()
    logger.info("[%s] starting", name.upper())
    results: Dict[str, Any] = {}
    errors: List[str] = []
    data_files: List[str] = []

    for key, script in REGISTRY[name]:
        runner, load_error = load_runner(script)
        if runner is None:
            errors.append(load_error)
            envelope = module_envelope(key, target, {}, "failed", [load_error], started)
        else:
            try:
                envelope = runner(target, workspace, config, logger, options)
                if not isinstance(envelope, dict):
                    raise TypeError("module run() did not return a dict")
                envelope.setdefault("module", key)
                envelope.setdefault("target", target)
                envelope.setdefault("status", "success")
                envelope.setdefault("errors", [])
                envelope.setdefault("data", {})
                envelope.setdefault("started_at", started)
            except Exception as exc:  # noqa: BLE001 - keep going, never lose other results
                message = f"{key}: {type(exc).__name__}: {exc}"
                logger.exception("[%s] %s failed: %s", name.upper(), key, exc)
                errors.append(message)
                envelope = module_envelope(key, target, {}, "failed", [message], started)

        results[key] = envelope
        written = workspace.save(name, f"{key}.json", envelope)
        if written:
            data_files.append(f"{key}.json")
        for error in envelope.get("errors", []):
            errors.append(f"{key}: {error}")

    merged: Dict[str, Any] = {}
    for key, envelope in results.items():
        merged[key] = envelope
        payload = envelope.get("data")
        if isinstance(payload, dict):
            merged.update(payload)

    statuses = [env.get("status", "failed") for env in results.values()]
    effective = ["success" if item == "skipped" else item for item in statuses]
    if all(item == "success" for item in effective):
        status = "success"
    elif any(item in ("success", "partial") for item in effective):
        status = "partial"
    else:
        status = "failed"

    aggregate = module_envelope(name, target, merged, status, errors, started)
    aggregate["scripts"] = {key: env.get("status") for key, env in results.items()}
    data_file = workspace.data_file(name)
    written = workspace.save(name, data_file, aggregate)
    if written:
        data_files.append(data_file)
    workspace.record(name, status, errors, list(dict.fromkeys(data_files)), {"scripts": aggregate["scripts"]})
    logger.info("[%s] finished: %s (%d error(s))", name.upper(), status, len(errors))
    return aggregate


def choose_modules_interactive() -> Optional[List[str]]:
    print_banner()
    print("HAKIMIX menu")
    print("  1) Full run (all modules)")
    print("  2) Run one module")
    print("  3) Check tool availability")
    print("  4) List modules")
    print("  0) Exit")
    try:
        choice = input("\nSelect [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None

    if choice == "0":
        return None
    if choice == "3":
        show_tools(load_config())
        return None
    if choice == "4":
        list_modules()
        return None

    if choice == "1":
        selected = list(REGISTRY.keys())
    elif choice == "2":
        list_modules()
        try:
            selected_name = input("Module name: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if selected_name not in REGISTRY:
            print(f"[!] unknown module: {selected_name}")
            return None
        selected = [selected_name]
    else:
        print("[!] invalid selection")
        return None

    try:
        target = input("Target (IP / hostname): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not target:
        print("[!] no target provided")
        return None
    return [target, ",".join(selected)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hakimix.py",
        description="HAKIMIX - HTB / OSCP / CTF automation toolkit (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 hakimix.py 10.10.11.25\n"
            "  python3 hakimix.py 10.10.11.25 --module recon\n"
            "  python3 hakimix.py target.htb --module web --reuse\n"
            "  python3 hakimix.py 10.10.11.25 --full-scan --yes\n"
        ),
    )
    parser.add_argument("target", nargs="?", help="target IP address or hostname")
    parser.add_argument("-m", "--module", default="all", choices=list(REGISTRY) + ["all"], help="module to run (default: all)")
    parser.add_argument("--all", action="store_true", help="run all modules (same as --module all)")
    parser.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt (you must be authorized)")
    parser.add_argument("--reuse", action="store_true", help="reuse fresh existing JSON results instead of rescanning")
    parser.add_argument("--full-scan", action="store_true", help="allow full 1-65535 TCP port scan")
    parser.add_argument("--timeout", type=int, default=0, help="override command timeout in seconds")
    parser.add_argument("--config", default=str(ROOT / "config.json"), help="path to config.json")
    parser.add_argument("--output-dir", help="override output directory")
    parser.add_argument("--wordlist", help="wordlist for directory/subdomain discovery")
    parser.add_argument("--hash", help="single hash value for the hash module")
    parser.add_argument("--hashfile", help="hash file for the hash module (offline only)")
    parser.add_argument("--hash-type", help="hint for hash type (md5, sha1, sha256, sha512, ntlm, bcrypt)")
    parser.add_argument("--user", help="hash owner/username hint")
    parser.add_argument("--no-crack", action="store_true", help="only identify hashes, do not run john/hashcat")
    parser.add_argument("--no-report", action="store_true", help="skip final report generation")
    parser.add_argument("--check-tools", action="store_true", help="show installed tools and exit")
    parser.add_argument("--list-modules", action="store_true", help="show modules and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        list_modules()
        return 0
    if args.check_tools:
        show_tools(load_config(args.config))
        return 0

    if not args.target:
        interactive = choose_modules_interactive()
        if not interactive:
            return 0
        args.target, args.module = interactive

    validation = validate_target(args.target)
    if not validation["valid"]:
        print(f"[!] invalid target: {validation['error']}")
        return 2
    target = validation["value"]

    config = load_config(args.config)
    if args.output_dir:
        config.setdefault("general", {})["output_dir"] = args.output_dir
    if args.timeout > 0:
        config.setdefault("general", {})["default_timeout"] = args.timeout
    if args.reuse:
        config["general"]["reuse_existing"] = True
    if args.verbose:
        config["general"]["verbose"] = True
    if args.wordlist:
        config.setdefault("scan", {}).setdefault("web", {})["directory_wordlist"] = args.wordlist
        config["scan"].setdefault("dns", {})["subdomain_wordlist"] = args.wordlist

    print_banner()
    show_tools(config)

    if config.get("general", {}).get("confirm_authorization", True) and not confirm_authorization(target, args.yes):
        print("[!] authorization not confirmed - nothing was executed")
        return 3

    try:
        workspace = Workspace(target, config=config).ensure()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] workspace error: {exc}")
        return 2

    logger = get_logger("controller", workspace.log_file, args.verbose)

    options: Dict[str, Any] = {
        "authorized": True,
        "reuse": bool(args.reuse or config.get("general", {}).get("reuse_existing", False)),
        "timeout": int(config.get("general", {}).get("default_timeout", 120)),
        "verbose": bool(args.verbose),
        "full_scan": bool(args.full_scan),
        "wordlist": args.wordlist,
        "hash": args.hash,
        "hashfile": args.hashfile,
        "hash_type": args.hash_type,
        "user": args.user,
        "no_crack": bool(args.no_crack),
        "target_type": validation["type"],
    }

    selected = list(REGISTRY.keys()) if (args.module == "all" or args.all) else [args.module]
    summary: Dict[str, str] = {}
    for name in selected:
        aggregate = run_module(name, target, workspace, config, logger, options)
        summary[name] = str(aggregate.get("status"))

    if not args.no_report:
        try:
            generate_report(workspace, config)
            summary["report"] = "success"
        except Exception as exc:  # noqa: BLE001
            logger.exception("report generation failed: %s", exc)
            summary["report"] = "failed"
            write_json(workspace.file("report", "error.json"), {"error": str(exc)})

    print("\n=== HAKIMIX summary ===")
    for name, status in summary.items():
        print(f"  {name:<12} {status}")
    print(f"  Output: {workspace.base}")
    if not args.no_report:
        print(f"  Report: {workspace.file('report', 'report.html')}")
    return 0 if all(status in ("success", "partial") for status in summary.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
