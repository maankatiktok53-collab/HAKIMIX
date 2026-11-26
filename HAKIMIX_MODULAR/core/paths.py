#!/usr/bin/env python3
"""Workspace and JSON-based communication layer for HAKIMIX modules."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .utils import ROOT, safe_name, utcnow, write_json, read_json, WorkspaceError

MODULE_DIRS = ("recon", "web", "network", "analysis", "privesc", "hash", "report")

DEFAULT_DATA_FILES = {
    "recon": "recon.json",
    "web": "web.json",
    "network": "network.json",
    "analysis": "analysis.json",
    "privesc": "privesc.json",
    "hash": "hash.json",
}


class Workspace:
    """Own all paths for one target and the shared module manifest.

    Modules exchange data only through JSON files under this workspace,
    which keeps every script independently runnable.
    """

    def __init__(
        self,
        target: str,
        root: Optional[os.PathLike | str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target = str(target)
        self.root = Path(root) if root else ROOT
        general = (config or {}).get("general", {})
        self.base = self.root / general.get("output_dir", "output") / safe_name(self.target)
        self.dirs: Dict[str, Path] = {name: self.base / name for name in MODULE_DIRS}
        self.manifest_file = self.base / "manifest.json"
        self.log_file = self.base / "hakimix.log"

    def ensure(self) -> "Workspace":
        try:
            self.base.mkdir(parents=True, exist_ok=True)
            for directory in self.dirs.values():
                directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"cannot create workspace {self.base}: {exc}") from exc
        return self

    def dir(self, module: str) -> Path:
        if module not in self.dirs:
            raise WorkspaceError(f"unknown module directory: {module}")
        path = self.dirs[module]
        path.mkdir(parents=True, exist_ok=True)
        return path

    def file(self, module: str, filename: str) -> Path:
        return self.dir(module) / filename

    def save(self, module: str, filename: str, data: Any) -> Optional[Path]:
        path = self.file(module, filename)
        return path if write_json(path, data) else None

    def load(self, module: str, filename: str, default: Any = None) -> Any:
        return read_json(self.file(module, filename), default)

    def data_file(self, module: str) -> str:
        return DEFAULT_DATA_FILES.get(module, f"{module}.json")

    def load_module(self, module: str, default: Any = None) -> Any:
        return self.load(module, self.data_file(module), default)

    def load_manifest(self) -> Dict[str, Any]:
        manifest = read_json(self.manifest_file, None)
        if not isinstance(manifest, dict):
            manifest = {"target": self.target, "created_at": utcnow(), "modules": {}}
        manifest.setdefault("modules", {})
        return manifest

    def save_manifest(self, manifest: Dict[str, Any]) -> bool:
        manifest["target"] = self.target
        manifest["updated_at"] = utcnow()
        return write_json(self.manifest_file, manifest)

    def record(
        self,
        module: str,
        status: str,
        errors: Optional[List[str]] = None,
        data_files: Optional[List[str]] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        manifest = self.load_manifest()
        entry: Dict[str, Any] = {
            "status": status,
            "at": utcnow(),
            "errors": errors or [],
            "data_files": data_files or [],
        }
        if detail:
            entry["detail"] = detail
        manifest["modules"][module] = entry
        self.save_manifest(manifest)
        return manifest

    def status(self, module: str) -> str:
        return str(self.load_manifest()["modules"].get(module, {}).get("status", "not_run"))

    def fresh_json(
        self,
        module: str,
        filename: str,
        max_age_hours: float = 24,
        reuse: bool = False,
    ) -> Optional[Any]:
        """Return cached JSON only when reuse is enabled and data is fresh."""
        if not reuse:
            return None
        path = self.file(module, filename)
        if not path.exists():
            return None
        try:
            age_hours = (time.time() - path.stat().st_mtime) / 3600
        except OSError:
            return None
        if age_hours > max_age_hours:
            return None
        return read_json(path, None)

    def tree_summary(self) -> Dict[str, List[str]]:
        summary: Dict[str, List[str]] = {}
        for module, directory in self.dirs.items():
            try:
                summary[module] = sorted(p.name for p in directory.iterdir() if p.is_file())
            except OSError:
                summary[module] = []
        return summary
