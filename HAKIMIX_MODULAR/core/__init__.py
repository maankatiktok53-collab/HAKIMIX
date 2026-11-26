"""HAKIMIX core package: shared utilities for every module."""

from .paths import Workspace, WorkspaceError  # noqa: F401
from .utils import ROOT  # noqa: F401

__all__ = ["ROOT", "Workspace", "WorkspaceError"]
