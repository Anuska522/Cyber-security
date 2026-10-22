"""Ingestion subsystem for SecretGuard."""

from secretguard.ingest.fs_scanner import FileSystemScanner
from secretguard.ingest.git_diff import GitDiffParser
from secretguard.ingest.ignore import IgnoreMatcher

__all__ = [
    "FileSystemScanner",
    "GitDiffParser",
    "IgnoreMatcher",
]
