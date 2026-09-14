"""Shared pytest policy for lab-scout.

A skipped test is a failure here: a skip hides a guard that never ran, and a
green run that silently skipped it manufactures confidence.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Any

import pytest

_SKIPPED: list[str] = []


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        _SKIPPED.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if _SKIPPED and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if _SKIPPED:
        terminalreporter.write_line(f"FAILING THE RUN: {len(_SKIPPED)} test(s) skipped: {', '.join(_SKIPPED)}", red=True)


class NetworkRefused(OSError):
    pass


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process HTTP and DNS are refused, so a missed seam fails loudly
    instead of reaching GitHub, Discord or the web."""

    def refuse_open(self: Any, fullurl: Any, data: Any = None, timeout: Any = None) -> Any:
        raise urllib.error.URLError("sandbox: network refused")

    def refuse_dns(*args: Any, **kwargs: Any) -> Any:
        raise NetworkRefused("sandbox: DNS refused")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse_open)
    monkeypatch.setattr(socket, "getaddrinfo", refuse_dns)
