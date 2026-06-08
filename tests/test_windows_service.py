from __future__ import annotations

import service_windows


def test_windows_service_reports_unsupported_on_non_windows():
    if service_windows.supported():
        assert service_windows.install_or_dispatch(["status"]) in {"handled", "missing_pywin32_dependency"}
    else:
        assert service_windows.install_or_dispatch(["status"]) == "unsupported_platform"


def test_main_parser_accepts_windows_service_subcommand():
    from main import build_parser

    args = build_parser().parse_args(["--windows-service", "status"])

    assert args.windows_service == ["status"]
