"""
CyberRecon Final Repository Audit

This script performs a read-only audit of the final
CyberRecon repository before the codebase is frozen.

Usage:

    uv run python scripts/project_audit.py
"""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys

from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


# =========================================================
# CONFIGURATION
# =========================================================


REQUIRED_FILES = [
    "README.md",
    "pyproject.toml",
    "uv.lock",
    ".gitignore",
    ".env.example",

    "run.py",
    "wsgi.py",

    "src/cyberrecon/__init__.py",
    "src/cyberrecon/app.py",
    "src/cyberrecon/storage.py",

    "src/cyberrecon/scanner/__init__.py",
    "src/cyberrecon/scanner/assessment.py",
    "src/cyberrecon/scanner/comparison.py",
    "src/cyberrecon/scanner/reconnaissance.py",
    "src/cyberrecon/scanner/security_analysis.py",
    "src/cyberrecon/scanner/target.py",

    "src/cyberrecon/templates/index.html",
    "src/cyberrecon/templates/results.html",
    "src/cyberrecon/templates/dashboard.html",
    "src/cyberrecon/templates/history.html",
    "src/cyberrecon/templates/scan_detail.html",
    "src/cyberrecon/templates/compare.html",
    "src/cyberrecon/templates/report.html",
    "src/cyberrecon/templates/login.html",
    "src/cyberrecon/templates/register.html",

    "src/cyberrecon/static/css/style.css",

    "demo_target/app.py",

    "scripts/final_validation.py",
    "scripts/project_audit.py",

    "tests/conftest.py",
    "tests/test_target.py",
    "tests/test_security_analysis.py",
    "tests/test_storage.py",
    "tests/test_auth.py",
    "tests/test_app_integration.py",
    "tests/test_security_hardening.py",
    "tests/test_csrf.py",
    "tests/test_ssrf_protection.py",
    "tests/test_production_config.py",
]


REQUIRED_ROUTES = {
    "/",
    "/register",
    "/login",
    "/logout",
    "/scan",
    "/dashboard",
    "/history",
    "/history/<scan_id>",
    "/history/<scan_id>/report",
    "/compare",
}


SUSPICIOUS_TRACKED_PATTERNS = (
    ".env",
    ".session_secret",
    ".db",
    ".db-wal",
    ".db-shm",
    "__pycache__",
    ".pytest_cache",
    ".venv",
)


STALE_TEXT_PATTERNS = (
    "Review 1",
    "review 1",
    "30%",
    "seven passive checks",
    "Seven passive checks",
    "seven security checks",
    "Seven security checks",
    "only seven",
    "v0.6",
)


TODO_PATTERNS = (
    "TODO",
    "FIXME",
    "XXX",
)


TEXT_EXTENSIONS = {
    ".py",
    ".md",
    ".html",
    ".css",
    ".toml",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
}


# =========================================================
# OUTPUT HELPERS
# =========================================================


def heading(title: str) -> None:

    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def passed(message: str) -> None:

    print(
        f"[PASS] {message}"
    )


def failed(message: str) -> None:

    print(
        f"[FAIL] {message}"
    )


def warning(message: str) -> None:

    print(
        f"[WARN] {message}"
    )


def info(message: str) -> None:

    print(
        f"[INFO] {message}"
    )


# =========================================================
# COMMAND HELPER
# =========================================================


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:

    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )


# =========================================================
# CHECK 1
# =========================================================


def check_required_files() -> bool:

    heading(
        "1. REQUIRED FILES"
    )

    missing = []


    for relative_path in REQUIRED_FILES:

        path = (
            PROJECT_ROOT
            / relative_path
        )


        if path.exists():

            passed(
                relative_path
            )

        else:

            failed(
                relative_path
            )

            missing.append(
                relative_path
            )


    if missing:

        failed(
            f"{len(missing)} required file(s) missing."
        )

        return False


    passed(
        "All required project files are present."
    )

    return True


# =========================================================
# CHECK 2
# =========================================================


def check_python_compilation() -> bool:

    heading(
        "2. PYTHON COMPILATION"
    )


    result = run_command(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "src",
            "tests",
            "scripts",
            "run.py",
            "wsgi.py",
        ]
    )


    if result.returncode == 0:

        passed(
            "All Python files compile successfully."
        )

        return True


    failed(
        "Python compilation failed."
    )


    if result.stdout:

        print(
            result.stdout
        )


    if result.stderr:

        print(
            result.stderr
        )


    return False


# =========================================================
# CHECK 3
# =========================================================


def check_dependencies() -> bool:

    heading(
        "3. INSTALLED DEPENDENCIES"
    )


    important_packages = [
        "flask",
        "requests",
        "werkzeug",
        "pytest",
        "gunicorn",
    ]


    result = True


    for package in important_packages:

        try:

            version = (
                importlib.metadata.version(
                    package
                )
            )


            passed(
                f"{package} {version}"
            )


        except (
            importlib.metadata
            .PackageNotFoundError
        ):

            failed(
                f"{package} is not installed."
            )

            result = False


    return result


# =========================================================
# CHECK 4
# =========================================================


def check_pytest() -> bool:

    heading(
        "4. COMPLETE AUTOMATED TEST SUITE"
    )


    result = run_command(
        [
            "uv",
            "run",
            "pytest",
            "-q",
        ]
    )


    combined_output = (
        result.stdout
        + result.stderr
    ).strip()


    if combined_output:

        print(
            combined_output
        )


    if result.returncode == 0:

        passed(
            "Complete pytest suite passed."
        )

        return True


    failed(
        "One or more automated tests failed."
    )

    return False


# =========================================================
# CHECK 5
# =========================================================


def check_routes() -> bool:

    heading(
        "5. FLASK ROUTES"
    )


    script = r"""
from cyberrecon.app import create_app

app = create_app(
    {
        "TESTING": True,
        "CSRF_PROTECTION_ENABLED": False,
    }
)

for rule in sorted(
    app.url_map.iter_rules(),
    key=lambda item: item.rule,
):
    if rule.endpoint != "static":
        print(rule.rule)
"""


    result = run_command(
        [
            "uv",
            "run",
            "python",
            "-c",
            script,
        ]
    )


    if result.returncode != 0:

        failed(
            "Unable to inspect Flask route map."
        )


        print(
            result.stderr
        )

        return False


    routes = {
        line.strip()
        for line
        in result.stdout.splitlines()
        if line.strip()
    }


    for route in sorted(
        routes
    ):

        print(
            f"  {route}"
        )


    missing = (
        REQUIRED_ROUTES
        - routes
    )


    if missing:

        for route in sorted(
            missing
        ):

            failed(
                f"Missing route: {route}"
            )

        return False


    passed(
        "All expected application routes exist."
    )

    return True


# =========================================================
# CHECK 6
# =========================================================


def get_tracked_files() -> list[str]:

    result = run_command(
        [
            "git",
            "ls-files",
        ]
    )


    if result.returncode != 0:

        return []


    return [
        line.strip()
        for line
        in result.stdout.splitlines()
        if line.strip()
    ]


def check_tracked_runtime_files() -> bool:

    heading(
        "6. TRACKED SECRET / RUNTIME FILES"
    )


    tracked_files = (
        get_tracked_files()
    )


    suspicious = []


    for tracked_file in tracked_files:

        normalized = (
            tracked_file.lower()
        )


        if (
            normalized == ".env"
            or normalized.endswith(
                ".session_secret"
            )
            or normalized.endswith(
                ".db"
            )
            or normalized.endswith(
                ".db-wal"
            )
            or normalized.endswith(
                ".db-shm"
            )
            or "/__pycache__/" in normalized
            or normalized.startswith(
                "__pycache__/"
            )
            or ".pytest_cache/" in normalized
            or normalized.startswith(
                ".venv/"
            )
        ):

            suspicious.append(
                tracked_file
            )


    if suspicious:

        for item in suspicious:

            failed(
                f"Tracked runtime/sensitive file: {item}"
            )

        return False


    passed(
        "No runtime database, secret, cache or virtual-environment files are tracked."
    )

    return True


# =========================================================
# CHECK 7
# =========================================================


def check_gitignore() -> bool:

    heading(
        "7. GITIGNORE SECURITY"
    )


    protected_files = [
        ".env",
        "data/cyberrecon.db",
        "data/.session_secret",
    ]


    result = True


    for protected_file in protected_files:

        check = run_command(
            [
                "git",
                "check-ignore",
                "-q",
                protected_file,
            ]
        )


        if check.returncode == 0:

            passed(
                f"{protected_file} is ignored."
            )

        else:

            failed(
                f"{protected_file} is NOT ignored."
            )

            result = False


    example_check = run_command(
        [
            "git",
            "check-ignore",
            "-q",
            ".env.example",
        ]
    )


    if example_check.returncode != 0:

        passed(
            ".env.example is available for Git."
        )

    else:

        failed(
            ".env.example is incorrectly ignored."
        )

        result = False


    return result


# =========================================================
# CHECK 8
# =========================================================


def check_wsgi() -> bool:

    heading(
        "8. WSGI PRODUCTION ENTRY POINT"
    )


    result = run_command(
        [
            "uv",
            "run",
            "python",
            "-c",
            (
                "from wsgi import app; "
                "print(app.name)"
            ),
        ]
    )


    if result.returncode != 0:

        failed(
            "Unable to import wsgi:app."
        )

        print(
            result.stderr
        )

        return False


    app_name = (
        result.stdout.strip()
    )


    info(
        f"Application name: {app_name}"
    )


    passed(
        "WSGI application imports successfully."
    )

    return True


# =========================================================
# CHECK 9
# =========================================================


def check_ssrf_default() -> bool:

    heading(
        "9. SSRF DEFAULT POLICY"
    )


    environment = (
        os.environ.copy()
    )


    environment.pop(
        "CYBERRECON_ALLOW_PRIVATE_TARGETS",
        None,
    )


    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "-c",
            (
                "from "
                "cyberrecon.scanner.target "
                "import private_targets_allowed; "
                "print(private_targets_allowed())"
            ),
        ],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )


    observed = (
        result.stdout.strip()
    )


    info(
        f"private_targets_allowed() = {observed}"
    )


    if (
        result.returncode == 0
        and observed == "False"
    ):

        passed(
            "Private network targets are blocked by default."
        )

        return True


    failed(
        "Private-network scanning is unexpectedly enabled."
    )

    return False


# =========================================================
# CHECK 10
# =========================================================


def read_tracked_text_files():

    tracked_files = (
        get_tracked_files()
    )


    for relative_path in tracked_files:

        path = (
            PROJECT_ROOT
            / relative_path
        )


        if not path.is_file():

            continue


        if (
            path.suffix.lower()
            not in TEXT_EXTENSIONS
        ):

            continue


        try:

            text = path.read_text(
                encoding="utf-8"
            )

        except (
            UnicodeDecodeError,
            OSError,
        ):

            continue


        yield (
            relative_path,
            text,
        )


def check_stale_project_wording() -> bool:

    heading(
        "10. STALE PROTOTYPE WORDING"
    )


    matches = []


    for (
        relative_path,
        text,
    ) in read_tracked_text_files():

        # Test source may intentionally mention old
        # strings, so the audit script itself is skipped.
        if (
            relative_path
            == "scripts/project_audit.py"
        ):

            continue


        for pattern in (
            STALE_TEXT_PATTERNS
        ):

            if pattern in text:

                matches.append(
                    (
                        relative_path,
                        pattern,
                    )
                )


    if not matches:

        passed(
            "No obvious Review-1/prototype wording found in tracked text files."
        )

        return True


    for path, pattern in matches:

        warning(
            f'{path}: contains "{pattern}"'
        )


    warning(
        "Review these references before final submission."
    )

    # Warning only.
    return True


# =========================================================
# CHECK 11
# =========================================================


def check_todos() -> bool:

    heading(
        "11. TODO / FIXME REVIEW"
    )


    matches = []


    for (
        relative_path,
        text,
    ) in read_tracked_text_files():

        if (
            relative_path
            == "scripts/project_audit.py"
        ):

            continue


        for pattern in (
            TODO_PATTERNS
        ):

            if pattern in text:

                matches.append(
                    (
                        relative_path,
                        pattern,
                    )
                )


    if not matches:

        passed(
            "No TODO/FIXME/XXX markers found."
        )

        return True


    for path, pattern in matches:

        warning(
            f"{path}: {pattern}"
        )


    warning(
        "Review remaining development markers."
    )

    return True


# =========================================================
# CHECK 12
# =========================================================


def check_git_status() -> bool:

    heading(
        "12. GIT WORKING TREE"
    )


    result = run_command(
        [
            "git",
            "status",
            "--short",
        ]
    )


    status = (
        result.stdout.strip()
    )


    if not status:

        passed(
            "Git working tree is clean."
        )

        return True


    warning(
        "Uncommitted changes are present:"
    )

    print()
    print(
        status
    )


    return True


# =========================================================
# CHECK 13
# =========================================================


def show_recent_commits() -> bool:

    heading(
        "13. RECENT GIT HISTORY"
    )


    result = run_command(
        [
            "git",
            "log",
            "--oneline",
            "-8",
        ]
    )


    if result.returncode != 0:

        warning(
            "Unable to read Git history."
        )

        return True


    print(
        result.stdout.strip()
    )


    return True


# =========================================================
# MAIN
# =========================================================


def main() -> int:

    heading(
        "CYBERRECON FINAL REPOSITORY AUDIT"
    )


    print(
        f"Project root: {PROJECT_ROOT}"
    )


    checks = [
        (
            "Required files",
            check_required_files,
        ),

        (
            "Python compilation",
            check_python_compilation,
        ),

        (
            "Dependencies",
            check_dependencies,
        ),

        (
            "Automated tests",
            check_pytest,
        ),

        (
            "Application routes",
            check_routes,
        ),

        (
            "Tracked runtime files",
            check_tracked_runtime_files,
        ),

        (
            "Gitignore security",
            check_gitignore,
        ),

        (
            "WSGI import",
            check_wsgi,
        ),

        (
            "SSRF policy",
            check_ssrf_default,
        ),

        (
            "Stale wording",
            check_stale_project_wording,
        ),

        (
            "TODO review",
            check_todos,
        ),

        (
            "Git status",
            check_git_status,
        ),

        (
            "Git history",
            show_recent_commits,
        ),
    ]


    results = []


    for name, function in checks:

        try:

            result = function()

        except Exception as error:

            failed(
                f"{name}: {error}"
            )

            result = False


        results.append(
            (
                name,
                result,
            )
        )


    heading(
        "FINAL AUDIT SUMMARY"
    )


    passed_count = 0


    for name, result in results:

        marker = (
            "PASS"
            if result
            else "FAIL"
        )


        print(
            f"[{marker}] {name}"
        )


        if result:

            passed_count += 1


    print()
    print(
        f"Passed: "
        f"{passed_count}/"
        f"{len(results)}"
    )


    critical_failures = [
        name
        for name, result
        in results
        if not result
    ]


    if critical_failures:

        print()
        print(
            "CyberRecon repository audit "
            "found issues that should be fixed "
            "before final code freeze."
        )

        print()

        for failure_name in (
            critical_failures
        ):

            print(
                f" - {failure_name}"
            )


        return 1


    print()
    print(
        "CyberRecon repository passed "
        "the final technical audit."
    )

    print(
        "The codebase is ready for the "
        "final code-freeze stage."
    )


    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
    