"""
CyberRecon Final Validation Utility

Runs a set of non-destructive checks against the
CyberRecon project before final submission.

Usage:

    uv run python scripts/final_validation.py
"""

from __future__ import annotations

import os
import subprocess
import sys

from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


REQUIRED_FILES = [
    "run.py",
    "wsgi.py",
    "pyproject.toml",
    "uv.lock",
    "README.md",
    ".gitignore",
    ".env.example",

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
    "src/cyberrecon/templates/history.html",
    "src/cyberrecon/templates/scan_detail.html",
    "src/cyberrecon/templates/compare.html",
    "src/cyberrecon/templates/dashboard.html",
    "src/cyberrecon/templates/report.html",
    "src/cyberrecon/templates/login.html",
    "src/cyberrecon/templates/register.html",

    "src/cyberrecon/static/css/style.css",

    "demo_target/app.py",

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
    "/scan",
    "/dashboard",
    "/history",
    "/history/<scan_id>",
    "/history/<scan_id>/report",
    "/compare",
    "/register",
    "/login",
    "/logout",
}


def heading(title: str) -> None:
    print()
    print("=" * 68)
    print(title)
    print("=" * 68)


def success(message: str) -> None:
    print(f"[PASS] {message}")


def warning(message: str) -> None:
    print(f"[WARN] {message}")


def failure(message: str) -> None:
    print(f"[FAIL] {message}")


def run_command(
    command: list[str],
    *,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a command from the CyberRecon project root.
    """

    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=capture,
        check=False,
    )


def check_required_files() -> bool:
    heading(
        "1. Required Project Files"
    )

    passed = True

    for relative_path in REQUIRED_FILES:

        path = (
            PROJECT_ROOT
            / relative_path
        )

        if path.exists():

            success(
                relative_path
            )

        else:

            failure(
                f"Missing: {relative_path}"
            )

            passed = False

    return passed


def check_python_compilation() -> bool:
    heading(
        "2. Python Compilation"
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

        success(
            "All Python files compiled successfully."
        )

        return True

    failure(
        "Python compilation failed."
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return False


def check_test_suite() -> bool:
    heading(
        "3. Automated Test Suite"
    )

    result = run_command(
        [
            "uv",
            "run",
            "pytest",
            "-q",
        ]
    )

    output = (
        result.stdout
        + result.stderr
    ).strip()

    if output:
        print(output)

    if result.returncode == 0:

        success(
            "Automated test suite passed."
        )

        return True

    failure(
        "One or more automated tests failed."
    )

    return False


def check_wsgi_import() -> bool:
    heading(
        "4. Production WSGI Import"
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

        failure(
            "Unable to import wsgi:app."
        )

        print(
            result.stderr
        )

        return False

    app_name = (
        result.stdout.strip()
    )

    print(
        f"Application: {app_name}"
    )

    success(
        "Production WSGI entry point imports."
    )

    return True


def check_routes() -> bool:
    heading(
        "5. Flask Route Map"
    )

    code = """
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
            code,
        ]
    )

    if result.returncode != 0:

        failure(
            "Could not inspect Flask routes."
        )

        print(
            result.stderr
        )

        return False

    actual_routes = {
        line.strip()
        for line
        in result.stdout.splitlines()
        if line.strip()
    }

    for route in sorted(
        actual_routes
    ):

        print(
            f"  {route}"
        )

    missing = (
        REQUIRED_ROUTES
        - actual_routes
    )

    if missing:

        for route in sorted(
            missing
        ):

            failure(
                f"Missing route: {route}"
            )

        return False

    success(
        "All required CyberRecon routes exist."
    )

    return True


def check_secret_files() -> bool:
    heading(
        "6. Secret / Runtime File Protection"
    )

    checks = [
        ".env",
        "data/cyberrecon.db",
        "data/.session_secret",
    ]

    passed = True

    for path in checks:

        result = run_command(
            [
                "git",
                "check-ignore",
                "-q",
                path,
            ]
        )

        if result.returncode == 0:

            success(
                f"{path} is ignored by Git."
            )

        else:

            failure(
                f"{path} is NOT ignored by Git."
            )

            passed = False


    example_result = run_command(
        [
            "git",
            "check-ignore",
            "-q",
            ".env.example",
        ]
    )

    if (
        example_result.returncode
        != 0
    ):

        success(
            ".env.example remains commit-safe."
        )

    else:

        failure(
            ".env.example is unexpectedly ignored."
        )

        passed = False

    return passed


def check_private_target_default() -> bool:
    heading(
        "7. SSRF Default Policy"
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
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    value = (
        result.stdout
        .strip()
    )

    if (
        result.returncode == 0
        and value == "False"
    ):

        success(
            "Private/internal targets are blocked by default."
        )

        return True

    failure(
        "Private-target default policy is not disabled."
    )

    print(
        f"Observed value: {value}"
    )

    return False


def check_git_status() -> bool:
    heading(
        "8. Git Working Tree"
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

        success(
            "Git working tree is clean."
        )

        return True

    warning(
        "Git working tree contains uncommitted changes:"
    )

    print()
    print(status)

    # This is a warning, not a technical validation failure.
    return True


def main() -> int:
    heading(
        "CYBERRECON FINAL VALIDATION"
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
            "Automated tests",
            check_test_suite,
        ),
        (
            "WSGI import",
            check_wsgi_import,
        ),
        (
            "Flask routes",
            check_routes,
        ),
        (
            "Secret protection",
            check_secret_files,
        ),
        (
            "SSRF defaults",
            check_private_target_default,
        ),
        (
            "Git status",
            check_git_status,
        ),
    ]

    results = []

    for name, check in checks:

        try:

            result = check()

        except Exception as error:

            failure(
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
        "FINAL SUMMARY"
    )

    passed_count = 0

    for name, passed in results:

        if passed:

            print(
                f"[PASS] {name}"
            )

            passed_count += 1

        else:

            print(
                f"[FAIL] {name}"
            )


    print()
    print(
        f"Passed: "
        f"{passed_count}/"
        f"{len(results)}"
    )


    if all(
        passed
        for _, passed
        in results
    ):

        print()
        print(
            "CyberRecon final validation "
            "completed successfully."
        )

        return 0


    print()
    print(
        "CyberRecon is NOT ready to be "
        "frozen for final submission."
    )

    return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )