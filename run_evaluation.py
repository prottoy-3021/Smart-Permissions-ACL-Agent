import json
from datetime import datetime
from pathlib import Path

import pytest


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_PATH = PROJECT_DIR / "evaluation_report.json"


class EvaluationReporter:
    """Collect individual pytest results for the evaluation report."""

    def __init__(self):
        self.results = []

    def pytest_runtest_logreport(self, report):
        # Record the final result of each test's execution phase.
        if report.when == "call":
            self.results.append(
                {
                    "test": report.nodeid,
                    "status": report.outcome.upper(),
                }
            )


def main():
    reporter = EvaluationReporter()

    print("Running Smart Permissions Agent evaluation tests...")
    print("Real permission changes are not performed by this runner.\n")

    exit_code = pytest.main(
        ["tests/test_evaluation.py", "-q"],
        plugins=[reporter],
    )

    passed = sum(
        result["status"] == "PASSED"
        for result in reporter.results
    )
    failed = sum(
        result["status"] == "FAILED"
        for result in reporter.results
    )
    skipped = sum(
        result["status"] == "SKIPPED"
        for result in reporter.results
    )

    total = len(reporter.results)

    report = {
        "project": "Smart Permissions & ACL Agent",
        "generated_at": datetime.now().astimezone().isoformat(),
        "evaluation_type": "Automated tests using mocked scenarios",
        "real_permissions_changed": False,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "pass_rate_percent": round(
                passed / total * 100, 2
            ) if total else 0,
        },
        "results": reporter.results,
        "pytest_exit_code": exit_code,
        "limitations": [
            "Mocked tests do not establish real Windows effective access.",
            "The evaluation does not authorize permission changes.",
        ],
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    print("\nEVALUATION SUMMARY")
    print("-" * 40)
    print(f"Total tests: {total}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")
    print(f"Skipped:     {skipped}")
    print(f"Pass rate:   {report['summary']['pass_rate_percent']}%")
    print(f"\nReport saved to: {REPORT_PATH}")

    if exit_code != 0 or failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
