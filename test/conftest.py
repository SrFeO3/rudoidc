import pytest
import json
import os
import time

# Store test results to dump to JSON at the end
test_results = []

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Execute all other hooks to obtain the report object
    outcome = yield
    report = outcome.get_result()

    if report.when == "call":
        test_results.append({
            "nodeid": item.nodeid,
            "outcome": report.outcome,
            "duration": report.duration
        })

def pytest_sessionfinish(session, exitstatus):
    output_file = "test_results.json"
    with open(output_file, "w") as f:
        json.dump(test_results, f, indent=2)
    print(f"\nTest results saved to {output_file}")
