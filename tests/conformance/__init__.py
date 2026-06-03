"""
tests/conformance/

Shani Conformance Test Suite.

This package verifies that a Shani implementation meets the normative
requirements defined in the Shani specification.  Tests are split into
two categories:

    MUST_FAIL  — the implementation MUST reject / deny the operation.
    MUST_PASS  — the implementation MUST accept / allow the operation.

Entry points:
    python -m tests.conformance.runner          # run all, print structured report
    python tests/conformance/test_must_fail.py  # run MUST FAIL suite directly
    python tests/conformance/test_must_pass.py  # run MUST PASS suite directly
"""
