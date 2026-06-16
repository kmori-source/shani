"""
tests/fixtures/__init__.py

Common fixtures package for the Shani test suites.

Re-exports all public symbols so callers can do:
    from tests.fixtures import make_evaluator, make_proposal, ...

Or, with tests/fixtures/ on sys.path:
    from keys import make_evaluator
    from proposals import make_proposal
    ...
"""

from __future__ import annotations
