import sys
import os

# Ensure tests/replay picks up tests/conformance/fixtures.py
# instead of tests/propagation/fixtures.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../conformance"))
