.PHONY: check test tests demo lint clean

# Quick end-to-end ADO issuance check (zero dependencies)
check:
	shani check

# Full test suite
test tests:
	pytest

# HITL demo (auto-approve mode)
demo:
	shani demo

# Lint with ruff
lint:
	pip install ruff -q && ruff check shani/ --ignore E501,F401

# Remove compiled Python files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
