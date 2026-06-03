# Releasing Shani

This document describes the release process for publishing a new version of Shani to PyPI.

---

## Prerequisites

```bash
pip install build twine
```

A PyPI API token is required. Store it in `~/.pypirc` or set `TWINE_PASSWORD` in CI.

---

## Release Checklist

### 1. Update version

Edit `pyproject.toml`:

```toml
[project]
version = "0.3.1"   # bump here
```

### 2. Update CHANGELOG.md

Add a new section at the top:

```markdown
## [0.3.1] — YYYY-MM

### Fixed
- ...

### Changed
- ...
```

### 3. Run all tests

```bash
shani check && pytest
```

All suites must pass before release.

### 4. Run the CI spec-check locally

```bash
python -c "
src = open('shani/boundary/capability.py').read()
assert '_DECISION_TYPE_OPS' not in src
assert 'CapabilityMatrixLoader' not in src
src2 = open('shani/hitl/approval/gate.py').read()
assert 'authority_map = {' not in src2
print('spec-check OK')
"
```

### 5. Commit and tag

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "chore: release v0.3.1"
git tag v0.3.1
git push origin main --tags
```

### 6. Build

```bash
python -m build
```

This creates `dist/shani-0.3.1.tar.gz` and `dist/shani-0.3.1-py3-none-any.whl`.

### 7. Publish to TestPyPI (optional but recommended)

```bash
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ shani==0.3.1
python -c "import shani; print(shani.__version__)"
```

### 8. Publish to PyPI

```bash
twine upload dist/*
```

### 9. Verify

```bash
pip install shani==0.3.1
python -c "import shani; print('OK')"
```

---

## Version Scheme

Shani follows [Semantic Versioning](https://semver.org/):

| Change type | Version bump | Example |
|---|---|---|
| Breaking API or schema change | MINOR | 0.3.0 → 0.4.0 |
| New feature, backward-compatible | MINOR | 0.3.0 → 0.3.1 |
| Bug fix | PATCH | 0.3.0 → 0.3.1 |
| Security fix | PATCH (urgent) | release immediately |

Breaking changes MUST be documented in CHANGELOG.md and spec/shani-v0.4.md.

---

## GitHub Actions (automated)

The `.github/workflows/ci.yml` pipeline runs on every push and PR:

- **test**: Python 3.11 + 3.12, zero-dep check + full suite
- **lint**: ruff
- **spec-check**: verifies no hardcoded policy values in code

To trigger a release from CI, push a tag:

```bash
git tag v0.3.1 && git push origin v0.3.1
```

Add a `release` job to `ci.yml` that runs `twine upload` when a tag is pushed
(requires `PYPI_TOKEN` secret in the repository settings).

---

## Security releases

For security fixes:

1. Open a private GitHub Security Advisory
2. Prepare the fix on a private fork
3. Release the patch without public pre-announcement
4. Publish the advisory after the release is live
