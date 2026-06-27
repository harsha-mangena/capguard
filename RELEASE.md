# Release checklist

CapGuard publishes the PyPI distribution `capguard-runtime`. The Python import
package and console command remain `capguard`.

## One-time setup

Before the first tag, configure PyPI Trusted Publishing:

- PyPI project name: `capguard-runtime`
- GitHub owner / repository: `harsha-mangena/capguard`
- Workflow filename: `release.yml`
- GitHub environment: `pypi`

Create the matching GitHub environment named `pypi` and protect it with the
reviewers or branch/tag rules you want for production release authority.

## Preflight

1. Confirm `pyproject.toml` and `capguard/__init__.py` have the same version.
2. Confirm docs say `pip install capguard-runtime`, not `pip install capguard`.
3. Confirm the release workflow still uses Trusted Publishing with
   `id-token: write` only in the publish job and no password/token secret.
4. Run the local gate:

```bash
python -m pip install -e ".[dev,yaml,crypto,cloud]"
ruff check capguard tests examples
pytest -q
capguard bench
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*
```

5. Smoke install the wheel in a clean environment:

```bash
python -m venv /tmp/capguard-release-smoke
/tmp/capguard-release-smoke/bin/python -m pip install --upgrade pip
/tmp/capguard-release-smoke/bin/python -m pip install dist/*.whl
/tmp/capguard-release-smoke/bin/capguard version
/tmp/capguard-release-smoke/bin/python - <<'PY'
import importlib.metadata as md
import capguard

assert md.version("capguard-runtime") == capguard.__version__
print(f"smoke ok {capguard.__version__}")
PY
```

## Publish

Create and push an annotated version tag that matches the package version:

```bash
git tag -a v0.1.0 -m "capguard-runtime 0.1.0"
git push origin v0.1.0
```

The `release` workflow tests, builds, checks metadata, smoke-installs the wheel,
then publishes to PyPI via Trusted Publishing.

## Post-release

Verify the public package from a fresh environment:

```bash
python -m venv /tmp/capguard-pypi-verify
/tmp/capguard-pypi-verify/bin/python -m pip install --upgrade pip
/tmp/capguard-pypi-verify/bin/python -m pip install capguard-runtime
/tmp/capguard-pypi-verify/bin/capguard version
/tmp/capguard-pypi-verify/bin/python - <<'PY'
import importlib.metadata as md
import capguard

assert md.version("capguard-runtime") == capguard.__version__
print(f"verified {capguard.__version__}")
PY
```
