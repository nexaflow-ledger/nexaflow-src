# Contributing to NexaFlow

Thank you for considering contributing to NexaFlow! This document explains how
to set up the project, run tests, and submit changes.

---

## Getting Started

### Prerequisites

- Python ≥ 3.9
- A C compiler (Xcode Command Line Tools on macOS, `build-essential` on Linux)
- Git

### Setup

```bash
git clone https://github.com/nexaflow-ledger/nexaflow-src.git
cd nexaflow-src

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Compile Cython extensions
python setup.py build_ext --inplace
```

### Verify

```bash
make test       # run the full test suite
make lint       # check code style (ruff)
make typecheck  # run mypy
```

---

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. **Write code** — keep changes focused and well-scoped.
3. **Add tests** — all new functionality must include tests.
4. **Run the full suite** before opening a PR:
   ```bash
   make test lint typecheck
   ```
5. **Open a Pull Request** against `main` with a clear description.

---

## Code Style

- **Python:** Follow PEP 8. We use **ruff** for linting and formatting.
  ```bash
  make format   # auto-format
  make lint     # check
  ```
- **Cython (`.pyx`):** Follow the same conventions. Use `cdef`/`cpdef` for
  performance-critical methods. Avoid `cdef` inside regular `def` methods —
  use typed assignments or casts instead.
- **Commit messages:** Use conventional, imperative-mood messages:
  ```
  Add staking persistence to SQLite storage layer
  Fix early-cancel penalty calculation for flexible tier
  ```

---

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `nexaflow_core/` | Core library — Cython extensions, wallet, networking, API |
| `nexaflow_gui/` | Optional PyQt6 desktop GUI |
| `tests/` | Pytest test suite (aim for ≥ 90 % coverage) |
| `scripts/` | Dev/ops helper scripts |
| `diagrams/` | Graphviz architecture diagrams |

---

## Testing

```bash
# Full suite
make test

# Single file
pytest tests/test_staking.py -v

# With coverage report
make coverage
```

- All tests must pass on Python 3.9–3.13 (Ubuntu and macOS).
- Tests should be deterministic — avoid sleeping or using real wall-clock time
  when possible (pass explicit `now` parameters).

---

## Cython Extensions

After modifying any `.pyx` file, rebuild:

```bash
python setup.py build_ext --inplace
```

### Common Pitfalls

- `cdef` type declarations are **not allowed** inside regular `def` methods.
  Use plain Python assignments or `<Type>` casts instead.
- Importing `cdef` classes between Cython modules requires `.pxd` files.

---

## Documentation

- Update the **README** when adding user-facing features or API endpoints.
- Add docstrings to all public functions and classes.
- Use Google-style docstring format.

---

## Security

If you discover a security issue, **do not open a public issue**. Instead,
follow the process in [SECURITY.md](SECURITY.md).

---

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
