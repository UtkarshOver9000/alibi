# Contributing to ALIBI

Thank you for your interest in contributing to **ALIBI — The Open-Source Planetary Tech & Defense Terminal**!

We welcome contributions from security engineers, researchers, data scientists, and developers worldwide.

---

## Core Guiding Principles

Before writing any code, please review our core operational rules:

1. **Real Data Only; Nothing Synthetic:**
   No fake indicators, no mock honeypots, no randomized datasets. All intelligence feeds, indicators, and models must use verified 2026 public telemetry or real-world observations.
2. **Keyless Public Access:**
   Public demo endpoints are keyless and rate-limited. Third-party provider keys live strictly server-side in environment variables.
3. **Always Present & Resilient:**
   Feeds refresh on automated schedules. Stale-while-revalidate ensures no UI panel or API endpoint ever returns a blank failure.
4. **Honest, Plain-English Copy:**
   No security theater or hype. Never claim more than the verified code and data support.

---

## Development Setup

We use modern Python tooling powered by [`uv`](https://github.com/astral-sh/uv).

### 1. Clone the repository
```bash
git clone https://github.com/UtkarshOver9000/alibi.git
cd alibi
```

### 2. Install dependencies
```bash
uv sync --all-extras
```

### 3. Run the development server
```bash
uv run uvicorn ittravel.api.app:app --reload --port 8000
```
Open [http://localhost:8000](http://localhost:8000) to view the live planetary dashboard.

---

## Quality Standards

All pull requests must pass automated linting and unit test suites:

### Linting & Formatting
We enforce formatting and linting via Ruff (max line length: 120 characters):
```bash
uv run ruff check .
uv run ruff format --check .
```

### Test Suite
Run the full test suite:
```bash
uv run pytest
```
Ensure all tests pass before submitting your PR.

---

## Submitting Pull Requests

1. Fork the repo and create a topic branch from `main` (e.g. `feature/my-enhancement`).
2. Keep commits focused, descriptive, and atomic.
3. Add unit tests for any new features or bug fixes.
4. Ensure `uv run ruff check .` and `uv run pytest` pass cleanly.
5. Open a Pull Request with a clear description of the problem solved and test evidence.

---

## Security Disclosures

If you discover a security vulnerability within ALIBI, please refer to [`.well-known/security.txt`](.well-known/security.txt) or email `security@alibi-intel.org`. Please do not report security vulnerabilities through public GitHub issues.
