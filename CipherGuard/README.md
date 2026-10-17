# CipherGuard

**Generate smarter. Analyze stronger. Stay secure.**

CipherGuard is a privacy-first password security toolkit. Phase 1 established the Flask/Jinja2 application shell, shared navigation, responsive design system, six routes, security guidance, and privacy disclosures. Phase 2 implements secure password generation with configurable length and character sets, including accessible Reveal/Hide and Copy controls. Phase 3 adds optional comma-separated personal-information exclusions and case-sensitive required characters/terms, with bounded candidate validation. Phase 4 adds a browser-local heuristic password strength analyzer. Phase 5 adds a browser-local crack-time estimator that compares documented hypothetical online and offline guessing rates.

## Requirements

- Python 3.12 or newer
- pip

## Setup

### Windows (PowerShell)

```powershell
cd CipherGuard
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### macOS / Linux

```bash
cd CipherGuard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run locally

```bash
python app.py
```

Open `http://127.0.0.1:5000`. The entry point explicitly disables Flask debug mode. The built-in Flask server is for local development only; use a production WSGI server for deployment and keep debug mode disabled.

## Run tests

```bash
python -m pytest -q
```

## Pages

- `/` — Dashboard
- `/generate` — Generate Password (secure generation and optional personal-information exclusions)
- `/analyze` — Analyze Password (browser-local heuristic analysis)
- `/crack-time` — Crack-Time Estimate (browser-local scenario ranges)
- `/security` — Security Guidance
- `/privacy` — Settings and Privacy

## Architecture

- `app.py` — development entry point
- `cipherguard/__init__.py` — Flask application factory and routes; explicitly resolves root-level `templates/` and `static/` directories
- `cipherguard/generator.py` — cryptographically secure password generation and validation\n- `cipherguard/analyzer.py` — deterministic educational analysis heuristics used for unit tests and documented scoring behavior
- `cipherguard/crack_time.py` — deterministic, coarse crack-time scenario model and duration formatting
- `cipherguard/exclusion.py` — comma-separated exclusion parsing, normalization and matching
- `cipherguard/generator.py` — required-term parsing and combined inclusion/exclusion constraint validation
- `templates/` — shared Jinja2 layout and page templates
- `static/css/` — design tokens, reusable components, and page/layout styling
- `static/js/app.js` — accessible responsive navigation, generator controls, browser-local analyzer, and browser-local crack-time estimator
- `tests/` — route and response tests

There is no database, user account system, credential storage, analytics integration, or external password-analysis API. Phase 2 generates passwords using Python's `secrets` module, returns the result in the immediate HTTP response, and does not intentionally log or persist the generated value. Treat the local application as trusted only on a device you control; do not expose the development server to untrusted networks. Personal-information exclusion accepts comma-separated terms and supports case-insensitive matching that ignores punctuation/separators after Unicode NFKC normalization (for example, `Jane Doe`, `jane-doe`, and `janedoe` are treated as variations). It does not infer all spellings, transliterations, encoded dates, or indirect references. Required inclusion entries are comma-separated, case-sensitive contiguous substrings; each character must belong to an enabled character category. The generator validates the complete candidate against exact length, selected character classes, all inclusion entries, and all supported exclusion matches, using bounded retries. These constraints can bias the distribution compared with unconstrained random generation, and overly restrictive combinations return an error. Both input values are echoed into the immediate HTML response to keep them editable after success or failure; Jinja autoescaping is relied on, and POST responses use no-store headers. Values are not intentionally persisted or logged, but their presence in the DOM increases local exposure. The application does not use a database, cookies, browser storage, analytics, or external services for these inputs. Generated passwords necessarily appear in the immediate response DOM for the Reveal/Hide and Copy controls, so users should treat the local device and browser as sensitive. The password strength analyzer runs in the browser and does not submit the password to Flask. It checks length, character groups, repetition, a small bundled common-password list, common sequences/keyboard walks, year-like numbers, and predictable substitutions. Its deterministic score is a heuristic estimate, not a guarantee and not a substitute for breach checking or attacker-specific analysis. The Python `cipherguard/analyzer.py` module mirrors the documented heuristic for unit testing; the live page uses bundled vanilla JavaScript so the password remains client-side. The crack-time estimator runs entirely in browser JavaScript; it does not submit passwords to Flask or external services, and it does not use a database, cookies, localStorage, or sessionStorage. The Python `cipherguard/crack_time.py` module is a deterministic reference implementation for unit testing; it is not used to receive passwords from the page. Four illustrative rates are documented: one guess per 10 minutes for rate-limited online guessing, one guess per second for permissive online guessing, 1,000 guesses/second for an illustrative slow password hash, and 10 billion guesses/second for a hypothetical fast-hash attacker. These rates are scenario assumptions, not universal benchmarks. The estimator approximates effective guess difficulty from length and visible character categories, then reduces the estimate for common passwords, recognizable sequences, repetition, year-like numbers, and repeated chunks. It does not use character-set size raised to password length as its sole estimate and does not claim measured entropy. Results are deliberately coarse ranges, using roughly one-quarter to one times the modeled guess count rather than a statistical confidence interval; real-world time depends on password choice, attacker strategy, hardware, hashing algorithm/work factor, throttling, lockouts, MFA, and breach-derived guesses. Clear removes the input and rendered results from the page. Neither Phase 4 nor Phase 5 has been browser-tested by this workspace run; run the full test suite and manually verify interactions in the local Windows environment before considering the phase integrated.


## Project status record

- **Phase 1 — Application shell:** reported verified in the user's local Windows environment; all six pages open and the then-current 12-test suite passed. Comprehensive security auditing and complete mobile-browser verification were not claimed.
- **Phase 2 — Secure password generator:** reported verified in the user's local Windows environment, including Reveal/Hide, Copy, and a passing full test suite. The latest Windows pytest count was not provided, so no newer count is recorded here.
- **Phase 3 — Personal-information exclusion:** implemented in this workspace copy. Exclusions and inclusions are optional comma-separated inputs retained in the immediate form response. Exclusion matching is case-insensitive and ignores punctuation/separators after Unicode NFKC normalization and case-folding; single-character normalized exclusions are rejected as overly broad. Inclusion entries are case-sensitive contiguous terms and must use enabled character categories. Candidate generation uses bounded retries and validates the entire candidate against all constraints.
- **Phase 3 review in this workspace:** Updated privacy tests to reflect the active generator and the explicit form-retention trade-off; added tests for comma-separated parsing, Unicode normalization, empty and duplicate terms, required entries, category conflicts, impossible lengths, combined constraints, and escaped retained values. Python syntax compilation and JavaScript syntax validation passed. Unit and full pytest runs were attempted but test collection is blocked because Flask is unavailable in this workspace Python environment (`ModuleNotFoundError: No module named 'flask'`). No pytest pass is claimed. Earlier smoke checks do not substitute for the full suite.
- **Phase 4 — Password strength analyzer:** implemented in this workspace copy as browser-local JavaScript, with a deterministic Python heuristic module and tests. Browser interaction and complete pytest execution must be verified in the target Windows environment before marking the phase accepted.
- **Phase 5 — Crack-time estimator:** implemented in this workspace copy as browser-local JavaScript plus a deterministic Python reference module and tests. Four hypothetical online/offline rates are documented, with coarse time ranges and limitations. Full pytest and manual browser verification must be completed in the target Windows environment before marking this phase accepted.

The user's local Windows project remains the source of truth. This workspace snapshot is a proposed integration source; review/merge these Phase 3 changes into the local project rather than replacing locally verified files wholesale.


## Creator and social links

Every page uses the shared footer in `templates/base.html`. It includes the creator credit, an email contact link, and local inline SVG icons linking to the configured email, GitHub, LinkedIn, and Instagram profiles. The icons require no third-party requests or additional dependencies. Social links open in a new tab with `noopener noreferrer`; keyboard focus is visible.
