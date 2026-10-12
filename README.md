# SecureFlow AppSec Lab

**Live website:** [SecureFlow](https://secure-flow-lab.netlify.app/)

A Python application-security project that reproduces web vulnerabilities, explains their root causes, implements focused fixes, and verifies the result with regression tests and security automation.

The lab models orders, product search, sessions and coupon redemption. Each vulnerable implementation has a fixed comparison. All data is synthetic and the server binds only to `127.0.0.1`.

[![AppSec checks](https://github.com/wwhosjess/SecureFlow-AppSec/actions/workflows/security.yml/badge.svg)](https://github.com/wwhosjess/SecureFlow-AppSec/actions/workflows/security.yml)

## Start here

- **Review the design:** [architecture, trust boundaries and security requirements](docs/architecture.md).
- **Reproduce the behavior:** [HTTP reproduction guide](docs/reproduction.md).
- **Assess the fixes:** [findings, regression coverage and scanner limitations](docs/security-review.md).
- **Inspect evidence:** [dated results and ZAP triage](evidence/README.md), including unchanged raw alerts.
- **Read the implementation:** [application](lab/app.py), [scanner orchestration](security_scan.py), [Semgrep rule](rules/unsafe-sql.yaml), [tests](tests/).

## What this project demonstrates

| Security problem | Vulnerable behavior | Fixed behavior | Verification |
| --- | --- | --- | --- |
| Broken object authorization | Alice can read Bob's order | Ownership checked against verified identity | Cross-user rejection plus own-order success |
| SQL injection | Concatenated input bypasses the public-product filter | SQLite parameter binding | Hidden-record attack and normal search |
| Reflected XSS | User input inserted as raw HTML | HTML text encoding and restrictive CSP | Encoding regression, HTTP reflection probe, historical ZAP |
| Forged identity | Client header chooses the user | Signed session with expiry validation | Header rejection, valid session, tampering and expiry tests |
| Coupon race | Concurrent requests both redeem the coupon | Check-and-consume protected by one process lock | Deterministic vulnerable race and fixed single redemption |
| Vulnerable dependency fixture | Old pin matches known advisories | Comparison pin re-audited | pip-audit with alias deduplication |

The engineering work includes a custom Semgrep rule with positive/negative fixtures, actual HTTP probes, dependency-advisory normalization, scanner-failure handling, and GitHub Actions integration. The 17 regression tests cover valid behavior as well as attacks. This is an educational lab, not a production shop or a claim of complete security.

## Run the lab

Requires Python 3.12+. The application itself uses only the standard library. From the repository root, use separate terminals:

```bash
python -m lab.app --mode vulnerable --port 5050
python -m lab.app --mode fixed --port 5051
```

Both services bind only to loopback. Choose unused ports if necessary and stop each server with Ctrl+C. Do not expose the vulnerable service through a public proxy.

```bash
curl -i http://127.0.0.1:5050/me
curl -i http://127.0.0.1:5050/orders/1002
```

The first request identifies the default synthetic Alice; the second exposes Bob's order. Vulnerable mode does not authenticate that identity. For real fixed-mode login, signed-cookie requests and expected 401/403/200 responses, use the [reproduction guide](docs/reproduction.md). On Windows use `curl.exe`; use `py -3.12` instead of `python` if needed.

The fake accounts are `alice` and `bob`, both with the fixture password `demo-password`. Secrets used to sign sessions are generated in memory when each lab instance starts. These accounts and passwords are intentionally public test data.

## Run the tests and tools

```bash
python -m unittest discover -s tests -v
python -m venv .venv-tools
# macOS/Linux:
source .venv-tools/bin/activate
python -m pip install -r requirements-tools.txt
semgrep --test --config rules/unsafe-sql.yaml rules/unsafe-sql.py
python security_scan.py --mode vulnerable
python security_scan.py --mode fixed
```

Windows PowerShell setup, without an activation script:

```powershell
python -m venv .venv-tools
if ($LASTEXITCODE -ne 0) { throw 'Environment creation failed' }
$tools = (Resolve-Path '.venv-tools\Scripts').Path
& "$tools\python.exe" -m pip install -r requirements-tools.txt
if ($LASTEXITCODE -ne 0) { throw 'Tool installation failed' }
& "$tools\python.exe" -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Tool dependencies are inconsistent' }
$env:PATH = "$tools;$env:PATH"
$env:PYTHONUTF8 = '1'
$env:SEMGREP_SEND_METRICS = 'off'
& "$tools\semgrep.exe" --test --config rules/unsafe-sql.yaml rules/unsafe-sql.py
if ($LASTEXITCODE -ne 0) { throw 'Rule tests failed' }
& "$tools\python.exe" security_scan.py --mode vulnerable
$vulnerableExit = $LASTEXITCODE
& "$tools\python.exe" security_scan.py --mode fixed
$fixedExit = $LASTEXITCODE
[pscustomobject]@{ Vulnerable=$vulnerableExit; Fixed=$fixedExit }
```

Tool installation and advisory lookup require internet access. Never install `lab/dependencies-vulnerable.txt`; pip-audit reads it as a scan-only fixture. Keep `PYTHONUTF8=1` on Windows to avoid decoding scanner output with a legacy code page.

The runner creates temporary loopback servers and executes the regressions itself. Generated results go to ignored `reports/`; committed historical evidence is separate under `evidence/`.

- Vulnerable exit **1** is expected only when the summary says `gate: findings` and required checks completed.
- Fixed exit **0** means zero findings within the selected scopes and passing regressions.
- Missing tools, failed scanners, malformed output or failed regressions block the gate. Inspect the summary, not the exit code alone.

## Recorded results and CI

The initial evidence set was imported from earlier executions. It is explicitly historical, with timestamps, original source identifiers and SHA-256 hashes in [the manifest](evidence/manifest.json); it is not represented as a new run of this repository. Subsequent runs of this repository are available under [Actions](https://github.com/wwhosjess/SecureFlow-AppSec/actions).

| Recorded check | Vulnerable | Fixed | Scope |
| --- | --- | --- | --- |
| Regression suite, 4 Oct 2026 | 17 passed | 17 passed | Attacks, valid behavior, headers, session handling and scanner failure states |
| SAST, 4 Oct 2026 | 1 finding | 0 | One custom SQL construction rule |
| SCA, 4 Oct 2026 | 5 unique advisories / 10 raw records | 0 | Direct dependency fixtures only |
| Targeted HTTP, 4 Oct 2026 | 5 exposed checks | 0 exposed checks | Known attacks; no JavaScript execution |
| ZAP raw alert types, High/Medium/Low/Info | 3/2/6/1 on 3 Oct | 1/0/0/1 on 4 Oct | Unauthenticated scans at different source revisions |

The High source-disclosure alert remains visible with a **likely false-positive** assessment supported by captured traffic and code. ZAP missed the known vulnerable SQL injection; browser callback failures further limit its coverage. Details and original reports are in [the evidence review](evidence/README.md).

The standard workflow checks the Semgrep fixtures, verifies expected vulnerable findings, enforces the fixed gate and uploads actual reports. Optional ZAP is manually dispatched against a disposable loopback target; it preserves raw JSON/HTML and diagnostics. A successful ZAP job means usable evidence collection, not zero findings. The pipeline's own ZAP `not_run` value is separate from the optional workflow.

## Scope and limitations

The project demonstrates web authorization, authentication, input handling, business logic, source review and security automation. It does not cover production TLS deployment, distributed locking, full session lifecycle management, comprehensive CSRF protection, or AI/LLM security. SAST is not full-project taint analysis; SCA excludes transitive dependencies; generic scanning does not understand every business rule. Fixed mode is not fully secure.

The project includes the interactive browser showcase in `dist/`, alongside the Python lab, technical documentation, tests, workflows and selected historical evidence. Netlify hosts only `dist/`; the Python service and security scanners do not run on the website. The browser exercises use safe synthetic simulations, and the evidence view displays dated recorded results. Personal preparation notes, local environments and source archives are excluded from the published website.
