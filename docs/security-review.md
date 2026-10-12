# Findings and verification coverage

This is a review of intentionally constructed lab flaws, not findings against an external organization. The comparisons use synthetic data. The test suite and raw evidence can be inspected alongside each claim.

## Broken object authorization and forged identity

**Impact:** a caller can retrieve another user's order. In vulnerable mode, `Shop.authenticate` accepts `X-User` or defaults to Alice, and `Shop.order` returns an order by ID without verifying ownership. These are separate authentication and authorization defects.

**Fix:** verify the signed session, then compare the object's owner with the verified user. A missing/invalid session returns 401; a known user requesting another user's order receives 403; their own order remains available.

**Proof:** `test_cross_user_order_blocked`, `test_own_order_is_available`, `test_header_is_not_authentication`, `test_signed_session_and_tampering`, `test_expired_session_rejected`, and the HTTP login/order regression. A generic unauthenticated scanner cannot establish the Alice/Bob ownership relationship.

## SQL injection

**Impact:** the payload `' OR 1=1 -- ` changes concatenated SQL and returns the hidden product despite `public = 1`. Read [vulnerable_sql.py](../lab/vulnerable_sql.py).

**Fix:** [fixed_sql.py](../lab/fixed_sql.py) binds the search value to `?`; the payload remains data. The fixed attack response is a successful search with no matches, not an HTTP rejection.

**Proof:** `test_sql_injection_and_normal_search` verifies both hidden-product exposure and continued legitimate search. The targeted HTTP probe verifies hidden-record behavior. The custom Semgrep rule flags the vulnerable construction, but historical generic ZAP did not identify this known SQLi.

## Reflected XSS

**Impact:** raw input becomes part of the HTML response in vulnerable mode.

**Fix:** encode HTML metacharacters in the text context and apply restrictive CSP in fixed mode. CSP supplements the encoding; it is not the justification for leaving unsafe interpolation in place.

**Proof:** encoding unit/HTTP regressions, a raw-reflection probe, and historical ZAP XSS alerts. The HTTP probe does not execute JavaScript. Final ZAP browser-extension callback errors limit browser-dependent confidence.

## Coupon race

**Impact:** two requests can both observe unused state and receive a discount before either consumes the coupon.

**Fix:** perform the check and state change inside one lock. This protects the single-process lab. A multi-instance service would require a storage-level atomic operation or an equivalent design.

**Proof:** `test_parallel_coupon_redemption` synchronizes the vulnerable race with a barrier and checks two acceptances; fixed mode accepts exactly one and rejects the other. `test_coupon_repeat_rejected` checks sequential reuse. The actual parallel HTTP probe complements these tests but its timing varies.

## Dependency fixture and scanner integrity

The old `requests` pin is a scan-only fixture; it is never installed as an application dependency. pip-audit returned 10 raw advisory records grouped into 5 unique advisories in the imported vulnerable run. The comparison pin had zero direct-fixture findings at that time. A matching advisory is not proof of reachable exploitation in this standard-library app.

`tests/test_scan_runner.py` covers missing tools, malformed output, nonaccepted exits, stale report reuse and advisory alias grouping. A scanner that did not complete cannot produce a passing gate.

## What each check can establish

| Check | Useful evidence | Does not establish |
| --- | --- | --- |
| Semgrep fixture tests and one SQL rule | Rule behavior for positive/negative examples and selected source construction | Complete taint analysis, all authorization defects, or all code paths |
| pip-audit direct manifests | Known advisory matches at the recorded time | Transitive coverage, app reachability, or future absence of advisories |
| Targeted HTTP probes | Known attack behavior against the executable service | Exhaustive payload coverage or browser JavaScript execution |
| Regression suite | Specific security requirements and valid behavior remain true | Complete security of the application |
| Generic ZAP | Discovered unauthenticated HTTP/HTML issues and raw alerts | Two-user ownership policy, coupon races, or exhaustive browser coverage |

The current 17-test suite does not claim a complete endpoint/role matrix. Extending authenticated two-user coverage and resolving the scanner browser-callback issue are bounded future improvements. Production TLS, distributed state and AI/LLM security are outside this project.
