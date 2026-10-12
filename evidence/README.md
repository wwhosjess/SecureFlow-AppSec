# Recorded execution evidence

These selected artifacts were imported byte-for-byte from earlier private development executions. Their dates and original source identifiers are retained in [manifest.json](manifest.json). The new repository does not contain the old Git history; these are historical reports, not claims that the new repository has already run ZAP.

The manifest records SHA-256 for every included artifact and the source files copied into the clean baseline. The earlier source commit identifiers are provenance labels, not commits reachable through this repository. No private-repository links are required to inspect the included evidence.

## Pipeline — 4 October 2026

| Result | Vulnerable | Fixed |
| --- | --- | --- |
| Gate | findings | pass |
| SAST | 1 finding | 0 |
| SCA | 5 unique advisories, 10 raw records | 0 |
| Targeted HTTP | 5 exposed checks | 0 |
| Regressions | 17 passed | 17 passed |

Inspect the [vulnerable summary](2026-10-04/pipeline/vulnerable/summary.json), [fixed summary](2026-10-04/pipeline/fixed/summary.json), raw `sast.json` / `sca.json`, scanner logs and `tests.txt` in each directory. The pipeline's ZAP `not_run` is truthful: ZAP ran in a separate workflow.

## ZAP comparison

| Raw alert types | Vulnerable, 3 Oct | Hardened fixed, 4 Oct |
| --- | ---: | ---: |
| High | 3 | 1 |
| Medium | 2 | 0 |
| Low | 6 | 0 |
| Informational | 1 | 1 |

Both recorded workflows succeeded and produced usable JSON/HTML with ZAP exit **2 (warnings)**. Counts are alert types, not distinct root causes. The runs used different dates and source revisions; this is not a same-revision comparison.

- Vulnerable: [original JSON](2026-10-03/zap-vulnerable/zap.json), [original HTML](2026-10-03/zap-vulnerable/zap.html), [console](2026-10-03/zap-vulnerable/scan-console.txt).
- Fixed: [original JSON](2026-10-04/zap-fixed/zap.json), [original HTML](2026-10-04/zap-fixed/zap.html), [scanner debug log](2026-10-04/zap-fixed/zap.log), [server log](2026-10-04/zap-fixed/server.log), [diagnostics](2026-10-04/zap-fixed/diagnostics.json), [compressed HTTP history](2026-10-04/zap-fixed/http-messages.jsonl.gz).

Expected vulnerable XSS and missing-header alerts are absent from the hardened fixed report. Fixed mode adds CSP `form-action` and other browser-policy headers. The remaining alerts are preserved below, not suppressed.

### High: source disclosure — likely false positive

Rule 43 sent:

```http
GET http://127.0.0.1:5050/reflect?q=reflect HTTP/1.1
```

The response was HTTP 200 with body:

```html
<h1>Search results</h1><p>reflect</p>
```

A random string returned the same template with that literal string. The final raw alert reports a 56% similarity comparison against a 75% threshold, with an empty evidence field. [Exact scanner exchanges](2026-10-04/zap-fixed/source-disclosure-exchanges.json) preserve request/response headers, bodies and IDs; [code evidence](2026-10-04/code-evidence.json) records the reviewed source. The `/reflect` path returns a constant template plus `html.escape(term)` in fixed mode and does no file read. This supports **likely false positive**, not demonstrated source disclosure. Raw High severity and original reports remain unchanged.

### Informational: non-storable content — intentional

`Cache-Control: no-store` is appropriate for this lab's responses. This informational alert remains visible.

## Reliability and coverage limitations

The fixed retained history contains 54 HTTP 501 responses: 24 TRACE, 24 OPTIONS and 6 TRACK requests. Server logs agree. These are rejections of unimplemented methods. No HTTP 500 or application traceback was found in those retained logs; that is not proof that errors are impossible.

Final network counters report 13 failed and 1,505 successful sends. [Individual events](2026-10-04/network-failure-evidence.json) attribute 12 failures to internal `https://zap/...` callback DNS resolution during browser setup and one to probing HTTPS on the HTTP-only lab port. Four extension-setup warnings remain unresolved. The HTML report's 1% is an aggregate; it is not the application's failure rate. Older vulnerable logs cannot establish the cause of every individual failure in that run.

Generic discovery was unauthenticated. It did not establish Alice/Bob ownership or coupon-concurrency coverage, and it missed the known vulnerable SQL injection. Browser callback problems limit the assurance from absent DOM-XSS alerts. Source review, targeted probes and regressions complement the scan. Fixed mode is not fully secure.

The Docker image is pinned in the optional workflow, but ZAP add-ons may update at startup. Installed versions are recorded in logs; the image digest alone does not lock all scanner behavior.
