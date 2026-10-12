"""Run real tools and HTTP probes. Missing/failed scanners are never a PASS."""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from urllib import error, parse, request
from lab.app import create_server

ROOT = Path(__file__).resolve().parent


def external(name, command, output, accepted=(0, 1)):
    if not shutil.which(command[0]):
        return {"tool": name, "status": "not_run", "reason": command[0] + " is not installed"}, None
    try:
        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        output.with_suffix(".log").write_text(result.stderr)
        # Never use an earlier run's report if this command fails.
        parsed = json.loads(result.stdout)
        output.write_text(json.dumps(parsed, indent=2))
        if result.returncode not in accepted:
            return {"tool": name, "status": "error", "reason": "Scanner exit " + str(result.returncode)}, None
        return {"tool": name, "status": "completed", "exit_code": result.returncode}, parsed
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        return {"tool": name, "status": "error", "reason": str(exc)[:200]}, None


def http(base, path, cookie=None, body=None, extra=None):
    headers = dict(extra or {})
    if cookie:
        headers["Cookie"] = cookie
    data = json.dumps(body).encode() if body is not None else None
    if data:
        headers["Content-Type"] = "application/json"
    req = request.Request(base + path, data=data, headers=headers)
    try:
        response = request.urlopen(req, timeout=10)
    except error.HTTPError as exc:
        response = exc
    with response:
        return response.status, response.read().decode(), dict(response.headers)


def probe(mode):
    server = create_server(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    results = []
    try:
        status, _, headers = http(base, "/login", body={"username": "alice", "password": "demo-password"})
        if status != 200:
            raise RuntimeError("Login failed")
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, body, _ = http(base, "/orders/1002", cookie)
        results.append({"scenario": "idor", "exploitable": status == 200 and '"owner_id": "bob"' in body,
                        "evidence": f"Cross-user order request: HTTP {status}"})
        status, body, _ = http(base, "/search?q=" + parse.quote("' OR 1=1 -- "))
        results.append({"scenario": "sqli", "exploitable": "Unreleased prototype" in body,
                        "evidence": f"SQLi search: HTTP {status}, hidden product returned={('Unreleased prototype' in body)}"})
        payload = '<img src=x onerror="alert(1)">'
        status, body, _ = http(base, "/reflect?q=" + parse.quote(payload))
        results.append({"scenario": "xss", "exploitable": payload in body,
                        "evidence": "Raw executable HTML reflected=" + str(payload in body),
                        "limitation": "HTTP reflection probe; does not execute JavaScript in a browser."})
        status, body, _ = http(base, "/me", extra={"X-User": "bob"})
        results.append({"scenario": "auth", "exploitable": status == 200 and '"bob"' in body,
                        "evidence": f"Unsigned identity header: HTTP {status}"})
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            replies = list(pool.map(lambda _: http(base, "/coupon/redeem", cookie, body={}), range(2)))
        count = sum(r[0] == 200 for r in replies)
        results.append({"scenario": "race", "exploitable": count > 1,
                        "evidence": f"Two parallel redemptions: {count} accepted",
                        "limitation": "HTTP scheduling varies; deterministic concurrency regression also runs."})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return {"tool": "SecureFlow HTTP probes", "status": "completed", "mode": mode, "checks": results,
            "finding_count": sum(r["exploitable"] for r in results)}


def normalize_sca(data):
    findings = []
    raw_count = 0
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            raw_count += 1
            identifiers = {vuln["id"], *vuln.get("aliases", [])}
            match = next((f for f in findings if f["package"] == dep["name"] and f["version"] == dep["version"]
                          and identifiers.intersection({f["id"], *f["aliases"]})), None)
            if match:
                match["aliases"] = sorted(({*match["aliases"], *identifiers}) - {match["id"]})
                match["fix_versions"] = sorted(set(match["fix_versions"] + vuln["fix_versions"]))
            else:
                findings.append({"id": vuln["id"], "aliases": sorted(vuln.get("aliases", [])),
                                 "package": dep["name"], "version": dep["version"],
                                 "fix_versions": vuln["fix_versions"], "description": vuln.get("description", "")})
    return findings, raw_count


def run(mode, out):
    out.mkdir(parents=True, exist_ok=True)
    target = "lab/vulnerable_sql.py" if mode == "vulnerable" else "lab/fixed_sql.py"
    sast, data = external("Semgrep custom rule", ["semgrep", "scan", "--config", "rules/unsafe-sql.yaml", "--json", "--metrics=off", target], out / "sast.json")
    if data is not None:
        if data.get("errors"):
            sast.update(status="error", reason="Semgrep reported scan errors")
        sast["findings"] = [{"id": r["check_id"], "severity": r["extra"]["severity"], "path": r["path"],
                             "line": r["start"]["line"], "message": r["extra"]["message"]} for r in data.get("results", [])]
        sast["finding_count"] = len(sast["findings"])
        sast["scope"] = "One custom SQL construction rule on " + target
    sca, data = external("pip-audit", ["pip-audit", "-r", f"lab/dependencies-{mode}.txt", "--no-deps", "--disable-pip", "--format", "json", "--progress-spinner", "off"], out / "sca.json")
    if data is not None:
        sca["findings"], sca["raw_finding_count"] = normalize_sca(data)
        sca["finding_count"] = len(sca["findings"])
        sca["scope"] = "Scan-only direct dependency fixture. No transitive dependency coverage."
    try:
        dast = probe(mode)
    except Exception as exc:
        dast = {"tool": "SecureFlow HTTP probes", "status": "error", "reason": str(exc)[:200]}
    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, capture_output=True, text=True)
    (out / "tests.txt").write_text(tests.stdout + tests.stderr)
    digest = hashlib.sha256()
    sources = [ROOT / "security_scan.py", ROOT / "requirements-tools.txt"]
    for folder in ("lab", "rules", "tests"):
        sources.extend(p for p in (ROOT / folder).iterdir() if p.is_file() and p.suffix in {".py", ".txt", ".yaml"})
    for path in sorted(sources):
        digest.update(str(path.relative_to(ROOT)).encode() + path.read_bytes())
    scans = {"sast": sast, "sca": sca, "dast": dast}
    complete = all(s["status"] == "completed" for s in scans.values()) and tests.returncode == 0
    finding_count = sum(s.get("finding_count", 0) for s in scans.values())
    gate = "blocked" if not complete else "findings" if finding_count else "pass"
    report = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "mode": mode,
              "source_sha256": digest.hexdigest(), "gate": gate, "scans": scans,
              "regression": {"status": "pass" if tests.returncode == 0 else "fail", "exit_code": tests.returncode},
              "zap": {"status": "not_run", "reason": "Optional Docker workflow is configured separately."}}
    (out / "summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"mode": mode, "gate": gate, "report": str(out / "summary.json"), "findings": finding_count}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["fixed", "vulnerable"], default="fixed")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.mode, args.output or ROOT / "reports" / args.mode)
    # A deliberately vulnerable run fails by design. In CI, inspect the report rather than swallowing errors.
    sys.exit(0 if result["gate"] == "pass" else 1)
