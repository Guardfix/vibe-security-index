"""Scan collected projects for known vulnerabilities in their dependencies.

For each project: shallow-clone the latest commit, run Trivy and OSV-Scanner on its lockfiles,
keep only the results, delete the clone. No project code is ever executed: nothing is
installed, built or run, and git hooks and symlinks are disabled during the clone.

Usage:
  python scan.py projects.json results.jsonl --workers 3

Needs `git`, `trivy` and `osv-scanner` on PATH (versions used for the census: see METHODOLOGY.md).
For extra isolation run it inside a throwaway container or VM; the census did so, with the
project mounted read-only and no network for the scanners.

The output format (one JSON record per project) is what aggregate.py reads.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

TRIVY = os.environ.get("TRIVY", "trivy")
OSV = os.environ.get("OSV_SCANNER", "osv-scanner")
SKIP_DIRS = ("**/node_modules", "**/.next", "**/.venv", "**/.git", "**/dist")

# Lockfile types where Trivy (with --include-dev-deps) sets "Dev": true on development packages,
# so a package without the flag is a production one.
DEV_AWARE_TYPES = {"npm", "yarn", "gradle"}
# Python has no dev flag in requirements files: the file name is the convention.
DEV_REQUIREMENTS = re.compile(r"(^|/)requirements[-_.]?(dev|devel|develop|test|tests|testing|lint|docs|ci)\.(txt|in)$"
                              r"|(^|/)requirements/(dev|devel|develop|test|tests|testing|lint|docs|ci)\.(txt|in)$")


def clone(repo, dest):
    env = {"PATH": os.environ["PATH"], "HOME": tempfile.gettempdir(), "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    subprocess.run(["git", "-c", "core.symlinks=false", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1",
                    "--single-branch", "--no-tags", f"https://github.com/{repo}.git", str(dest)],
                   check=True, env=env, timeout=300, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def dependency_scope(result, v, packages):
    pkg = packages.get(v.get("PkgID")) or {}
    rel = pkg.get("Relationship")
    direct = True if rel == "direct" else False if rel == "indirect" else None
    if pkg.get("Dev"):
        scope = "dev"
    elif pkg and result.get("Type") in DEV_AWARE_TYPES:
        scope = "prod"
    elif DEV_REQUIREMENTS.search(PurePosixPath(result.get("Target", "")).as_posix().lower()):
        scope = "dev"
    else:
        scope = "unknown"
    return {"dependency_scope": scope, "direct": direct}


def trivy(root, work):
    """Trivy on lockfiles. It auto-loads trivy.yaml and .trivyignore from its working directory,
    so it runs from an empty directory with empty config files: a project cannot hide its own findings."""
    cfg = Path(tempfile.mkdtemp(prefix="trivy-cfg-", dir=work))
    (cfg / "trivy.yaml").write_text("{}\n")
    (cfg / ".trivyignore").write_text("")
    out = cfg / "report.json"
    cmd = [TRIVY, "fs", "--quiet", "--format", "json", "--output", str(out), "--list-all-pkgs",
           "--scanners", "vuln", "--include-dev-deps",
           "--config", str(cfg / "trivy.yaml"), "--ignorefile", str(cfg / ".trivyignore"),
           *[a for d in SKIP_DIRS for a in ("--skip-dirs", d)], str(root)]
    try:
        subprocess.run(cmd, cwd=cfg, check=True, timeout=600, capture_output=True, text=True,
                       env={**os.environ, "TRIVY_NO_PROGRESS": "true"})
        report = json.loads(out.read_text() or "{}")
    finally:
        shutil.rmtree(cfg, ignore_errors=True)
    findings = []
    for result in report.get("Results") or []:
        packages = {p.get("ID"): p for p in result.get("Packages") or []}
        for v in result.get("Vulnerabilities") or []:
            findings.append({
                "source": "trivy", "kind": "vulnerability", "rule_id": v["VulnerabilityID"],
                "severity": (v.get("Severity") or "unknown").lower(),
                "location": {"path": result.get("Target", "")},
                "package": {"name": v.get("PkgName"), "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion")},
                "evidence": dependency_scope(result, v, packages),
            })
    return findings


def osv(root):
    """OSV-Scanner on lockfiles only (no call analysis, nothing executed)."""
    p = subprocess.run([OSV, "scan", "source", "-r", "--format", "json", "--no-call-analysis=all", str(root)],
                       capture_output=True, text=True, timeout=600)
    if "No package sources found" in p.stderr:
        return {"vulns": [], "no_sources": True}
    if p.returncode not in (0, 1):
        return {"error": p.stderr[-500:]}
    data = json.loads(p.stdout or "{}")
    vulns = []
    for res in data.get("results") or []:
        src = os.path.relpath(res["source"]["path"], root)
        for pk in res.get("packages") or []:
            info = pk["package"]
            for g in pk.get("groups") or []:
                vulns.append({"lockfile": src, "ecosystem": info.get("ecosystem"), "name": info["name"],
                              "version": info.get("version"), "ids": sorted(g["ids"]), "max_severity": g.get("max_severity")})
    return {"vulns": vulns}


def scan_one(project, work):
    started = time.time()
    record = {"repo": project["repo"], "group": project["group"], "engines_ok": []}
    dest = Path(tempfile.mkdtemp(prefix="vsi-", dir=work))
    try:
        clone(project["repo"], dest / "src")
        root = dest / "src"
        shutil.rmtree(root / ".git", ignore_errors=True)
        record["findings"] = trivy(root, work)
        record["engines_ok"].append("trivy")
        record["osv"] = osv(root)
    except Exception as e:  # one broken project never stops the run
        record["error"] = f"{type(e).__name__}: {str(e)[-300:]}"
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    record["seconds"] = round(time.time() - started, 1)
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("projects")
    ap.add_argument("results")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--workdir", default=os.path.join(tempfile.gettempdir(), "vsi-work"))
    a = ap.parse_args()
    Path(a.workdir).mkdir(parents=True, exist_ok=True)
    data = json.load(open(a.projects))
    todo = [dict(p, group=g) for g, items in data.items() if not g.startswith("_") for p in items]
    done = set()
    if os.path.exists(a.results):  # resume an interrupted run
        done = {json.loads(line)["repo"] for line in open(a.results) if line.strip()}
    todo = [p for p in todo if p["repo"] not in done]
    print(f"{len(todo)} to scan, {len(done)} already done", file=sys.stderr, flush=True)
    with open(a.results, "a") as out, ThreadPoolExecutor(a.workers) as pool:
        for n, rec in enumerate(pool.map(lambda p: scan_one(p, a.workdir), todo), 1):
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"[{n}/{len(todo)}] {rec['group']} {rec['seconds']}s {rec.get('error', '')}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
