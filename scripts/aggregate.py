"""Turn scan records into the Index tables.

Usage:
  python aggregate.py results.jsonl projects.json --out ../data
  python aggregate.py results.jsonl projects.json --out -     # print every table as one JSON object

Input: results.jsonl from scan.py (one record per project) and projects.json from collect.py
(used only for the lockfiles found at each project's root).

What counts (the headline number):
  a project is "vulnerable" when Trivy reports at least one known vulnerability that is
  - rated high or critical by the advisory,
  - in a dependency that is not development-only (not marked Dev by the lockfile, not in a
    requirements-dev.txt style file), and
  - has a fixed version published (Trivy's FixedVersion is set).
Versions come from lockfiles (or pinned requirements files) only. Nothing is installed or run.
OSV-Scanner is the second opinion: the agreement column says how often both scanners agree
on whether a project has any known vulnerability at all.

Only dependency vulnerabilities are aggregated. The scan records may hold other findings;
they are ignored here on purpose.
"""

import argparse
import collections
import csv
import hashlib
import io
import json
import os
import re
import statistics
import sys

AI_GROUPS = ["lovable", "cursor", "claude-code", "gemini", "codex", "bolt"]
ORDER = AI_GROUPS + ["baseline"]
MIN_GROUP = 30  # below this a group is shown but marked too small to compare

MANAGERS = [  # lockfile name -> package manager label
    (re.compile(r"(^|/)package-lock\.json$"), "npm"),
    (re.compile(r"(^|/)pnpm-lock\.yaml$"), "pnpm"),
    (re.compile(r"(^|/)yarn\.lock$"), "yarn"),
    (re.compile(r"(^|/)bun\.lockb?$"), "bun"),
    (re.compile(r"(^|/)(uv\.lock|poetry\.lock|Pipfile\.lock|requirements[^/]*\.txt)$"), "python"),
]


def manager(path):
    for rx, name in MANAGERS:
        if rx.search(path or ""):
            return name
    return "other"


def pid(repo):
    """Public id of a project: the first 12 hex chars of sha256("owner/name")."""
    return hashlib.sha256(repo.encode()).hexdigest()[:12]


def severity(f):
    # the census scanner lowered dev dependencies one level and kept the advisory's own rating
    return (f.get("evidence") or {}).get("original_severity") or f.get("severity")


def prod_high(f):
    if f.get("source") != "trivy" or f.get("kind") != "vulnerability":
        return False
    return (f.get("evidence") or {}).get("dependency_scope") != "dev" and severity(f) in ("high", "critical")


def fixable(f):
    return bool((f.get("package") or {}).get("fixed_version"))


def key(f):
    p = f.get("package") or {}
    return (f["rule_id"], p.get("name"), p.get("installed_version"))


def usable(r):
    """A record is counted only if the clone worked and both scanners ran."""
    if r.get("error") or "osv" not in r or r["osv"].get("error"):
        return False
    ok = r.get("engines_ok")
    return ok is None or "trivy" in ok


def project_row(r, root_lockfiles):
    findings = r.get("findings") or []
    trivy_vulns = [f for f in findings if f.get("source") == "trivy" and f.get("kind") == "vulnerability"]
    high = [f for f in findings if prod_high(f)]
    high_fix = [f for f in high if fixable(f)]
    fix_keys = {key(f) for f in high_fix}
    crit_keys = {key(f) for f in high_fix if severity(f) == "critical"}
    return {
        "id": pid(r["repo"]),
        "group": r["group"],
        "managers": sorted({manager(p) for p in root_lockfiles}),
        "vuln_managers": sorted({manager(f["location"]["path"]) for f in high_fix}),
        "high_crit_fixable": len(fix_keys),
        "critical_fixable": len(crit_keys),
        "high_crit_prod_any": len({key(f) for f in high}),
        "direct_fixable": len({key(f) for f in high_fix if (f.get("evidence") or {}).get("direct") is True}),
        "osv_vulns": len(r["osv"].get("vulns") or []),
        "trivy_any": bool(trivy_vulns),
        # the draft's definition (analyze.py, 09.11): any prod high/critical, fix or not
        "draft_prod_high": bool(high),
    }


def pct(n, d):
    return round(100 * n / d, 1) if d else ""


def median(xs):
    if not xs:
        return ""
    m = statistics.median(xs)
    return int(m) if m == int(m) else round(m, 1)


def summary(rows_by_group):
    out = []
    groups = [(g, rows_by_group.get(g, [])) for g in ORDER]
    ai_all = [r for g in AI_GROUPS if g != "bolt" for r in rows_by_group.get(g, [])]
    groups.insert(len(AI_GROUPS), ("all-ai-tools", ai_all))
    for g, rows in groups:
        n = len(rows)
        vuln = sum(1 for r in rows if r["high_crit_fixable"])
        out.append({
            "group": g,
            "projects": n,
            "with_vuln": vuln,
            "share_pct": pct(vuln, n),
            "median_vulns": median([r["high_crit_fixable"] for r in rows]),
            "median_vulns_if_any": median([r["high_crit_fixable"] for r in rows if r["high_crit_fixable"]]),
            "with_vuln_in_direct_dep_pct": pct(sum(1 for r in rows if r["direct_fixable"]), n),
            "osv_trivy_agree_pct": pct(sum(1 for r in rows if bool(r["osv_vulns"]) == r["trivy_any"]), n),
            "too_small": "yes" if n < MIN_GROUP else "",
        })
    return out


def by_severity(rows_by_group):
    out = []
    for g in ORDER:
        rows = rows_by_group.get(g, [])
        n = len(rows)
        crit = sum(1 for r in rows if r["critical_fixable"])
        high_only = sum(1 for r in rows if r["high_crit_fixable"] and not r["critical_fixable"])
        out.append({
            "group": g, "projects": n,
            "with_critical": crit, "with_critical_pct": pct(crit, n),
            "with_high_only": high_only, "with_high_only_pct": pct(high_only, n),
            "total_high_crit": sum(r["high_crit_fixable"] for r in rows),
            "total_critical": sum(r["critical_fixable"] for r in rows),
            "too_small": "yes" if n < MIN_GROUP else "",
        })
    return out


def by_manager(rows):
    """Per package manager, over all groups: projects with that lockfile at the root, and the share
    with a fixable high/critical vulnerability found in a lockfile of that manager."""
    out = []
    for m in ["npm", "pnpm", "yarn", "bun", "python"]:
        have = [r for r in rows if m in r["managers"]]
        vuln = sum(1 for r in have if m in r["vuln_managers"])
        out.append({"manager": m, "projects": len(have), "with_vuln": vuln, "share_pct": pct(vuln, len(have)),
                    "too_small": "yes" if len(have) < MIN_GROUP else ""})
    return out


def to_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("projects")
    ap.add_argument("--out", default="data")
    a = ap.parse_args()

    projects = json.load(open(a.projects))
    lockfiles, membership = {}, collections.defaultdict(set)
    for g, items in projects.items():
        if g.startswith("_"):
            continue
        for p in items:
            lockfiles[p["repo"]] = p.get("lockfiles") or []
            membership[p["repo"]].add(g)
    # a project picked by two groups (e.g. Claude commit trailers and codex/ PRs) means two tools: drop it
    ambiguous = {repo for repo, gs in membership.items() if len(gs) > 1}

    records = {}
    for line in open(a.results):
        if line.strip():
            r = json.loads(line)
            records[r["repo"]] = r  # the last record of a project wins
    rows_by_group, errors, draft = collections.defaultdict(list), collections.Counter(), collections.defaultdict(list)
    for r in records.values():
        if r["repo"] not in membership:
            continue  # scanned in an earlier run but not part of this sample
        if r["repo"] in ambiguous:
            errors["_in_two_groups"] += 1
            continue
        if not usable(r):
            errors[r["group"]] += 1
            continue
        row = project_row(r, lockfiles.get(r["repo"], []))
        rows_by_group[r["group"]].append(row)
    all_rows = [r for g in ORDER for r in rows_by_group.get(g, [])]

    tables = {
        "summary.csv": summary(rows_by_group),
        "by_severity.csv": by_severity(rows_by_group),
        "by_manager.csv": by_manager(all_rows),
    }
    check = {g: {"projects": len(rows), "errors": errors[g],
                 "draft_def_pct": pct(sum(r["draft_prod_high"] for r in rows), len(rows)),
                 "fixable_pct": pct(sum(1 for r in rows if r["high_crit_fixable"]), len(rows))}
             for g, rows in rows_by_group.items()} | {"_in_two_groups": errors["_in_two_groups"]}
    print(json.dumps({"check": check}), file=sys.stderr)

    if a.out == "-":
        json.dump({name: to_csv(rows) for name, rows in tables.items()} | {"_check": check}, sys.stdout)
        return
    os.makedirs(a.out, exist_ok=True)
    for name, rows in tables.items():
        with open(os.path.join(a.out, name), "w") as fh:
            fh.write(to_csv(rows))


if __name__ == "__main__":
    main()
