"""Find public GitHub projects built with AI coding tools, plus a comparison group.

Each project is assigned to one group by the trace its tool leaves:
  claude-code  commits co-authored by Claude
  cursor       a .cursor/rules folder
  lovable      the lovable-tagger package in package.json
  bolt         a .bolt folder
  codex        merged pull requests from codex/ branches (Codex cloud)
  gemini       GEMINI.md or a .gemini folder (Gemini CLI)
  baseline     none of the traces above (and no other AI tool files)

Projects with traces of more than one tool are dropped, so a group means one tool.
Usage: GITHUB_TOKEN=<your token> python collect.py --per-group 300 --out projects.json
(the census of 2026-11-09 used --per-group 300 and the default seed; GitHub search results change
over time, so a rerun finds a similar sample, not the same one)
"""

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
LANGS = {"JavaScript", "TypeScript", "Python"}
LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"]
TRACES = {  # path at the repo root -> tool it points to
    ".cursor": "cursor", ".cursorrules": "cursor", ".bolt": "bolt",
    "CLAUDE.md": "claude-code", ".claude": "claude-code",
    ".windsurf": "other", ".windsurfrules": "other", "AGENTS.md": "agents-md", ".github/copilot-instructions.md": "other",
    ".aider.conf.yml": "other", ".clinerules": "other", "GEMINI.md": "gemini", ".gemini": "gemini", ".agent": "other",
}
MIN_STARS, MAX_STARS, MIN_COMMITS = 3, 1000, 10
CREATED_AFTER = "2025-01-01"  # the AI coding era: Claude Code, Cursor agents, Lovable, Bolt


def call(url, token, body=None):
    for attempt in range(30):
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                              "User-Agent": "vibe-security-index"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503, 504):
                reset = e.headers.get("x-ratelimit-reset")
                limited = reset and e.headers.get("x-ratelimit-remaining") == "0"
                wait = max(5, int(reset) - int(time.time()) + 2) if limited else 30 * (attempt + 1)
                print(f"  rate limited, waiting {min(wait, 120)}s", file=sys.stderr)
                time.sleep(min(wait, 120))
                continue
            if e.code == 422:
                return {}
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:  # network blips on long runs
            print(f"  network error ({e}), retrying in 60s", file=sys.stderr)
            time.sleep(60)
    raise RuntimeError(f"gave up on {url}")


def search(kind, q, token, pages):
    for page in range(1, pages + 1):
        data = call(f"{API}/search/{kind}?q={urllib.parse.quote(q)}&per_page=100&page={page}", token)
        items = data.get("items", [])
        for it in items:
            if kind == "repositories":
                yield it["full_name"]
            elif kind == "issues":
                yield it["repository_url"].split("/repos/", 1)[1]
            else:
                yield it["repository"]["full_name"]
        time.sleep(6.5 if kind == "code" else 2.2)
        if len(items) < 100:
            break


def candidates(group, token, rng):
    """Repo names for a group, from many narrow queries so one result cap does not decide the sample."""
    months = [f"{y}-{m:02d}" for y in (2025, 2026) for m in range(1, 13) if (y, m) <= (2026, 10)]
    if group == "claude-code":
        days = [f"{m}-{d:02d}" for m in months for d in (3, 10, 17, 24)]
        rng.shuffle(days)
        for day in days:
            yield from search("commits", f'"Co-authored-by: Claude" author-date:{day}', token, 3)
    elif group == "cursor":
        sizes = list(range(0, 6000, 300))
        rng.shuffle(sizes)
        for lo in sizes:
            yield from search("code", f"path:.cursor/rules size:{lo}..{lo + 299}", token, 5)
    elif group == "lovable":
        sizes = list(range(400, 12000, 200))
        rng.shuffle(sizes)
        for lo in sizes:
            yield from search("code", f"lovable-tagger filename:package.json size:{lo}..{lo + 199}", token, 5)
        # top-up (2026-11-16): Lovable's default README and its old gpt-engineer script tag
        for lo in range(0, 8000, 250):
            yield from search("code", f'"lovable.dev/projects" filename:README.md size:{lo}..{lo + 249}', token, 5)
        for lo in range(0, 6000, 250):
            yield from search("code", f"cdn.gpteng.co filename:index.html size:{lo}..{lo + 249}", token, 5)
    elif group == "bolt":
        yield from search("code", "path:.bolt filename:prompt", token, 6)
        yield from search("code", "path:.bolt filename:config.json", token, 3)
    elif group == "codex":
        # every day, not four a month: the 2026-11-16 top-up needed a wider search to reach 300
        days = [f"{m}-{d:02d}" for m in months if m >= "2025-05" for d in range(1, 29)]
        rng.shuffle(days)
        for day in days:
            yield from search("issues", f"is:pr is:merged head:codex/ created:{day}", token, 3)
    elif group == "gemini":
        sizes = list(range(0, 20000, 500))
        rng.shuffle(sizes)
        for lo in sizes:
            yield from search("code", f"filename:GEMINI.md size:{lo}..{lo + 499}", token, 5)
        # top-up (2026-11-16): finer slices, and the .gemini settings folder
        for lo in range(0, 20000, 100):
            yield from search("code", f"filename:GEMINI.md size:{lo}..{lo + 99}", token, 5)
        yield from search("code", "path:.gemini filename:settings.json", token, 10)
    elif group == "baseline":
        for month in months:
            for lang in ("TypeScript", "JavaScript", "Python"):
                yield from search("repositories", f"created:{month} stars:{MIN_STARS}..{MAX_STARS} language:{lang} fork:false", token, 1)


QUERY = """
fragment R on Repository {
  nameWithOwner isFork isArchived stargazerCount createdAt diskUsage
  primaryLanguage { name }
  defaultBranchRef { target { ... on Commit { history { totalCount } } } }
  %s
  pkg: object(expression: "HEAD:package.json") { ... on Blob { text } }
}
"""


def details(names, token):
    paths = LOCKFILES + list(TRACES)
    fields = " ".join(f'f{i}: object(expression: "HEAD:{p}") {{ id }}' for i, p in enumerate(paths))
    out = {}
    for i in range(0, len(names), 10):
        chunk = names[i:i + 10]
        parts = []
        for j, n in enumerate(chunk):
            owner, name = n.split("/", 1)
            parts.append(f"r{j}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) {{ ...R }}")
        data = call(f"{API}/graphql", token, {"query": QUERY % fields + "query {" + " ".join(parts) + "}"})
        for j, n in enumerate(chunk):
            r = (data.get("data") or {}).get(f"r{j}")
            if not r:
                continue
            present = [p for k, p in enumerate(paths) if r.get(f"f{k}")]
            pkg = (r.get("pkg") or {}).get("text") or ""
            traces = {TRACES[p] for p in present if p in TRACES}
            if "lovable-tagger" in pkg:
                traces.add("lovable")
            hist = ((r.get("defaultBranchRef") or {}).get("target") or {}).get("history") or {}
            out[n] = {
                "repo": n, "stars": r["stargazerCount"], "fork": r["isFork"], "archived": r["isArchived"],
                "created": r["createdAt"], "size_kb": r["diskUsage"], "language": (r.get("primaryLanguage") or {}).get("name"),
                "commits": hist.get("totalCount", 0), "lockfiles": [p for p in present if p in LOCKFILES],
                "traces": sorted(traces),
            }
        time.sleep(0.5)
    return out


def eligible(d, group):
    if d["fork"] or d["archived"] or not d["lockfiles"] or d["language"] not in LANGS:
        return False
    if not (MIN_STARS <= d["stars"] <= MAX_STARS) or d["commits"] < MIN_COMMITS or d["created"] < CREATED_AFTER:
        return False
    if (d["size_kb"] or 0) > 200_000:
        return False
    if group == "baseline":
        return not d["traces"]
    # one tool only; AGENTS.md is read by many agents, so it neither marks nor excludes a project
    return not (set(d["traces"]) - {group, "agents-md"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-group", type=int, default=100)
    ap.add_argument("--groups", default="claude-code,cursor,lovable,bolt,baseline,codex,gemini")
    ap.add_argument("--out", default="data/projects.json")
    ap.add_argument("--seed", type=int, default=20261108)
    ap.add_argument("--pool-factor", type=float, default=3, help="stop searching at this many eligible per needed project")
    a = ap.parse_args()
    token = os.environ["GITHUB_TOKEN"]
    rng = random.Random(a.seed)
    result = json.load(open(a.out)) if os.path.exists(a.out) else {}
    for group in a.groups.split(","):
        have = result.get(group, [])
        need = a.per_group - len(have)
        if need <= 0:
            continue
        # a bigger sample keeps the projects already scanned and adds new ones
        seen, pool, batch = {d["repo"] for d in have}, [], []

        def flush():
            pool.extend(d for d in details(batch, token).values() if eligible(d, group))
            batch.clear()
            print(f"{group}: seen {len(seen)}, eligible {len(pool)}", file=sys.stderr)

        for name in candidates(group, token, rng):
            if name in seen:
                continue
            seen.add(name)
            batch.append(name)
            if len(batch) >= 200:
                flush()
                if len(pool) >= need * a.pool_factor:
                    break
        if batch:
            flush()
        rng.shuffle(pool)
        result[group] = sorted(have + pool[:need], key=lambda d: d["repo"])
        meta = result.setdefault("_meta", {}).setdefault(group, {"seen": 0, "eligible": 0})
        meta["seen"] += len(seen) - len(have)
        meta["eligible"] += len(pool)
        json.dump(result, open(a.out, "w"), indent=1)
        print(f"{group}: kept {len(result[group])} of {len(pool)} eligible ({len(seen)} seen)", file=sys.stderr)


if __name__ == "__main__":
    main()
