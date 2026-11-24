# Methodology

Census date: **2026-11-09** (collection 2026-11-08, scan finished 2026-11-09).

## 1. Finding projects

`scripts/collect.py` searches GitHub (REST search + GraphQL details) for public repositories that carry the trace a specific AI coding tool leaves behind:

| Group | Trace | How it was searched |
|---|---|---|
| lovable | the `lovable-tagger` package in `package.json` | code search `lovable-tagger filename:package.json`, sliced by file size |
| cursor | a `.cursor/rules` folder | code search `path:.cursor/rules`, sliced by file size |
| claude-code | commits with the trailer `Co-authored-by: Claude` | commit search, sliced by author date (4 days per month, Jan 2025 – Oct 2026) |
| codex | merged pull requests from `codex/` branches (Codex cloud) | issue search `is:pr is:merged head:codex/`, sliced by date (May 2025 – Oct 2026) |
| gemini | a `GEMINI.md` file (Gemini CLI) | code search `filename:GEMINI.md`, sliced by file size |
| bolt | a `.bolt` folder | code search `path:.bolt` |
| baseline | none of the AI tool files below | repository search by creation month × language with the same star range |

Queries are sliced (by size or date) so that GitHub's 1,000-result cap on a single query does not decide the sample; slices are visited in a seeded random order (seed `20261108`).

### Filters (all groups)

- public, not a fork, not archived;
- created on or after 2025-01-01;
- 3 to 1,000 stars; at least 10 commits on the default branch; repository size under 200 MB;
- primary language JavaScript, TypeScript or Python;
- at least one of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt` at the repository root.

### One tool per project

Every candidate is checked at the repository root for files of AI tools: `.cursor`, `.cursorrules`, `.bolt`, `CLAUDE.md`, `.claude`, `GEMINI.md`, `.gemini`, `.agent`, `.windsurf`, `.windsurfrules`, `.github/copilot-instructions.md`, `.aider.conf.yml`, `.clinerules`, plus `lovable-tagger` in `package.json`.

- A project in a tool group is dropped if it has files of any **other** tool. `AGENTS.md` is read by many agents, so it neither marks nor excludes a project.
- A **baseline** project must have **none** of these files (including `AGENTS.md`).
- Two projects were picked by two groups (one by claude-code and codex, one by claude-code and baseline); both are excluded from every group.

Up to 300 projects were drawn at random per group from the eligible pool.

### Selection funnel

| Group | Candidates seen | Eligible | Sampled | Scanned and counted |
|---|---:|---:|---:|---:|
| lovable | 9,186 | 161 | 140 | 138 |
| cursor | 9,318 | 407 | 300 | 299 |
| claude-code | 17,400 | 548 | 300 | 297 |
| gemini | 18,120 | 317 | 230 | 227 |
| codex | 47,198 | 611 | 300 | 295 |
| bolt | 834 | 3 | 3 | 3 |
| baseline | 1,600 | 564 | 300 | 294 |

"Scanned and counted" excludes 16 projects whose clone or scan failed and the 2 projects that were in two groups.

## 2. Scanning

`scripts/scan.py`, for each project:

1. `git clone --depth 1` of the default branch with hooks and symlinks disabled; `.git` is removed.
2. **Trivy 0.76.1** `trivy fs --scanners vuln --include-dev-deps --list-all-pkgs`, skipping `node_modules`, `.next`, `.venv`, `dist`. It runs from an empty directory with empty config and ignore files, so a project cannot suppress its own findings.
3. **OSV-Scanner 2.7.0** `osv-scanner scan source -r --no-call-analysis=all` on the same tree, as a second opinion.
4. The clone is deleted; only the scanner results are kept.

Nothing is installed, built or run. For the census the scanners ran in disposable containers with no network and the project mounted read-only; Trivy and OSV-Scanner used their vulnerability databases as of the scan days (the exact database build was not recorded).

## 3. What counts

A project is counted as **vulnerable** when Trivy reports at least one vulnerability that is:

- **high or critical** by the advisory's own severity;
- in a dependency that is **not development-only**: packages Trivy marks as dev (from the lockfile) are excluded, and so are packages in `requirements-dev.txt` / `requirements-test.txt` style files; where Trivy gives no dev marking, the package is treated as production (see biases);
- in an **exact version** recorded in a lockfile (or pinned in `requirements.txt`);
- **fixable**: the advisory lists a fixed version.

"Median vulnerabilities" counts distinct (advisory, package, version) triples meeting all four conditions, per project, over all projects in the group (including zeros).

`by_severity.csv` splits vulnerable projects into those with at least one critical and those with high only. `by_manager.csv` counts, over all groups, projects that have a given lockfile at the root and how many of them have a counted vulnerability found in a lockfile of that manager. Per-project rows are not published: a hash of a public repository name can be reversed by trying names, and the census found projects whose owners have not been told yet.

Only dependency vulnerabilities are published from this census.

### Difference from the first internal count

The first internal count (same data, 2026-11-09) used "any high/critical in a non-dev dependency" without the fixable condition and kept the two projects that were in two groups:

| Group | First count | This release | Why |
|---|---:|---:|---|
| lovable | 97.8% (n=138) | 97.8% (n=138) | same |
| cursor | 82.3% (n=299) | 82.3% (n=299) | same |
| claude-code | 72.9% (n=299) | 72.7% (n=297) | two-group projects removed |
| gemini | 72.2% (n=227) | 72.2% (n=227) | same |
| codex | 57.6% (n=191) | 56.9% (n=295) | 107 projects added on 2026-11-17 (see below) |
| baseline | 71.8% (n=294) | 71.4% (n=294) | one project has high/critical advisories, none with a fixed version |

## 4. Limitations and biases

- **Public repositories only.** Popular-enough (3+ stars) open projects are not a random sample of everything built with these tools; private and commercial apps are not covered.
- **Trace heuristic.** A trace shows a tool was used at some point, not how much of the code it wrote. Tools that leave no file (or whose users delete it) are invisible; Claude Code is found by commit trailers, which only some users keep. The baseline is "no visible AI tool files", not "no AI": a baseline project can still contain AI-written code, and commit trailers were not checked for baseline projects.
- **Different discovery channels per group.** Each group comes from a different search (code, commits, PRs, repositories), which can favour different kinds of projects. Groups were not matched on size, framework or age beyond the shared filters.
- **Lockfile-only scanning.** A vulnerable version in a lockfile does not prove the vulnerable code is reachable or exploitable in that app. Conversely, projects without a lockfile were excluded, and vendored or bundled code is not seen.
- **Dev/prod split is approximate.** Where a lockfile format gives Trivy no dev marking, packages are treated as production; this can overcount for those managers (notably pnpm and bun).
- **Code not executed.** No install, build, test or exploit was run.
- **Snapshot.** Vulnerability databases grow daily; a later scan of the same commits finds more. Some projects have been updated since the census.
- **Codex top-up.** The first census found 191 Codex projects. On 2026-11-17 we widened the Codex search (every day of the period instead of wider slices) and scanned 107 more with the same tools and rules, so this group was scanned 8 days later than the rest, against a newer vulnerability database. The other groups were not topped up: their eligible pools under these filters were already used or nearly so.
- **Small groups.** Bolt has 3 projects and is not compared. Lovable has 138 because the eligible pool was small.
