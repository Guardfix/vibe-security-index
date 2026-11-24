# Scripts

Python 3.10+, standard library only.

| Script | What it does | Needs |
|---|---|---|
| `collect.py` | Finds candidate projects through GitHub search, applies the filters and the one-tool rule, samples up to N per group. Writes `projects.json` (contains repository names; it is not published here). | `GITHUB_TOKEN` env var (a token with public read access) |
| `scan.py` | Shallow-clones each project, runs Trivy and OSV-Scanner on its lockfiles, deletes the clone. Writes `results.jsonl`, one record per project. Resumable. Never installs or runs project code. | `git`, `trivy` (0.76.1 used), `osv-scanner` (2.7.0 used) |
| `aggregate.py` | Turns `results.jsonl` + `projects.json` into `data/*.csv`. The definition of "counted" lives here. | — |
| `chart.py` | Draws `assets/chart-light.svg` and `assets/chart-dark.svg` from `data/summary.csv`. | — |

```sh
export GITHUB_TOKEN=<your token>
python collect.py --per-group 300 --out projects.json   # hours: GitHub search is rate limited
python scan.py projects.json results.jsonl --workers 3  # roughly 30 s per project
python aggregate.py results.jsonl projects.json --out ../data
python chart.py
```

`python aggregate.py ... --out -` prints all tables as one JSON object instead of writing files.

Notes:
- The census ran Trivy through a container launcher (no network, read-only mount) with the same flags as `scan.py`; the standalone `scan.py` calls the binaries directly. Run it in a throwaway VM or container if you want the same isolation.
- The census scan records also held other scanner output (secrets, code patterns). They are not part of this release, and `aggregate.py` reads only dependency vulnerabilities, so it gives the same numbers on either record format.
- Rerunning finds a similar, not identical, sample: GitHub search results and vulnerability databases change daily.
