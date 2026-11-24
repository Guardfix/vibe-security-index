"""Draw the README images from data/summary.csv, in the GuardFix site style, light and dark:
assets/hero-{light,dark}.svg (headline numbers) and assets/chart-{light,dark}.svg (share per tool).

Headings use Source Serif 4 (SIL OFL, assets/source-serif-4-OFL.txt), subset and embedded so the
images look the same everywhere. Standard library only.
"""

import base64
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = {"lovable": "Lovable", "cursor": "Cursor", "claude-code": "Claude Code", "gemini": "Gemini CLI",
          "codex": "Codex", "all-ai-tools": "All AI tools", "baseline": "No AI traces"}
SANS = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif"
SERIF = "GFSerif,Source Serif 4,Georgia,serif"
# GuardFix verified fixes on 45 Index projects it had never seen (closed test set, 2026-11-13): 138 of 169.
FIXED = (138, 169, 45)
THEMES = {
    "light": {"panel": "#c9ddd1", "dot": "#173b31", "dot_op": ".13", "ink": "#173b31", "sub": "#33493f",
              "card": "#fffefa", "line": "#dee5d9", "num": "#1a624b", "muted": "#596b5e", "pill": "#fffefa",
              "pill_ink": "#1a624b", "bg": "#fffefa", "grid": "#dee5d9", "bar": "#1a624b", "hot": "#0f3d2f",
              "ref": "#9aa89f"},
    "dark": {"panel": "#12302a", "dot": "#eaf0e4", "dot_op": ".08", "ink": "#eef3ec", "sub": "#b9c9bf",
             "card": "#173b31", "line": "#2a5146", "num": "#8fd3b4", "muted": "#a9bbb0", "pill": "#173b31",
             "pill_ink": "#8fd3b4", "bg": "#12302a", "grid": "#2a5146", "bar": "#5fbf95", "hot": "#a6e3c6",
             "ref": "#6f8479"},
}


def font_css():
    path = ROOT / "assets" / "source-serif-4-subset.woff2"
    if not path.exists():
        return ""
    data = base64.b64encode(path.read_bytes()).decode()
    return f'<style>@font-face{{font-family:GFSerif;src:url(data:font/woff2;base64,{data}) format("woff2")}}</style>'


def phrase(share):
    """75.6 -> "3 in 4": the simple fraction closest to the share."""
    n, d = min(((1, 2), (2, 3), (3, 4), (4, 5), (9, 10)), key=lambda f: abs(f[0] / f[1] - share / 100))
    return f"{n} in {d}"


def hero(rows, t, css, scanned):
    by = {r["group"]: r for r in rows}
    ai = float(by["all-ai-tools"]["share_pct"])
    total = scanned
    W, H = 1200, 540
    cards = [(f'{float(by["lovable"]["share_pct"]):.0f}%', "of Lovable apps", f'median {by["lovable"]["median_vulns"]} such vulnerabilities each'),
             (f"{total:,}", "public repos scanned", "Trivy + OSV-Scanner, nothing executed"),
             (f"{round(100 * FIXED[0] / FIXED[1])}%", "fixed automatically by GuardFix", f"and verified to build, on {FIXED[2]} unseen repos")]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" '
           f'aria-label="{phrase(ai)} AI-built apps ship a known vulnerable dependency">', css,
           f'<defs><pattern id="d" width="22" height="22" patternUnits="userSpaceOnUse">'
           f'<circle cx="3" cy="3" r="1.2" fill="{t["dot"]}" opacity="{t["dot_op"]}"/></pattern></defs>',
           f'<rect width="{W}" height="{H}" rx="28" fill="{t["panel"]}"/><rect width="{W}" height="{H}" rx="28" fill="url(#d)"/>',
           f'<rect x="{W / 2 - 215}" y="44" width="430" height="34" rx="17" fill="{t["pill"]}" opacity=".85"/>',
           f'<text x="{W / 2}" y="66" text-anchor="middle" font-family="{SANS}" font-size="13" font-weight="600" '
           f'letter-spacing="1.6" fill="{t["pill_ink"]}">VIBE SECURITY INDEX · NOVEMBER 2026</text>',
           f'<text x="{W / 2}" y="160" text-anchor="middle" font-family="{SERIF}" font-size="62" fill="{t["ink"]}">'
           f'{phrase(ai)} AI-built apps ship</text>',
           f'<text x="{W / 2}" y="232" text-anchor="middle" font-family="{SERIF}" font-size="62" fill="{t["ink"]}">'
           f'a known vulnerable dependency.</text>',
           f'<text x="{W / 2}" y="290" text-anchor="middle" font-family="{SANS}" font-size="21" fill="{t["sub"]}">'
           f'Every one of those vulnerabilities already has a fix. Nobody applied it.</text>']
    cw, gap = 330, 30
    x0 = (W - 3 * cw - 2 * gap) / 2
    for i, (num, label, note) in enumerate(cards):
        x = x0 + i * (cw + gap)
        out += [f'<rect x="{x}" y="340" width="{cw}" height="150" rx="20" fill="{t["card"]}" stroke="{t["line"]}"/>',
                f'<text x="{x + 28}" y="404" font-family="{SERIF}" font-size="48" fill="{t["num"]}">{num}</text>',
                f'<text x="{x + 28}" y="438" font-family="{SANS}" font-size="16" font-weight="600" fill="{t["ink"]}">{label}</text>',
                f'<text x="{x + 28}" y="464" font-family="{SANS}" font-size="13.5" fill="{t["muted"]}">{note}</text>']
    out.append("</svg>")
    return "\n".join(out) + "\n"


def chart(rows, t, css):
    W, left, right, top, bar, gap = 720, 190, 70, 84, 26, 12
    plot = W - left - right
    tools = sorted((r for r in rows if r["group"] in LABELS and r["group"] not in ("all-ai-tools", "baseline")),
                   key=lambda r: -float(r["share_pct"]))
    ref = [r for r in rows if r["group"] in ("all-ai-tools", "baseline")]
    items = [(r, False) for r in tools] + [(None, None)] + [(r, True) for r in ref]
    H = top + sum(10 if r is None else bar + gap for r, _ in items) + 44
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
           f'font-family="{SANS}" role="img" '
           f'aria-label="Share of projects with a known, already fixed high or critical vulnerability in production dependencies">',
           css, f'<rect width="{W}" height="{H}" rx="18" fill="{t["bg"]}" stroke="{t["grid"]}"/>',
           f'<text x="28" y="40" font-family="{SERIF}" font-size="20" fill="{t["ink"]}">AI-built apps shipping a known high/critical vulnerability with a fix</text>',
           f'<text x="28" y="62" font-size="12" fill="{t["muted"]}">Share of projects, production dependencies only. Census of November 2026, Trivy + OSV-Scanner.</text>']
    y = top
    bottom = H - 44
    for p in (0, 25, 50, 75, 100):
        x = left + plot * p / 100
        out.append(f'<line x1="{x:.1f}" y1="{top - 4}" x2="{x:.1f}" y2="{bottom}" stroke="{t["grid"]}" stroke-width="1"/>')
        out.append(f'<text x="{x:.1f}" y="{bottom + 16}" font-size="11" text-anchor="middle" fill="{t["muted"]}">{p}%</text>')
    for r, is_ref in items:
        if r is None:
            y += 10
            continue
        share = float(r["share_pct"])
        w = plot * share / 100
        color = t["ref"] if r["group"] == "baseline" else t["hot"] if r["group"] == "all-ai-tools" else t["bar"]
        cy = y + bar / 2 + 4
        weight = "600" if is_ref else "400"
        out.append(f'<text x="{left - 12}" y="{cy - 1}" font-size="13" font-weight="{weight}" text-anchor="end" fill="{t["ink"]}">{LABELS[r["group"]]}</text>')
        out.append(f'<text x="{left - 12}" y="{cy + 12}" font-size="10.5" text-anchor="end" fill="{t["muted"]}">n = {r["projects"]}</text>')
        # bar with a rounded data end, square at the baseline
        out.append(f'<path d="M{left},{y} h{w - 6:.1f} a6,6 0 0 1 6,6 v{bar - 12} a6,6 0 0 1 -6,6 h-{w - 6:.1f} z" fill="{color}">'
                   f'<title>{LABELS[r["group"]]}: {r["with_vuln"]} of {r["projects"]} projects ({share:.0f}%)</title></path>')
        out.append(f'<text x="{left + w + 8:.1f}" y="{cy}" font-size="13" font-weight="600" fill="{t["ink"]}">{share:.0f}%</text>')
        y += bar + gap
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "summary.csv"
    every = list(csv.DictReader(open(src)))
    rows = [r for r in every if not r.get("too_small")]
    scanned = sum(int(r["projects"]) for r in every if r["group"] != "all-ai-tools")  # Bolt included
    css = font_css()
    (ROOT / "assets").mkdir(exist_ok=True)
    for name, t in THEMES.items():
        (ROOT / "assets" / f"hero-{name}.svg").write_text(hero(rows, t, css, scanned))
        (ROOT / "assets" / f"chart-{name}.svg").write_text(chart(rows, t, css))


if __name__ == "__main__":
    main()
