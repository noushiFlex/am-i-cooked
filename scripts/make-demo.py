#!/usr/bin/env python3
"""Render docs/demo.svg: an animated terminal built from the scanner's real output on tests/fixtures."""
import subprocess, html, re

out = subprocess.run(
    ["node", "skills/am-i-cooked/scripts/scan.mjs", "tests/fixtures"],
    capture_output=True, text=True,
).stdout.splitlines()
trim = lambda l: l if len(l) <= 80 else l[:79] + "…"
lines = ["$ am-i-cooked ."] + [trim(l) for l in out[:22]]

W, LH, PAD = 900, 22, 20
H = PAD * 2 + LH * len(lines) + 8

def cls(line):
    if line.startswith("$"): return "cmd"
    if line.startswith("Verdict: COOKED"): return "bad"
    if line.startswith("Verdict: A BIT"): return "warn"
    if line.startswith("Verdict: SAFE"): return "ok"
    if re.match(r"^(CVE|GHSA)-", line): return "id"
    if line.startswith("Upgrade plan"): return "dim"
    if line.startswith("  ") and "->" in line and "(" not in line.split("->")[0]: return "fg"
    return "fg"

rows = []
for i, line in enumerate(lines):
    text = html.escape(line).replace(" ", "&#160;")
    if "MAJOR jump" in line:
        a, b = text.split("(MAJOR", 1)
        text = f'{a}<tspan class="warn">(MAJOR{b}</tspan>'
    rows.append(
        f'<text class="l {cls(line)}" x="{PAD}" y="{PAD + 14 + i * LH}" style="animation-delay:{0.35 * i:.2f}s">{text}</text>'
    )

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" role="img" aria-label="am-i-cooked scanning a project and printing a COOKED verdict with an upgrade plan">
<style>
  .bg{{fill:#0d1117}} .bar{{fill:#161b22}}
  text{{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}}
  .fg{{fill:#c9d1d9}} .dim{{fill:#8b949e}} .cmd{{fill:#7ee787}} .id{{fill:#79c0ff;font-weight:700}}
  .bad{{fill:#ff7b72;font-weight:700}} .warn{{fill:#e3b341}} .ok{{fill:#7ee787;font-weight:700}}
  .l{{opacity:0;animation:in .01s forwards}}
  @keyframes in{{to{{opacity:1}}}}
  @media (prefers-reduced-motion:reduce){{.l{{opacity:1;animation:none}}}}
</style>
<rect class="bg" width="{W}" height="{H}" rx="10"/>
<rect class="bar" width="{W}" height="0"/>
{chr(10).join(rows)}
</svg>
'''
open("docs/demo.svg", "w").write(svg)
print(f"docs/demo.svg: {len(lines)} lines")
