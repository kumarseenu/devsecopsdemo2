#!/usr/bin/env python
"""
DevSecOps Security Scan – HTML Report Generator
Reads JSON from Bandit, pip-audit, and Trivy and produces a
self-contained single-file HTML report with filtering + search.

Usage:
    python generate-report.py
        --bandit    bandit-report.json
        --pip-audit pip-audit-report.json
        --trivy     trivy-report.json
        --image     "pygoat-vulnerable:latest"
        --output    security-report.html
"""

import argparse
import json
import os
import sys
from datetime import datetime


# ── helpers ────────────────────────────────────────────────────────────────

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        print("WARNING: could not read {}: {}".format(path, exc))
        return {}


def sev_order(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
        str(s).upper(), 4
    )


# ── data extraction ────────────────────────────────────────────────────────

def parse_bandit(data):
    results = data.get("results", [])
    counts = {}
    for r in results:
        s = r.get("issue_severity", "UNKNOWN").upper()
        counts[s] = counts.get(s, 0) + 1
    return results, counts


def parse_pipaudit(data):
    deps = data.get("dependencies", [])
    vulns = []
    for dep in deps:
        for v in dep.get("vulns", []):
            vulns.append(
                {
                    "package": dep.get("name", ""),
                    "version": dep.get("version", ""),
                    "id": v.get("id", ""),
                    "description": v.get("description", ""),
                    "fix_versions": v.get("fix_versions", []),
                }
            )
    return deps, vulns


def parse_trivy(data):
    results = data.get("Results", [])
    vulns = []
    counts = {}
    for r in results:
        for v in r.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            vulns.append(
                {
                    "severity": sev,
                    "cve": v.get("VulnerabilityID", ""),
                    "pkg": v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", "") or "No fix",
                    "title": v.get("Title", "") or v.get("Description", "")[:80],
                    "target": r.get("Target", ""),
                }
            )
    vulns.sort(key=lambda x: sev_order(x["severity"]))
    return vulns, counts


# ── HTML blocks ────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #111827; color: #e5e7eb; font-size: 14px; }

/* header */
.hdr { background: linear-gradient(135deg,#1e3a5f 0%,#0f2444 100%); padding: 28px 40px; border-bottom: 3px solid #3b82f6; }
.hdr h1 { color: #fff; font-size: 26px; margin-bottom: 6px; }
.hdr .img-tag { color: #60a5fa; font-size: 15px; font-weight: 600; margin-top: 4px; }
.hdr .meta { color: #9ca3af; font-size: 12px; margin-top: 4px; }

/* layout */
.wrap { max-width: 1440px; margin: 0 auto; padding: 30px 40px; }

/* summary cards */
.cards { display: grid; grid-template-columns: repeat(4,1fr); gap: 18px; margin-bottom: 32px; }
.card { background: #1f2937; border-radius: 10px; padding: 22px 18px; border-left: 4px solid; text-align: center; }
.card .num { font-size: 40px; font-weight: 900; }
.card .lbl { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.c-crit { border-color:#ef4444; } .c-crit .num { color:#ef4444; }
.c-high { border-color:#f97316; } .c-high .num { color:#f97316; }
.c-pkg  { border-color:#a78bfa; } .c-pkg  .num { color:#a78bfa; }
.c-code { border-color:#34d399; } .c-code .num { color:#34d399; }

/* section */
.sec { background: #1f2937; border-radius: 10px; padding: 24px; margin-bottom: 28px; }
.sec h2 { font-size: 17px; color: #fff; border-bottom: 1px solid #374151; padding-bottom: 10px; margin-bottom: 16px; }
.badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-left: 8px; vertical-align: middle; }
.b-trivy    { background:#1d4ed8; color:#fff; }
.b-bandit   { background:#065f46; color:#fff; }
.b-pipaudit { background:#4c1d95; color:#fff; }

/* filter pills */
.pills { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.pill { padding: 4px 14px; border-radius: 20px; border: 1px solid; cursor: pointer; font-size: 12px; font-weight: 600; background: transparent; }
.pill[data-s="all"]      { border-color:#9ca3af; color:#9ca3af; }
.pill[data-s="CRITICAL"] { border-color:#ef4444; color:#ef4444; }
.pill[data-s="HIGH"]     { border-color:#f97316; color:#f97316; }
.pill[data-s="MEDIUM"]   { border-color:#fbbf24; color:#fbbf24; }
.pill[data-s="LOW"]      { border-color:#60a5fa; color:#60a5fa; }
.pill.active { opacity:1; font-weight:900; }
.pill:not(.active) { opacity:.45; }

/* search */
.srch { width:100%; padding:9px 13px; border-radius:7px; border:1px solid #374151; background:#111827; color:#e5e7eb; font-size:13px; margin-bottom:13px; }
.srch:focus { outline:none; border-color:#3b82f6; }

/* chips */
.chips { display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }
.chip { padding:4px 12px; border-radius:20px; font-size:12px; font-weight:600; }
.ch-c { background:rgba(239,68,68,.15);  color:#ef4444; }
.ch-h { background:rgba(249,115,22,.15); color:#f97316; }
.ch-m { background:rgba(251,191,36,.15); color:#fbbf24; }
.ch-l { background:rgba(96,165,250,.15); color:#60a5fa; }
.ch-i { background:rgba(156,163,175,.15);color:#9ca3af; }

/* table */
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:#111827; color:#9ca3af; font-weight:600; padding:9px 11px; text-align:left; text-transform:uppercase; font-size:11px; letter-spacing:.4px; position:sticky; top:0; }
td { padding:9px 11px; border-bottom:1px solid #374151; vertical-align:top; }
tr:hover td { background:#253347; }

/* severity labels */
.sv { display:inline-block; padding:1px 9px; border-radius:20px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.4px; }
.sv-CRITICAL { background:rgba(239,68,68,.18);  color:#ef4444; border:1px solid #ef4444; }
.sv-HIGH     { background:rgba(249,115,22,.18); color:#f97316; border:1px solid #f97316; }
.sv-MEDIUM   { background:rgba(251,191,36,.18); color:#fbbf24; border:1px solid #fbbf24; }
.sv-LOW      { background:rgba(96,165,250,.18); color:#60a5fa; border:1px solid #60a5fa; }
.sv-UNKNOWN  { background:rgba(156,163,175,.18);color:#9ca3af; border:1px solid #9ca3af; }

.fix  { color:#34d399; font-size:12px; }
.nofix{ color:#f87171; font-size:12px; }
.cve-a{ color:#60a5fa; text-decoration:none; }
.cve-a:hover { text-decoration:underline; }
.empty { text-align:center; padding:28px; color:#4b5563; font-size:14px; }
.footer { text-align:center; padding:18px; color:#4b5563; font-size:11px; }
"""

JS = """
function filterTrivy(sev){
  document.querySelectorAll('#tf .pill').forEach(b=>b.classList.remove('active'));
  document.querySelector('#tf [data-s="'+sev+'"]').classList.add('active');
  document.querySelectorAll('#tt tbody tr').forEach(r=>{
    r.style.display=(sev==='all'||r.dataset.s===sev)?'':'none';
  });
}
function search(tid,q){
  var lq=q.toLowerCase();
  document.querySelectorAll('#'+tid+' tbody tr').forEach(r=>{
    r.style.display=r.textContent.toLowerCase().includes(lq)?'':'none';
  });
}
"""


def _sv(sev):
    return '<span class="sv sv-{0}">{0}</span>'.format(sev)


def _cve_link(cve_id):
    if cve_id.startswith("CVE-"):
        url = "https://nvd.nist.gov/vuln/detail/" + cve_id
    elif cve_id.startswith("GHSA-"):
        url = "https://github.com/advisories/" + cve_id
    else:
        url = "https://osv.dev/vulnerability/" + cve_id
    return '<a href="{}" target="_blank" class="cve-a">{}</a>'.format(url, cve_id)


# ── main generator ─────────────────────────────────────────────────────────

def generate(args):
    b_data   = load_json(args.bandit)
    pa_data  = load_json(args.pip_audit)
    tr_data  = load_json(args.trivy)

    b_results, b_counts  = parse_bandit(b_data)
    pa_deps,   pa_vulns  = parse_pipaudit(pa_data)
    tr_vulns,  tr_counts = parse_trivy(tr_data)
    tr_total             = sum(tr_counts.values())
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── HTML open ──────────────────────────────────────────────────────────
    out = []
    out.append("""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevSecOps Security Scan Report</title>
<style>{css}</style>
</head><body>""".format(css=CSS))

    # header
    out.append("""<div class="hdr">
  <h1>&#128737; DevSecOps Security Scan Report</h1>
  <div class="img-tag">Image: {img}</div>
  <div class="meta">Generated: {ts} &nbsp;|&nbsp; Tools: Trivy &bull; Bandit &bull; pip-audit</div>
</div>
<div class="wrap">""".format(img=args.image, ts=ts))

    # summary cards
    out.append("""<div class="cards">
  <div class="card c-crit"><div class="num">{crit}</div><div class="lbl">Critical CVEs (Trivy)</div></div>
  <div class="card c-high"><div class="num">{high}</div><div class="lbl">High CVEs (Trivy)</div></div>
  <div class="card c-pkg"> <div class="num">{pkg}</div> <div class="lbl">Dep CVEs (pip-audit)</div></div>
  <div class="card c-code"><div class="num">{code}</div><div class="lbl">Code Issues (Bandit)</div></div>
</div>""".format(
        crit=tr_counts.get("CRITICAL", 0),
        high=tr_counts.get("HIGH", 0),
        pkg=len(pa_vulns),
        code=b_counts.get("HIGH", 0) + b_counts.get("MEDIUM", 0),
    ))

    # ── Trivy section ──────────────────────────────────────────────────────
    out.append("""<div class="sec">
<h2>Container Vulnerabilities <span class="badge b-trivy">Trivy</span></h2>
<div class="chips">
  <span class="chip ch-c">CRITICAL: {crit}</span>
  <span class="chip ch-h">HIGH: {high}</span>
  <span class="chip ch-m">MEDIUM: {med}</span>
  <span class="chip ch-l">LOW: {low}</span>
  <span class="chip ch-i">TOTAL: {tot}</span>
</div>
<div class="pills" id="tf">
  <button class="pill active" data-s="all"      onclick="filterTrivy('all')">All</button>
  <button class="pill"        data-s="CRITICAL" onclick="filterTrivy('CRITICAL')">Critical</button>
  <button class="pill"        data-s="HIGH"     onclick="filterTrivy('HIGH')">High</button>
  <button class="pill"        data-s="MEDIUM"   onclick="filterTrivy('MEDIUM')">Medium</button>
  <button class="pill"        data-s="LOW"      onclick="filterTrivy('LOW')">Low</button>
</div>
<input class="srch" placeholder="Search CVEs, packages, descriptions..." oninput="search('tt',this.value)">
""".format(
        crit=tr_counts.get("CRITICAL", 0), high=tr_counts.get("HIGH", 0),
        med=tr_counts.get("MEDIUM", 0),    low=tr_counts.get("LOW", 0),
        tot=tr_total,
    ))

    if tr_vulns:
        out.append("""<table id="tt">
<thead><tr>
  <th>Severity</th><th>CVE ID</th><th>Package</th>
  <th>Installed</th><th>Fixed In</th><th>Title</th><th style="font-size:11px">Target</th>
</tr></thead><tbody>""")
        for v in tr_vulns:
            fix_html = (
                '<span class="fix">{}</span>'.format(v["fixed"])
                if v["fixed"] and v["fixed"] != "No fix"
                else '<span class="nofix">No fix</span>'
            )
            out.append(
                '<tr data-s="{sev}"><td>{sv}</td><td>{cve}</td><td>{pkg}</td>'
                "<td>{ins}</td><td>{fix}</td>"
                '<td style="color:#d1d5db">{title}</td>'
                '<td style="font-size:11px;color:#6b7280">{tgt}</td></tr>'.format(
                    sev=v["severity"],
                    sv=_sv(v["severity"]),
                    cve=_cve_link(v["cve"]),
                    pkg=v["pkg"],
                    ins=v["installed"],
                    fix=fix_html,
                    title=v["title"][:80],
                    tgt=v["target"][-45:],
                )
            )
        out.append("</tbody></table>")
    else:
        out.append('<div class="empty">No container vulnerabilities found.</div>')
    out.append("</div>")  # end trivy sec

    # ── pip-audit section ──────────────────────────────────────────────────
    out.append("""<div class="sec">
<h2>Python Dependency CVEs <span class="badge b-pipaudit">pip-audit</span></h2>
<div class="chips">
  <span class="chip ch-i">Packages Scanned: {pkgs}</span>
  <span class="chip ch-h">CVEs Found: {total}</span>
</div>""".format(pkgs=len(pa_deps), total=len(pa_vulns)))

    if pa_vulns:
        out.append("""<input class="srch" placeholder="Search packages, CVE IDs..." oninput="search('pt',this.value)">
<table id="pt">
<thead><tr><th>Package</th><th>Version</th><th>CVE / Advisory</th><th>Fix Available</th><th>Description</th></tr></thead>
<tbody>""")
        for v in pa_vulns:
            fix = ", ".join(v["fix_versions"]) if v["fix_versions"] else "Check PyPI"
            out.append(
                "<tr><td><strong>{pkg}</strong></td>"
                "<td>{ver}</td><td>{cve}</td>"
                '<td><span class="fix">{fix}</span></td>'
                '<td style="color:#9ca3af">{desc}</td></tr>'.format(
                    pkg=v["package"],
                    ver=v["version"],
                    cve=_cve_link(v["id"]),
                    fix=fix,
                    desc=v["description"][:120],
                )
            )
        out.append("</tbody></table>")
    else:
        out.append('<div class="empty">No dependency CVEs found.</div>')
    out.append("</div>")

    # ── Bandit section ─────────────────────────────────────────────────────
    sorted_bandit = sorted(b_results, key=lambda r: sev_order(r.get("issue_severity", "LOW")))
    out.append("""<div class="sec">
<h2>Python Source Code Analysis <span class="badge b-bandit">Bandit</span></h2>
<div class="chips">
  <span class="chip ch-c">HIGH: {h}</span>
  <span class="chip ch-m">MEDIUM: {m}</span>
  <span class="chip ch-l">LOW: {l}</span>
  <span class="chip ch-i">TOTAL: {t}</span>
</div>""".format(
        h=b_counts.get("HIGH", 0), m=b_counts.get("MEDIUM", 0),
        l=b_counts.get("LOW", 0),  t=len(b_results),
    ))

    if sorted_bandit:
        out.append("""<input class="srch" placeholder="Search findings, files, tests..." oninput="search('bt',this.value)">
<table id="bt">
<thead><tr><th>Severity</th><th>Confidence</th><th>Test</th><th>Issue</th><th>File : Line</th></tr></thead>
<tbody>""")
        for r in sorted_bandit:
            fname = r.get("filename", "").replace("\\", "/")
            fname = fname[-55:] if len(fname) > 55 else fname
            out.append(
                "<tr><td>{sev}</td><td>{conf}</td>"
                '<td style="font-size:11px;color:#9ca3af">{tid}</td>'
                "<td>{text}</td>"
                '<td style="font-size:11px;color:#6b7280">{fname}:{line}</td></tr>'.format(
                    sev=_sv(r.get("issue_severity", "LOW")),
                    conf=_sv(r.get("issue_confidence", "LOW")),
                    tid=r.get("test_id", ""),
                    text=r.get("issue_text", "")[:100],
                    fname=fname,
                    line=r.get("line_number", ""),
                )
            )
        out.append("</tbody></table>")
    else:
        out.append('<div class="empty">No code issues found.</div>')
    out.append("</div>")

    # close
    out.append("</div>")  # .wrap
    out.append('<div class="footer">DevSecOps Pipeline Report &bull; {ts}</div>'.format(ts=ts))
    out.append("<script>{}</script>".format(JS))
    out.append("</body></html>")

    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Generate security scan HTML report")
    parser.add_argument("--bandit",    required=True)
    parser.add_argument("--pip-audit", required=True, dest="pip_audit")
    parser.add_argument("--trivy",     required=True)
    parser.add_argument("--image",     required=True)
    parser.add_argument("--output",    required=True)
    args = parser.parse_args()

    html = generate(args)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html)
    size_kb = os.path.getsize(args.output) // 1024
    print("Report written: {} ({}KB)".format(args.output, size_kb))


if __name__ == "__main__":
    main()
