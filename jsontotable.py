#!/usr/bin/env python3
import json
import html
import sys
from pathlib import Path
from datetime import datetime

INPUT_FILE = "report.json"
OUTPUT_FILE = "trivy-report.html"


def esc(value):
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_results(data):
    # Trivy JSON can be either:
    # 1) {"Results": [...]}
    # 2) already a list-like structure
    # 3) a flat object with Vulnerabilities/Misconfigurations
    if isinstance(data, dict):
        if isinstance(data.get("Results"), list):
            return data["Results"]

        # fallback: wrap whole object as one synthetic result
        if any(k in data for k in ("Vulnerabilities", "Misconfigurations")):
            return [data]

    if isinstance(data, list):
        return data

    return []


def vuln_severity(v):
    sev = v.get("Severity")
    if sev:
        return sev

    nested = v.get("Vulnerability")
    if isinstance(nested, dict):
        return nested.get("Severity", "UNKNOWN")

    return "UNKNOWN"


def vuln_references(v):
    nested = v.get("Vulnerability")
    if isinstance(nested, dict) and isinstance(nested.get("References"), list):
        return nested["References"]

    refs = v.get("References")
    if isinstance(refs, list):
        return refs

    primary = v.get("PrimaryURL")
    return [primary] if primary else []


def render_links(links):
    if not links:
        return ""

    cleaned = []
    seen = set()
    for link in links:
        if not link:
            continue
        s = str(link).strip()
        if s and s not in seen:
            seen.add(s)
            cleaned.append(s)

    cleaned.sort()
    return "\n".join(
        f'<a href="{esc(link)}">{esc(link)}</a>' for link in cleaned
    )


def render_vuln_rows(vulns):
    if not vulns:
        return '<tr><th colspan="6">No Vulnerabilities found</th></tr>'

    rows = [
        """
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
        """.rstrip()
    ]

    for v in vulns:
        severity = esc(vuln_severity(v) or "UNKNOWN")
        pkg_name = esc(v.get("PkgName", ""))
        vuln_id = esc(v.get("VulnerabilityID", ""))
        installed = esc(v.get("InstalledVersion", ""))
        fixed = esc(v.get("FixedVersion", ""))
        links_html = render_links(vuln_references(v))

        rows.append(f"""
      <tr class="severity-{severity}">
        <td class="pkg-name">{pkg_name}</td>
        <td>{vuln_id}</td>
        <td class="severity">{severity}</td>
        <td class="pkg-version">{installed}</td>
        <td>{fixed}</td>
        <td class="links" data-more-links="off">
          {links_html}
        </td>
      </tr>
        """.rstrip())

    return "\n".join(rows)


def render_misconf_rows(misconfigs):
    if not misconfigs:
        return '<tr><th colspan="6">No Misconfigurations found</th></tr>'

    rows = [
        """
      <tr class="sub-header">
        <th>Type</th>
        <th>Misconf ID</th>
        <th>Check</th>
        <th>Severity</th>
        <th>Message</th>
      </tr>
        """.rstrip()
    ]

    for m in misconfigs:
        severity = esc(m.get("Severity", "UNKNOWN"))
        mtype = esc(m.get("Type", ""))
        mid = esc(m.get("ID", ""))
        title = esc(m.get("Title", ""))
        message = esc(m.get("Message", ""))
        primary = m.get("PrimaryURL", "")

        primary_html = (
            f'<br><a href="{esc(primary)}">{esc(primary)}</a></br>'
            if primary else ""
        )

        rows.append(f"""
      <tr class="severity-{severity}">
        <td class="misconf-type">{mtype}</td>
        <td>{mid}</td>
        <td class="misconf-check">{title}</td>
        <td class="severity">{severity}</td>
        <td class="link" data-more-links="off" style="white-space:normal;">
          {message}
          {primary_html}
        </td>
      </tr>
        """.rstrip())

    return "\n".join(rows)


def report_title(data, results):
    target = None
    if results:
        target = results[0].get("Target")

    if not target and isinstance(data, dict):
        target = data.get("ArtifactName") or data.get("ReportID") or "Trivy Report"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{target} - Trivy Report - {now}"


def render_html(data):
    results = normalize_results(data)
    title = report_title(data, results)

    if not results:
        return f"""<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>{esc(title)}</title>
  </head>
  <body>
    <h1>Trivy Returned Empty Report</h1>
  </body>
</html>
"""

    body_parts = []

    for result in results:
        rtype = result.get("Type", "Unknown")
        vulns = result.get("Vulnerabilities") or []
        misconfigs = result.get("Misconfigurations") or []

        body_parts.append(f'<tr class="group-header"><th colspan="6">{esc(rtype)}</th></tr>')
        body_parts.append(render_vuln_rows(vulns))
        body_parts.append(render_misconf_rows(misconfigs))

    return f"""<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * {{
        font-family: Arial, Helvetica, sans-serif;
      }}
      h1 {{
        text-align: center;
      }}
      .group-header th {{
        font-size: 200%;
      }}
      .sub-header th {{
        font-size: 150%;
      }}
      table, th, td {{
        border: 1px solid black;
        border-collapse: collapse;
        white-space: nowrap;
        padding: .3em;
      }}
      table {{
        margin: 0 auto;
      }}
      .severity {{
        text-align: center;
        font-weight: bold;
        color: #fafafa;
      }}
      .severity-LOW .severity {{ background-color: #5fbb31; }}
      .severity-MEDIUM .severity {{ background-color: #e9c600; }}
      .severity-HIGH .severity {{ background-color: #ff8800; }}
      .severity-CRITICAL .severity {{ background-color: #e40000; }}
      .severity-UNKNOWN .severity {{ background-color: #747474; }}
      .severity-LOW {{ background-color: #5fbb3160; }}
      .severity-MEDIUM {{ background-color: #e9c60060; }}
      .severity-HIGH {{ background-color: #ff880060; }}
      .severity-CRITICAL {{ background-color: #e4000060; }}
      .severity-UNKNOWN {{ background-color: #74747460; }}
      table tr td:first-of-type {{
        font-weight: bold;
      }}
      .links a,
      .links[data-more-links=on] a {{
        display: block;
      }}
      .links[data-more-links=off] a:nth-of-type(1n+5) {{
        display: none;
      }}
      a.toggle-more-links {{ cursor: pointer; }}
    </style>
    <title>{esc(title)}</title>
    <script>
      window.onload = function() {{
        document.querySelectorAll('td.links').forEach(function(linkCell) {{
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {{
            return a.href > b.href ? 1 : -1;
          }});
          links.forEach(function(link, idx) {{
            if (links.length > 3 && 3 === idx) {{
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }}
            linkCell.appendChild(link);
          }});
        }});
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {{
          toggleLink.onclick = function() {{
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          }};
        }});
      }};
    </script>
  </head>
  <body>
    <h1>{esc(title)}</h1>
    <table>
      {"".join(body_parts)}
    </table>
  </body>
</html>
"""


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(INPUT_FILE)
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(OUTPUT_FILE)

    data = load_report(input_path)
    html_out = render_html(data)
    output_path.write_text(html_out, encoding="utf-8")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()