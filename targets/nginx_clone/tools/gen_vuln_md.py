#!/usr/bin/env python3
# Generate vulnInfo/EXTRA-*.md pages from ground_truth.json extras.
# Style mirrors the source CVE-*.md files (frontmatter + sections).
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(ROOT, "ground_truth.json")
OUT = os.path.join(ROOT, "vulnInfo")

FM = """---
id: "{id}"
title: "{title}"
severity: "planted-extra"
planted: true
cwe: [{cwe}]
modeled_on: "{modeled}"
source: "ground_truth.json (benchmark insert)"
---
# {id} — {title}

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** {cwe_disp}
- **Modeled on:** {modeled}
- **Site:** `{file}` → `{fn}`

## Description

{note}

## Verification

{verify}
"""


def title_of(e):
    t = e.get("modeled_on") or e["id"]
    return t[0].upper() + t[1:]


def verify_of(e):
    tid = e["id"]
    return (
        "Live trigger is in `poc/http/live.sh` (run "
        f"`bash poc/http/live.sh {tid}`); check `logs/` and ASan output "
        "for the crash/evidence. Unit-style harnesses live under `poc/unit/`."
    )


def main():
    g = json.load(open(GT))
    made = 0
    for e in g.get("extras", []):
        eid = e["id"]
        if not re.fullmatch(r"[A-Z0-9\-]+", eid):
            continue
        cwe = e.get("cwe", "")
        cwe_list = f'"{cwe}"' if cwe else ""
        body = FM.format(
            id=eid,
            title=title_of(e).replace('"', "'"),
            cwe=cwe_list,
            cwe_disp=cwe or "n/a",
            modeled=e.get("modeled_on", "").replace('"', "'"),
            file=e.get("file", "?"),
            fn=e.get("fn", "?"),
            note=e.get("note", ""),
            verify=verify_of(e),
        )
        with open(os.path.join(OUT, f"{eid}.md"), "w") as f:
            f.write(body)
        made += 1
    print(f"wrote {made} EXTRA-*.md files")


if __name__ == "__main__":
    main()
