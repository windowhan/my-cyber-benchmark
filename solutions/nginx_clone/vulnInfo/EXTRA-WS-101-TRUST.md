---
id: "EXTRA-WS-101-TRUST"
title: "Upgrade token not verified"
severity: "planted-extra"
planted: true
cwe: ["CWE-345"]
modeled_on: "upgrade token not verified"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-WS-101-TRUST — Upgrade token not verified

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-345
- **Modeled on:** upgrade token not verified
- **Site:** `src/mod/snx_mod_proxy.c` → `snx_proxy_tunnel`

## Description

any upstream 101 opens the duplex tunnel; reply Upgrade token never matched to the request. Live: /split/ + Upgrade: websocket.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-WS-101-TRUST`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
