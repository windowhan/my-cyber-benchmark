---
id: "EXTRA-UP-KEEPALIVE-STALE"
title: "Upstream keepalive stale-fd reuse"
severity: "planted-extra"
planted: true
cwe: ["CWE-664"]
modeled_on: "upstream keepalive stale-fd reuse"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-UP-KEEPALIVE-STALE — Upstream keepalive stale-fd reuse

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-664
- **Modeled on:** upstream keepalive stale-fd reuse
- **Site:** `src/mod/snx_mod_proxy.c` → `snx_ka_get/snx_proxy_upstream`

## Description

idle fds cached by host:port with no liveness probe; peer close leaves dead fd reused on next request (request 1: 200, request 2: 502 via cached dead conn). live-verified on /up/.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-UP-KEEPALIVE-STALE`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
