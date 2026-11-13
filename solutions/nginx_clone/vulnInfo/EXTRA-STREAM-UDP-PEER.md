---
id: "EXTRA-STREAM-UDP-PEER"
title: "UDP session mixup"
severity: "planted-extra"
planted: true
cwe: ["CWE-200"]
modeled_on: "UDP session mixup"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-STREAM-UDP-PEER — UDP session mixup

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-200
- **Modeled on:** UDP session mixup
- **Site:** `src/snx_stream.c` → `snx_stream_udp_conn`

## Description

static last_peer pins the first client sockaddr; later datagrams' replies leak to that peer. Live: two clients on :9003.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-STREAM-UDP-PEER`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
