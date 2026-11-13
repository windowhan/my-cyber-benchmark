---
id: "EXTRA-HPACK-HUFF-EXPAND"
title: "Huffman expansion sized on wire length"
severity: "planted-extra"
planted: true
cwe: ["CWE-787"]
modeled_on: "huffman expansion sized on wire length"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-HPACK-HUFF-EXPAND — Huffman expansion sized on wire length

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-787
- **Modeled on:** huffman expansion sized on wire length
- **Site:** `src/proto/snx_hpack.c` → `snx_huff_decode/snx_hpack_str`

## Description

str reader bounds wire length (ln < cap) but decode emits up to 1.6x into the same stack buf; 1563B huffman of 5-bit symbols -> 2500B into vbuf[2048] -> stack OOB write (ASan live-confirmed via h2 HEADERS).

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-HPACK-HUFF-EXPAND`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
