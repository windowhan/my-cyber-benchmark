#!/usr/bin/env bash
# PoC runner: live wire triggers + unit harnesses, one process at a time.
# usage: poc/run_all.sh           (everything)
#        poc/run_all.sh unit      (harnesses only)
#        poc/run_all.sh http      (live server triggers only)
cd "$(dirname "$0")/.."
export ASAN_OPTIONS="detect_stack_use_after_return=1:allocator_may_return_null=1"

UNIT_BINS="h_resolver h_proto h_tlsmail h_mem"
UNIT_CVES_h_resolver="CVE-2021-23017 CVE-2016-0742 CVE-2016-0746 CVE-2016-0747 CVE-2011-4315 CVE-2026-40701"
UNIT_CVES_h_proto="CVE-2019-9511 CVE-2019-9513 CVE-2019-9516 CVE-2018-16843 CVE-2018-16844 CVE-2014-0133 CVE-2014-0088 CVE-2026-90439 CVE-2026-42530 CVE-2026-95101 CVE-2026-40460 CVE-2024-32760 CVE-2024-31079 CVE-2024-35200 CVE-2024-34161 CVE-2024-24989 CVE-2024-24990"
UNIT_CVES_h_tlsmail="CVE-2014-3616 CVE-2025-23419 CVE-2026-97629 CVE-2009-3555 CVE-2026-1642 CVE-2026-28755 CVE-2014-3556 CVE-2026-27651 CVE-2026-28753 CVE-2025-53859"
UNIT_CVES_h_mem="CVE-2009-2629 CVE-2016-4450"

run_unit() {
    local b c hits=0 total=0
    for b in $UNIT_BINS; do
        eval "set -- \$UNIT_CVES_$b"
        for c in "$@"; do
            total=$((total + 1))
            if "poc/unit/$b" "$c" >/tmp/poc_unit_out 2>&1; then
                :
            fi
            if grep -q 'AddressSanitizer\|runtime error\|VULNERABLE' /tmp/poc_unit_out; then
                hits=$((hits + 1))
                printf '%-18s PASS (%s)\n' "$c" "$b"
            else
                printf '%-18s FAIL (%s)\n' "$c" "$b"
            fi
        done
    done
    echo "unit: $hits/$total triggered"
}

case "${1:-all}" in
    http) bash poc/http/live.sh ;;
    unit) run_unit ;;
    all)  bash poc/http/live.sh; echo; run_unit ;;
esac
