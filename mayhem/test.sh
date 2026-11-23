#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer functional tests for the fuzzed edk2-platforms modules
# (mayhem/out/edk2_selftest, built by mayhem/build.sh with normal flags; source in
# mayhem/harnesses/selftest.c). Ext4Dxe must return the exact bytes/sizes mkfs.ext4 wrote into
# the committed seed images (nested dirs, a symlink, a multi-block file, a missing file), and
# AmdHiiConfigRouting ConfigToBlock/BlockToConfig must produce the exact block bytes / config
# string for fixed requests. Every expected test name must report PASS; a missing line fails.
# FitGen (mayhem/out/fitgen_test) must write a FIT with the exact entries the committed
# mayhem/fitgen_gen seed FDs list, put the FIT pointer at 4 GiB - 0x40, decode the seed's
# startup ACM, and reject an image with no firmware volume.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/out/edk2_selftest"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh did not build the selftest" >&2
  emit_ctrf edk2-selftest 0 1
  exit 1
fi

EXPECTED=()
for img in extents blockmap nocsum; do
  for t in mount read_nested symlink read_multiblock missing_file; do EXPECTED+=("ext4_${t}_${img}.img"); done
done
EXPECTED+=(hii_config_to_block_values hii_config_to_block_too_small hii_config_to_block_bad_header
  hii_block_to_config_value hii_block_to_config_out_of_range)

out="$("$RUNNER" "$SRC/mayhem/fuzz_ext4/testsuite" 2>&1)"
echo "$out"
passed=0; failed=0
for name in "${EXPECTED[@]}"; do
  if grep -qx "PASS $name" <<<"$out"; then passed=$((passed + 1)); else echo "FAILED: $name"; failed=$((failed + 1)); fi
done

# --- FitGen known answers (seeds from mayhem/fitgen_gen/make_seeds.py) ---
FITGEN="$SRC/mayhem/out/fitgen_test"
FITSEEDS="$SRC/mayhem/fitgen_gen/testsuite"
BIOSINFO=09D0D15C-E9F0-4DFC-9E0B-39331FCA6685
work="$(mktemp -d "${TMPDIR:-/tmp}/fitgen-test.XXXXXX")"
check() {  # check <name> <condition...>
  local name="$1"; shift
  if "$@"; then echo "PASS $name"; passed=$((passed + 1)); else echo "FAILED: $name"; failed=$((failed + 1)); fi
}
fit_u32() { od -An -tx4 -j "$2" -N4 "$1" | tr -d ' '; }  # little-endian dword at offset

if [ ! -x "$FITGEN" ]; then
  echo "test.sh: $FITGEN missing — mayhem/build.sh did not build it" >&2; failed=$((failed + 1))
else
  mc_out="$("$FITGEN" -D "$FITSEEDS/fd_microcode_bios" "$work/mc.fd" -I "$BIOSINFO" 2>&1)"; mc_rc=$?
  echo "$mc_out" | tail -12
  check fitgen_microcode_bios_exit0 test "$mc_rc" -eq 0
  check fitgen_microcode_bios_entries grep -Eq '^ 03: +00000000ffff10e8 000200 +0100 +07-BIOS_MODULE' <<<"$mc_out"
  check fitgen_microcode_bios_microcode grep -Eq '^ 02: +00000000ffff08d0 000000 +0100 +01-MICROCODE' <<<"$mc_out"
  check fitgen_microcode_bios_fit_pointer test "$(fit_u32 "$work/mc.fd" $((0x10000 - 0x40)))" = fffffe40
  check fitgen_microcode_bios_fit_header test "$(od -An -c -j $((0xfe40)) -N5 "$work/mc.fd" | tr -d ' ')" = _FIT_

  acm_out="$("$FITGEN" -D "$FITSEEDS/fd_acm_manifests" "$work/acm.fd" -I "$BIOSINFO" 2>&1)"; acm_rc=$?
  check fitgen_acm_exit0 test "$acm_rc" -eq 0
  check fitgen_acm_decoded grep -Eq '^  ChipsetID +- 0b00$' <<<"$acm_out"
  check fitgen_acm_startup_entry grep -Eq '^ 02: +00000000ffff00d8 000000 +0200 +02-STARTUP_ACM' <<<"$acm_out"
  check fitgen_acm_key_manifest grep -Eq '^ 04: +00000000ffff2920 000400 +0100 +0b-KEYMANIFEST' <<<"$acm_out"

  head -c 4096 "$FITSEEDS/fd_microcode_bios" > "$work/truncated.fd"
  bad_out="$("$FITGEN" -D "$work/truncated.fd" "$work/bad.fd" -I "$BIOSINFO" 2>&1)"; bad_rc=$?
  check fitgen_no_fv_rejected test "$bad_rc" -ne 0
  check fitgen_no_fv_message grep -q 'FvRecovery not found in Fd file' <<<"$bad_out"
fi
rm -rf "$work"
emit_ctrf edk2-selftest "$passed" "$failed"
