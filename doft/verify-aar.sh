#!/usr/bin/env bash
# Verify a freshly built libv2ray.aar before anyone can ship it.
#
# The AAR this replaces was a 54 MB binary committed with no source, no build and no pin —
# so "does the new one still do what the app needs" could not be answered by reading a
# diff. These three checks answer it mechanically:
#
#   1. THE JAVA SURFACE IS A SUPERSET of what the app already calls. A missing symbol
#      means the plugin does not compile; a CHANGED one is worse, because it can compile
#      against a different overload and fail at runtime on a user's phone.
#   2. EVERY .so IS 16 KB PAGE-ALIGNED. Google Play REQUIRES it for Android 15+, and the
#      only reason this project ever changed plugins was a 4 KB-aligned libgojni.so.
#      NDK r27+ defaults to it, which is exactly the kind of default that changes
#      silently when a toolchain is bumped.
#   3. ALL FOUR ABIs ARE PRESENT. gomobile will happily emit fewer if -target is wrong,
#      and an APK missing x86_64 fails on emulators and some Chromebooks.
set -euo pipefail

AAR="${1:?usage: verify-aar.sh <path/to/libv2ray.aar>}"
REQ="${2:-$(dirname "$0")/REQUIRED-JAVA-API.txt}"
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; find "$WORK" -depth -delete 2>/dev/null || true' EXIT

[ -f "$AAR" ] || { echo "verify-aar: no such file: $AAR"; exit 1; }
echo "verify-aar: $AAR ($(du -h "$AAR" | cut -f1))"

unzip -q -o "$AAR" -d "$WORK/aar"

# ── 3. ABIs ───────────────────────────────────────────────────────────────────
missing_abi=0
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
	if [ -f "$WORK/aar/jni/$abi/libv2jni.so" ]; then
		printf '  abi %-12s %s\n' "$abi" "$(du -h "$WORK/aar/jni/$abi/libv2jni.so" | cut -f1)"
	else
		echo "  abi $abi MISSING"; missing_abi=1
	fi
done
[ "$missing_abi" = 0 ] || { echo "verify-aar: FAIL — not every ABI was built"; exit 1; }

# ── 2. 16 KB alignment ────────────────────────────────────────────────────────
# A LOAD segment's align field must be >= 0x4000. readelf prints it in hex ("0x4000")
# on some versions and as a power expression on others, so parse the hex form and
# compare numerically rather than grepping for a literal.
bad_align=0
for so in "$WORK"/aar/jni/*/libv2jni.so; do
	abi="$(basename "$(dirname "$so")")"
	worst=""
	while read -r align; do
		[ -n "$align" ] || continue
		dec=$((align))
		if [ -z "$worst" ] || [ "$dec" -lt "$worst" ]; then worst="$dec"; fi
	done < <(readelf -lW "$so" | awk '$1=="LOAD"{print $NF}')
	if [ -z "$worst" ]; then
		echo "  align $abi: NO LOAD SEGMENTS PARSED — refusing to guess"; bad_align=1; continue
	fi
	if [ "$worst" -lt 16384 ]; then
		echo "  align $abi: $worst (< 16384) — Google Play rejects this"; bad_align=1
	else
		printf '  align %-12s %s bytes OK\n' "$abi" "$worst"
	fi
done
[ "$bad_align" = 0 ] || { echo "verify-aar: FAIL — a .so is not 16 KB aligned"; exit 1; }

# ── 1. the Java surface ───────────────────────────────────────────────────────
unzip -q -o "$WORK/aar/classes.jar" -d "$WORK/classes"
missing_api=0
while IFS= read -r line; do
	case "$line" in ''|\#*) continue ;; esac
	cls="${line%%::*}"
	want="${line#*::}"
	if ! javap -classpath "$WORK/classes" "$cls" 2>/dev/null | grep -qF "$want"; then
		echo "  MISSING  $cls :: $want"
		missing_api=1
	fi
done < "$REQ"
if [ "$missing_api" != 0 ]; then
	echo "verify-aar: FAIL — the app calls symbols this AAR does not export"
	echo "            (see doft/REQUIRED-JAVA-API.txt; javap output below)"
	javap -classpath "$WORK/classes" libv2ray.Libv2ray libv2ray.CoreController 2>&1 || true
	exit 1
fi
echo "  api      every required symbol present ($(grep -cv '^\s*\(#\|$\)' "$REQ") checked)"

echo "verify-aar: OK"
