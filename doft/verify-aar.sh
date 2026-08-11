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

# Smallest LOAD-segment alignment in an ELF, in bytes, or empty when no tool can read it.
_min_align() {
	_f="$1"; _min=""
	if command -v readelf >/dev/null 2>&1; then
		for _a in $(readelf -lW "$_f" 2>/dev/null | awk '$1=="LOAD"{print $NF}'); do
			case "$_a" in 0x*|[0-9]*) _d=$((_a)) ;; *) continue ;; esac
			[ -z "$_min" ] || [ "$_d" -ge "$_min" ] || _min="$_d"
			[ -n "$_min" ] || _min="$_d"
		done
	elif command -v objdump >/dev/null 2>&1; then
		for _e in $(objdump -p "$_f" 2>/dev/null | awk '/LOAD/{for(i=1;i<=NF;i++) if($i=="align") print $(i+1)}'); do
			# objdump writes `2**14`; take the exponent after the last asterisk.
			_x="${_e##*\*}"
			case "$_x" in [0-9]*) _d=$((1 << _x)) ;; *) continue ;; esac
			[ -z "$_min" ] || [ "$_d" -ge "$_min" ] || _min="$_d"
			[ -n "$_min" ] || _min="$_d"
		done
	fi
	printf '%s' "$_min"
}

[ -f "$AAR" ] || { echo "verify-aar: no such file: $AAR"; exit 1; }
echo "verify-aar: $AAR ($(du -h "$AAR" | cut -f1))"

unzip -q -o "$AAR" -d "$WORK/aar"

# ── 3. ABIs, and the JNI library NAME ─────────────────────────────────────────
# ⚠ THE NAME IS NOT HARD-CODED, IT IS DERIVED FROM THE AAR ITSELF. gomobile decides it,
# and the first build here proved that assuming `libv2jni.so` gets you a red step for the
# wrong reason. What actually matters is that the .so present under each ABI is the one
# `go.Seq` calls System.loadLibrary on — get THAT wrong and the AAR builds, ships, and
# throws UnsatisfiedLinkError on the user's phone at the first connect.
unzip -q -o "$WORK/aar/classes.jar" -d "$WORK/classes"
WANT_LIB="$(javap -c -p -classpath "$WORK/classes" go.Seq 2>/dev/null \
	| grep -B 2 'loadLibrary' | grep -o 'String [A-Za-z0-9_]*' | awk '{print $2}' | head -1)"
[ -n "$WANT_LIB" ] || { echo "verify-aar: FAIL — could not read the library name out of go.Seq"; exit 1; }
echo "  jni      go.Seq loads lib${WANT_LIB}.so"

missing_abi=0
for abi in arm64-v8a armeabi-v7a x86 x86_64; do
	so="$WORK/aar/jni/$abi/lib${WANT_LIB}.so"
	if [ -f "$so" ]; then
		printf '  abi %-12s %s\n' "$abi" "$(du -h "$so" | cut -f1)"
	else
		echo "  abi $abi MISSING lib${WANT_LIB}.so — contains: $(ls "$WORK/aar/jni/$abi" 2>/dev/null | tr '\n' ' ')"
		missing_abi=1
	fi
done
[ "$missing_abi" = 0 ] || { echo "verify-aar: FAIL — an ABI is missing the library go.Seq loads"; exit 1; }

# ── 2. 16 KB alignment — 64-BIT ABIs ONLY ─────────────────────────────────────
# ⚠ THE FIRST VERSION OF THIS CHECK FAILED A CORRECT BUILD. It demanded 16 KB on all
# four ABIs; armeabi-v7a and x86 came back at 4096 and the step went red. They are
# supposed to: 16 KB page size is a 64-BIT Android feature, and Google's requirement is
# about 64-bit devices. The two 32-bit ABIs are 4 KB-aligned and always will be.
#
# Verified against the AAR currently IN PRODUCTION rather than argued from the docs —
# `objdump -p` on the committed libv2ray.aar gives 2**14 for arm64-v8a and x86_64 and
# 2**12 for armeabi-v7a and x86, i.e. exactly the shape this build produces. A gate that
# fails what is already shipping and passing Play review is testing the wrong property.
bad_align=0
checked_align=0
for so in "$WORK"/aar/jni/*/lib${WANT_LIB}.so; do
	abi="$(basename "$(dirname "$so")")"
	case "$abi" in
		arm64-v8a|x86_64) ;;
		*) printf '  align %-12s 32-bit ABI — 16 KB does not apply\n' "$abi"; continue ;;
	esac
	# readelf on Linux (the CI runner) prints `0x4000`; objdump on macOS (a laptop
	# checking a published artefact) prints `2**14`. Both are normalised to bytes by a
	# helper rather than parsed inline, because the inline version silently produced NO
	# alignment lines at all and the script still printed OK — a gate that passes without
	# checking is worse than no gate.
	worst="$(_min_align "$so")" || worst=""
	if ! printf '%s' "$worst" | grep -qE '^[0-9]+$'; then
		echo "  align $abi: COULD NOT BE READ (need readelf or objdump) — refusing to guess"
		bad_align=1; continue
	fi
	checked_align=$((checked_align + 1))
	if [ "$worst" -lt 16384 ]; then
		echo "  align $abi: $worst (< 16384) — Google Play rejects this"; bad_align=1
	else
		printf '  align %-12s %s bytes OK\n' "$abi" "$worst"
	fi
done
# ⚠ AND THE COUNT IS CHECKED. Both 64-bit ABIs must actually have been measured; without
# this, a parsing change that yields zero measurements reads as success.
if [ "$checked_align" -lt 2 ]; then
	echo "  align: only $checked_align of 2 64-bit ABIs were measured"
	bad_align=1
fi
[ "$bad_align" = 0 ] || { echo "verify-aar: FAIL — alignment unverified or below 16 KB (see above)"; exit 1; }

# ── 1. the Java surface ───────────────────────────────────────────────────────
# (classes.jar was already extracted above, to read the library name)
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

# ── 4. the manifest floor ─────────────────────────────────────────────────────
#
# ⚠ THE ONE PROPERTY THIS SCRIPT DID NOT CHECK IS THE ONE THAT BROKE THE APP BUILD.
# gomobile stamps `-androidapi` into the AAR's own AndroidManifest.xml, and the app's
# manifest merger refuses outright when a library declares a floor above the app's:
#
#   uses-sdk:minSdkVersion 23 cannot be smaller than version 24 declared in
#   library [:libv2ray:] ... as the library might be using APIs not available in 23
#
# Everything else here passed on that AAR — four ABIs, 16 KB alignment, 26/26 symbols —
# so "verify-aar: OK" was printed on an artifact that could not be built into an app at
# all. The production AAR the fork replaces declares 21; the app floor is 23. Checked
# against the APP's floor rather than a constant, so raising the app one day does not
# silently make this gate meaningless.
APP_MIN_SDK="${APP_MIN_SDK:-23}"
man="$WORK/AndroidManifest.xml"
if [ ! -f "$man" ]; then
	unzip -o -q "$AAR" AndroidManifest.xml -d "$WORK" 2>/dev/null || true
fi
if [ -f "$man" ]; then
	# The AAR manifest is plain XML (only an APK's is binary), so strings/sed is enough.
	aar_min="$(sed -n 's/.*minSdkVersion="\([0-9]\{1,\}\)".*/\1/p' "$man" | head -1)"
	if [ -z "$aar_min" ]; then
		echo "verify-aar: FAIL — no minSdkVersion in the AAR manifest to check"; exit 1
	fi
	if [ "$aar_min" -gt "$APP_MIN_SDK" ]; then
		echo "  minsdk   AAR declares $aar_min, the app floor is $APP_MIN_SDK"
		echo "verify-aar: FAIL — the manifest merger will refuse this AAR."
		echo "            Build with -androidapi $APP_MIN_SDK or lower, or raise the app's minSdk"
		echo "            deliberately (that drops real devices; it is not a build detail)."
		exit 1
	fi
	echo "  minsdk   $aar_min <= app floor $APP_MIN_SDK OK"
else
	echo "verify-aar: FAIL — could not read the AAR manifest"; exit 1
fi

echo "verify-aar: OK"
