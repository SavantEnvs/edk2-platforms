#!/usr/bin/env bash
#
# mayhem/build.sh — host (Linux user-space) libFuzzer builds of edk2-platforms drivers.
#
# EDK2's own `build` (BaseTools, DSC/INF) produces PE/COFF firmware images, not host
# executables, so the fuzzed modules are compiled here directly with clang against the
# headers of a pinned tianocore/edk2 tree (baked into the image under
# /opt/toolchains/deps/edk2-<rev>/src by mayhem/Dockerfile). The EDK2 library classes
# they link (MemoryAllocationLib, BaseMemoryLib, DebugLib, boot services, the UefiLib
# calls) are host stand-ins in mayhem/harnesses/Edk2HostShim.c; BaseLib,
# OrderedCollectionLib and BaseUcs2Utf8Lib are edk2's own C sources, compiled
# uninstrumented (they are dependencies, not the target).
#
# Fuzzed modules (sanitized): Features/Ext4Pkg/Ext4Dxe, Platform/AMD/AmdPlatformPkg/
# Universal/HiiConfigRouting, Drivers/DisplayLink/DisplayLinkPkg/DisplayLinkGop (EDID +
# capability descriptor), Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdCoreDxe (ACPI DMAR
# table + PCI device inventory, with IntelVTdPeiDxeLib's DMAR dump walk), Drivers/ASIX/.../Ax88179
# and Ax88772c (SNP Receive over USB bulk-in data), Features/Intel/OutOfBandManagement/
# IpmiFeaturePkg/IpmiRedirFru (BMC FRU inventory -> SMBIOS strings), Silicon/Intel/IntelSiliconPkg/
# Feature/Capsule/MicrocodeUpdateDxe (microcode FMP SetImage capsule payload). Output: mayhem/out/<target>, mayhem/out/<target>-standalone,
# mayhem/out/edk2_selftest (normal flags, run by mayhem/test.sh). Also Silicon/Intel/Tools/FitGen as the
# raw file-input target mayhem/out/fitgen (+ mayhem/out/fitgen_test, normal flags, for test.sh); see 2b.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${EDK2_DIR:=/opt/toolchains/deps/edk2-7c0eaacf8bba/src}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must point at the base image run-once driver}"

cd "$SRC"
H="$SRC/mayhem/harnesses"
B="$SRC/mayhem/build"
OUT="$SRC/mayhem/out"
rm -rf "$B" "$OUT"
mkdir -p "$B"/{dep,fuzz,test} "$OUT"

EXT4="$SRC/Features/Ext4Pkg/Ext4Dxe"
AMDHII="$SRC/Platform/AMD/AmdPlatformPkg/Universal/HiiConfigRouting"
DLGOP="$SRC/Drivers/DisplayLink/DisplayLinkPkg/DisplayLinkGop"
VTD="$SRC/Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdCoreDxe"
AX179="$SRC/Drivers/ASIX/Bus/Usb/UsbNetworking/Ax88179"
AX772="$SRC/Drivers/ASIX/Bus/Usb/UsbNetworking/Ax88772c"
IPMIPKG="$SRC/Features/Intel/OutOfBandManagement/IpmiFeaturePkg"
MCU="$SRC/Silicon/Intel/IntelSiliconPkg/Feature/Capsule/MicrocodeUpdateDxe"

# EDK2 dialect: CHAR16 is 16-bit, no hosted libc headers, release DebugLib (MDEPKG_NDEBUG).
EDK2_CFLAGS=(-fshort-wchar -fno-strict-aliasing -fno-builtin -fwrapv -DMDEPKG_NDEBUG -DNO_MSABI_VA_FUNCS
  -include "$H/AutoGen.h" -I"$H"
  -I"$EDK2_DIR/MdePkg/Include" -I"$EDK2_DIR/MdePkg/Include/X64"
  -I"$EDK2_DIR/MdeModulePkg/Include" -I"$EDK2_DIR/RedfishPkg/Include" -I"$EDK2_DIR/NetworkPkg/Include"
  -I"$SRC/Features/Ext4Pkg/Include" -I"$EXT4" -I"$AMDHII" -I"$DLGOP"
  -I"$SRC/Silicon/Intel/IntelSiliconPkg/Include" -I"$VTD" -I"$AX179" -I"$AX772"
  -I"$IPMIPKG/Include" -I"$IPMIPKG/IpmiRedirFru"
  -Wno-everything -Werror=implicit-function-declaration -Werror=int-conversion)

# BaseLib: the portable C files only (string/math/list/checksum helpers).
BASELIB_SRCS=(String.c SafeString.c LinkedList.c CheckSum.c Math64.c Unaligned.c
  SwapBytes16.c SwapBytes32.c SwapBytes64.c LShiftU64.c RShiftU64.c ARShiftU64.c
  MultU64x32.c MultU64x64.c MultS64x64.c DivU64x32.c DivU64x32Remainder.c
  DivU64x64Remainder.c DivS64x64Remainder.c ModU64x32.c HighBitSet32.c HighBitSet64.c
  LowBitSet32.c LowBitSet64.c GetPowerOfTwo32.c GetPowerOfTwo64.c BitField.c
  RRotU32.c RRotU64.c LRotU32.c LRotU64.c FilePaths.c SafeString.c)

# compile <outdir> <flags...> -- <sources...>  (parallel, each to its own object)
compile() {
  local outdir="$1"; shift
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  printf '%s\n' "$@" | sort -u | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
    'src="$1"; shift; o="$0/$(echo "$src" | sed "s|^/||; s|/|_|g").o"; exec "$@" -c "$src" -o "$o"' \
    "$outdir" {} "$CC" "${flags[@]}"
}

DEP_SRCS=()
for f in "${BASELIB_SRCS[@]}"; do DEP_SRCS+=("$EDK2_DIR/MdePkg/Library/BaseLib/$f"); done
DEP_SRCS+=("$EDK2_DIR/MdePkg/Library/BaseOrderedCollectionRedBlackTreeLib/BaseOrderedCollectionRedBlackTreeLib.c"
  "$EDK2_DIR/RedfishPkg/Library/BaseUcs2Utf8Lib/BaseUcs2Utf8Lib.c"
  "$EDK2_DIR/MdePkg/Library/BasePrintLib/PrintLib.c" "$EDK2_DIR/MdePkg/Library/BasePrintLib/PrintLibInternal.c")

EXT4_SRCS=("$EXT4"/{BlockGroup,BlockMap,Collation,Directory,DiskUtil,Ext4Dxe,Extents,File,Inode,Partition,Superblock,Symlink}.c "$H/Ext4HostDisk.c")
HII_SRCS=("$AMDHII/AmdHiiConfigRouting.c")
DL_SRCS=("$DLGOP"/{Edid,CapabilityDescriptor,VideoModes,UsbTransfer}.c)
AX179_SRCS=("$AX179"/{Ax88179,SimpleNetwork}.c)
AX772_SRCS=("$AX772"/{Ax88772,SimpleNetwork}.c)
FRU_SRCS=("$IPMIPKG/IpmiRedirFru"/{IpmiRedirFru,FruSmbios}.c)
VTD_SRCS=("$VTD"/{DmarAcpiTable,PciInfo}.c "$SRC/Silicon/Intel/IntelSiliconPkg/Library/IntelVTdPeiDxeLib/IntelVTdPeiDxeLib.c")
MCU_SRCS=("$MCU"/{MicrocodeFmp,MicrocodeUpdate}.c)
SHIM_SRCS=("$H/Edk2HostShim.c")
# MicrocodeUpdateDxe also needs UefiCpuPkg's Register/ headers, and its FIT pointer read is
# relocated off the fixed 4G-0x40 address by mayhem/harnesses/fit (see the header there).
MCU_CFLAGS=(-I"$H/fit" -I"$EDK2_DIR/UefiCpuPkg/Include" -I"$MCU")

# 1) Dependencies: uninstrumented, debug info only. Shared by the fuzz and test builds.
compile "$B/dep" -O1 $DEBUG_FLAGS "${EDK2_CFLAGS[@]}" -- "${DEP_SRCS[@]}"

# 2) Fuzz build: the edk2-platforms modules + shim with the sanitizers.
# UBSan's alignment check is relaxed (only it): EDK2 targets x86/AArch64 firmware, where unaligned
# loads are legal and the code does them routinely (packed descriptors, USB/RX headers at odd
# offsets); left on, every input stops at the first such load. ASan and the rest of UBSan halt.
FUZZ_FLAGS=(-O1 $SANITIZER_FLAGS -fno-sanitize=alignment $DEBUG_FLAGS "${EDK2_CFLAGS[@]}")
compile "$B/fuzz" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link -- "${EXT4_SRCS[@]}" "${HII_SRCS[@]}" "${DL_SRCS[@]}" "${VTD_SRCS[@]}" "${AX179_SRCS[@]}" "${AX772_SRCS[@]}" "${FRU_SRCS[@]}" "${SHIM_SRCS[@]}"
compile "$B/fuzz" "${MCU_CFLAGS[@]}" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link -- "${MCU_SRCS[@]}"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

o() { local p; for p in "$@"; do echo "$B/fuzz/$(echo "$p" | sed 's|^/||; s|/|_|g').o"; done; }
DEP_OBJS=("$B"/dep/*.o)
SHIM_OBJS=($(o "${SHIM_SRCS[@]}"))
EXT4_OBJS=($(o "${EXT4_SRCS[@]}"))
HII_OBJS=($(o "${HII_SRCS[@]}"))
DL_OBJS=($(o "${DL_SRCS[@]}"))
VTD_OBJS=($(o "${VTD_SRCS[@]}"))
AX179_OBJS=($(o "${AX179_SRCS[@]}"))
AX772_OBJS=($(o "${AX772_SRCS[@]}"))
FRU_OBJS=($(o "${FRU_SRCS[@]}"))
MCU_OBJS=($(o "${MCU_SRCS[@]}"))

link_target() {
  local name="$1"; shift
  $CC "${MCU_CFLAGS[@]}" "${FUZZ_FLAGS[@]}" -fsanitize=fuzzer-no-link -c "$H/$name.c" -o "$B/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$name.o" "$@" "${SHIM_OBJS[@]}" \
    "${DEP_OBJS[@]}" "$B/lsan_off.o" -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$name.o" "$@" "${SHIM_OBJS[@]}" \
    "${DEP_OBJS[@]}" "$B/lsan_off.o" -o "$OUT/$name-standalone"
}
link_target fuzz_ext4 "${EXT4_OBJS[@]}"
link_target fuzz_hii_config_to_block "${HII_OBJS[@]}"
link_target fuzz_hii_block_to_config "${HII_OBJS[@]}"
link_target fuzz_displaylink "${DL_OBJS[@]}"
link_target fuzz_vtd_dmar "${VTD_OBJS[@]}"
link_target fuzz_ax88179_rx "${AX179_OBJS[@]}"
link_target fuzz_ax88772c_rx "${AX772_OBJS[@]}"
link_target fuzz_ipmi_fru "${FRU_OBJS[@]}"
link_target fuzz_microcode_fmp "${MCU_OBJS[@]}" -Wl,--wrap=AllocateZeroPool  # see the harness

# 2b) FitGen (Silicon/Intel/Tools/FitGen): the host CLI that reads a flash image (FD -> FV -> FFS,
# the BiosInfo file and the microcode / ACM / BIOS-module blobs it lists) and writes the FIT.
# Fuzzed as a raw file-input target, `fitgen -D @@ fitgen.out -I <BiosInfoGuid>`
# (Mayhemfile_fitgen_gen), so every input runs in a fresh process: FitGen's global
# gFitTableContext starts zeroed and its exit() paths stay as upstream wrote them. FitGen.c (which
# #includes BaseTools' EfiUtilityMsgs.c) gets the sanitizers; the BaseTools Common library it links
# (CommonLib, ParseInf, FvLib from the pinned edk2) is a dependency, built uninstrumented. No
# compile-time SanCov: Mayhem instruments a raw (non-libFuzzer) ELF itself.
BT="$EDK2_DIR/BaseTools/Source/C"
FITGEN_CFLAGS=(-I"$BT" -I"$BT/Include/Common" -I"$BT/Include" -I"$BT/Include/IndustryStandard" -I"$BT/Common"
  -I"$EDK2_DIR/MdePkg/Include/X64" -Wno-everything)
FITGEN_DEPS=("$BT/Common/CommonLib.c" "$BT/Common/ParseInf.c" "$BT/Common/FvLib.c")
mkdir -p "$B/fitgen-dep" "$B/fitgen-test"
compile "$B/fitgen-dep" -O1 $DEBUG_FLAGS "${FITGEN_CFLAGS[@]}" -- "${FITGEN_DEPS[@]}"
$CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS "${FITGEN_CFLAGS[@]}" -c "$SRC/Silicon/Intel/Tools/FitGen/FitGen.c" -o "$B/fitgen.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fitgen.o" "$B"/fitgen-dep/*.o "$B/lsan_off.o" -o "$OUT/fitgen"

# 3) Functional selftest with normal flags (no sanitizers), run by mayhem/test.sh.
TEST_FLAGS=(-O2 $COVERAGE_FLAGS "${EDK2_CFLAGS[@]}")
compile "$B/test" "${TEST_FLAGS[@]}" -- "${EXT4_SRCS[@]}" "${HII_SRCS[@]}" "${SHIM_SRCS[@]}" "$H/selftest.c"
$CC -O2 $COVERAGE_FLAGS -c "$H/selftest_io.c" -o "$B/selftest_io.o"
$CC $COVERAGE_FLAGS "$B"/test/*.o "$B/selftest_io.o" "${DEP_OBJS[@]}" -o "$OUT/edk2_selftest"
compile "$B/fitgen-test" -O2 $COVERAGE_FLAGS "${FITGEN_CFLAGS[@]}" -- "$SRC/Silicon/Intel/Tools/FitGen/FitGen.c" "${FITGEN_DEPS[@]}"
$CC $COVERAGE_FLAGS "$B"/fitgen-test/*.o -o "$OUT/fitgen_test"

ls -la "$OUT"
