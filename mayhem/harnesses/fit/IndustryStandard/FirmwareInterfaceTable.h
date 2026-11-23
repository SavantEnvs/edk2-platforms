/* Host-build override for fuzz_microcode_fmp only: the FIT pointer lives at the fixed physical
   address 4G-0x40 on real hardware, which is unmapped (and inside ASan's shadow gap) in a host
   process. Keep upstream's definitions and relocate just that one address to a harness-owned
   slot; the driver code that reads it is unchanged. */
#include_next <IndustryStandard/FirmwareInterfaceTable.h>
#undef FIT_POINTER_ADDRESS
extern UINT64  mMayhemFitPointer;
#define FIT_POINTER_ADDRESS  ((UINTN)&mMayhemFitPointer)
