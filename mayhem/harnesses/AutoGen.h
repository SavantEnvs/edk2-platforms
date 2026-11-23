/* Host build stand-in for the AutoGen.h that EDK2's `build` generates per module.
   Only the PCDs the compiled modules read are defined, with MdePkg.dec defaults. */
#ifndef MAYHEM_AUTOGEN_H_
#define MAYHEM_AUTOGEN_H_
#include <Base.h>
#include <Uefi.h>
#include <Library/PcdLib.h>

#define _PCD_VALUE_PcdMaximumAsciiStringLength            1000000U
#define _PCD_GET_MODE_32_PcdMaximumAsciiStringLength      1000000U
#define _PCD_VALUE_PcdMaximumUnicodeStringLength          1000000U
#define _PCD_GET_MODE_32_PcdMaximumUnicodeStringLength    1000000U
#define _PCD_VALUE_PcdMaximumLinkedListLength             1000000U
#define _PCD_GET_MODE_32_PcdMaximumLinkedListLength       1000000U
#define _PCD_VALUE_PcdVerifyNodeInList                    FALSE
#define _PCD_GET_MODE_BOOL_PcdVerifyNodeInList            FALSE
#define _PCD_VALUE_PcdSpeculationBarrierType              0x1
#define _PCD_GET_MODE_8_PcdSpeculationBarrierType         0x1
#define _PCD_VALUE_PcdControlFlowEnforcementPropertyMask  0x0
#define _PCD_GET_MODE_32_PcdControlFlowEnforcementPropertyMask 0x0
#define _PCD_VALUE_PcdUefiVariableDefaultPlatformLang     "en-US"
#define _PCD_GET_MODE_PTR_PcdUefiVariableDefaultPlatformLang ((VOID *)"en-US")
#define _PCD_VALUE_PcdUefiVariableDefaultLang             "engeng"
#define _PCD_GET_MODE_PTR_PcdUefiVariableDefaultLang      ((VOID *)"engeng")
#define _PCD_VALUE_PcdMaximumDevicePathNodeCount          0
#define _PCD_GET_MODE_32_PcdMaximumDevicePathNodeCount    0
#define _PCD_VALUE_PcdFixedDebugPrintErrorLevel           0xFFFFFFFFU
#define _PCD_GET_MODE_32_PcdFixedDebugPrintErrorLevel     0xFFFFFFFFU
#define _PCD_VALUE_PcdDebugPropertyMask                   0
#define _PCD_GET_MODE_8_PcdDebugPropertyMask              0

#define _PCD_GET_MODE_BOOL_PcdValidateOrderedCollection   FALSE

extern EFI_GUID  gEfiCallerIdGuid;
extern CHAR8     *gEfiCallerBaseName;

/* GUIDs that EDK2 AutoGen.h declares for IpmiRedirFru (from its .inf [Guids]). */
extern EFI_GUID  gEfiIpmiFormatFruGuid;
extern EFI_GUID  gEfiSystemTypeFruGuid;
extern EFI_GUID  gBdsEventAfterConsoleReadyBeforeBootOptionGuid;

/* MicrocodeUpdateDxe (fuzz_microcode_fmp): the microcode flash region is a heap buffer the
   harness owns, published through the two UefiCpuPkg PCDs the driver reads. */
extern UINT8  *mMayhemMicrocodeRegion;
#define _PCD_GET_MODE_64_PcdCpuMicrocodePatchAddress     ((UINT64)(UINTN)mMayhemMicrocodeRegion)
#define _PCD_GET_MODE_64_PcdCpuMicrocodePatchRegionSize  0x8000ULL
#endif
