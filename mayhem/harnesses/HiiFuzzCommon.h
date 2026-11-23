/** @file
  Shared input decoding for the AMD HiiConfigRouting harnesses: input bytes
  are widened one-for-one to CHAR16 and NUL-terminated, the shape a config
  string has when it reaches EFI_HII_CONFIG_ROUTING_PROTOCOL from a form
  browser, a driver or a UEFI variable.
**/
#ifndef HII_FUZZ_COMMON_H_
#define HII_FUZZ_COMMON_H_
#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>

STATIC
CHAR16 *
WidenToConfigString (
  CONST UINT8  *Data,
  UINTN        Size
  )
{
  CHAR16  *S = AllocatePool ((Size + 1) * sizeof (CHAR16));
  UINTN   I;

  if (S == NULL) {
    return NULL;
  }

  for (I = 0; I < Size; I++) {
    S[I] = Data[I];
  }

  S[Size] = 0;
  return S;
}
#endif
