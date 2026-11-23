/** @file
  libFuzzer harness for AmdPlatformPkg HiiConfigRouting:
  EFI_HII_CONFIG_ROUTING_PROTOCOL.BlockToConfig (HiiBlockToConfig).

  Input: bytes 0-1 (little endian) give the block size N (0..4096, capped at
  what is left), the next N bytes are the block (copied to an exact-size heap
  buffer), the rest is the <ConfigRequest> string with OFFSET/WIDTH pairs.
**/
#include "AutoGen.h"
#include "HiiFuzzCommon.h"
#include "AmdHiiConfigRouting.h"
#include <Library/BaseMemoryLib.h>

STATIC EFI_HII_CONFIG_ROUTING_PROTOCOL  mThis;

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  CHAR16      *Request;
  UINT8       *Block;
  UINTN       BlockSize;
  EFI_STRING  Config   = NULL;
  EFI_STRING  Progress = NULL;

  if (Size < 2) {
    return -1;
  }

  BlockSize = (Data[0] | ((UINTN)Data[1] << 8)) % 4097;
  Data     += 2;
  Size     -= 2;
  if (BlockSize > Size) {
    BlockSize = Size;
  }

  Block   = AllocateCopyPool (BlockSize, Data);
  Request = WidenToConfigString (Data + BlockSize, Size - BlockSize);
  if ((Block == NULL) || (Request == NULL)) {
    return 0;
  }

  HiiBlockToConfig (&mThis, Request, BlockSize ? Block : NULL, BlockSize, &Config, &Progress);

  if (Config != NULL) {
    FreePool (Config);
  }

  FreePool (Block);
  FreePool (Request);
  return 0;
}
