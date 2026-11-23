/** @file
  libFuzzer harness for AmdPlatformPkg HiiConfigRouting:
  EFI_HII_CONFIG_ROUTING_PROTOCOL.ConfigToBlock (HiiConfigToBlock).

  Input: bytes 0-1 (little endian) choose the caller's block size (0..4096),
  the rest is the <ConfigResp> string
  ("GUID=..&NAME=..&PATH=..&OFFSET=..&WIDTH=..&VALUE=.."). The block is an
  exact-size heap buffer so ASan catches any write past *BlockSize.
**/
#include "AutoGen.h"
#include "HiiFuzzCommon.h"
#include "AmdHiiConfigRouting.h"

STATIC EFI_HII_CONFIG_ROUTING_PROTOCOL  mThis;

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  CHAR16      *Resp;
  UINT8       *Block;
  UINTN       BlockSize;
  EFI_STRING  Progress;

  if (Size < 2) {
    return -1;
  }

  BlockSize = (Data[0] | ((UINTN)Data[1] << 8)) % 4097;
  Resp      = WidenToConfigString (Data + 2, Size - 2);
  Block     = BlockSize ? AllocateZeroPool (BlockSize) : NULL;
  if ((Resp == NULL) || ((BlockSize != 0) && (Block == NULL))) {
    return 0;
  }

  HiiConfigToBlock (&mThis, Resp, Block, &BlockSize, &Progress);

  if (Block != NULL) {
    FreePool (Block);
  }

  FreePool (Resp);
  return 0;
}
