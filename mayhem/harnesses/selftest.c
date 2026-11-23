/** @file
  Known-answer functional tests for the modules the harnesses fuzz, built with
  normal flags for mayhem/test.sh: Ext4Dxe must return the exact contents and
  sizes of files mkfs.ext4 wrote into the seed images (through directories and
  a symlink), and the AMD HiiConfigRouting ConfigToBlock/BlockToConfig must
  produce the exact block bytes / config string for a fixed request.

  Usage: edk2_selftest <dir with extents.img blockmap.img nocsum.img>
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "Ext4HostDisk.h"
#include "AmdHiiConfigRouting.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/FileInfo.h>

UINT8  *selftest_load (CONST CHAR8 *Path, UINT64 *Size);
VOID   selftest_report (CONST CHAR8 *Name, INT32 Ok);
VOID   selftest_note (CONST CHAR8 *What, CONST CHAR16 *S);
VOID   selftest_hex (UINT8 B);

STATIC INT32  mFailed;

STATIC
VOID
Check (
  CONST CHAR8  *Name,
  BOOLEAN      Ok
  )
{
  selftest_report (Name, Ok ? 1 : 0);
  if (!Ok) {
    mFailed++;
  }
}

STATIC
UINTN
ReadWhole (
  EFI_FILE_PROTOCOL  *Root,
  CHAR16             *Path,
  UINT8              *Buf,
  UINTN              Cap
  )
{
  EFI_FILE_PROTOCOL  *F;
  UINTN              Size = Cap;

  if (EFI_ERROR (Root->Open (Root, &F, Path, EFI_FILE_MODE_READ, 0))) {
    return (UINTN)-1;
  }

  if (EFI_ERROR (F->Read (F, &Size, Buf))) {
    Size = (UINTN)-1;
  }

  F->Close (F);
  return Size;
}

STATIC
UINT64
FileSizeOf (
  EFI_FILE_PROTOCOL  *Root,
  CHAR16             *Path
  )
{
  EFI_FILE_PROTOCOL  *F;
  UINT8              Buf[SIZE_OF_EFI_FILE_INFO + 256];
  UINTN              Size = sizeof (Buf);
  UINT64             R    = (UINT64)-1;

  if (EFI_ERROR (Root->Open (Root, &F, Path, EFI_FILE_MODE_READ, 0))) {
    return R;
  }

  if (!EFI_ERROR (F->GetInfo (F, &gEfiFileInfoGuid, &Size, Buf))) {
    R = ((EFI_FILE_INFO *)Buf)->FileSize;
  }

  F->Close (F);
  return R;
}

STATIC
VOID
TestExt4Image (
  CONST CHAR8  *Dir,
  CONST CHAR8  *Image
  )
{
  CHAR8                            Path[512];
  CHAR8                            Name[128];
  UINT8                            *Data;
  UINT64                           Size;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Sfs;
  EFI_FILE_PROTOCOL                *Root = NULL;
  STATIC UINT8                     Buf[8192];
  UINTN                            N;
  UINTN                            I;
  BOOLEAN                          AllA;
  CONST CHAR8                      *Oracle = "EDK2-EXT4-ORACLE\n";

  AsciiStrCpyS (Path, sizeof (Path), Dir);
  AsciiStrCatS (Path, sizeof (Path), "/");
  AsciiStrCatS (Path, sizeof (Path), Image);
  Data = selftest_load (Path, &Size);
  Sfs  = (Data != NULL) ? Ext4HostMount (Data, (UINTN)Size) : NULL;
  AsciiStrCpyS (Name, sizeof (Name), "ext4_mount_");
  AsciiStrCatS (Name, sizeof (Name), Image);
  Check (Name, Sfs != NULL && !EFI_ERROR (Sfs->OpenVolume (Sfs, &Root)));
  if (Root == NULL) {
    mFailed += 4;
    return;
  }

  N = ReadWhole (Root, L"dir\\sub\\oracle.txt", Buf, sizeof (Buf));
  AsciiStrCpyS (Name, sizeof (Name), "ext4_read_nested_");
  AsciiStrCatS (Name, sizeof (Name), Image);
  Check (Name, N == AsciiStrLen (Oracle) && CompareMem (Buf, Oracle, N) == 0);

  N = ReadWhole (Root, L"link", Buf, sizeof (Buf));
  AsciiStrCpyS (Name, sizeof (Name), "ext4_symlink_");
  AsciiStrCatS (Name, sizeof (Name), Image);
  Check (Name, N == AsciiStrLen (Oracle) && CompareMem (Buf, Oracle, N) == 0);

  N    = ReadWhole (Root, L"\\dir\\big.bin", Buf, sizeof (Buf));
  AllA = (N == 3000);
  for (I = 0; AllA && I < N; I++) {
    AllA = Buf[I] == 'A';
  }

  AsciiStrCpyS (Name, sizeof (Name), "ext4_read_multiblock_");
  AsciiStrCatS (Name, sizeof (Name), Image);
  Check (Name, AllA && FileSizeOf (Root, L"dir\\big.bin") == 3000);

  N = ReadWhole (Root, L"dir\\no-such-file", Buf, sizeof (Buf));
  AsciiStrCpyS (Name, sizeof (Name), "ext4_missing_file_");
  AsciiStrCatS (Name, sizeof (Name), Image);
  Check (Name, N == (UINTN)-1 && ReadWhole (Root, L"hello.txt", Buf, sizeof (Buf)) == 11);

  Root->Close (Root);
  Ext4HostUnmount ();
  FreePool (Data);
}

#define HDR  L"GUID=0123456789abcdef0123456789abcdef&NAME=0041&PATH=0102"

STATIC
VOID
TestHii (
  VOID
  )
{
  STATIC EFI_HII_CONFIG_ROUTING_PROTOCOL  This;
  UINT8                                   Block[8];
  UINTN                                   BlockSize = sizeof (Block);
  EFI_STRING                              Progress;
  EFI_STRING                              Config = NULL;
  EFI_STATUS                              Status;
  STATIC CONST UINT8                      Expect[8] = { 0x78, 0x56, 0x34, 0x12, 0xcd, 0xab, 0, 0 };
  STATIC CONST UINT8                      Src[4]    = { 0x11, 0x22, 0x33, 0x44 };
  STATIC CHAR16                           Req[128];
  STATIC CHAR16                           Resp[160];
  UINTN                                   I;

  ZeroMem (Block, sizeof (Block));
  StrCpyS (Resp, ARRAY_SIZE (Resp), HDR L"&OFFSET=0&WIDTH=4&VALUE=12345678&OFFSET=4&WIDTH=2&VALUE=abcd");
  Status = HiiConfigToBlock (&This, Resp, Block, &BlockSize, &Progress);
  for (I = 0; I < 8; I++) {
    selftest_hex (Block[I]);
  }
  Check ("hii_config_to_block_values", Status == EFI_SUCCESS && CompareMem (Block, Expect, 8) == 0);

  BlockSize = 2;
  StrCpyS (Resp, ARRAY_SIZE (Resp), HDR L"&OFFSET=0&WIDTH=4&VALUE=12345678");
  Status    = HiiConfigToBlock (&This, Resp, Block, &BlockSize, &Progress);
  Check ("hii_config_to_block_too_small", Status == EFI_BUFFER_TOO_SMALL && BlockSize == 4);

  StrCpyS (Resp, ARRAY_SIZE (Resp), L"GUID=zz&NAME=0041");
  Status = HiiConfigToBlock (&This, Resp, Block, &BlockSize, &Progress);
  Check ("hii_config_to_block_bad_header", Status == EFI_INVALID_PARAMETER);

  /* BlockToConfig edits the request in place (it NUL-splits the header), so it must be writable. */
  StrCpyS (Req, ARRAY_SIZE (Req), HDR L"&OFFSET=0&WIDTH=4");
  Status = HiiBlockToConfig (&This, Req, Src, sizeof (Src), &Config, &Progress);
  selftest_note ("BlockToConfig", Config);
  Check (
    "hii_block_to_config_value",
    Status == EFI_SUCCESS && Config != NULL &&
    StrCmp (Config, HDR L"&OFFSET=0&WIDTH=4&VALUE=44332211") == 0
    );
  if (Config != NULL) {
    FreePool (Config);
  }

  Config = NULL;
  StrCpyS (Req, ARRAY_SIZE (Req), HDR L"&OFFSET=2&WIDTH=4");
  Status = HiiBlockToConfig (&This, Req, Src, sizeof (Src), &Config, &Progress);
  Check ("hii_block_to_config_out_of_range", EFI_ERROR (Status));
  if (Config != NULL) {
    FreePool (Config);
  }
}

int
main (
  int   Argc,
  char  **Argv
  )
{
  if (Argc < 2) {
    return 2;
  }

  TestExt4Image (Argv[1], "extents.img");
  TestExt4Image (Argv[1], "blockmap.img");
  TestExt4Image (Argv[1], "nocsum.img");
  TestHii ();
  return mFailed ? 1 : 0;
}
