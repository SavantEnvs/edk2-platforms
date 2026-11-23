/** @file
  libFuzzer harness for Features/Ext4Pkg/Ext4Dxe.

  The input is a raw ext4 image served through a fake EFI_DISK_IO/BLOCK_IO.
  The harness mounts it via the driver's EFI_DRIVER_BINDING_PROTOCOL.Start,
  then exercises the installed EFI_SIMPLE_FILE_SYSTEM_PROTOCOL like a UEFI
  shell would: OpenVolume, walk directories (EFI_FILE.Read on a directory),
  Open every entry (following symlinks), Read file contents, Read at huge and
  unaligned positions, GetInfo for file/filesystem/volume label, and finally
  Stop (unmount + free). Nothing persists between inputs except the loaded
  driver binding, which is read-only after load.
**/
#include "AutoGen.h"
#include "Ext4HostDisk.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/FileInfo.h>
#include <Guid/FileSystemInfo.h>
#include <Guid/FileSystemVolumeLabelInfo.h>

#define MAX_DEPTH      6
#define MAX_ENTRIES    256
#define READ_CHUNK     4096
#define MAX_FILE_READ  (256 * 1024)

STATIC UINTN  mEntryBudget;

STATIC
VOID
ExerciseInfo (
  EFI_FILE_PROTOCOL  *File,
  EFI_GUID           *InfoType
  )
{
  UINTN       Size = 0;
  VOID        *Buf;
  EFI_STATUS  Status;

  Status = File->GetInfo (File, InfoType, &Size, NULL);
  if ((Status != EFI_BUFFER_TOO_SMALL) || (Size == 0) || (Size > 0x10000)) {
    return;
  }

  Buf = AllocateZeroPool (Size);
  if (Buf != NULL) {
    File->GetInfo (File, InfoType, &Size, Buf);
    FreePool (Buf);
  }
}

STATIC
VOID
ExerciseFile (
  EFI_FILE_PROTOCOL  *File
  )
{
  UINT8       *Buf;
  UINTN       Size;
  UINTN       Total = 0;
  UINT64      Pos;
  EFI_STATUS  Status;

  Buf = AllocatePool (READ_CHUNK);
  if (Buf == NULL) {
    return;
  }

  do {
    Size   = READ_CHUNK;
    Status = File->Read (File, &Size, Buf);
    Total += Size;
  } while (!EFI_ERROR (Status) && Size == READ_CHUNK && Total < MAX_FILE_READ);

  /* Reads at the end of the file, at an odd offset and far past the end. */
  File->SetPosition (File, 0xFFFFFFFFFFFFFFFFULL);
  File->GetPosition (File, &Pos);
  if (Pos > 0) {
    File->SetPosition (File, Pos - 1);
    Size = READ_CHUNK;
    File->Read (File, &Size, Buf);
  }

  File->SetPosition (File, 4093);
  Size = 7;
  File->Read (File, &Size, Buf);
  File->SetPosition (File, 0xFFFFFFFFFFFF0000ULL);
  Size = READ_CHUNK;
  File->Read (File, &Size, Buf);
  File->SetPosition (File, 0x7FFFFFFFFFFULL);
  Size = READ_CHUNK;
  File->Read (File, &Size, Buf);

  FreePool (Buf);
  ExerciseInfo (File, &gEfiFileInfoGuid);
}

STATIC
VOID
WalkDirectory (
  EFI_FILE_PROTOCOL  *Dir,
  UINTN              Depth
  )
{
  EFI_FILE_INFO      *Info;
  UINTN              InfoCap = SIZE_OF_EFI_FILE_INFO + 512;
  UINTN              Size;
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *Child;

  Info = AllocateZeroPool (InfoCap);
  if (Info == NULL) {
    return;
  }

  while (mEntryBudget > 0) {
    mEntryBudget--;
    Size   = InfoCap;
    Status = Dir->Read (Dir, &Size, Info);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      if (Size > 0x10000) {
        break;
      }

      FreePool (Info);
      InfoCap = Size;
      Info    = AllocateZeroPool (InfoCap);
      if (Info == NULL) {
        return;
      }

      continue;
    }

    if (EFI_ERROR (Status) || (Size == 0)) {
      break;
    }

    if ((StrCmp (Info->FileName, L".") == 0) || (StrCmp (Info->FileName, L"..") == 0)) {
      continue;
    }

    Status = Dir->Open (Dir, &Child, Info->FileName, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR (Status)) {
      continue;
    }

    if ((Info->Attribute & EFI_FILE_DIRECTORY) != 0) {
      if (Depth < MAX_DEPTH) {
        WalkDirectory (Child, Depth + 1);
      }
    } else {
      ExerciseFile (Child);
    }

    Child->Close (Child);
  }

  if (Info != NULL) {
    FreePool (Info);
  }

  ExerciseInfo (Dir, &gEfiFileInfoGuid);
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Sfs;
  EFI_FILE_PROTOCOL                *Root;
  EFI_FILE_PROTOCOL                *Child;
  STATIC CHAR16                    *Paths[] = { L"\\", L"..\\..\\a", L"lost+found", L"\\dir\\sub\\..\\.\\x" };
  UINTN                            I;

  Sfs = Ext4HostMount (Data, Size);
  if (Sfs != NULL) {
    if (!EFI_ERROR (Sfs->OpenVolume (Sfs, &Root))) {
      ExerciseInfo (Root, &gEfiFileSystemInfoGuid);
      ExerciseInfo (Root, &gEfiFileSystemVolumeLabelInfoIdGuid);
      for (I = 0; I < ARRAY_SIZE (Paths); I++) {
        if (!EFI_ERROR (Root->Open (Root, &Child, Paths[I], EFI_FILE_MODE_READ, 0))) {
          Child->Close (Child);
        }
      }

      mEntryBudget = MAX_ENTRIES;
      WalkDirectory (Root, 0);
      Root->Close (Root);
    }
  }

  Ext4HostUnmount ();
  return 0;
}
