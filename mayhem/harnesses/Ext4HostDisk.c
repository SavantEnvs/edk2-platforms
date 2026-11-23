/** @file
  Memory-backed disk for Ext4Dxe; see Ext4HostDisk.h.
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "Ext4HostDisk.h"
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/DiskIo.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DriverBinding.h>

extern EFI_DRIVER_BINDING_PROTOCOL  gExt4BindingProtocol;

EFI_STATUS
EFIAPI
Ext4EntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#define HOST_MEDIA_ID  0x45585434
/* The disk is a 16 MiB sparse device: the input is its leading bytes and the
   rest reads as zeros. Ext4Dxe only counts complete block groups (8192
   blocks), so a real image is >= 8 MiB, almost all of it zero; this keeps the
   seeds and mutations small while the driver still sees a full-size disk. */
#define HOST_DISK_SIZE  (16ULL * 1024 * 1024)

STATIC CONST UINT8          *mDiskData;
STATIC UINTN                mDiskSize;
STATIC EFI_BLOCK_IO_MEDIA   mMedia;
STATIC EFI_BLOCK_IO_PROTOCOL  mBlockIo;
STATIC EFI_DISK_IO_PROTOCOL   mDiskIo;
STATIC UINT8                mController;
STATIC BOOLEAN              mDriverLoaded;
STATIC BOOLEAN              mMounted;

STATIC
EFI_STATUS
EFIAPI
HostReadDisk (
  IN EFI_DISK_IO_PROTOCOL  *This,
  IN UINT32                MediaId,
  IN UINT64                Offset,
  IN UINTN                 BufferSize,
  OUT VOID                 *Buffer
  )
{
  if (MediaId != HOST_MEDIA_ID) {
    return EFI_MEDIA_CHANGED;
  }

  UINTN  InData;

  if ((Offset > HOST_DISK_SIZE) || (BufferSize > HOST_DISK_SIZE - Offset)) {
    return EFI_DEVICE_ERROR;
  }

  InData = 0;
  if (Offset < mDiskSize) {
    InData = (BufferSize < mDiskSize - Offset) ? BufferSize : (UINTN)(mDiskSize - Offset);
    CopyMem (Buffer, mDiskData + Offset, InData);
  }

  ZeroMem ((UINT8 *)Buffer + InData, BufferSize - InData);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
HostWriteDisk (
  IN EFI_DISK_IO_PROTOCOL  *This,
  IN UINT32                MediaId,
  IN UINT64                Offset,
  IN UINTN                 BufferSize,
  IN VOID                  *Buffer
  )
{
  return EFI_WRITE_PROTECTED;
}

EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *
Ext4HostMount (
  CONST UINT8  *Data,
  UINTN        Size
  )
{
  EFI_STATUS  Status;

  Edk2ShimInit ();
  if (!mDriverLoaded) {
    Ext4EntryPoint (gImageHandle, gST);
    mDriverLoaded = TRUE;
  }

  Edk2ShimResetProtocols ();
  Edk2ShimRegisterCollation ();

  mDiskData             = Data;
  mDiskSize             = (Size < HOST_DISK_SIZE) ? Size : HOST_DISK_SIZE;
  ZeroMem (&mMedia, sizeof (mMedia));
  mMedia.MediaId        = HOST_MEDIA_ID;
  mMedia.MediaPresent   = TRUE;
  mMedia.ReadOnly       = TRUE;
  mMedia.LogicalPartition = TRUE;
  mMedia.BlockSize      = 512;
  mMedia.LastBlock      = HOST_DISK_SIZE / 512 - 1;
  mBlockIo.Revision     = EFI_BLOCK_IO_PROTOCOL_REVISION;
  mBlockIo.Media        = &mMedia;
  mDiskIo.Revision      = EFI_DISK_IO_PROTOCOL_REVISION;
  mDiskIo.ReadDisk      = HostReadDisk;
  mDiskIo.WriteDisk     = HostWriteDisk;
  Edk2ShimRegisterProtocol ((EFI_HANDLE)&mController, &gEfiDiskIoProtocolGuid, &mDiskIo);
  Edk2ShimRegisterProtocol ((EFI_HANDLE)&mController, &gEfiBlockIoProtocolGuid, &mBlockIo);

  Status = gExt4BindingProtocol.Supported (&gExt4BindingProtocol, (EFI_HANDLE)&mController, NULL);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  Status = gExt4BindingProtocol.Start (&gExt4BindingProtocol, (EFI_HANDLE)&mController, NULL);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  mMounted = TRUE;
  return Edk2ShimFindProtocol ((EFI_HANDLE)&mController, &gEfiSimpleFileSystemProtocolGuid);
}

VOID
Ext4HostUnmount (
  VOID
  )
{
  if (mMounted) {
    gExt4BindingProtocol.Stop (&gExt4BindingProtocol, (EFI_HANDLE)&mController, 0, NULL);
    mMounted = FALSE;
  }
}
