/** @file
  A fake disk (EFI_DISK_IO + EFI_BLOCK_IO) backed by a memory buffer, and the
  driver-binding Start/Stop round trip that mounts it with Ext4Dxe.
**/
#ifndef EXT4_HOST_DISK_H_
#define EXT4_HOST_DISK_H_
#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>

/* Mounts Data through Ext4Dxe's EFI_DRIVER_BINDING_PROTOCOL.Start; returns the
   installed EFI_SIMPLE_FILE_SYSTEM_PROTOCOL or NULL if the driver refused it. */
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Ext4HostMount (CONST UINT8 *Data, UINTN Size);
/* Driver-binding Stop: unmounts and frees the partition. */
VOID Ext4HostUnmount (VOID);
#endif
