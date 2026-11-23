/** @file
  Host (Linux user-space) stand-ins for the EDK2 library classes the fuzzed
  modules link against: MemoryAllocationLib and BaseMemoryLib map onto libc
  (so ASan sees every allocation and copy exactly), DebugLib is the release
  (MDEPKG_NDEBUG) no-op, and a minimal boot-services table serves the protocol
  lookups the drivers make. The fake protocol instances are installed by each
  harness through Edk2ShimRegisterProtocol().
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/DiskIo.h>
#include <Protocol/DiskIo2.h>
#include <Protocol/BlockIo.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/UnicodeCollation.h>
#include <Protocol/HiiConfigRouting.h>
#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/EdidOverride.h>
#include <Protocol/UsbIo.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Guid/FileInfo.h>
#include <Guid/FileSystemInfo.h>
#include <Guid/FileSystemVolumeLabelInfo.h>

/* libc, declared by hand: libc headers clash with the EDK2 base types. */
void  *malloc (unsigned long);
void  *calloc (unsigned long, unsigned long);
void  *realloc (void *, unsigned long);
void  free (void *);
void  *memmove (void *, const void *, unsigned long);
void  *memset (void *, int, unsigned long);
int   memcmp (const void *, const void *, unsigned long);
void  abort (void);

EFI_GUID  gEfiCallerIdGuid                    = { 0x3ff1d1ad, 0x1a1e, 0x4f2a, { 0x8b, 0xe0, 0x6d, 0x4e, 0x45, 0x58, 0x54, 0x34 } };
CHAR8     *gEfiCallerBaseName                 = "MayhemHost";
EFI_GUID  gEfiDiskIoProtocolGuid              = EFI_DISK_IO_PROTOCOL_GUID;
EFI_GUID  gEfiDiskIo2ProtocolGuid             = EFI_DISK_IO2_PROTOCOL_GUID;
EFI_GUID  gEfiBlockIoProtocolGuid             = EFI_BLOCK_IO_PROTOCOL_GUID;
EFI_GUID  gEfiSimpleFileSystemProtocolGuid    = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
EFI_GUID  gEfiUnicodeCollation2ProtocolGuid   = EFI_UNICODE_COLLATION_PROTOCOL2_GUID;
EFI_GUID  gEfiHiiConfigRoutingProtocolGuid    = EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID;
EFI_GUID  gEfiComponentNameProtocolGuid       = EFI_COMPONENT_NAME_PROTOCOL_GUID;
EFI_GUID  gEfiComponentName2ProtocolGuid      = EFI_COMPONENT_NAME2_PROTOCOL_GUID;
EFI_GUID  gEfiDriverBindingProtocolGuid       = EFI_DRIVER_BINDING_PROTOCOL_GUID;
EFI_GUID  gEfiEdidOverrideProtocolGuid        = EFI_EDID_OVERRIDE_PROTOCOL_GUID;
EFI_GUID  gEfiPciRootBridgeIoProtocolGuid     = EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GUID;
EFI_GUID  gEfiUsbIoProtocolGuid               = EFI_USB_IO_PROTOCOL_GUID;
EFI_GUID  gEfiFileInfoGuid                    = EFI_FILE_INFO_ID;
EFI_GUID  gEfiFileSystemInfoGuid              = EFI_FILE_SYSTEM_INFO_ID;
EFI_GUID  gEfiFileSystemVolumeLabelInfoIdGuid = EFI_FILE_SYSTEM_VOLUME_LABEL_ID;

/* ---------------- MemoryAllocationLib ---------------- */
/* Pool requests beyond what a firmware heap could hold fail with NULL, as
   AllocatePool does when the pool is exhausted (instead of aborting in ASan's
   allocator on a size taken from the input). */
#define SHIM_MAX_POOL  (256UL * 1024 * 1024)
VOID *EFIAPI AllocatePool (UINTN Size) { return Size > SHIM_MAX_POOL ? NULL : malloc (Size ? Size : 1); }
VOID *EFIAPI AllocateZeroPool (UINTN Size) { return Size > SHIM_MAX_POOL ? NULL : calloc (1, Size ? Size : 1); }
VOID *EFIAPI AllocateRuntimePool (UINTN Size) { return AllocatePool (Size); }
VOID *EFIAPI AllocateRuntimeZeroPool (UINTN Size) { return AllocateZeroPool (Size); }
VOID *EFIAPI AllocateBootServicesData (UINTN Size) { return AllocatePool (Size); }

VOID *
EFIAPI
AllocateCopyPool (UINTN Size, CONST VOID *Buffer)
{
  VOID  *P = AllocatePool (Size);

  if (P != NULL) {
    memmove (P, Buffer, Size);
  }

  return P;
}

VOID *
EFIAPI
ReallocatePool (UINTN OldSize, UINTN NewSize, VOID *OldBuffer)
{
  VOID  *P = AllocateZeroPool (NewSize);

  if ((P != NULL) && (OldBuffer != NULL)) {
    memmove (P, OldBuffer, OldSize < NewSize ? OldSize : NewSize);
    free (OldBuffer);
  }

  return P;
}

VOID EFIAPI FreePool (VOID *Buffer) { free (Buffer); }

/* ---------------- BaseMemoryLib ---------------- */
VOID *EFIAPI CopyMem (VOID *D, CONST VOID *S, UINTN L) { return memmove (D, S, L); }
VOID *EFIAPI SetMem (VOID *B, UINTN L, UINT8 V) { return memset (B, V, L); }
VOID *EFIAPI ZeroMem (VOID *B, UINTN L) { return memset (B, 0, L); }
INTN EFIAPI CompareMem (CONST VOID *A, CONST VOID *B, UINTN L) { return L ? memcmp (A, B, L) : 0; }

VOID *
EFIAPI
SetMem16 (VOID *B, UINTN L, UINT16 V)
{
  UINT16  *P = B;
  UINTN   I;

  for (I = 0; I < L / sizeof (UINT16); I++) {
    P[I] = V;
  }

  return B;
}

VOID *
EFIAPI
SetMem32 (VOID *B, UINTN L, UINT32 V)
{
  UINT32  *P = B;
  UINTN   I;

  for (I = 0; I < L / sizeof (UINT32); I++) {
    P[I] = V;
  }

  return B;
}

VOID *
EFIAPI
SetMem64 (VOID *B, UINTN L, UINT64 V)
{
  UINT64  *P = B;
  UINTN   I;

  for (I = 0; I < L / sizeof (UINT64); I++) {
    P[I] = V;
  }

  return B;
}

BOOLEAN
EFIAPI
CompareGuid (CONST GUID *A, CONST GUID *B)
{
  return memcmp (A, B, sizeof (GUID)) == 0;
}

GUID *EFIAPI CopyGuid (GUID *D, CONST GUID *S) { memmove (D, S, sizeof (GUID)); return D; }

BOOLEAN
EFIAPI
IsZeroGuid (CONST GUID *G)
{
  static CONST GUID  Z = { 0 };

  return memcmp (G, &Z, sizeof (GUID)) == 0;
}

/* ---------------- DebugLib (release build: everything disabled) ---------------- */
VOID EFIAPI DebugPrint (UINTN ErrorLevel, CONST CHAR8 *Format, ...) { }
VOID EFIAPI DebugAssert (CONST CHAR8 *FileName, UINTN LineNumber, CONST CHAR8 *Description) { abort (); }
BOOLEAN EFIAPI DebugAssertEnabled (VOID) { return FALSE; }
BOOLEAN EFIAPI DebugPrintEnabled (VOID) { return FALSE; }
BOOLEAN EFIAPI DebugCodeEnabled (VOID) { return FALSE; }
BOOLEAN EFIAPI DebugClearMemoryEnabled (VOID) { return FALSE; }
BOOLEAN EFIAPI DebugPrintLevelEnabled (CONST UINTN ErrorLevel) { return FALSE; }
VOID *EFIAPI DebugClearMemory (VOID *Buffer, UINTN Length) { return Buffer; }

/* ---------------- Boot services ---------------- */
#define SHIM_MAX_PROTOCOLS  16

typedef struct {
  EFI_HANDLE    Handle;
  EFI_GUID      Guid;
  VOID          *Interface;
} SHIM_PROTOCOL_ENTRY;

STATIC SHIM_PROTOCOL_ENTRY  mProtocols[SHIM_MAX_PROTOCOLS];
STATIC UINTN                mProtocolCount;

VOID
Edk2ShimResetProtocols (
  VOID
  )
{
  mProtocolCount = 0;
}

VOID
Edk2ShimRegisterProtocol (
  EFI_HANDLE      Handle,
  CONST EFI_GUID  *Guid,
  VOID            *Interface
  )
{
  if (mProtocolCount < SHIM_MAX_PROTOCOLS) {
    mProtocols[mProtocolCount].Handle    = Handle;
    mProtocols[mProtocolCount].Guid      = *Guid;
    mProtocols[mProtocolCount].Interface = Interface;
    mProtocolCount++;
  }
}

VOID *
Edk2ShimFindProtocol (
  EFI_HANDLE      Handle,
  CONST EFI_GUID  *Guid
  )
{
  UINTN  I;

  for (I = 0; I < mProtocolCount; I++) {
    if (((Handle == NULL) || (mProtocols[I].Handle == Handle)) && CompareGuid (&mProtocols[I].Guid, Guid)) {
      return mProtocols[I].Interface;
    }
  }

  return NULL;
}

STATIC
VOID
ShimRemoveProtocol (
  EFI_HANDLE      Handle,
  CONST EFI_GUID  *Guid
  )
{
  UINTN  I;

  for (I = 0; I < mProtocolCount; I++) {
    if ((mProtocols[I].Handle == Handle) && CompareGuid (&mProtocols[I].Guid, Guid)) {
      mProtocols[I] = mProtocols[--mProtocolCount];
      return;
    }
  }
}

STATIC
EFI_STATUS
EFIAPI
ShimOpenProtocol (
  EFI_HANDLE  Handle,
  EFI_GUID    *Protocol,
  VOID        **Interface,
  EFI_HANDLE  AgentHandle,
  EFI_HANDLE  ControllerHandle,
  UINT32      Attributes
  )
{
  VOID  *P = Edk2ShimFindProtocol (Handle, Protocol);

  if (Interface != NULL) {
    *Interface = P;
  }

  return P == NULL ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ShimCloseProtocol (
  EFI_HANDLE  Handle,
  EFI_GUID    *Protocol,
  EFI_HANDLE  AgentHandle,
  EFI_HANDLE  ControllerHandle
  )
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ShimHandleProtocol (
  EFI_HANDLE  Handle,
  EFI_GUID    *Protocol,
  VOID        **Interface
  )
{
  return ShimOpenProtocol (Handle, Protocol, Interface, NULL, NULL, 0);
}

STATIC
EFI_STATUS
EFIAPI
ShimLocateProtocol (
  EFI_GUID  *Protocol,
  VOID      *Registration,
  VOID      **Interface
  )
{
  return ShimOpenProtocol (NULL, Protocol, Interface, NULL, NULL, 0);
}

STATIC
EFI_STATUS
EFIAPI
ShimLocateHandleBuffer (
  EFI_LOCATE_SEARCH_TYPE  SearchType,
  EFI_GUID                *Protocol,
  VOID                    *SearchKey,
  UINTN                   *NoHandles,
  EFI_HANDLE              **Buffer
  )
{
  UINTN  I;
  UINTN  N = 0;

  *Buffer = AllocateZeroPool (SHIM_MAX_PROTOCOLS * sizeof (EFI_HANDLE));
  for (I = 0; I < mProtocolCount; I++) {
    if ((Protocol == NULL) || CompareGuid (&mProtocols[I].Guid, Protocol)) {
      (*Buffer)[N++] = mProtocols[I].Handle;
    }
  }

  *NoHandles = N;
  if (N == 0) {
    FreePool (*Buffer);
    *Buffer = NULL;
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ShimInstallList (
  EFI_HANDLE  *Handle,
  VA_LIST     Args,
  BOOLEAN     Install
  )
{
  EFI_GUID  *Guid;
  VOID      *Interface;

  if (Install && (*Handle == NULL)) {
    *Handle = (EFI_HANDLE)AllocateZeroPool (8);
  }

  for ( ; ;) {
    Guid = VA_ARG (Args, EFI_GUID *);
    if (Guid == NULL) {
      break;
    }

    Interface = VA_ARG (Args, VOID *);
    if (Install) {
      Edk2ShimRegisterProtocol (*Handle, Guid, Interface);
    } else {
      ShimRemoveProtocol (*Handle, Guid);
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ShimInstallMultipleProtocolInterfaces (
  EFI_HANDLE  *Handle,
  ...
  )
{
  VA_LIST     Args;
  EFI_STATUS  Status;

  VA_START (Args, Handle);
  Status = ShimInstallList (Handle, Args, TRUE);
  VA_END (Args);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
ShimUninstallMultipleProtocolInterfaces (
  EFI_HANDLE  Handle,
  ...
  )
{
  VA_LIST     Args;
  EFI_STATUS  Status;

  VA_START (Args, Handle);
  Status = ShimInstallList (&Handle, Args, FALSE);
  VA_END (Args);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
ShimAllocatePool (
  EFI_MEMORY_TYPE  PoolType,
  UINTN            Size,
  VOID             **Buffer
  )
{
  *Buffer = AllocatePool (Size);
  return *Buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ShimFreePool (
  VOID  *Buffer
  )
{
  FreePool (Buffer);
  return EFI_SUCCESS;
}

STATIC EFI_TPL EFIAPI ShimRaiseTpl (EFI_TPL NewTpl) { return TPL_APPLICATION; }
STATIC VOID EFIAPI ShimRestoreTpl (EFI_TPL OldTpl) { }

STATIC
EFI_STATUS
EFIAPI
ShimUnsupported (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

STATIC EFI_STATUS EFIAPI ShimStall (UINTN Microseconds) { return EFI_SUCCESS; }

STATIC
EFI_STATUS
EFIAPI
ShimCreateEvent (
  UINT32            Type,
  EFI_TPL           NotifyTpl,
  EFI_EVENT_NOTIFY  NotifyFunction,
  VOID              *NotifyContext,
  EFI_EVENT         *Event
  )
{
  return EFI_UNSUPPORTED;
}

STATIC EFI_STATUS EFIAPI ShimCloseEvent (EFI_EVENT Event) { return EFI_SUCCESS; }
STATIC EFI_STATUS EFIAPI ShimSignalEvent (EFI_EVENT Event) { return EFI_SUCCESS; }
STATIC EFI_STATUS EFIAPI ShimCheckEvent (EFI_EVENT Event) { return EFI_NOT_READY; }
STATIC EFI_STATUS EFIAPI ShimSetTimer (EFI_EVENT Event, EFI_TIMER_DELAY Type, UINT64 TriggerTime) { return EFI_SUCCESS; }

STATIC EFI_BOOT_SERVICES     mBootServices;
STATIC EFI_RUNTIME_SERVICES  mRuntimeServices;
STATIC EFI_SYSTEM_TABLE      mSystemTable;

EFI_BOOT_SERVICES     *gBS;
EFI_RUNTIME_SERVICES  *gRT;
EFI_SYSTEM_TABLE      *gST;
EFI_HANDLE            gImageHandle = (EFI_HANDLE)&mSystemTable;

VOID
Edk2ShimInit (
  VOID
  )
{
  VOID   **Slot;
  UINTN  I;

  if (gBS != NULL) {
    return;
  }

  /* Services not modelled below fail with EFI_UNSUPPORTED instead of jumping to
     NULL (UBSan's function-type check flags a call to one: model it instead). */
  Slot = (VOID **)((UINT8 *)&mBootServices + sizeof (EFI_TABLE_HEADER));
  for (I = 0; I < (sizeof (mBootServices) - sizeof (EFI_TABLE_HEADER)) / sizeof (VOID *); I++) {
    Slot[I] = (VOID *)ShimUnsupported;
  }

  Slot = (VOID **)((UINT8 *)&mRuntimeServices + sizeof (EFI_TABLE_HEADER));
  for (I = 0; I < (sizeof (mRuntimeServices) - sizeof (EFI_TABLE_HEADER)) / sizeof (VOID *); I++) {
    Slot[I] = (VOID *)ShimUnsupported;
  }

  mBootServices.OpenProtocol                        = ShimOpenProtocol;
  mBootServices.CloseProtocol                       = ShimCloseProtocol;
  mBootServices.HandleProtocol                      = ShimHandleProtocol;
  mBootServices.LocateProtocol                      = ShimLocateProtocol;
  mBootServices.LocateHandleBuffer                  = ShimLocateHandleBuffer;
  mBootServices.InstallMultipleProtocolInterfaces   = ShimInstallMultipleProtocolInterfaces;
  mBootServices.UninstallMultipleProtocolInterfaces = ShimUninstallMultipleProtocolInterfaces;
  mBootServices.AllocatePool                        = ShimAllocatePool;
  mBootServices.FreePool                            = ShimFreePool;
  mBootServices.RaiseTPL                            = ShimRaiseTpl;
  mBootServices.Stall                               = ShimStall;
  mBootServices.CreateEvent                         = ShimCreateEvent;
  mBootServices.CloseEvent                          = ShimCloseEvent;
  mBootServices.SignalEvent                         = ShimSignalEvent;
  mBootServices.CheckEvent                          = ShimCheckEvent;
  mBootServices.SetTimer                            = ShimSetTimer;
  mBootServices.RestoreTPL                          = ShimRestoreTpl;
  mSystemTable.BootServices                         = &mBootServices;
  mSystemTable.RuntimeServices                      = &mRuntimeServices;
  gBS                                               = &mBootServices;
  gRT                                               = &mRuntimeServices;
  gST                                               = &mSystemTable;
}

/* ---------------- UefiLib (the pieces the drivers call) ---------------- */

/* No NV variable store on the host: "PlatformLang" is unset, so drivers fall
   back to their PCD default, as they would on a fresh platform. */
EFI_STATUS
EFIAPI
GetEfiGlobalVariable2 (
  IN CONST CHAR16  *Name,
  OUT VOID         **Value,
  OUT UINTN        *Size OPTIONAL
  )
{
  *Value = NULL;
  if (Size != NULL) {
    *Size = 0;
  }

  return EFI_NOT_FOUND;
}

/* RFC 4646 matching reduced to "first supported language": the fake collation
   protocol advertises exactly one. */
CHAR8 *
EFIAPI
GetBestLanguage (
  IN CONST CHAR8  *SupportedLanguages,
  IN UINTN        Iso639Language,
  ...
  )
{
  if ((SupportedLanguages == NULL) || (*SupportedLanguages == '\0')) {
    return NULL;
  }

  return AllocateCopyPool (AsciiStrSize (SupportedLanguages), SupportedLanguages);
}

EFI_STATUS
EFIAPI
EfiLibInstallAllDriverProtocols2 (
  IN CONST EFI_HANDLE  ImageHandle,
  IN CONST EFI_SYSTEM_TABLE  *SystemTable,
  IN EFI_DRIVER_BINDING_PROTOCOL  *DriverBinding,
  IN EFI_HANDLE  DriverBindingHandle,
  ...
  )
{
  DriverBinding->ImageHandle         = ImageHandle;
  DriverBinding->DriverBindingHandle = DriverBindingHandle;
  return EFI_SUCCESS;
}

/* ---------------- Fake EFI_UNICODE_COLLATION2 (ASCII case folding) ---------------- */
STATIC CHAR16
Fold (
  CHAR16  C
  )
{
  return (C >= L'a' && C <= L'z') ? (CHAR16)(C - 32) : C;
}

STATIC
INTN
EFIAPI
ShimStriColl (
  EFI_UNICODE_COLLATION_PROTOCOL  *This,
  CHAR16                          *S1,
  CHAR16                          *S2
  )
{
  while (*S1 != 0 && Fold (*S1) == Fold (*S2)) {
    S1++;
    S2++;
  }

  return (INTN)Fold (*S1) - (INTN)Fold (*S2);
}

STATIC
VOID
EFIAPI
ShimStrLwr (
  EFI_UNICODE_COLLATION_PROTOCOL  *This,
  CHAR16                          *S
  )
{
  for ( ; *S != 0; S++) {
    if ((*S >= L'A') && (*S <= L'Z')) {
      *S = (CHAR16)(*S + 32);
    }
  }
}

STATIC
VOID
EFIAPI
ShimStrUpr (
  EFI_UNICODE_COLLATION_PROTOCOL  *This,
  CHAR16                          *S
  )
{
  for ( ; *S != 0; S++) {
    *S = Fold (*S);
  }
}

STATIC EFI_UNICODE_COLLATION_PROTOCOL  mCollation = {
  ShimStriColl, NULL, ShimStrLwr, ShimStrUpr, NULL, NULL, "en-US"
};
STATIC UINT8                           mCollationHandle;

VOID
Edk2ShimRegisterCollation (
  VOID
  )
{
  Edk2ShimRegisterProtocol ((EFI_HANDLE)&mCollationHandle, &gEfiUnicodeCollation2ProtocolGuid, &mCollation);
}

/* Component-name / unload paths are not exercised; keep them linkable. */
EFI_STATUS
EFIAPI
EfiTestManagedDevice (
  IN CONST EFI_HANDLE  ControllerHandle,
  IN CONST EFI_HANDLE  DriverBindingHandle,
  IN CONST EFI_GUID    *ProtocolGuid
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
LookupUnicodeString2 (
  IN CONST CHAR8  *Language,
  IN CONST CHAR8  *SupportedLanguages,
  IN CONST VOID   *UnicodeStringTable,
  OUT CHAR16      **UnicodeString,
  IN BOOLEAN      Iso639Language
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
EfiLibUninstallAllDriverProtocols2 (
  IN EFI_DRIVER_BINDING_PROTOCOL  *DriverBinding,
  ...
  )
{
  return EFI_SUCCESS;
}
