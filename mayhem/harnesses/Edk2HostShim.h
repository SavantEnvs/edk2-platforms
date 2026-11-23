#ifndef EDK2_HOST_SHIM_H_
#define EDK2_HOST_SHIM_H_
#include <Uefi.h>

VOID  Edk2ShimInit (VOID);
VOID  Edk2ShimResetProtocols (VOID);
VOID  Edk2ShimRegisterProtocol (EFI_HANDLE Handle, CONST EFI_GUID *Guid, VOID *Interface);
VOID  *Edk2ShimFindProtocol (EFI_HANDLE Handle, CONST EFI_GUID *Guid);
VOID  Edk2ShimRegisterCollation (VOID);
#endif
