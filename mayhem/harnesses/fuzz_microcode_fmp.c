/** @file
  libFuzzer harness for Silicon/Intel/IntelSiliconPkg/Feature/Capsule/MicrocodeUpdateDxe:
  the microcode Firmware Management Protocol that a capsule update drives
  (EFI_FIRMWARE_MANAGEMENT_PROTOCOL.SetImage -> MicrocodeWrite -> VerifyMicrocode ->
  UpdateMicrocodeFlashRegion), plus GetImageInfo/GetImage on the result.

  The driver is started through its own entry point MicrocodeFmpMain(), which parses
  the microcode flash region (GetMicrocodeInfo), collects processor info through
  EFI_MP_SERVICES_PROTOCOL and installs the FMP instance; the harness captures that
  instance and calls Fmp->SetImage() with the capsule payload.

  Input layout:
    byte 0       flags: bit0 = fix up each capsule's header checksum (so the fuzzer gets
                 past CalculateSum32), bit1 = two processors instead of one,
                 bits 2-4 = platform ID reported by MSR_IA32_PLATFORM_ID,
                 bit5 = factory flash also holds a microcode for another CPU
    then up to 4 capsule payloads: the first three each as [little-endian UINT16 length N]
    [N bytes] (N clamped to what is left), the fourth as the rest of the input.
  The 32 KB microcode flash region starts as a factory image the harness builds (the
  driver exposes one FMP image per microcode already in flash, so an empty region has
  nothing to update): one well-formed 1 KB microcode, revision 1, for this CPU — plus,
  with flags bit5, a second one for another CPU — and 0xFF after it. From then on it
  only holds what the driver itself wrote: record k is applied with Fmp->SetImage() and the driver is then
  restarted (as after the reset an update requires) before record k+1, so later updates
  exercise the in-situ replace / reorg / append paths over earlier ones.

  Host model: CPUID(1).EAX = 0x000906EA; MSR_IA32_BIOS_SIGN_ID reports the revision of
  the last microcode loaded through MSR_IA32_BIOS_UPDT_TRIG (the header right before the
  trigger address), so a well-formed update "loads". MicrocodeFlashWrite() copies to the
  target address like a memory-mapped flash write, so an out-of-region write is an ASan
  report. No FIT (the FIT pointer slot reads 0).
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "MicrocodeUpdate.h"

#define REGION_SIZE        0x8000
#define HOST_CPU_SIGNATURE 0x000906EAU

EFI_GUID  gEfiMpServiceProtocolGuid          = EFI_MP_SERVICES_PROTOCOL_GUID;
EFI_GUID  gEfiFirmwareManagementProtocolGuid = EFI_FIRMWARE_MANAGEMENT_PROTOCOL_GUID;
EFI_GUID  gMicrocodeFmpImageTypeIdGuid       = MICROCODE_FMP_IMAGE_TYPE_ID_GUID;

UINT8   *mMayhemMicrocodeRegion;
UINT64  mMayhemFitPointer;

extern MICROCODE_FMP_PRIVATE_DATA  *mMicrocodeFmpPrivate;
EFI_STATUS EFIAPI MicrocodeFmpMain (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable);

STATIC UINT32                            mLoadedRevision;
STATIC UINT8                             mPlatformId;
STATIC UINTN                             mCpuCount;
STATIC EFI_FIRMWARE_MANAGEMENT_PROTOCOL  *mFmp;

/* ---- CPU model (BaseLib's x86 intrinsics are assembly; not built for the host) ---- */

UINT32
EFIAPI
AsmCpuid (
  IN  UINT32  Index,
  OUT UINT32  *RegisterEax OPTIONAL,
  OUT UINT32  *RegisterEbx OPTIONAL,
  OUT UINT32  *RegisterEcx OPTIONAL,
  OUT UINT32  *RegisterEdx OPTIONAL
  )
{
  if (RegisterEax != NULL) {
    *RegisterEax = (Index == CPUID_VERSION_INFO) ? HOST_CPU_SIGNATURE : 0;
  }
  if (RegisterEbx != NULL) {
    *RegisterEbx = 0;
  }
  if (RegisterEcx != NULL) {
    *RegisterEcx = 0;
  }
  if (RegisterEdx != NULL) {
    *RegisterEdx = 0;
  }
  return Index;
}

UINT64
EFIAPI
AsmReadMsr64 (
  IN UINT32  Index
  )
{
  if (Index == MSR_IA32_BIOS_SIGN_ID) {
    return LShiftU64 (mLoadedRevision, 32);
  }
  if (Index == MSR_IA32_PLATFORM_ID) {
    return LShiftU64 (mPlatformId, 50);
  }
  return 0;
}

UINT64
EFIAPI
AsmWriteMsr64 (
  IN UINT32  Index,
  IN UINT64  Value
  )
{
  if ((Index == MSR_IA32_BIOS_UPDT_TRIG) && (Value >= sizeof (CPU_MICROCODE_HEADER))) {
    mLoadedRevision = ((CPU_MICROCODE_HEADER *)(UINTN)(Value - sizeof (CPU_MICROCODE_HEADER)))->UpdateRevision;
  }
  return Value;
}

UINT64
EFIAPI
AsmMsrBitFieldRead64 (
  IN UINT32  Index,
  IN UINTN   StartBit,
  IN UINTN   EndBit
  )
{
  return BitFieldRead64 (AsmReadMsr64 (Index), StartBit, EndBit);
}

/* MicrocodeFlashAccessLib: a memory-mapped flash write. */
EFI_STATUS
EFIAPI
MicrocodeFlashWrite (
  IN EFI_PHYSICAL_ADDRESS  FlashAddress,
  IN VOID                  *Buffer,
  IN UINTN                 Length
  )
{
  CopyMem ((VOID *)(UINTN)FlashAddress, Buffer, Length);
  return EFI_SUCCESS;
}

/* ---- EFI_MP_SERVICES_PROTOCOL: APs run the procedure inline ---- */

STATIC
EFI_STATUS
EFIAPI
MpGetNumberOfProcessors (
  IN  EFI_MP_SERVICES_PROTOCOL  *This,
  OUT UINTN                     *NumberOfProcessors,
  OUT UINTN                     *NumberOfEnabledProcessors
  )
{
  *NumberOfProcessors        = mCpuCount;
  *NumberOfEnabledProcessors = mCpuCount;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MpWhoAmI (
  IN  EFI_MP_SERVICES_PROTOCOL  *This,
  OUT UINTN                     *ProcessorNumber
  )
{
  *ProcessorNumber = 0;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MpStartupThisAP (
  IN  EFI_MP_SERVICES_PROTOCOL  *This,
  IN  EFI_AP_PROCEDURE          Procedure,
  IN  UINTN                     ProcessorNumber,
  IN  EFI_EVENT                 WaitEvent OPTIONAL,
  IN  UINTN                     TimeoutInMicroseconds,
  IN  VOID                      *ProcedureArgument OPTIONAL,
  OUT BOOLEAN                   *Finished OPTIONAL
  )
{
  if ((ProcessorNumber == 0) || (ProcessorNumber >= mCpuCount)) {
    return EFI_NOT_FOUND;
  }
  Procedure (ProcedureArgument);
  if (Finished != NULL) {
    *Finished = TRUE;
  }
  return EFI_SUCCESS;
}

STATIC EFI_MP_SERVICES_PROTOCOL  mMpServices;

/* ---- Boot/runtime services the driver uses beyond the shared shim ---- */

STATIC
EFI_STATUS
EFIAPI
CaptureInstallProtocolInterface (
  IN OUT EFI_HANDLE      *Handle,
  IN     EFI_GUID        *Protocol,
  IN     EFI_INTERFACE_TYPE  InterfaceType,
  IN     VOID            *Interface
  )
{
  if (CompareGuid (Protocol, &gEfiFirmwareManagementProtocolGuid)) {
    mFmp = Interface;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
NoGetVariable (
  IN     CHAR16    *VariableName,
  IN     EFI_GUID  *VendorGuid,
  OUT    UINT32    *Attributes OPTIONAL,
  IN OUT UINTN     *DataSize,
  OUT    VOID      *Data OPTIONAL
  )
{
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
NoSetVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID      *Data
  )
{
  return EFI_SUCCESS;
}

STATIC
VOID
FixupChecksum (
  UINT8  *Image,
  UINTN  Size
  )
{
  CPU_MICROCODE_HEADER  *Header = (CPU_MICROCODE_HEADER *)Image;
  UINTN                 DataSize;
  UINTN                 Length;

  DataSize = (Header->DataSize == 0) ? (2048 - sizeof (CPU_MICROCODE_HEADER)) : Header->DataSize;
  if ((DataSize & 3) != 0) {
    return;
  }
  Length = DataSize + sizeof (CPU_MICROCODE_HEADER);
  if ((Length < DataSize) || (Length > Size)) {
    return;
  }
  Header->Checksum = 0;
  Header->Checksum = (UINT32)(0U - CalculateSum32 ((UINT32 *)Image, Length));
}

/* UpdateMicrocodeFlashRegion() allocates a region-sized scratch buffer per update and never
   frees it (harmless once per boot in firmware). The harness is linked with
   -Wl,--wrap=AllocateZeroPool so it can release those after each capsule; otherwise every
   iteration keeps 32 KB and libFuzzer runs out of memory. */
#define MAX_SCRATCH  8
STATIC VOID   *mScratch[MAX_SCRATCH];
STATIC UINTN  mScratchCount;

VOID *EFIAPI __real_AllocateZeroPool (UINTN AllocationSize);

VOID *
EFIAPI
__wrap_AllocateZeroPool (
  UINTN  AllocationSize
  )
{
  VOID  *Buffer = __real_AllocateZeroPool (AllocationSize);

  if ((Buffer != NULL) && (AllocationSize == REGION_SIZE) && (mScratchCount < MAX_SCRATCH)) {
    mScratch[mScratchCount++] = Buffer;
  }
  return Buffer;
}

/* A well-formed microcode (header + DataSize bytes of payload, checksum 0) at Entry. */
STATIC
VOID
WriteFactoryMicrocode (
  UINT8   *Entry,
  UINT32  Signature,
  UINT32  Revision
  )
{
  CPU_MICROCODE_HEADER  *Header = (CPU_MICROCODE_HEADER *)Entry;
  UINTN                 Index;

  ZeroMem (Header, sizeof (*Header));
  Header->HeaderVersion            = 1;
  Header->UpdateRevision           = Revision;
  Header->ProcessorSignature.Uint32 = Signature;
  Header->LoaderRevision           = 1;
  Header->ProcessorFlags           = 0xFF;
  Header->DataSize                 = SIZE_1KB - sizeof (CPU_MICROCODE_HEADER);
  Header->TotalSize                = SIZE_1KB;
  for (Index = sizeof (*Header); Index < SIZE_1KB; Index++) {
    Entry[Index] = (UINT8)(Index * 7);
  }
  FixupChecksum (Entry, SIZE_1KB);
}

STATIC
VOID
ReleaseDriver (
  VOID
  )
{
  if (mMicrocodeFmpPrivate == NULL) {
    return;
  }
  if (mMicrocodeFmpPrivate->ImageDescriptor != NULL) {
    FreePool (mMicrocodeFmpPrivate->ImageDescriptor);
  }
  if (mMicrocodeFmpPrivate->MicrocodeInfo != NULL) {
    FreePool (mMicrocodeFmpPrivate->MicrocodeInfo);
  }
  if (mMicrocodeFmpPrivate->ProcessorInfo != NULL) {
    FreePool (mMicrocodeFmpPrivate->ProcessorInfo);
  }
  if (mMicrocodeFmpPrivate->FitMicrocodeInfo != NULL) {
    FreePool (mMicrocodeFmpPrivate->FitMicrocodeInfo);
  }
  FreePool (mMicrocodeFmpPrivate);
  mMicrocodeFmpPrivate = NULL;
  mFmp                 = NULL;
}

/* Starts the driver (MicrocodeFmpMain), applies one capsule through SetImage and reads the
   resulting image info back, as the capsule-update flow and a later ESRT refresh would. */
STATIC
VOID
ApplyCapsule (
  CONST UINT8  *Data,
  UINTN        ImageSize,
  BOOLEAN      FixChecksum
  )
{
  UINT8                          *Image;
  CHAR16                         *AbortReason;
  UINTN                          InfoSize;
  UINT32                         DescriptorVersion;
  UINT8                          DescriptorCount;
  UINTN                          DescriptorSize;
  UINT32                         PackageVersion;
  CHAR16                         *PackageVersionName;
  EFI_FIRMWARE_IMAGE_DESCRIPTOR  *Info;

  /* VerifyMicrocode reads the fixed header before any size check; the capsule layer hands
     SetImage at least a header, so shorter payloads are not fed. */
  if (ImageSize < sizeof (CPU_MICROCODE_HEADER)) {
    return;
  }
  Image = AllocateCopyPool (ImageSize, Data);
  if (Image == NULL) {
    return;
  }
  if (FixChecksum) {
    FixupChecksum (Image, ImageSize);
  }

  mLoadedRevision = 0;
  if (!EFI_ERROR (MicrocodeFmpMain (gImageHandle, gST)) && (mFmp != NULL)) {
    AbortReason = NULL;
    mFmp->SetImage (mFmp, 1, Image, ImageSize, NULL, NULL, &AbortReason);
    if (AbortReason != NULL) {
      FreePool (AbortReason);
    }

    InfoSize = 0;
    if (mFmp->GetImageInfo (mFmp, &InfoSize, NULL, &DescriptorVersion, &DescriptorCount, &DescriptorSize, &PackageVersion, &PackageVersionName) == EFI_BUFFER_TOO_SMALL) {
      Info = AllocatePool (InfoSize);
      if (Info != NULL) {
        PackageVersionName = NULL;
        mFmp->GetImageInfo (mFmp, &InfoSize, Info, &DescriptorVersion, &DescriptorCount, &DescriptorSize, &PackageVersion, &PackageVersionName);
        if (PackageVersionName != NULL) {
          FreePool (PackageVersionName);   /* caller-owned per the UEFI spec */
        }
        FreePool (Info);
      }
    }
  }

  ReleaseDriver ();
  FreePool (Image);
  while (mScratchCount > 0) {
    FreePool (mScratch[--mScratchCount]);
  }
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  UINT8  Flags;
  UINTN  Record;
  UINTN  Length;

  if (Size < 1) {
    return -1;
  }
  Flags = Data[0];
  Data++;
  Size--;

  Edk2ShimInit ();
  Edk2ShimResetProtocols ();
  gBS->InstallProtocolInterface = CaptureInstallProtocolInterface;
  gRT->GetVariable              = NoGetVariable;
  gRT->SetVariable              = NoSetVariable;

  mMpServices.GetNumberOfProcessors = MpGetNumberOfProcessors;
  mMpServices.WhoAmI                = MpWhoAmI;
  mMpServices.StartupThisAP         = MpStartupThisAP;
  Edk2ShimRegisterProtocol (NULL, &gEfiMpServiceProtocolGuid, &mMpServices);

  mCpuCount         = (Flags & 2) ? 2 : 1;
  mPlatformId       = (Flags >> 2) & 7;
  mMayhemFitPointer = 0;
  mFmp              = NULL;

  mMayhemMicrocodeRegion = AllocatePool (REGION_SIZE);
  if (mMayhemMicrocodeRegion == NULL) {
    return 0;
  }
  SetMem (mMayhemMicrocodeRegion, REGION_SIZE, 0xFF);
  WriteFactoryMicrocode (mMayhemMicrocodeRegion, HOST_CPU_SIGNATURE, 1);
  if (Flags & 0x20) {
    WriteFactoryMicrocode (mMayhemMicrocodeRegion + SIZE_1KB, 0x000806ECU, 1);
  }

  for (Record = 0; (Record < 4) && (Size > 0); Record++) {
    Length = Size;
    if ((Record < 3) && (Size >= 2)) {
      Length = Data[0] | ((UINTN)Data[1] << 8);
      Data  += 2;
      Size  -= 2;
      if (Length > Size) {
        Length = Size;
      }
    }
    ApplyCapsule (Data, Length, (Flags & 1) != 0);
    Data += Length;
    Size -= Length;
  }

  FreePool (mMayhemMicrocodeRegion);
  mMayhemMicrocodeRegion = NULL;
  return 0;
}
