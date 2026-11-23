/** @file
  libFuzzer harness for Silicon/Intel/IntelSiliconPkg/Feature/VTd/IntelVTdCoreDxe:
  the ACPI DMAR table parse (DmarAcpiTable.c) and the PCI device inventory it
  builds per remapping unit (PciInfo.c).

  Input = an ACPI DMAR table followed by a fake PCI configuration space.
  The table is the first Header.Length bytes (an ACPI table is exactly
  Header.Length bytes long, ACPI 6.5 section 5.2.6), copied to an exact-size
  heap buffer and published as the platform's DMAR table, so the driver finds
  it through its own GetDmarAcpiTable() -> EfiLocateFirstAcpiTable(). The
  driver then runs ParseDmarAcpiTableDrhd() and ParseDmarAcpiTableRmrr() as
  in its SetupVtd() path.

  The trailing bytes model PCI config space for PciSegmentRead8/16/32: function
  number F (bus*256 + dev*8 + func) exists iff bit F of the trailing bytes is
  set, and its registers read from the trailing bytes too. VT-d MMIO reads 0.
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "DmaProtection.h"

UINTN                 mVtdUnitNumber;
VTD_UNIT_INFORMATION  *mVtdUnitInformation;

STATIC CONST UINT8  *mPci;
STATIC UINTN        mPciSize;

STATIC
UINT8
PciByte (
  UINTN  Address
  )
{
  UINTN  Function = (Address >> 12) & 0xFFFF;  /* bus:dev:func of PCI_SEGMENT_LIB_ADDRESS */
  UINTN  Offset   = Address & 0xFFF;

  if ((mPciSize == 0) || (Function / 8 >= mPciSize) || ((mPci[Function / 8] & (1 << (Function % 8))) == 0)) {
    return 0xFF;
  }

  return mPci[(Function * 31 + Offset) % mPciSize];
}

UINT8 EFIAPI PciSegmentRead8 (UINT64 Address) { return PciByte ((UINTN)Address); }
UINT16 EFIAPI PciSegmentRead16 (UINT64 Address) { return (UINT16)(PciByte ((UINTN)Address) | (PciByte ((UINTN)Address + 1) << 8)); }

UINT32
EFIAPI
PciSegmentRead32 (
  UINT64  Address
  )
{
  return (UINT32)PciSegmentRead16 (Address) | ((UINT32)PciSegmentRead16 (Address + 2) << 16);
}

UINT8 EFIAPI MmioRead8 (UINTN Address) { return 0; }
UINT16 EFIAPI MmioRead16 (UINTN Address) { return 0; }
UINT32 EFIAPI MmioRead32 (UINTN Address) { return 0; }
UINT64 EFIAPI MmioRead64 (UINTN Address) { return 0; }

UINT32 EFIAPI MmioWrite32 (UINTN Address, UINT32 Value) { return Value; }
UINT64 EFIAPI MmioWrite64 (UINTN Address, UINT64 Value) { return Value; }

/* RMRR regions are mapped into the second-level page tables (TranslationTable.c),
   which program VT-d hardware; out of scope here. */
EFI_STATUS
SetAccessAttribute (
  IN UINT16         Segment,
  IN VTD_SOURCE_ID  SourceId,
  IN UINT64         BaseAddress,
  IN UINT64         Length,
  IN UINT64         IoMmuAccess
  )
{
  return EFI_SUCCESS;
}

/* VTd event log: recording only, nothing parsed. */
VOID
VTdLogAddDataEvent (
  IN  CONST VTDLOG_EVENT_TYPE  EventType,
  IN  CONST UINT64             Param,
  IN  CONST VOID               *Data,
  IN  CONST UINT32             DataSize
  )
{
}

VOID
VTdLogAddEvent (
  IN CONST VTDLOG_EVENT_TYPE  EventType,
  IN CONST UINT64             Data1,
  IN CONST UINT64             Data2
  )
{
}

STATIC VOID  *mPublishedTable;

/* UefiLib: the configuration-table lookup the driver uses to find DMAR. */
EFI_ACPI_COMMON_HEADER *
EFIAPI
EfiLocateFirstAcpiTable (
  IN UINT32  Signature
  )
{
  if ((mPublishedTable != NULL) && (((EFI_ACPI_DESCRIPTION_HEADER *)mPublishedTable)->Signature == Signature)) {
    return (EFI_ACPI_COMMON_HEADER *)mPublishedTable;
  }

  return NULL;
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  UINT32  Length;
  UINTN   Index;

  if (Size < sizeof (EFI_ACPI_DMAR_HEADER)) {
    return -1;
  }

  CopyMem (&Length, Data + OFFSET_OF (EFI_ACPI_DESCRIPTION_HEADER, Length), sizeof (Length));
  if ((Length < sizeof (EFI_ACPI_DMAR_HEADER)) || (Length > Size)) {
    return -1;
  }

  Edk2ShimInit ();
  mPublishedTable     = AllocateCopyPool (Length, Data);
  mPci                = Data + Length;
  mPciSize            = Size - Length;
  mAcpiDmarTable      = NULL;
  mVtdUnitInformation = NULL;
  mVtdUnitNumber      = 0;
  if (mPublishedTable == NULL) {
    return 0;
  }

  if (!EFI_ERROR (GetDmarAcpiTable ())) {
    if (!EFI_ERROR (ParseDmarAcpiTableDrhd ())) {
      ParseDmarAcpiTableRmrr ();
    }
  }

  if (mVtdUnitInformation != NULL) {
    for (Index = 0; Index < mVtdUnitNumber; Index++) {
      if (mVtdUnitInformation[Index].PciDeviceInfo != NULL) {
        FreePool (mVtdUnitInformation[Index].PciDeviceInfo);
      }
    }

    FreePool (mVtdUnitInformation);
  }

  FreePool (mPublishedTable);
  mPublishedTable = NULL;
  mAcpiDmarTable  = NULL;
  return 0;
}
