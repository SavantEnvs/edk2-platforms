/** @file
  libFuzzer harness for Features/Intel/OutOfBandManagement/IpmiFeaturePkg/
  IpmiRedirFru: the FRU inventory a BMC returns, turned into SMBIOS type 1/2/3
  strings.

  Input = the raw FRU EEPROM image. A fake BMC behind IpmiSubmitCommand
  answers Get Device ID (FRU inventory supported) and Read FRU Data from the
  image (honest offsets and counts, cut to the caller's response buffer).
  The driver's entry point InitializeSmRedirFruLayer runs once and registers
  its "after console ready" notify; each input then signals that notify
  (GenerateFruSmbiosType123DataNotified), which reads the common header and
  the product/board/chassis areas over the redirection protocol, extracts the
  strings (GetFruInfoArea/GetStringFromFru/FruStrLen) and updates fake SMBIOS
  type 1/2/3 records through EFI_SMBIOS_PROTOCOL.
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "IpmiRedirFru.h"
#include <IndustryStandard/IpmiNetFnApp.h>
#include <IndustryStandard/IpmiNetFnStorage.h>

EFI_GUID  gEfiIpmiFormatFruGuid                          = { 0x3531fdc6, 0xeae, 0x4cd2, { 0xb0, 0xa6, 0x5f, 0x48, 0xa0, 0xdf, 0xe3, 0x8 } };
EFI_GUID  gEfiSystemTypeFruGuid                          = { 0xaab16018, 0x679d, 0x4461, { 0xba, 0x20, 0xe7, 0xc, 0xf7, 0x86, 0x6a, 0x9b } };
EFI_GUID  gEfiRedirFruProtocolGuid                       = { 0x28638cfa, 0xea88, 0x456c, { 0x92, 0xa5, 0xf2, 0x49, 0xca, 0x48, 0x85, 0x35 } };
EFI_GUID  gBdsEventAfterConsoleReadyBeforeBootOptionGuid = { 0x8eb3d5dc, 0xf4e7, 0x4b57, { 0xa9, 0xe7, 0x27, 0x39, 0x10, 0xf2, 0x18, 0x9f } };
EFI_GUID  gEfiSmbiosProtocolGuid                         = EFI_SMBIOS_PROTOCOL_GUID;

EFI_STATUS
EFIAPI
InitializeSmRedirFruLayer (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

STATIC CONST UINT8  *mFru;
STATIC UINTN        mFruSize;

/* IpmiBaseLib: the fake BMC. */
EFI_STATUS
EFIAPI
IpmiSubmitCommand (
  IN UINT8    NetFunction,
  IN UINT8    Command,
  IN UINT8    *CommandData,
  IN UINT32   CommandDataSize,
  OUT UINT8   *ResponseData,
  OUT UINT32  *ResponseDataSize
  )
{
  IPMI_READ_FRU_DATA_REQUEST  *Req;
  UINTN                       Count;
  UINTN                       Cap;

  if ((NetFunction == IPMI_NETFN_APP) && (Command == IPMI_APP_GET_DEVICE_ID)) {
    IPMI_GET_DEVICE_ID_RESPONSE  Resp;

    ZeroMem (&Resp, sizeof (Resp));
    Resp.DeviceSupport.Bits.FruInventorySupport = 1;
    Count = MIN (*ResponseDataSize, sizeof (Resp));
    CopyMem (ResponseData, &Resp, Count);
    *ResponseDataSize = (UINT32)Count;
    return EFI_SUCCESS;
  }

  if ((NetFunction == IPMI_NETFN_STORAGE) && (Command == IPMI_STORAGE_READ_FRU_DATA) &&
      (CommandDataSize >= sizeof (IPMI_READ_FRU_DATA_REQUEST)) && (*ResponseDataSize >= 2))
  {
    Req   = (IPMI_READ_FRU_DATA_REQUEST *)CommandData;
    Count = Req->CountToRead;
    if (Req->InventoryOffset >= mFruSize) {
      Count = 0;
    } else if (Count > mFruSize - Req->InventoryOffset) {
      Count = mFruSize - Req->InventoryOffset;
    }

    Cap = *ResponseDataSize - 2;
    if (Count > Cap) {
      Count = Cap;
    }

    ResponseData[0] = 0;
    ResponseData[1] = (UINT8)Count;
    CopyMem (ResponseData + 2, mFru + Req->InventoryOffset, Count);
    *ResponseDataSize = (UINT32)(Count + 2);
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

VOID IoWrite8 (IN UINT64 Address, IN UINT8 Data) { }
UINT8 IoRead8 (IN UINT64 Address) { return 0xFF; }

/* ---- fake EFI_SMBIOS_PROTOCOL holding SMBIOS type 1, 2 and 3 records ---- */
#pragma pack(1)
typedef struct {
  SMBIOS_TABLE_TYPE1    T1;
  CHAR8                 S1[16];
  SMBIOS_TABLE_TYPE2    T2;
  CHAR8                 S2[16];
  SMBIOS_TABLE_TYPE3    T3;
  CHAR8                 S3[16];
} FAKE_SMBIOS;
#pragma pack()

STATIC FAKE_SMBIOS  mTables;

STATIC
EFI_STATUS
EFIAPI
FakeSmbiosGetNext (
  IN CONST EFI_SMBIOS_PROTOCOL  *This,
  IN OUT EFI_SMBIOS_HANDLE      *SmbiosHandle,
  IN EFI_SMBIOS_TYPE            *Type OPTIONAL,
  OUT EFI_SMBIOS_TABLE_HEADER   **Record,
  OUT EFI_HANDLE                *ProducerHandle OPTIONAL
  )
{
  EFI_SMBIOS_TABLE_HEADER  *All[3] = { &mTables.T1.Hdr, &mTables.T2.Hdr, &mTables.T3.Hdr };
  UINTN                    Start   = (*SmbiosHandle == SMBIOS_HANDLE_PI_RESERVED) ? 0 : (UINTN)*SmbiosHandle;
  UINTN                    I;

  for (I = Start; I < 3; I++) {
    if ((Type == NULL) || (All[I]->Type == *Type)) {
      *SmbiosHandle = (EFI_SMBIOS_HANDLE)(I + 1);
      *Record       = All[I];
      return EFI_SUCCESS;
    }
  }

  *SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
FakeSmbiosUpdateString (
  IN CONST EFI_SMBIOS_PROTOCOL  *This,
  IN EFI_SMBIOS_HANDLE          *SmbiosHandle,
  IN UINTN                      *StringNumber,
  IN CHAR8                      *String
  )
{
  /* The real protocol copies the string into a resized record; read all of it. */
  return (AsciiStrLen (String) > SMBIOS_STRING_MAX_LENGTH) ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

STATIC EFI_SMBIOS_PROTOCOL  mSmbios;
STATIC EFI_EVENT_NOTIFY     mNotify;

STATIC
EFI_STATUS
EFIAPI
CaptureCreateEventEx (
  IN UINT32            Type,
  IN EFI_TPL           NotifyTpl,
  IN EFI_EVENT_NOTIFY  NotifyFunction OPTIONAL,
  IN CONST VOID        *NotifyContext OPTIONAL,
  IN CONST EFI_GUID    *EventGroup OPTIONAL,
  OUT EFI_EVENT        *Event
  )
{
  mNotify = NotifyFunction;
  *Event  = (EFI_EVENT)&mNotify;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
FakeInstallProtocolInterface (
  IN OUT EFI_HANDLE      *Handle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  )
{
  return EFI_SUCCESS;
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  STATIC BOOLEAN  Loaded;

  if (!Loaded) {
    Edk2ShimInit ();
    gBS->CreateEventEx            = CaptureCreateEventEx;
    gBS->InstallProtocolInterface = FakeInstallProtocolInterface;
    mSmbios.GetNext               = FakeSmbiosGetNext;
    mSmbios.UpdateString          = FakeSmbiosUpdateString;
    mFru                          = NULL;
    mFruSize                      = 0;
    InitializeSmRedirFruLayer (gImageHandle, gST);
    Loaded = TRUE;
  }

  if (mNotify == NULL) {
    return 0;
  }

  /* Fresh SMBIOS records per input (the notify writes the chassis type into type 3). */
  ZeroMem (&mTables, sizeof (mTables));
  mTables.T1.Hdr.Type   = EFI_SMBIOS_TYPE_SYSTEM_INFORMATION;
  mTables.T1.Hdr.Length = sizeof (SMBIOS_TABLE_TYPE1);
  mTables.T2.Hdr.Type   = EFI_SMBIOS_TYPE_BASEBOARD_INFORMATION;
  mTables.T2.Hdr.Length = sizeof (SMBIOS_TABLE_TYPE2);
  mTables.T3.Hdr.Type   = EFI_SMBIOS_TYPE_SYSTEM_ENCLOSURE;
  mTables.T3.Hdr.Length = sizeof (SMBIOS_TABLE_TYPE3);

  Edk2ShimResetProtocols ();
  Edk2ShimRegisterProtocol ((EFI_HANDLE)&mSmbios, &gEfiSmbiosProtocolGuid, &mSmbios);
  mFru     = Data;
  mFruSize = Size;
  mNotify ((EFI_EVENT)&mNotify, NULL);
  return 0;
}
