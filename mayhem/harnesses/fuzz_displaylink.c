/** @file
  libFuzzer harness for Drivers/DisplayLink/DisplayLinkPkg/DisplayLinkGop: the
  data a DisplayLink USB device hands the driver.

  Byte 0 selects the path:
    even: the rest is what the device returns for GET_OUTPUT_EDID. It is served
          through a fake EFI_USB_IO_PROTOCOL.UsbControlTransfer to DlReadEdid
          (the driver's own read + signature/checksum validation), then the
          active EDID is parsed the way the GOP QueryMode/SetMode paths do:
          DlEdidGetNumSupportedModesInEdid and
          DlEdidGetSupportedVideoModeWithFallback for every index.
    odd:  the rest is the vendor capability descriptor read during
          DriverBinding.Start, parsed by UsbDisplayLinkParseCapabilitiesDescriptor
          and checked by UsbDisplayLinkCapabilitiesSufficientToBind. It is an
          exact-size heap copy, so over-reads are caught.
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "UsbDisplayLink.h"
#include "UsbDescriptors.h"
#include "Edid.h"

STATIC CONST UINT8  *mCtrlData;
STATIC UINTN        mCtrlSize;

STATIC
EFI_STATUS
EFIAPI
FakeUsbControlTransfer (
  IN EFI_USB_IO_PROTOCOL         *This,
  IN EFI_USB_DEVICE_REQUEST      *Request,
  IN EFI_USB_DATA_DIRECTION      Direction,
  IN UINT32                      Timeout,
  IN OUT VOID                    *Data OPTIONAL,
  IN UINTN                       DataLength OPTIONAL,
  OUT UINT32                     *Status
  )
{
  *Status = 0;
  if ((Direction != EfiUsbDataIn) || (Data == NULL)) {
    return EFI_SUCCESS;
  }

  /* A device that sends a short reply leaves the transfer failed. */
  if (mCtrlSize < DataLength) {
    *Status = EFI_USB_ERR_TIMEOUT;
    return EFI_DEVICE_ERROR;
  }

  CopyMem (Data, mCtrlData, DataLength);
  return EFI_SUCCESS;
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  STATIC EFI_USB_IO_PROTOCOL  UsbIo;
  USB_DISPLAYLINK_DEV         *Dev;
  CONST struct VideoMode      *Mode;
  VendorDescriptor            Desc;
  UINT8                       *Copy;
  UINT32                      N;
  UINT32                      I;

  if (Size < 1) {
    return -1;
  }

  Edk2ShimInit ();
  Edk2ShimResetProtocols ();

  if ((Data[0] & 1) == 0) {
    mCtrlData                = Data + 1;
    mCtrlSize                = Size - 1;
    UsbIo.UsbControlTransfer = FakeUsbControlTransfer;
    Dev                      = AllocateZeroPool (sizeof (*Dev));
    if (Dev == NULL) {
      return 0;
    }

    Dev->UsbIo = &UsbIo;
    DlReadEdid (Dev);
    N = DlEdidGetNumSupportedModesInEdid (Dev->EdidActive.Edid, Dev->EdidActive.SizeOfEdid);
    for (I = 0; I <= N + 1; I++) {
      DlEdidGetSupportedVideoModeWithFallback (I, Dev->EdidActive.Edid, Dev->EdidActive.SizeOfEdid, &Mode);
    }

    if (Dev->EdidDiscovered.Edid != NULL) {
      FreePool (Dev->EdidDiscovered.Edid);
    }

    FreePool (Dev);
  } else {
    Copy = AllocateCopyPool (Size - 1, Data + 1);
    if (Copy == NULL) {
      return 0;
    }

    if (!EFI_ERROR (UsbDisplayLinkParseCapabilitiesDescriptor (Copy, Size - 1, &Desc))) {
      UsbDisplayLinkCapabilitiesSufficientToBind (&Desc);
    }

    FreePool (Copy);
  }

  return 0;
}
