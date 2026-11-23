/** @file
  libFuzzer harness for Drivers/ASIX/Bus/Usb/UsbNetworking/Ax88772c: frames a
  USB Ethernet adapter delivers through EFI_SIMPLE_NETWORK_PROTOCOL.Receive.

  The NIC is brought up through the driver's own SN_Setup / Start /
  Initialize over a fake EFI_USB_IO_PROTOCOL whose control transfers succeed
  with zeroed register values. The link is then marked up and Receive is
  called repeatedly with large and small caller buffers. Every bulk-in
  transfer the driver issues (Ax88772BulkIn, which walks the per-packet
  length/~length headers) is served from the input:
  a sequence of chunks, each a 2-byte little-endian length followed by that
  many bytes (cut to what the driver asked for); once the input is used up the
  endpoint times out, as a quiet device does.
**/
#include "AutoGen.h"
#include "Edk2HostShim.h"
#include "Ax88772.h"
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

STATIC CONST UINT8  *mIn;
STATIC UINTN        mInSize;

STATIC
EFI_STATUS
EFIAPI
FakeControlTransfer (
  IN EFI_USB_IO_PROTOCOL     *This,
  IN EFI_USB_DEVICE_REQUEST  *Request,
  IN EFI_USB_DATA_DIRECTION  Direction,
  IN UINT32                  Timeout,
  IN OUT VOID                *Data OPTIONAL,
  IN UINTN                   DataLength OPTIONAL,
  OUT UINT32                 *Status
  )
{
  *Status = EFI_USB_NOERROR;
  if ((Direction == EfiUsbDataIn) && (Data != NULL)) {
    ZeroMem (Data, DataLength);
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
FakeBulkTransfer (
  IN EFI_USB_IO_PROTOCOL  *This,
  IN UINT8                DeviceEndpoint,
  IN OUT VOID             *Data,
  IN OUT UINTN            *DataLength,
  IN UINTN                Timeout,
  OUT UINT32              *Status
  )
{
  UINTN  Len;

  if ((DeviceEndpoint & USB_ENDPOINT_DIR_IN) == 0) {
    *Status = EFI_USB_NOERROR;
    return EFI_SUCCESS;
  }

  if (mInSize < 2) {
    *DataLength = 0;
    *Status     = EFI_USB_ERR_TIMEOUT;
    return EFI_TIMEOUT;
  }

  Len      = mIn[0] | ((UINTN)mIn[1] << 8);
  mIn     += 2;
  mInSize -= 2;
  if (Len > mInSize) {
    Len = mInSize;
  }

  if (Len > *DataLength) {
    Len = *DataLength;
  }

  CopyMem (Data, mIn, Len);
  mIn        += Len;
  mInSize    -= Len;
  *DataLength = Len;
  *Status     = EFI_USB_NOERROR;
  return EFI_SUCCESS;
}

/* The interrupt endpoint (link-change notifications) stays silent; the
   harness sets the link state itself. */
STATIC
EFI_STATUS
EFIAPI
FakeSyncInterruptTransfer (
  IN EFI_USB_IO_PROTOCOL  *This,
  IN UINT8                DeviceEndpoint,
  IN OUT VOID             *Data,
  IN OUT UINTN            *DataLength,
  IN UINTN                Timeout,
  OUT UINT32              *Status
  )
{
  *DataLength = 0;
  *Status     = EFI_USB_ERR_TIMEOUT;
  return EFI_TIMEOUT;
}

int
LLVMFuzzerTestOneInput (
  const UINT8  *Data,
  UINTN        Size
  )
{
  STATIC EFI_USB_IO_PROTOCOL   UsbIo;
  NIC_DEVICE                   *Nic;
  EFI_SIMPLE_NETWORK_PROTOCOL  *Snp;
  STATIC UINT8                 Frame[MAX_ETHERNET_PKT_SIZE + 64];
  EFI_MAC_ADDRESS              Src;
  EFI_MAC_ADDRESS              Dst;
  UINT16                       Protocol;
  UINTN                        HeaderSize;
  UINTN                        BufferSize;
  UINTN                        I;

  Edk2ShimInit ();
  UsbIo.UsbControlTransfer = FakeControlTransfer;
  UsbIo.UsbBulkTransfer    = FakeBulkTransfer;
  UsbIo.UsbSyncInterruptTransfer = FakeSyncInterruptTransfer;
  mIn                      = NULL;
  mInSize                  = 0;

  Nic = AllocateZeroPool (sizeof (*Nic));
  if (Nic == NULL) {
    return 0;
  }

  Nic->Signature = DEV_SIGNATURE;
  Nic->UsbIo     = &UsbIo;
  if (EFI_ERROR (SN_Setup (Nic))) {
    goto Done;
  }

  Snp = &Nic->SimpleNetwork;
  Snp->Start (Snp);
  Snp->Initialize (Snp, 0, 0);
  /* Link state comes from PHY interrupts the fake device never raises. */
  Snp->Mode->State   = EfiSimpleNetworkInitialized;
  Nic->LinkUp        = TRUE;
  Nic->Complete      = TRUE;
  Nic->PktCnt        = 0;

  mIn     = Data;
  mInSize = Size;
  for (I = 0; I < 64; I++) {
    HeaderSize = 0;
    BufferSize = (I % 4 == 3) ? 64 : sizeof (Frame);
    Snp->Receive (Snp, &HeaderSize, &BufferSize, Frame, &Src, &Dst, &Protocol);
    if ((mInSize < 2) && (Nic->PktCnt == 0)) {
      break;
    }
  }

Done:
  /* What DriverBinding.Stop frees: the two SN_Setup buffers. */
  if (Nic->BulkInbuf != NULL) {
    FreePool (Nic->BulkInbuf);
  }

  if (Nic->TxTest != NULL) {
    FreePool (Nic->TxTest);
  }

  FreePool (Nic);
  return 0;
}
