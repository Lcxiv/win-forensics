# Driver classes for DPC and ISR time

The `xperf -a dpcisr` report names the driver image that ran each DPC or interrupt service routine (`storport.sys`, `ntoskrnl.exe`). The decoder gives every module of `dpcisr_module_cpu` a driver class and says how it decided, and sums the classes per CPU in `dpcisr_class_cpu` ([contracts/decoded-tables.md](contracts/decoded-tables.md) sections 5.1, 5.21 and 5.22). The classes are `gpu`, `network`, `usb`, `bluetooth`, `audio`, `storage`, `kernel`, `other` and `unclassified`. The code is `scripts/driver_classes.py`; this page and that file must agree, and `tests/test_driver_classes.py` checks that they do.

Map version 1.0.0. Any change to an entry below is a new map version, and every row records the version it was classed with.

## How a module gets its class

1. **The PC's own inventory** (`classification_source` `inventory`). When the decoder is given a decoded `driver-inventory` bundle of the same machine (`--inventory`), it looks the module's file name up, ignoring case, in that bundle's `driver_service_class` table. A row there is one driver service from Win32_SystemDriver, with the file name at the end of its `PathName` ("Fully qualified path to the service binary file that implements the service") and the device setup classes of the present Plug and Play devices whose Win32_PnPEntity `Service` ("Name of the service that supports this Plug and Play device") is that service. Microsoft documents the same pairing as the Win32_SystemDriverPNPEntity association; the collector joins on the service name instead because the association's references carry device instance paths. The setup classes give a driver class through the table below. This is the only way a vendor driver (a network adapter, graphics or audio vendor driver) is ever classed: the map never names a vendor binary.
2. **The inbox map** (`inbox-map`). When the inventory gives no class (no inventory, no service runs a file of that name, or the service's devices sit only in classes that say nothing), a Microsoft inbox binary listed below gets the class of its entry, and the row's `classification_reference` is the Learn page that names the binary and its role.
3. **Nothing** (`none`). Any other module is `unclassified`, with the reason in words.

The inventory wins over the map: it is what the machine itself says. When two services run files of the same name and their classes differ, the module is `unclassified` from the inventory, with both services named. A service whose present devices sit in setup classes of two different driver classes is `unclassified` for the same reason.

Pages: <https://learn.microsoft.com/windows/win32/cimwin32prov/win32-systemdriver>, <https://learn.microsoft.com/windows/win32/cimwin32prov/win32-pnpentity>, <https://learn.microsoft.com/windows/win32/cimwin32prov/win32-systemdriverpnpentity>.

## What the classes can and cannot say

- A class is a statement about which driver ran the routine, not about which device raised the work. Time in `ndis.sys` is network stack time; the adapter's own driver is separate.
- `Wdf01000.sys` (the KMDF framework library) is deliberately `unclassified`: its DPC objects run callbacks of client drivers of any class, so its time cannot be given to one class from the report.
- `unclassified` holds every module no rule names, so a class with no row in `dpcisr_class_cpu` is not a class that ran nothing: its time may sit in `unclassified`. No row is written for a class with no module.
- The Media setup class ("Audio and DVD multimedia devices, joystick ports, and full-motion video capture devices") maps to `audio`; a video capture driver in that class would be counted as audio. The setup class name stays in the inventory row so a reader can see it.
- System, SoftwareDevice, SoftwareComponent and Unknown say nothing about the driver class (System holds buses, bridges, the HAL and the High Definition Audio bus controller alike), so a service whose devices sit only there falls through to the map. A class GUID not in the table below says nothing either.
- The inventory is a snapshot taken when the `driver-inventory` collector ran, not when the trace ran. The `driver_inventory_join` check records the inventory bundle and when it was captured.
- That the module name in the report is the file name of the driver image, and that a module named like an inbox binary is the Microsoft one, are not documented by Microsoft; both are on the verification list in [collectors/windows/README.md](../collectors/windows/README.md).

## Inbox binaries

| File | Class | Learn page |
|---|---|---|
| `dxgkrnl.sys` | gpu | <https://learn.microsoft.com/windows-hardware/drivers/display/windows-vista-and-later-display-driver-model-architecture> |
| `dxgmms1.sys` | gpu | <https://learn.microsoft.com/windows-hardware/drivers/display/windows-vista-and-later-display-driver-model-architecture> |
| `dxgmms2.sys` | gpu | <https://learn.microsoft.com/windows-hardware/drivers/display/windows-vista-and-later-display-driver-model-architecture> |
| `basicdisplay.sys` | gpu | <https://learn.microsoft.com/windows-hardware/drivers/display/microsoft-basic-display-driver> |
| `ndis.sys` | network | <https://learn.microsoft.com/windows-hardware/drivers/network/linking-to-the-ndis-library> |
| `usbxhci.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture> |
| `ucx01000.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture> |
| `usbhub3.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture> |
| `usbport.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows> |
| `usbehci.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows> |
| `usbohci.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows> |
| `usbuhci.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows> |
| `usbhub.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows> |
| `usbccgp.sys` | usb | <https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-common-class-generic-parent-driver> |
| `bthport.sys` | bluetooth | <https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-profile-drivers-overview> |
| `bthenum.sys` | bluetooth | <https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-profile-drivers-overview> |
| `bthusb.sys` | bluetooth | <https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-profile-drivers-overview> |
| `portcls.sys` | audio | <https://learn.microsoft.com/windows-hardware/drivers/audio/introduction-to-port-class> |
| `hdaudbus.sys` | audio | <https://learn.microsoft.com/windows-hardware/drivers/audio/low-latency-audio> |
| `hdaudio.sys` | audio | <https://learn.microsoft.com/windows/win32/coreaudio/user-mode-audio-components> |
| `usbaudio.sys` | audio | <https://learn.microsoft.com/windows/win32/coreaudio/user-mode-audio-components> |
| `usbaudio2.sys` | audio | <https://learn.microsoft.com/windows-hardware/drivers/audio/usb-audio-not-playing> |
| `storport.sys` | storage | <https://learn.microsoft.com/windows-hardware/drivers/storage/storage-port-drivers> |
| `scsiport.sys` | storage | <https://learn.microsoft.com/windows-hardware/drivers/storage/storage-port-drivers> |
| `ataport.sys` | storage | <https://learn.microsoft.com/windows-hardware/drivers/storage/storage-port-drivers> |
| `stornvme.sys` | storage | <https://learn.microsoft.com/windows-hardware/drivers/storage/nvme-features-supported-by-stornvme> |
| `storahci.sys` | storage | <https://learn.microsoft.com/windows-server/storage/troubleshoot-firmware-update> |
| `ntoskrnl.exe` | kernel | <https://learn.microsoft.com/windows-hardware/drivers/kernel/windows-kernel-mode-executive-support-library> |
| `hal.dll` | kernel | <https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0x79--mismatched-hal> |
| `acpi.sys` | other | <https://learn.microsoft.com/windows-hardware/drivers/kernel/acpi-driver> |
| `wdf01000.sys` | unclassified | <https://learn.microsoft.com/windows-hardware/drivers/ddi/wdfdpc/nf-wdfdpc-wdfdpcgetparentobject> |

Left out on purpose: `tcpip.sys`, `netio.sys` and the NetAdapterCx library (Learn gives no page naming the binary and its role), `ks.sys` (kernel streaming serves audio and video alike), and `BthLEEnum` and `HidBth` (Learn names them as components without a file name). They fall to `none` unless the inventory names them.

## Device setup classes

The class names and GUIDs are Microsoft's system defined device setup classes. A class whose driver class is `none` here does not decide anything.

| Setup class | GUID | Driver class | Learn page |
|---|---|---|---|
| Display | `4d36e968-e325-11ce-bfc1-08002be10318` | gpu | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Net | `4d36e972-e325-11ce-bfc1-08002be10318` | network | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| NetClient | `4d36e973-e325-11ce-bfc1-08002be10318` | network | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| NetService | `4d36e974-e325-11ce-bfc1-08002be10318` | network | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| NetTrans | `4d36e975-e325-11ce-bfc1-08002be10318` | network | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| USB | `36fc9e60-c465-11cf-8056-444553540000` | usb | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use> |
| USBDevice | `88bae032-5a81-49f0-bc3d-a4ff138216d6` | usb | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| UCM | `e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53` | usb | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Bluetooth | `e0cbf06c-cd8b-4647-bb8a-263b43f0f974` | bluetooth | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Media | `4d36e96c-e325-11ce-bfc1-08002be10318` | audio | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| AudioProcessingObject | `5989fce8-9cd0-467d-8a6a-5419e31529d4` | audio | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| AudioEndpoint | `c166523c-fe0c-4a94-a586-f1a80cfbbf3e` | audio | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use> |
| CDROM | `4d36e965-e325-11ce-bfc1-08002be10318` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| DiskDrive | `4d36e967-e325-11ce-bfc1-08002be10318` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| HDC | `4d36e96a-e325-11ce-bfc1-08002be10318` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| SCSIAdapter | `4d36e97b-e325-11ce-bfc1-08002be10318` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| NvmeDisk | `75416e63-5912-4dfa-ae8f-3efaccaffb14` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Volume | `71a27cdd-812a-11d0-bec7-08002be2092f` | storage | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| HIDClass | `745a17a0-74d3-11d0-b6fe-00a0c90f57da` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Keyboard | `4d36e96b-e325-11ce-bfc1-08002be10318` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Mouse | `4d36e96f-e325-11ce-bfc1-08002be10318` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Monitor | `4d36e96e-e325-11ce-bfc1-08002be10318` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Processor | `50127dc3-0f36-415e-a6cc-4cb3be910b65` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Battery | `72631e54-78a4-11d0-bcf7-00aa00b7b32a` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Camera | `ca3e7ab9-b4c3-4ae6-8251-579ef933890f` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Image | `6bdd1fc6-810f-11d0-bec7-08002be2092f` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Ports | `4d36e978-e325-11ce-bfc1-08002be10318` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Securitydevices | `d94ee5d8-d189-4994-83d2-f68d7d41b0e6` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Sensor | `5175d334-c371-4806-b3ba-71fd53c9258d` | other | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| System | `4d36e97d-e325-11ce-bfc1-08002be10318` | none | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| SoftwareDevice | `62f9c741-b25a-46ce-b54c-9bccce08b6f2` | none | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use> |
| SoftwareComponent | `5c4c3332-344d-483c-8739-259e934c9cc8` | none | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors> |
| Unknown | `4d36e97e-e325-11ce-bfc1-08002be10318` | none | <https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use> |
