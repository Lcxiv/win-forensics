"""Driver classes for the modules of a DPC and ISR report.

A module row of ``dpcisr_module_cpu`` names a driver image (``storport.sys``).
This module gives it one of the driver classes below and says how:

* ``inventory``: the PC's own driver inventory (the ``driver_service_class``
  table, decoded by ``scripts/decode_driver_inventory.py`` from the
  ``driver-inventory`` collector) names a driver service whose binary has this
  file name and whose present Plug and Play devices sit in device setup
  classes that map to one driver class (``SETUP_CLASSES`` below). This is the
  first choice, and the only way a vendor driver is ever classed.
* ``inbox-map``: the file name is one of the Microsoft inbox binaries in
  ``INBOX_MAP`` (or ``INBOX_UNCLASSIFIED``), each with the Microsoft Learn page
  that says what it is.
* ``none``: neither applies; the class is ``unclassified``.

Both maps are versioned together by ``MAP_VERSION``: any change to an entry is
a new version, and the decoders record the version they used. docs/driver-classes.md
explains the rules and lists every entry with its citation; tests/test_driver_classes.py
checks that the document and these maps agree.
"""
from __future__ import annotations

from typing import Any

MAP_VERSION = "1.0.0"

DRIVER_CLASSES = ("gpu", "network", "usb", "bluetooth", "audio", "storage", "kernel", "other", "unclassified")
SOURCES = ("inventory", "inbox-map", "none")

DOC_WDDM = "https://learn.microsoft.com/windows-hardware/drivers/display/windows-vista-and-later-display-driver-model-architecture"
DOC_BASIC_DISPLAY = "https://learn.microsoft.com/windows-hardware/drivers/display/microsoft-basic-display-driver"
DOC_NDIS = "https://learn.microsoft.com/windows-hardware/drivers/network/linking-to-the-ndis-library"
DOC_USB3_STACK = "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture"
DOC_USB_ETW = "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-event-tracing-for-windows"
DOC_USBCCGP = "https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-common-class-generic-parent-driver"
DOC_BLUETOOTH = "https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-profile-drivers-overview"
DOC_PORTCLS = "https://learn.microsoft.com/windows-hardware/drivers/audio/introduction-to-port-class"
DOC_LOW_LATENCY_AUDIO = "https://learn.microsoft.com/windows-hardware/drivers/audio/low-latency-audio"
DOC_AUDIO_COMPONENTS = "https://learn.microsoft.com/windows/win32/coreaudio/user-mode-audio-components"
DOC_USBAUDIO2 = "https://learn.microsoft.com/windows-hardware/drivers/audio/usb-audio-not-playing"
DOC_STORAGE_PORTS = "https://learn.microsoft.com/windows-hardware/drivers/storage/storage-port-drivers"
DOC_STORNVME = "https://learn.microsoft.com/windows-hardware/drivers/storage/nvme-features-supported-by-stornvme"
DOC_STORAHCI = "https://learn.microsoft.com/windows-server/storage/troubleshoot-firmware-update"
DOC_NTOSKRNL = "https://learn.microsoft.com/windows-hardware/drivers/kernel/windows-kernel-mode-executive-support-library"
DOC_HAL = "https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0x79--mismatched-hal"
DOC_ACPI = "https://learn.microsoft.com/windows-hardware/drivers/kernel/acpi-driver"
DOC_WDFDPC = "https://learn.microsoft.com/windows-hardware/drivers/ddi/wdfdpc/nf-wdfdpc-wdfdpcgetparentobject"
DOC_SETUP_CLASSES = "https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors"
DOC_SETUP_CLASSES_RESERVED = "https://learn.microsoft.com/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use"

# Microsoft inbox binaries by lower case file name: (driver class, Learn page that names the binary and its role).
INBOX_MAP: dict[str, tuple[str, str]] = {
    "dxgkrnl.sys": ("gpu", DOC_WDDM),
    "dxgmms1.sys": ("gpu", DOC_WDDM),
    "dxgmms2.sys": ("gpu", DOC_WDDM),
    "basicdisplay.sys": ("gpu", DOC_BASIC_DISPLAY),
    "ndis.sys": ("network", DOC_NDIS),
    "usbxhci.sys": ("usb", DOC_USB3_STACK),
    "ucx01000.sys": ("usb", DOC_USB3_STACK),
    "usbhub3.sys": ("usb", DOC_USB3_STACK),
    "usbport.sys": ("usb", DOC_USB_ETW),
    "usbehci.sys": ("usb", DOC_USB_ETW),
    "usbohci.sys": ("usb", DOC_USB_ETW),
    "usbuhci.sys": ("usb", DOC_USB_ETW),
    "usbhub.sys": ("usb", DOC_USB_ETW),
    "usbccgp.sys": ("usb", DOC_USBCCGP),
    "bthport.sys": ("bluetooth", DOC_BLUETOOTH),
    "bthenum.sys": ("bluetooth", DOC_BLUETOOTH),
    "bthusb.sys": ("bluetooth", DOC_BLUETOOTH),
    "portcls.sys": ("audio", DOC_PORTCLS),
    "hdaudbus.sys": ("audio", DOC_LOW_LATENCY_AUDIO),
    "hdaudio.sys": ("audio", DOC_AUDIO_COMPONENTS),
    "usbaudio.sys": ("audio", DOC_AUDIO_COMPONENTS),
    "usbaudio2.sys": ("audio", DOC_USBAUDIO2),
    "storport.sys": ("storage", DOC_STORAGE_PORTS),
    "scsiport.sys": ("storage", DOC_STORAGE_PORTS),
    "ataport.sys": ("storage", DOC_STORAGE_PORTS),
    "stornvme.sys": ("storage", DOC_STORNVME),
    "storahci.sys": ("storage", DOC_STORAHCI),
    "ntoskrnl.exe": ("kernel", DOC_NTOSKRNL),
    "hal.dll": ("kernel", DOC_HAL),
    "acpi.sys": ("other", DOC_ACPI),
}

# Inbox binaries that are deliberately left unclassified, with the reason and the page it rests on.
INBOX_UNCLASSIFIED: dict[str, tuple[str, str]] = {
    "wdf01000.sys": ("the KMDF framework library: its DPC objects run callbacks of client drivers of any class, so its time cannot be given to one class",
                     DOC_WDFDPC),
}

# Device setup classes by lower case GUID without braces: (class name, driver class or None, Learn page).
# None marks a class that does not say which driver class a device belongs to (System holds buses, bridges,
# the HAL and the High Definition Audio bus controller alike), so the inventory gives no class through it.
SETUP_CLASSES: dict[str, tuple[str, str | None, str]] = {
    "4d36e968-e325-11ce-bfc1-08002be10318": ("Display", "gpu", DOC_SETUP_CLASSES),
    "4d36e972-e325-11ce-bfc1-08002be10318": ("Net", "network", DOC_SETUP_CLASSES),
    "4d36e973-e325-11ce-bfc1-08002be10318": ("NetClient", "network", DOC_SETUP_CLASSES),
    "4d36e974-e325-11ce-bfc1-08002be10318": ("NetService", "network", DOC_SETUP_CLASSES),
    "4d36e975-e325-11ce-bfc1-08002be10318": ("NetTrans", "network", DOC_SETUP_CLASSES),
    "36fc9e60-c465-11cf-8056-444553540000": ("USB", "usb", DOC_SETUP_CLASSES_RESERVED),
    "88bae032-5a81-49f0-bc3d-a4ff138216d6": ("USBDevice", "usb", DOC_SETUP_CLASSES),
    "e6f1aa1c-7f3b-4473-b2e8-c97d8ac71d53": ("UCM", "usb", DOC_SETUP_CLASSES),
    "e0cbf06c-cd8b-4647-bb8a-263b43f0f974": ("Bluetooth", "bluetooth", DOC_SETUP_CLASSES),
    "4d36e96c-e325-11ce-bfc1-08002be10318": ("Media", "audio", DOC_SETUP_CLASSES),
    "5989fce8-9cd0-467d-8a6a-5419e31529d4": ("AudioProcessingObject", "audio", DOC_SETUP_CLASSES),
    "c166523c-fe0c-4a94-a586-f1a80cfbbf3e": ("AudioEndpoint", "audio", DOC_SETUP_CLASSES_RESERVED),
    "4d36e965-e325-11ce-bfc1-08002be10318": ("CDROM", "storage", DOC_SETUP_CLASSES),
    "4d36e967-e325-11ce-bfc1-08002be10318": ("DiskDrive", "storage", DOC_SETUP_CLASSES),
    "4d36e96a-e325-11ce-bfc1-08002be10318": ("HDC", "storage", DOC_SETUP_CLASSES),
    "4d36e97b-e325-11ce-bfc1-08002be10318": ("SCSIAdapter", "storage", DOC_SETUP_CLASSES),
    "75416e63-5912-4dfa-ae8f-3efaccaffb14": ("NvmeDisk", "storage", DOC_SETUP_CLASSES),
    "71a27cdd-812a-11d0-bec7-08002be2092f": ("Volume", "storage", DOC_SETUP_CLASSES),
    "745a17a0-74d3-11d0-b6fe-00a0c90f57da": ("HIDClass", "other", DOC_SETUP_CLASSES),
    "4d36e96b-e325-11ce-bfc1-08002be10318": ("Keyboard", "other", DOC_SETUP_CLASSES),
    "4d36e96f-e325-11ce-bfc1-08002be10318": ("Mouse", "other", DOC_SETUP_CLASSES),
    "4d36e96e-e325-11ce-bfc1-08002be10318": ("Monitor", "other", DOC_SETUP_CLASSES),
    "50127dc3-0f36-415e-a6cc-4cb3be910b65": ("Processor", "other", DOC_SETUP_CLASSES),
    "72631e54-78a4-11d0-bcf7-00aa00b7b32a": ("Battery", "other", DOC_SETUP_CLASSES),
    "ca3e7ab9-b4c3-4ae6-8251-579ef933890f": ("Camera", "other", DOC_SETUP_CLASSES),
    "6bdd1fc6-810f-11d0-bec7-08002be2092f": ("Image", "other", DOC_SETUP_CLASSES),
    "4d36e978-e325-11ce-bfc1-08002be10318": ("Ports", "other", DOC_SETUP_CLASSES),
    "d94ee5d8-d189-4994-83d2-f68d7d41b0e6": ("Securitydevices", "other", DOC_SETUP_CLASSES),
    "5175d334-c371-4806-b3ba-71fd53c9258d": ("Sensor", "other", DOC_SETUP_CLASSES),
    "4d36e97d-e325-11ce-bfc1-08002be10318": ("System", None, DOC_SETUP_CLASSES),
    "62f9c741-b25a-46ce-b54c-9bccce08b6f2": ("SoftwareDevice", None, DOC_SETUP_CLASSES_RESERVED),
    "5c4c3332-344d-483c-8739-259e934c9cc8": ("SoftwareComponent", None, DOC_SETUP_CLASSES),
    "4d36e97e-e325-11ce-bfc1-08002be10318": ("Unknown", None, DOC_SETUP_CLASSES_RESERVED),
}


def normalise_guid(value: Any) -> str | None:
    """A class GUID as lower case text without braces, or None when it is not a GUID."""
    if not isinstance(value, str):
        return None
    text = value.strip().strip("{}").lower()
    parts = text.split("-")
    if [len(p) for p in parts] != [8, 4, 4, 4, 12] or any(c not in "0123456789abcdef" for p in parts for c in p):
        return None
    return text


def file_name_of(path: Any) -> str | None:
    """The file name at the end of a service binary path (``\\SystemRoot\\System32\\drivers\\afd.sys`` gives ``afd.sys``).

    Quotes around the path are dropped. Anything after the first space past the
    file extension is not expected for a driver; such a path yields None rather
    than a guess.
    """
    if not isinstance(path, str):
        return None
    text = path.strip().strip('"').strip()
    if not text:
        return None
    name = text.replace("/", "\\").rsplit("\\", 1)[-1]
    if not name or " " in name or "." not in name:
        return None
    return name


def classify_service(setup_classes: list[dict[str, Any]]) -> tuple[str | None, str]:
    """The driver class a service's present devices give, and why.

    ``setup_classes`` holds one entry per class GUID seen among the service's
    present devices (``class_guid``, ``setup_class``, ``device_count``). Classes
    whose map value is None and GUIDs not in the map say nothing; when the rest
    name one driver class that is the answer, when they name several the answer
    is ``unclassified``, and when nothing is left the answer is None (the
    inventory gives no class and a later step may use the inbox map).
    """
    if not setup_classes:
        return None, "no present Plug and Play device names this service"
    informative: dict[str, list[str]] = {}
    silent: list[str] = []
    for entry in setup_classes:
        guid = entry.get("class_guid")
        mapped = SETUP_CLASSES.get(guid) if guid else None
        if mapped is None:
            silent.append(f"{guid or 'no class GUID'} (not in the setup class map)")
        elif mapped[1] is None:
            silent.append(f"{mapped[0]} (says nothing about the driver class)")
        else:
            informative.setdefault(mapped[1], []).append(mapped[0])
    if len(informative) == 1:
        driver_class, names = next(iter(informative.items()))
        reason = f"present devices in setup class {', '.join(sorted(names))}"
        if silent:
            reason += f"; also {', '.join(sorted(silent))}"
        return driver_class, reason
    if len(informative) > 1:
        parts = [f"{cls} ({', '.join(sorted(names))})" for cls, names in sorted(informative.items())]
        return "unclassified", "present devices in setup classes of different driver classes: " + "; ".join(parts)
    return None, "present devices only in " + ", ".join(sorted(silent))


class InventoryIndex:
    """The ``driver_service_class`` rows of one inventory, by lower case driver file name."""

    def __init__(self, rows: list[dict[str, Any]], reference_prefix: str) -> None:
        self.by_file: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for line_no, row in enumerate(rows, start=1):
            name = row.get("driver_file")
            if name:
                self.by_file.setdefault(name.lower(), []).append((line_no, row))
        self.reference_prefix = reference_prefix

    def lookup(self, module: str) -> tuple[str | None, str, str | None]:
        """(driver class or None, reason, reference) for a module, or (None, reason, None) when the inventory says nothing."""
        hits = self.by_file.get(module.lower())
        if not hits:
            return None, "no driver service in the inventory runs a file of this name", None
        ref = self.reference_prefix + ";".join(f"line:{n}" for n, _ in hits)
        classes = {r["driver_class"] for _, r in hits if r.get("driver_class")}
        services = ", ".join(sorted(r["service"] for _, r in hits))
        if len(classes) == 1:
            cls = classes.pop()
            reasons = "; ".join(r["class_reason"] for _, r in hits if r.get("driver_class"))
            return cls, f"service {services}: {reasons}", ref
        if len(classes) > 1:
            return "unclassified", f"services {services} run a file of this name with different driver classes ({', '.join(sorted(classes))})", ref
        reasons = "; ".join(f"{r['service']}: {r['class_reason']}" for _, r in hits)
        return None, f"the inventory gives no class ({reasons})", ref


def classify_module(module: str, inventory: InventoryIndex | None) -> dict[str, Any]:
    """The four classification columns of a ``dpcisr_module_cpu`` row."""
    inventory_note = "no driver inventory was given"
    if inventory is not None:
        cls, reason, ref = inventory.lookup(module)
        if cls is not None:
            return {"driver_class": cls, "classification_source": "inventory", "classification_reason": reason, "classification_reference": ref}
        inventory_note = reason
    key = module.lower()
    if key in INBOX_MAP:
        cls, url = INBOX_MAP[key]
        return {"driver_class": cls, "classification_source": "inbox-map",
                "classification_reason": f"Microsoft inbox binary in the driver class map {MAP_VERSION}; inventory: {inventory_note}",
                "classification_reference": url}
    if key in INBOX_UNCLASSIFIED:
        why, url = INBOX_UNCLASSIFIED[key]
        return {"driver_class": "unclassified", "classification_source": "inbox-map",
                "classification_reason": f"{why}; inventory: {inventory_note}", "classification_reference": url}
    return {"driver_class": "unclassified", "classification_source": "none",
            "classification_reason": f"not in the driver class map {MAP_VERSION}; inventory: {inventory_note}",
            "classification_reference": None}
