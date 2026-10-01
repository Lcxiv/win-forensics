# RF survey: the method, its limits, and the before and after test

The question behind `collectors/windows/rf-survey.ps1` and `scripts/analyze_rf_survey.py`: is something in the 2.4 GHz band around the desk interfering with the wireless mouse and headset of a gaming PC that is itself on Ethernet, and what can be changed about it? This document says what the survey measures, what it cannot, why a packet capture does not answer the question, and how to test a change so the answer is the PC's and not a guess.

## Why Wireshark alone cannot answer this

A wireless mouse or headset receiver suffers from the noise floor and the busy time of the 2.4 GHz band at its antenna. A packet capture shows frames, not noise, and on Windows it mostly shows the PC's own traffic:

- Wireshark's capture notes for wireless adapters: "On Windows, you can see 802.11 headers when capturing, and capture non-data frames, and capture traffic other than traffic to or from your own machine, only in monitor mode", and monitor mode depends on Npcap and on the adapter and driver ("Npcap, which supports Windows 7 and later, supports monitor mode; WinPcap doesn't support monitor mode"). [Wireshark wiki, CaptureSetup/WLAN](https://wiki.wireshark.org/CaptureSetup/WLAN)
- Npcap's guide: the raw 802.11 option must be selected at install time, the `WlanHelper` tool that switches an adapter into monitor mode "must run under Administrator privilege", and "Switching to Monitor Mode will disconnect your wireless network from the AP". [Npcap developer's guide](https://npcap.com/guide/npcap-devguide.html)
- Even a perfect monitor mode capture shows Wi-Fi frames only. Bluetooth hops across the same band, the proprietary 2.4 GHz protocols of mouse and headset receivers are not 802.11 at all, and the broadband noise a USB 3 port radiates is not a frame of any kind. Intel measured that noise: it "falls within the band of operation of the wireless device (2.4 to 2.5 GHz)" and "cannot be filtered out". [Intel, USB 3.0 Radio Frequency Interference Impact on 2.4 GHz Wireless Devices, April 2012](https://www.usb.org/sites/default/files/327216.pdf)

So the survey does not capture packets. It asks Windows what it already knows, with nothing changed and no scan forced, and leaves the one measurement that matters, how the mouse and headset behave, to a test the owner runs.

## What the survey captures

One read only collector, run through the SSH front door as the standard collector account, with every source carrying its own measurement status ([measurement-status.md](contracts/measurement-status.md)):

| Source | What it answers | Read with |
|---|---|---|
| `net_adapters`, `default_routes` | Which adapter carries the PC's traffic (the interface behind the IPv4 default route) | `MSFT_NetAdapter`, `MSFT_NetRoute` |
| `wlan_networks` | Every access point the Wi-Fi adapter can see, with band, channel, signal and radio type | `netsh wlan show networks mode=bssid` |
| `wlan_interfaces`, `wlan_drivers`, `wlan_profiles` | The adapter's state, its driver's radio types, the networks this PC has a profile for | `netsh wlan show interfaces`, `show drivers`, `show profiles` |
| `wlan_report` | The HTML wireless report, if the owner generated it earlier | the file under ProgramData, copied |
| `wlan_autoconfig_events` | The Wi-Fi service's own log | the WLAN AutoConfig operational channel |
| `usb_device_tree` | Every USB, input, audio and network device with its hub chain to the host controller | `Win32_PnPEntity`, `Get-PnpDeviceProperty` |
| `bluetooth_devices` | The Bluetooth radio and its paired devices | the same |

Network names and hardware addresses are other people's as much as the owner's, so the collector replaces every one of them with a pseudonym before writing (`ssid-<12 hex>`, `mac-<12 hex>`, keyed with a random salt that is never stored). The analysis still matches the saved profile against the scan, because the same name gets the same pseudonym inside one bundle. The decoder (`scripts/decode_rf_survey.py`) turns the exports into typed tables, and the analyzer reads those tables, never the raw text.

The adapter does not have to be connected to anything. On this PC it is a receiver: it hears the beacons of the router and the neighbours' access points on 2.4 GHz, which is exactly what the mouse and headset receivers share the band with.

## What the analysis says

The analyzer writes `reports/rf-survey.md` and `reports/rf-survey.json` into the bundle and its evidence rows into `evidence.jsonl`. The coverage table comes first, so the reader learns what was and was not measured before any finding.

1. Traffic path. The adapter behind the default route and its medium, from `MSFT_NetRoute` and `MSFT_NetAdapter` (Microsoft documents the physical medium values: 14 is 802.3, 9 is Native 802.11). When it is Ethernet, the PC's own Wi-Fi link is ruled out as a cause.
2. The 2.4 GHz airspace. Per channel: how many access points and how strong, with the signal percentage converted to an estimated dBm by Microsoft's mapping (0 percent is minus 100 dBm, 100 percent is minus 50 dBm). The router is identified as the network a saved profile on this PC names, or failing that as the strongest 2.4 GHz signal, and the report says which. A 2.4 GHz channel is 22 MHz wide and the channels are 5 MHz apart, so networks within four channel numbers of each other overlap and only 1, 6 and 11 (25 MHz apart) do not (Cisco; Intel counts "three non-overlapping channels" in the band). The recommendation is the one of 1, 6 and 11 with the fewest networks within four channels, the owner's router excluded, ties broken by the weaker strongest signal. If the router's name is also on the air on 5 GHz, the household's other devices belong there, because 802.11a, 802.11ac and 5 GHz 802.11n and ax traffic does not share the receivers' band (Intel).
3. USB receivers. Devices whose name says receiver, dongle, wireless, Unifying or Lightspeed are followed up the device tree to their host controller. Windows loads the xHCI stack (Usbxhci.sys, Usbhub3.sys) for USB 3 controllers and the EHCI stack for USB 2 controllers, and "the USB driver stack that Windows loads correlates to the type of host controller, not to the connected device's speed" (Microsoft). So the survey can say that a receiver shares a USB 3 capable controller or hub with USB 3 devices; it cannot say which speed any port negotiated, and the report says so. Intel's measurements are the reason to care: a mouse dongle stacked above a USB 3 port gave no response at 2, 3 and 5 feet while the same dongle on a USB 2 extension cable on the far side of the machine worked, and an external USB 3 drive raised the 2.4 GHz noise floor by nearly 20 dB. Logitech's guidance matches: separate the receiver from USB 3 connectors as far as possible, use an extender, and keep the receiver as close to the device as possible.
4. Radios that are on but unused. A Wi-Fi adapter that is enabled but not behind the default route keeps scanning, and an 802.11 scan transmits probe requests (Microsoft, OID_WDI_TASK_SCAN). A Bluetooth radio with nothing paired is a 2.4 GHz radio too (Microsoft's Bluetooth FAQ: both "operate in the 2.4-GHz frequency range"). The report says they could be switched off; the owner does that, never the collector.
5. Receiver placement. Distance and line of sight cannot be measured by any of this. The report carries Logitech's guidance (receiver in direct line of sight, as little distance as possible, no metal or electronics between, a front panel port rather than a PC under the desk, phones, routers and microwaves away from the work area) and Intel's (antenna as far as possible from USB 3 connectors and devices), and the test below.
6. Wi-Fi service events. Counts per event id from the WLAN AutoConfig log, as context about the PC's own Wi-Fi service, with no claim about the receivers.

## What the survey can and cannot prove

It can show which networks are on the air and on which channels, which adapter carries the traffic, where each receiver sits on the USB tree, and which radios are on. It cannot measure the noise floor at the receiver, the negotiated speed of a USB port, the distance or the obstacles between receiver and mouse, the router's channel width, or whether any of these is what the mouse and headset suffer from. A scan is a moment; neighbours' networks come and go. And the scan can be withheld: on Windows 11 the APIs behind `netsh wlan show networks` return access denied without location consent, and a session started by sshd cannot answer the consent prompt, so an empty list is reported as `capture_failed`, never as a quiet airspace (see the verification list in `collectors/windows/README.md`).

Only the test below can show that a change helped.

## The before and after test

Change one thing at a time. Before the first change and after every change, run the same two checks for one minute each, in the game or the application where the problem shows, and write the result down with the time:

- Mouse: move it in slow circles and in fast flicks for a minute; count visible stutters, jumps, or moments where the pointer stops following, and missed or doubled clicks. The pass is "none noticed in a minute".
- Headset: play music or a voice call for a minute at normal distance; count dropouts, crackle, or delay changes. The pass is "none noticed in a minute".

Then, one at a time, keeping each change only if it helped (or if it is harmless and you want to keep it), in this order:

1. Receiver port. If the report says a receiver sits on the USB 3 controller and the PC has a USB 2 controller, move it to a port served by that controller. If not, go to step 2.
2. Extension cable. Put the receiver on a short USB 2 extension cable so it sits as far from the case's USB 3 connectors and any USB 3 drive as possible and as close to the mouse or headset as possible, in direct line of sight, with nothing metal between.
3. USB 3 devices. Unplug the USB 3 drives and hubs the report lists, one at a time, and repeat the checks after each.
4. Radios. If the report says the Wi-Fi adapter is on and carries no traffic, turn it off in Settings and repeat the checks; the same for Bluetooth if nothing is paired. Turn Wi-Fi back on when you want to run the survey again.
5. Router channel. Set the router's 2.4 GHz channel to the one the report recommends, with a 20 MHz width if the router offers the choice, and repeat the checks. Move the household's other devices to the router's 5 GHz network if it has one.
6. Router channel again, after a day. Neighbours' networks change; run the survey again and compare the channel table.

Record the result of every step. A step that did not change anything can be undone. The survey run again after the changes shows whether the airspace or the device tree changed as expected; the checks show whether the mouse and headset did.

## Sources

- Wireshark wiki, CaptureSetup/WLAN. https://wiki.wireshark.org/CaptureSetup/WLAN
- Npcap developer's guide, raw 802.11 and WlanHelper. https://npcap.com/guide/npcap-devguide.html
- Intel, USB 3.0 Radio Frequency Interference Impact on 2.4 GHz Wireless Devices, white paper 327216-001, April 2012 (hosted by USB-IF). https://www.usb.org/sites/default/files/327216.pdf
- Intel, Different Wi-Fi Protocols and Data Rates. https://www.intel.com/content/www/us/en/support/articles/000005725/wireless/legacy-intel-wireless-products.html
- Cisco, WLAN Radio Frequency Design Considerations, IEEE 802.11b direct sequence channels. https://www.cisco.com/en/US/docs/solutions/Enterprise/Mobility/emob30dg/RFDesign.html
- Logitech, Wireless product not working properly when also using a USB 3.0 device. https://support.logi.com/hc/en-ca/articles/360023414273-Wireless-product-not-working-properly-when-also-using-a-USB-3-0-device
- Logitech, Operating distance between the mouse or keyboard and USB receiver. https://support.logi.com/hc/en-us/articles/360023402233-Operating-distance-between-the-mouse-or-keyboard-and-USB-receiver
- Logitech, Troubleshooting recommendations for interference issues. https://hub.sync.logitech.com/mx-master-3s/post/troubleshooting-recommendations-for-interference-issues-goEfm9QOsiJ4efB
- Microsoft, Advanced troubleshooting wireless network connectivity. https://learn.microsoft.com/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting
- Microsoft, Changes to API behavior for Wi-Fi access and location. https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes
- Microsoft, WLAN_ASSOCIATION_ATTRIBUTES (signal quality to dBm). https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_association_attributes
- Microsoft, USB host side drivers in Windows. https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-3-0-driver-stack-architecture
- Microsoft, USB in Windows FAQ. https://learn.microsoft.com/windows-hardware/drivers/usbcon/usb-faq--introductory-level
- Microsoft, Bluetooth FAQ. https://learn.microsoft.com/windows-hardware/drivers/bluetooth/bluetooth-faq
- Microsoft, OID_WDI_TASK_SCAN. https://learn.microsoft.com/windows-hardware/drivers/netcx/oid-wdi-task-scan
- Microsoft, MSFT_NetAdapter class. https://learn.microsoft.com/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapter
- Microsoft, MSFT_NetRoute class. https://learn.microsoft.com/windows/win32/fwp/wmi/nettcpipprov/msft-netroute
