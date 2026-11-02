# Bluetooth radio settings

Wendy Net supports three radio modes for the ESP32-C5 and ESP32-C6: `normal`
(legacy 1M advertising and 1M data), `coded-s2` (500 kbit/s coded data), and
`coded-s8` (125 kbit/s coded data). Coded modes use extended advertisements with
Coded PHY on both the primary and secondary channels. They scan and establish
connections directly on Coded PHY; a nearby 1M connection is not required first.

Configure both devices through USB using a CLI and firmware with radio-profile
support. For example, replace `PORT` with the device's serial port:

```sh
wendy --device wendy-lite:PORT device wendy-net configure \
  --participate=true --ble-mode=coded-s8 --infrastructure-wifi=false \
  --nan=false --max-links=1 --ble-links=1
wendy --device wendy-lite:PORT device wendy-net status
```

A radio-mode change saves the configuration and restarts the device after the
reply. Reconnect afterwards and inspect the saved profile and runtime state with
`wendy device bluetooth mode --device wendy-lite:PORT` and
`wendy device wendy-net status --device wendy-lite:PORT`. Check that the desired
and applied profiles agree after the restart, then verify actual peer
connectivity as well as the saved setting. Other mode values are `normal`, `coded-s2`, and `off`; `off` disables the BLE mesh
carrier while retaining its saved radio profile. Choose one `--ble-mode` value;
do not combine it with `--ble`. Firmware without the requested coded-mode support
returns an error.

Infrastructure Wi-Fi stays available for management even
when its mesh carrier is disabled. The example therefore uses BLE for all mesh
traffic while allowing normal Wi-Fi management. The C6 still permits only one
mesh carrier at a time.

Use the same profile at both ends for range comparisons. A normal-mode scanner
will not discover the Coded advertisements. A Coded scanner can decode both S2
and S8, so a pair using different coded profiles can still discover each other;
its practical range can be limited by the weaker direction.

Coded modes trade throughput and radio airtime for range. The firmware uses
60 ms connection intervals for S2 and 120 ms for S8, with longer connection-event
budgets and an 8 second supervision timeout. Infrastructure Wi-Fi shares the
radio and can affect these results. Carrier setup is bounded to 60 seconds
for normal mode, 90 seconds for S2, and 180 seconds for S8. Guest VIP setup allows
120 seconds normally and 240 seconds for S8, allowing for certificate transfer
over the slower carrier. These are setup limits, not delays added to each
connection.

Start with `normal` for ordinary connections. Capable WendyOS adapters can also
use Coded mesh advertising, scanning and connections. On WendyOS, S2/S8 are
connected-data coding preferences, while advertising coding remains
controller-selected; HCI PHY readback confirms Coded but does not distinguish
S2 from S8. Check the selected adapter's reported support. S2 provides faster coded data
than S8; S8 uses stronger coding at a lower data rate. Neither promises a fixed
range, and radio rates are not application throughput.

`wendy device bluetooth mode coded-s2 --device wendy-lite:PORT` selects a profile
without enabling BLE or changing participation. In contrast, the configure
command with `--ble-mode=coded-s2` selects the profile and enables BLE; it still
preserves participation unless `--participate` is supplied. `bluetooth mode` does
not accept `off`. To disable the only mesh carrier, also stop participation or
select another supported carrier.

Bluetooth power is configurable independently of the mesh mode. Inspect first;
then change only the settings you need:

```sh
wendy device bluetooth power --device wendy-lite:PORT
# Explicitly opt in to maximum power on supported C5/C6 firmware:
wendy device bluetooth power --device wendy-lite:PORT \
  --advertising maximum --connections maximum
# Change advertising power while preserving connection power:
wendy device bluetooth power --device wendy-lite:PORT --advertising -6
# Restore both firmware controller defaults:
wendy device bluetooth power --device wendy-lite:PORT \
  --advertising default --connections default
```

The policy applies to management/application Bluetooth as well as mesh, and
survives reboot. Without a saved policy, both settings retain the firmware
controller default used before radio management was added; maximum power is an
explicit opt-in. Existing saved choices survive firmware updates. A board with a
previously saved maximum policy needs the explicit `default` command above to
return to controller defaults.

Advertising power controls announcements. Connection power controls established
link traffic and also applies to scanning/initiation. Raising one setting does not
raise the other or change the other peer's power. Omitted settings are preserved.
Use integer dBm values without a unit suffix. `default` restores the firmware
controller default, `maximum` requests +20 dBm on C5/C6, and a dBm request rounds down to a supported
level between -15 and +20 dBm. Connection settings cover existing and future
links. Status distinguishes saved policy,
applied policy, pending changes and actual controller readbacks. Power changes
require no reboot. `power` always prints JSON: query again while `pending` is true,
check `error`, and compare `desired` with `applied`. Read `advertisingDbm`,
`connectionDefaultDbm` and each connection's `currentDbm` as measured values only
when the corresponding `advertisingKnown`, `connectionDefaultKnown` or
`currentKnown` flag is true. `supportedLevelsDbm` lists the discrete levels.

The CLI's text `mode` view shows the saved profile and runtime state; `--json`
also includes `bleProfilesSupported`, where bits 0, 1 and 2 represent normal, S2
and S8. To return a coded device to normal, use your working management path:

```sh
wendy device bluetooth mode normal --device wendy-lite:PORT
```

The maximum-power example above is specific to Lite. On WendyOS Linux/BlueZ,
advertising power can be set if the adapter reports support. An explicit local
connected-link power setter is not implemented for the tested Intel controller;
WendyOS reports current and maximum power for mesh links when supported, and
rejects non-default connection-power requests. Missing readbacks are unknown.
See the WendyOS Bluetooth command reference for capability checks, coding
preferences and advertisement-registration fields.

Apply changes over USB or infrastructure Wi-Fi if reducing Bluetooth power could
make the management link unreachable. A power change updates controller power
in place without restarting advertisements or deliberately closing established
links. The new policy is applied only
after its management reply has drained.

Guest BLE advertisements use a separate, bounded advertising set and remain on
1M for compatibility with existing guest BLE APIs. They do not replace the
management or mesh payload. Device-wide power changes cover both sets. A guest
advertising request can fail when the controller has no connection capacity
left; it does not take a slot from an established mesh connection. Guest
advertisements omit the optional TX-power data field so that an in-place power
change cannot leave a stale value in their payload.
