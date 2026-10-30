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
reply. Reconnect afterwards and check that `desired` and `applied` agree. Other
mode values are `normal`, `coded-s2`, and `off`; `off` disables the BLE mesh
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

Bluetooth power is configurable independently of the mesh mode:

```sh
wendy device bt power --advertising maximum --connections maximum
wendy device bt power --advertising -6 --connections 9
wendy device bt power
```

The policy applies to management/application Bluetooth as well as mesh, and
survives reboot. New installations start at maximum power. Advertising and
connection settings are independent; omitted settings are preserved. `default` restores the firmware controller default,
`maximum` requests +20 dBm on C5/C6, and a dBm request rounds down to a supported
level between -15 and +20 dBm. Connection power also applies to scanning and
initiation, existing links and future links. Status distinguishes saved policy,
applied policy, pending changes and actual controller readbacks.

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
