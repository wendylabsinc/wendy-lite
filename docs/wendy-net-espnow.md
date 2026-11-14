# Wendy Net over ESP-NOW

PSRAM full routers can carry Wendy Net links to their radio neighbours over
ESP-NOW. The hop needs no access point, IP network or mDNS: two boards on the
same Wi-Fi channel and in range are enough.

Security is the same as on the other carriers. An ESP-NOW link is the ordinary
mutually authenticated TLS mesh link with tenant trust, signed manifests and
routing proofs. ESP-NOW is an untrusted transport underneath it, and its
discovery adverts are dial hints only, like mDNS and BLE sightings.

**Status: experimental and not yet tried on hardware.** The firmware builds for
the Seeed XIAO ESP32S3 native profile, and the stream layer passes its host
tests against a simulated lossy radio. No link has been formed between real
boards. See [What is untested](#what-is-untested).

## Build

The carrier is compiled out by default. Add `boards/wendy_net_espnow.defaults`
after a PSRAM board profile that already includes Wendy Net:

```sh
idf.py -B build/xiao-espnow -D SDKCONFIG=build/xiao-espnow/sdkconfig \
  -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;boards/seeed_xiao_esp32s3_native.defaults;boards/wendy_net_espnow.defaults" \
  set-target esp32s3
idf.py -B build/xiao-espnow -D SDKCONFIG=build/xiao-espnow/sdkconfig build
```

| Option | Default | Meaning |
| --- | --- | --- |
| `CONFIG_WENDY_NET_ESPNOW` | off | Compile the carrier. Requires PSRAM and the full router profile. |
| `CONFIG_WENDY_NET_ESPNOW_CHANNEL` | 1 | The channel every board shares. |
| `CONFIG_WENDY_NET_ESPNOW_LINKS` | 4 | Most ESP-NOW links at once, inside the total link limit. |
| `CONFIG_WENDY_NET_ESPNOW_ADVERT_MS` | 5000 | Base interval between discovery adverts. |
| `CONFIG_WENDY_NET_ESPNOW_FRAME_BYTES` | 1024 | Largest frame, from 250 to the ESP-NOW v2 limit of 1470. |

## Enable

The management protocol has no flag for this carrier, so there is nothing new
in the CLI: in a build that includes it, the carrier runs whenever the mesh is
enabled. The existing infrastructure Wi-Fi setting decides what the radio does.

A board that should stay on its Wi-Fi network keeps that carrier on. Its
ESP-NOW links use the network's channel:

```sh
wendy --device wendy-lite:PORT device wendy-net configure \
  --participate=true --infrastructure-wifi=true
```

A board that should need no network turns it off:

```sh
wendy --device wendy-lite:PORT device wendy-net configure \
  --participate=true --infrastructure-wifi=false
```

That board pauses its Wi-Fi station and keeps the radio on the configured
channel. Saved Wi-Fi credentials are kept, but management over the LAN and
Cloud connectivity stop while the mesh is enabled; use USB, BLE or the mesh.
Disabling the mesh resumes the station. At start the board first waits up to
20 seconds for signed time (see below) before it leaves its network.

The firmware accepts `--ble=false --infrastructure-wifi=false` in such a build,
which leaves ESP-NOW as the only carrier. Other builds still reject it.
`status` and `topology` have no ESP-NOW fields; a link's transport is reported
as the number 4, which current clients do not name.

## Every board on one channel

ESP-NOW has no channel negotiation. Boards hear each other only on the same
channel, so:

- boards without a network all use `CONFIG_WENDY_NET_ESPNOW_CHANNEL`;
- a board that stays on a Wi-Fi network is on that network's channel, whatever
  is configured, and logs a warning when the two differ. Set the configured
  channel of the other boards to that network's channel, and fix the channel on
  the access point so it does not move.

## Signed time still needs one board with a network

Every mesh link requires fresh signed time from the enrolled timestamp
authority, renewed every few minutes. That rule is unchanged, so a mesh in
which no board can reach the Internet cannot form links on any carrier.

A board without a network gets its time through a neighbour that has one:

- at start, over ESP-NOW. A board on a network advertises that it can relay
  time; a board without time opens a separate stream to it, and the neighbour
  forwards the encrypted exchange to the timestamp authority. This is the same
  relay the BLE time channel provides, and the reply is verified locally.
- afterwards, through any established mesh link to a neighbour with a network,
  as on the other carriers.

The neighbour has to be a direct one: time requests are not forwarded across
several mesh hops. In practice each board without a network needs a board on a
network within radio range.

## What it costs

ESP-NOW reception needs the radio awake. While the mesh is enabled in such a
build, modem sleep is switched off (`WIFI_PS_NONE`) and the receiver stays on,
on boards with and without a network. Expect the current draw of a listening
Wi-Fi radio continuously: on the order of 100 mA on an ESP32-S3 by its
datasheet, not measured here. The previous setting is restored when the mesh
stops.

Transmissions are kept sparse:

- discovery: one 53-byte broadcast per advert interval, jittered by a quarter
  either way, and only while the node can accept a link or relay time. A node
  that already has an ESP-NOW link advertises four times less often. A node
  that can do neither sends nothing, which includes every node that has no
  signed time and no network.
- an idle link carries only the mesh's own traffic, mainly a routing hello
  every four seconds in each direction, plus one small acknowledgement for
  each. The stream layer has no keepalive of its own and never polls.
- an ESP-NOW link is not opened, and an existing one is closed, when a cheaper
  LAN link to the same device is up. The same rule already applied to BLE.
- only the board with the lower device id dials, so two boards that hear each
  other do one TLS handshake, not two.

## Limits

- PSRAM full routers only. Constrained profiles and boards without PSRAM do
  not get this carrier.
- At most `CONFIG_WENDY_NET_ESPNOW_LINKS` links, within `max-links`. ESP-NOW's
  own peer table holds 20 addresses for the whole device, shared with any
  application.
- Each link buffers at most sixteen frames (eight per direction), allocated on
  demand from the mesh memory ledger and released when idle. Received frames
  wait in one fixed ring of sixteen (about 24 KiB) while the mesh is enabled.
- Only Lite boards built with this carrier speak it. WendyOS peers and
  operator clients keep using the LAN and BLE.
- ESP-NOW's default 1 Mbit/s rate bounds throughput to well under that.
- Routing cost is 1024 per hop: dearer than a LAN hop (128), far cheaper than
  BLE (8192).

## Sharing ESP-NOW with an application

ESP-NOW delivers every received frame to a single callback. A native
application that uses ESP-NOW itself must therefore go through the small
dispatcher in `wendy_wifi` (`wendy_espnow.h`, `CONFIG_WENDY_ESPNOW`, selected
automatically by the carrier) instead of calling `esp_now_init`,
`esp_now_register_recv_cb` or `esp_now_deinit`:

```c
#include "wendy_espnow.h"

static void on_radio(const esp_now_recv_info_t *info, const uint8_t *data, int len);

wendy_espnow_subscribe("TL", 2, on_radio); /* frames that start with 'T','L' */
```

The callback has ESP-NOW's own signature and is called in the Wi-Fi task with
the driver's arguments, `rx_ctrl` and its timestamp included, after a few byte
comparisons and nothing else. The dispatcher adds the broadcast peer; the
application adds any unicast peers and calls `esp_now_send` as before. Mesh
frames start with `WNEN` and are never delivered to the application.

The application and the mesh share one radio. If the application also sets the
channel, it must choose the same one.

## How it works

Wendy Net carriers are byte streams under TLS. ESP-NOW gives unordered
datagrams, so `espnow_stream.c` supplies a small reliable stream, in portable C
with no SDK dependencies:

- every frame is `WNEN`, a version, a type, flags, the sender's free receive
  window, both stream identifiers, a sequence number and a cumulative
  acknowledgement (24 bytes), then data;
- a stream is opened with SYN and SYN-ACK carrying random identifiers, and
  names its purpose: a mesh link or a time relay. A frame for an unknown
  stream is answered with a reset, so a restarted peer is noticed at once;
- data is cut into numbered segments. The receiver buffers up to a window of
  them, delivers in order and acknowledges cumulatively, at once when
  something is missing and otherwise after 20 ms or two segments;
- unacknowledged data is resent after 100 ms, doubling to 2 s, and a stream
  fails after six unanswered tries (about seven seconds) or 60 seconds of
  silence. A closed receive window is probed, not abandoned;
- closing delivers what is queued, then tells the peer, which reads
  end-of-stream.

`espnow_carrier.c` binds this to ESP-NOW. The receive callback copies frames
into a fixed ring and wakes the mesh actor, which does everything else without
blocking. Wi-Fi control calls run on the existing I/O worker.

## What is untested

Nothing here has run on a board. In particular:

- ESP-NOW unicast with frames above 250 bytes between two boards whose
  stations are not joined to a network. The reference application established
  broadcast only. If large unicast frames fail, set
  `CONFIG_WENDY_NET_ESPNOW_FRAME_BYTES=250`.
- a complete TLS handshake and Babel adjacency over the carrier, the time
  relay, and behaviour beside a live BLE carrier or a camera stream;
- real loss, delay and throughput. The timers and window are defaults chosen
  for one radio hop, not measurements;
- memory and task stack high-water marks with ESP-NOW links up;
- the CLI's own handling of `--ble=false --infrastructure-wifi=false`.
