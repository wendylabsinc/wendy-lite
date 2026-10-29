# Boot-only C6 no-WiFi-radio experiment

`CONFIG_WENDY_NET_TEST_NO_WIFI_RADIO=y` is a default-off laboratory profile,
not the meaning of the management WiFi-carrier switch. It requires native BLE,
the native router, diagnostic support and the normal WiFi component, and excludes
NAN, ESP-NOW and Cloud. Normal C5/C6 boot behavior is unchanged when disabled.

The profile initializes shared lwIP/default events and the native 5054 acceptor,
but does not create the station netif, initialize the WiFi driver, create the
WiFi services/mDNS tasks, or read station credentials. Physical BLE management,
the guest runtime and native VIP/application listeners remain present. The
common server skips its mDNS advertisement; mesh mDNS does not start because
WiFi/NAN configurations are unsupported. It supplies no clock: cold BLE must
obtain ordinary signed time before authenticating mesh connections.

Management reports WiFi/NAN unsupported. Valid BLE-only saved mesh settings are
read normally; incompatible saved WiFi settings remain on flash and this boot
starts disabled. All mesh setting updates in this profile are RAM-only. Neither
station enable nor provisioning may initialize the absent radio. Station disable
and WiFi deinit preserve the shared IP/listener lifetime. Rebooting a normal image
restores the original saved policy. Other ordinary boot persistence (PKI boot
revision/time handling, explicit guest operations) is unchanged.

Host checks exercise normal idempotent driver initialization, profile idempotent
shared-IP initialization with zero driver/STA/services/mDNS/credential accesses,
and ordinary settings load/change/reboot/capabilities with zero NVS writes.
The broad pre-existing WiFi recovery fixture fails its fallback
`driver_starts == 2 && station_start_events == 2` assertion in both unchanged
`dd9e7cf` and this branch; this experiment does not change that recovery path.
The SDK adapter also lacked the existing production NOT_CONNECT error constant;
its test stub now supplies it.

Initial comparison must keep the constrained one-BLE profile, eight-key limit,
bounded FIFO and guest unchanged. This option alone does not enable transit.
A later two-BLE SRAM profile needs explicit separation of non-transit policy
from eight-key/DER-retirement/demand-service/pending-eight bounds; simply turning
constrained mode off removes these useful memory limits. Two simultaneous mesh
BLE connections also need a third GAP connection if physical BLE management must
remain available. None of those additional changes is included here.

Expected savings are unmeasured until an MCU A/B run. Known omitted nominal
allocations include the 6656-byte WiFi task, four roughly 1600-byte static RX
buffers, 4096-byte WiFi-services stack and 4096-byte mDNS stack. Driver/netif/
control bookkeeping is additional; shared lwIP/tcpip, physical management and
native acceptor stacks are retained and must not be counted as savings.
