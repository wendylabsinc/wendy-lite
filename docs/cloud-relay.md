# Cloud TLS handoff

The firmware opens an outbound device-authenticated mTLS connection to the
configured broker. It processes only four-byte control records on that connection:
`57 52 01 01` is ping, `57 52 01 02` is pong, and `57 52 01 03` is upgrade.
There are no WendyCom messages between cloud and the device.

On upgrade, the firmware waits for the broker's TLS close notification, sends
its own, and releases the TLS session while preserving the socket. ESP-IDF 5.5.4
`esp_tls_server_session_delete` frees TLS without closing the descriptor;
`esp_tls_conn_destroy` must not be used for this handoff.

The same socket then gets a fresh TLS server session. Only a valid same-tenant
operator certificate with explicit client-auth EKU is admitted. Its URI SAN must
be `spiffe://wendy.sh/tenant/<uuid>/operator/<subject>`. Device certificates,
service certificates, missing identities, and ambiguous identities are rejected.
The device derives its tenant from its own provisioned device certificate.

After operator authentication, the local server hands the socket to WendyCom.
The cloud task immediately loops back and establishes a new control connection,
while the accepted operator link runs independently. Connection errors retry
using `CONFIG_WENDY_CLOUD_RECONNECT_DELAY_MS`. Control pings have a 30-second
receive deadline; TLS shutdown and the operator handshake each have a 10-second
deadline. Stopping cloud stops its control loop; accepted operator sockets belong
to the local server until their sessions close.

The broker must implement the matching opaque-byte handoff in cloud PR #753,
tracked by WDY-3512. Clients must carry a full mTLS byte stream in relay payloads,
then frame WendyCom themselves. The old bare-protobuf relay client and tinycloud
protocol are incompatible with this handoff. A client must also verify and pin
the intended device's certificate, rather than trusting the broker's routing.

Build with ESP-IDF 5.5.4 and `CONFIG_WENDY_CLOUD=y`. Provisioned credentials and
TLS support for their issuing CA are required. This change does not replace the
firmware's cryptographic backend or provision credentials.

The URI policy has a host test, including truncated buffers and embedded NULs:

```sh
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  tests/operator_identity_test.c -o /tmp/operator-identity-test
/tmp/operator-identity-test
```

A physical-board trial with real device and operator credentials remains required.
