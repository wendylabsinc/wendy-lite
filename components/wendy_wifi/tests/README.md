# WiFi service startup and reconnection regression

Run without ESP-IDF or a board:

```sh
cmake -S components/wendy_wifi/tests -B /tmp/wendy-wifi-tests
cmake --build /tmp/wendy-wifi-tests
ctest --test-dir /tmp/wendy-wifi-tests --output-on-failure
```

The test compiles the production WiFi source against deterministic ESP-IDF and
FreeRTOS stubs. It delivers an IP event after the synchronous connection wait has
timed out, runs the worker until idle, and verifies that network services start.
It also exercises startup failures, repeated IP events, disconnects during retry,
and mDNS hostname failure after successful mDNS initialization.

The driver model also covers an access point returning after a simulated
five-minute outage, recovery after losing an established connection, refused
connection requests that emit no event, and cancellation on IP arrival or
shutdown. It checks that reconnection does not duplicate service startup and
that security diagnostics do not log the password or change authentication
settings. The outage case fails against the original implementation, which
stops after the initial attempt and five retries.

Credential fallback cases exercise the public initialization and provisioning
APIs. The model delivers station-start events asynchronously, rejects
configuration changes while a connection is in flight, and queues disconnect
events when the radio stops. It verifies that exhausted
retries, refused requests, and a synchronous timeout during an active scan do
not prevent the next credential source or newly supplied credentials from
connecting. Handoff drains old events with retries disabled before configuring
the next network. It also covers a missing drain acknowledgement and an IP
event arriving after shutdown.

CI runs this suite with AddressSanitizer and UndefinedBehaviorSanitizer.
