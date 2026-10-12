# WiFi service startup regression

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
