# Cloud worker host test

Build and run without ESP-IDF or hardware:

```sh
cmake -S components/wendy_cloud/tests -B .build/cloud-tests
cmake --build .build/cloud-tests
ctest --test-dir .build/cloud-tests --output-on-failure
```

The fixture runs the production worker with stubbed PKI and scheduler boundaries.
It checks immediate replacement after planned renewal and operator handoff,
backoff after connect, allocation and control failures, reset of connection failure
counts, and connection/fd ownership during normal operation and stop. Descriptor
zero is a valid successful handoff. Unknown negative results retain backoff.
