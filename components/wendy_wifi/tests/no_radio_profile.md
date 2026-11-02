# Runtime boot radio policy

The constrained C6 firmware compiles both BLE and Wi-Fi. Saved WendyCom settings
choose which radio is initialized at boot; switching returns APPLIED_RESTARTING
and reboots after management output and mesh ownership have drained. USB remains
available. The radio-disabled path initializes shared IP and the native listener
without a station driver, Wi-Fi worker, mDNS or credential access.

The normal adapter fixture and runtime-disabled fixture exercise this same
production policy. There are no separate BLE-only/no-Wi-Fi firmware flags.
