"""Exercise the firmware's CMake guard against resolved sdkconfig values."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
GUARD = ROOT / "cmake/network_profile.cmake"


class NetworkProfileTests(unittest.TestCase):
    def config(self):
        return {
            "WENDY_WIFI_TEST_PSRAM_THROUGHPUT": "y", "IDF_TARGET": "esp32s3",
            "WENDY_WIFI_ENABLED": "y", "SPIRAM": "y", "SPIRAM_BOOT_INIT": "y",
            "SPIRAM_USE_MALLOC": "y", "SPIRAM_TRY_ALLOCATE_WIFI_LWIP": "y",
            "SPIRAM_MALLOC_RESERVE_INTERNAL": "98304", "SPIRAM_MALLOC_ALWAYSINTERNAL": "1024",
            "LWIP_MAX_SOCKETS": "10", "LWIP_TCP_MSS": "1440",
            "LWIP_TCP_SND_BUF_DEFAULT": "32768", "LWIP_TCP_WND_DEFAULT": "32768",
            "LWIP_TCP_RECVMBOX_SIZE": "32", "LWIP_TCPIP_RECVMBOX_SIZE": "64",
            "ESP_WIFI_STATIC_TX_BUFFER": "y", "ESP_WIFI_STATIC_RX_BUFFER_NUM": "8",
            "ESP_WIFI_STATIC_TX_BUFFER_NUM": "8", "ESP_WIFI_DYNAMIC_RX_BUFFER_NUM": "32",
            "ESP_WIFI_CACHE_TX_BUFFER_NUM": "32", "ESP_WIFI_RX_BA_WIN": "6",
        }

    def validate(self, config, error=None):
        with tempfile.TemporaryDirectory() as directory:
            sdkconfig = pathlib.Path(directory) / "sdkconfig.cmake"
            sdkconfig.write_text("\n".join(f'set(CONFIG_{key} "{value}")' for key, value in config.items()))
            result = subprocess.run(
                ["cmake", f"-DWENDY_NETWORK_CONFIG={sdkconfig}", "-P", str(GUARD)],
                text=True, capture_output=True, check=False,
            )
        output = result.stdout + result.stderr
        if error:
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(error, " ".join(output.split()))
        else:
            self.assertEqual(result.returncode, 0, output)
        return output

    def test_xiao_profile(self):
        self.assertIn("TCP 32768/32768", self.validate(self.config()))

    def test_c5_profile_keeps_board_reserve(self):
        config = self.config()
        config.update(IDF_TARGET="esp32c5", SPIRAM_MALLOC_RESERVE_INTERNAL="32768",
                      SPIRAM_MALLOC_ALWAYSINTERNAL="64", LWIP_MAX_SOCKETS="24")
        self.assertIn("internal reserve 32768", self.validate(config))

    def test_normal_firmware_is_unchanged(self):
        self.assertEqual(self.validate({"IDF_TARGET": "esp32c6"}), "")

    def test_rejects_unsupported_targets(self):
        for target in ["esp32c6", "esp32p4", "esp32s31"]:
            with self.subTest(target=target):
                config = self.config()
                config["IDF_TARGET"] = target
                self.validate(config, "supports only ESP32-C5 and ESP32-S3")

    def test_rejects_missing_required_memory_and_transport(self):
        for key in ["WENDY_WIFI_ENABLED", "SPIRAM", "SPIRAM_BOOT_INIT", "SPIRAM_USE_MALLOC",
                    "SPIRAM_TRY_ALLOCATE_WIFI_LWIP", "ESP_WIFI_STATIC_TX_BUFFER"]:
            with self.subTest(key=key):
                config = self.config()
                del config[key]
                self.validate(config, f"requires CONFIG_{key}=y")

    def test_rejects_psram_fallback_and_constrained_profile(self):
        for key in ["SPIRAM_IGNORE_NOTFOUND", "WENDY_NET_CONSTRAINED_PROFILE"]:
            with self.subTest(key=key):
                config = self.config()
                config[key] = "y"
                self.validate(config, "requires PSRAM at boot and a non-constrained board")

    def test_rejects_insufficient_internal_reserve(self):
        config = self.config()
        config["SPIRAM_MALLOC_RESERVE_INTERNAL"] = "16384"
        self.validate(config, "requires at least 32768 bytes of internal reserve")
        del config["SPIRAM_MALLOC_RESERVE_INTERNAL"]
        self.validate(config, "requires at least 32768 bytes of internal reserve")

    def test_rejects_internal_network_allocations(self):
        config = self.config()
        config["SPIRAM_MALLOC_ALWAYSINTERNAL"] = "32768"
        self.validate(config, "internal allocation threshold at most 1024")

    def test_rejects_unbounded_socket_budget(self):
        config = self.config()
        config["LWIP_MAX_SOCKETS"] = "64"
        self.validate(config, "supports 1 to 24 lwIP sockets")

    def test_rejects_stale_or_overridden_window_and_buffer_settings(self):
        # A fresh overlay can be ignored by an existing sdkconfig. Fail with
        # the actual mismatched key instead of silently testing the old values.
        for key in ["LWIP_TCP_SND_BUF_DEFAULT", "LWIP_TCP_WND_DEFAULT", "LWIP_TCP_RECVMBOX_SIZE",
                    "LWIP_TCPIP_RECVMBOX_SIZE", "ESP_WIFI_STATIC_RX_BUFFER_NUM",
                    "ESP_WIFI_STATIC_TX_BUFFER_NUM", "ESP_WIFI_DYNAMIC_RX_BUFFER_NUM",
                    "ESP_WIFI_CACHE_TX_BUFFER_NUM", "ESP_WIFI_RX_BA_WIN", "LWIP_TCP_MSS"]:
            with self.subTest(key=key):
                config = self.config()
                config[key] = "0"
                self.validate(config, f"requires CONFIG_{key}=")


if __name__ == "__main__":
    unittest.main()
