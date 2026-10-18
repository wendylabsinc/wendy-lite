"""Check that qualification reports cannot silently accept invalid device logs."""

import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("korvo_benchmark", Path(__file__).parents[1] / "korvo_benchmark.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def boot_records():
    return [
        {"test": "heap", "time_us": 10_000_000, "internal_min": 10000,
         "internal_largest": 8000, "dma_largest": 8000, "psram_free": 1000000},
        {"test": "memcpy", "memory": "internal", "block_bytes": 16384,
         "iterations": 32, "elapsed_us": 1000, "ok": True},
        {"test": "memcpy", "memory": "psram", "block_bytes": 262144,
         "iterations": 32, "elapsed_us": 100000, "ok": True},
        {"test": "conv_int8_1x1", "core": 1, "iterations": 32,
         "ansi_us": 3200, "pie_us": 400, "ok": True},
        {"test": "complete", "ok": True},
    ]


def sensor(time_us, frames, completed=None):
    return {"test": "sensor", "channel": 0, "time_us": time_us,
            "frames_submitted": frames, "frames_completed": frames if completed is None else completed,
            "bytes_submitted": frames * 1000, "capture_errors": 0, "queue_rejected": 0,
            "completion_time_us": frames * 100, "completion_time_max_us": 100}


def summarize(records):
    # Real IDF logs include prefixes, terminal colour resets, and other output.
    return benchmark.summarize(["unrelated boot message\n"] + [
        "I (10000) wendy_bench: WENDY_BENCH " + json.dumps(r) + "\x1b[0m\n"
        for r in records
    ])


class BenchmarkLogTests(unittest.TestCase):
    def test_valid_timing_units_and_sensor_interval(self):
        records = boot_records() + [sensor(11_000_000, 0), sensor(16_000_000, 10)]
        report = summarize(records)
        self.assertEqual(report["copies"]["internal"]["mib_per_s"], 500)
        self.assertEqual(report["copies"]["psram"]["mib_per_s"], 80)
        self.assertEqual(report["convolution"], {"ansi_us": 100, "pie_us": 12.5, "speedup": 8})
        self.assertEqual(report["sensors"]["0"]["submitted_bytes_per_s"], 2000)
        self.assertEqual(report["sensors"]["0"]["mean_buffer_hold_us"], 100)

    def test_no_stream_activity_is_not_a_delivery_measurement(self):
        report = summarize(boot_records() + [sensor(11_000_000, 0)])
        self.assertIsNone(report["sensors"]["0"]["submitted_bytes_per_s"])
        self.assertIsNone(report["sensors"]["0"]["mean_buffer_hold_us"])

    def test_missing_record_rejected(self):
        for missing in range(len(boot_records())):
            records = boot_records()
            del records[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                summarize(records)

    def test_two_completed_boots_rejected(self):
        with self.assertRaises(ValueError):
            summarize(boot_records() * 2)

    def test_partial_second_boot_rejected(self):
        with self.assertRaises(ValueError):
            summarize(boot_records() + [sensor(11_000_000, 4), sensor(2_000_000, 0)])

    def test_counters_cannot_reset_and_then_recover(self):
        with self.assertRaises(ValueError):
            summarize(boot_records() + [sensor(11_000_000, 4), sensor(12_000_000, 0), sensor(13_000_000, 8)])

    def test_wrong_core_and_invalid_timings_rejected(self):
        for field, value in (("core", 0), ("core", True), ("ansi_us", 0),
                             ("pie_us", -1), ("iterations", True)):
            records = boot_records()
            records[3][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                summarize(records)

    def test_failed_output_validation_rejected(self):
        records = boot_records()
        records[3] = {"test": "conv_int8_1x1", "ok": False, "error": "output_mismatch"}
        with self.assertRaises(ValueError):
            summarize(records)

    def test_truncated_json_rejected(self):
        with self.assertRaises(ValueError):
            benchmark.summarize(['I (10) WENDY_BENCH {"test": "heap"'])


if __name__ == "__main__":
    unittest.main()
