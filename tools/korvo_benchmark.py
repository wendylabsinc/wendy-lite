#!/usr/bin/env python3
"""Summarize WENDY_BENCH JSON records from a Korvo-1 serial log.

Usage: python3 tools/korvo_benchmark.py benchmark.log
       python3 tools/korvo_benchmark.py benchmark.log --json

Stop the monitor after the workload finishes. Missing, failed, and truncated
benchmark runs exit nonzero. This reports kernel/copy timings, not model or
end-to-end network performance. A log containing several boots is rejected;
capture one boot per report so results cannot silently mix firmware runs.
"""

import argparse
import json
import sys
from pathlib import Path


def summarize(lines):
    records = []
    decoder = json.JSONDecoder()
    for number, line in enumerate(lines, 1):
        marker = "WENDY_BENCH "
        if marker not in line:
            continue
        try:
            record, _ = decoder.raw_decode(line.split(marker, 1)[1].lstrip())
        except (ValueError, TypeError) as error:
            raise ValueError(f"Malformed benchmark JSON on line {number}") from error
        if not isinstance(record, dict):
            raise ValueError(f"Expected a benchmark object on line {number}")
        records.append(record)

    complete = [r for r in records if r.get("test") == "complete"]
    if len(complete) != 1:
        raise ValueError("Expected one completed benchmark run; capture exactly one boot")
    if complete[0].get("ok") is not True or any(r.get("ok") is False for r in records):
        raise ValueError("The device reported a failed benchmark; inspect the serial log")
    timestamps = [r["time_us"] for r in records if "time_us" in r]
    if any(type(t) is not int or t < 0 for t in timestamps):
        raise ValueError("Invalid sample timestamp")
    if any(later < earlier for earlier, later in zip(timestamps, timestamps[1:])):
        raise ValueError("Sample timestamps decreased; capture exactly one boot")

    result = {"copies": {}}
    for memory in ("internal", "psram"):
        candidates = [r for r in records if r.get("test") == "memcpy" and r.get("memory") == memory]
        if len(candidates) != 1 or candidates[0].get("ok") is not True:
            raise ValueError(f"Expected one successful {memory} memcpy result")
        r = candidates[0]
        for key in ("block_bytes", "iterations", "elapsed_us"):
            if type(r.get(key)) is not int or r[key] <= 0:
                raise ValueError(f"Invalid {memory} memcpy {key}")
        result["copies"][memory] = {
            "block_bytes": r["block_bytes"],
            "mib_per_s": r["block_bytes"] * r["iterations"] * 1_000_000 / r["elapsed_us"] / 1024**2,
        }
    candidates = [r for r in records if r.get("test") == "conv_int8_1x1"]
    if len(candidates) != 1 or candidates[0].get("ok") is not True:
        raise ValueError("Expected one successful INT8 convolution result")
    r = candidates[0]
    if type(r.get("core")) is not int or r["core"] != 1:
        raise ValueError("The S31 PIE benchmark must run on Core 1")
    for key in ("iterations", "ansi_us", "pie_us"):
        if type(r.get(key)) is not int or r[key] <= 0:
            raise ValueError(f"Invalid convolution {key}")
    result["convolution"] = {
        "ansi_us": r["ansi_us"] / r["iterations"],
        "pie_us": r["pie_us"] / r["iterations"],
        "speedup": r["ansi_us"] / r["pie_us"],
    }
    heaps = [r for r in records if r.get("test") == "heap"]
    if not heaps:
        raise ValueError("No heap samples in the log")
    keys = ("internal_min", "internal_largest", "dma_largest", "psram_free")
    for r in heaps:
        if any(type(r.get(key)) is not int or r[key] < 0 for key in keys):
            raise ValueError("Invalid heap sample")
    result["heap_samples"] = len(heaps)
    result["minimum_bytes"] = {key: min(r[key] for r in heaps) for key in keys}
    result["sensors"] = {}
    for channel in (0, 1):
        samples = [r for r in records if r.get("test") == "sensor" and r.get("channel") == channel]
        if not samples:
            continue
        fields = ("time_us", "frames_submitted", "frames_completed", "bytes_submitted",
                  "capture_errors", "queue_rejected", "completion_time_us", "completion_time_max_us")
        if any(type(r.get(key)) is not int or r[key] < 0 for r in samples for key in fields):
            raise ValueError(f"Invalid sensor sample for channel {channel}")
        first, last = samples[0], samples[-1]
        if any(later[key] < earlier[key] for earlier, later in zip(samples, samples[1:]) for key in fields):
            raise ValueError(f"Sensor counters decreased for channel {channel}; capture one boot")
        seconds = (last["time_us"] - first["time_us"]) / 1_000_000
        # These measure submissions and buffer ownership, not successful wire delivery.
        result["sensors"][str(channel)] = {
            "frames_submitted": last["frames_submitted"],
            "capture_errors": last["capture_errors"],
            "queue_rejected": last["queue_rejected"],
            "mean_buffer_hold_us": last["completion_time_us"] / last["frames_completed"] if last["frames_completed"] else None,
            "max_buffer_hold_us": last["completion_time_max_us"],
            "submitted_bytes_per_s": (last["bytes_submitted"] - first["bytes_submitted"]) / seconds if seconds > 0 else None,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="serial log, or - for standard input")
    parser.add_argument("--json", action="store_true", help="print a machine-readable summary")
    args = parser.parse_args()
    try:
        if args.log == "-":
            result = summarize(sys.stdin)
        else:
            with Path(args.log).open(errors="replace") as log:
                result = summarize(log)
    except (OSError, ValueError) as error:
        print(f"Benchmark report failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for memory, r in result["copies"].items():
            print(f"{memory} memcpy, {r['block_bytes'] // 1024} KiB blocks: {r['mib_per_s']:.2f} MiB/s")
        r = result["convolution"]
        print(f"INT8 1x1 convolution: ANSI {r['ansi_us']:.1f} us, PIE {r['pie_us']:.1f} us, {r['speedup']:.2f}x")
        print(f"Minimum headroom across {result['heap_samples']} heap samples:")
        for key, value in result["minimum_bytes"].items():
            print(f"  {key}: {value} bytes")
        for channel, r in result["sensors"].items():
            print(f"Channel {channel}: {r['frames_submitted']} frames submitted, "
                  f"{r['capture_errors']} capture errors, {r['queue_rejected']} queue refusals, "
                  f"{r['max_buffer_hold_us']} us maximum buffer hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
