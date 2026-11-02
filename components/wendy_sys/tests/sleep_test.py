#!/usr/bin/env python3
"""Check production host-sleep cancellation with a simulated FreeRTOS clock.

Run with python3 components/wendy_sys/tests/sleep_test.py [--sanitize].
No ESP-IDF installation or hardware is required.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    source = (tests.parent / "src/wendy_sys.c").read_text()
    start = source.index("static void sys_sleep_ms_wrapper(")
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    with tempfile.TemporaryDirectory(prefix="wendy-host-sleep-") as temp:
        work = Path(temp)
        (work / "sleep_production.inc").write_text(source[start:end] + "\n")
        for tick_ms in (1, 10, 100):
            binary = work / f"sleep-{tick_ms}"
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-parameter", "-Wno-unused-function",
                f"-DTICK_MS={tick_ms}", "-I", str(work),
                str(tests / "sleep_test.c"), "-o", str(binary),
            ]
            if args.sanitize:
                command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            subprocess.run(command, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
