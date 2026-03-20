#!/usr/bin/env python3
"""Walk a directory reading files, and write a log — 2s pause between each."""

import os
import sys
import time
import tempfile

target = sys.argv[1] if len(sys.argv) > 1 else "/etc"
logfile = os.path.join(tempfile.gettempdir(), "walker_log.txt")

print(f"[pid {os.getpid()}] Walking {target}, 2s between ops...")
print(f"[pid {os.getpid()}] Writing log to {logfile}\n")

with open(logfile, "w") as log:
    for root, dirs, files in os.walk(target):
        for name in sorted(files):
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as f:
                    data = f.read(4096)
                msg = f"read {path} ({len(data)} bytes)\n"
                print(f"  {msg}", end="")
                log.write(msg)
                log.flush()
            except (PermissionError, OSError) as e:
                print(f"  skip {path} ({e})")
            time.sleep(2)
