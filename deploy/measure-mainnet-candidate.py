#!/usr/bin/env python3
"""Reproducible local or server benchmark runner. Does not install or deploy anything."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=("accelerated", "sustained"), default="sustained")
parser.add_argument("--transactions", type=int, default=1024,
                    help="accelerated mode only; 1..18000")
args = parser.parse_args()
if not 1 <= args.transactions <= 18000:
    parser.error("--transactions must be between 1 and 18000")

name = ("benchmark_local_confirmed_pipeline" if args.mode == "accelerated"
        else "benchmark_sustained_confirmed_tps")
command = ["cargo", "test", "--locked", "--release", "--features", "mainnet-candidate",
           "--lib", "candidate_node::tests::" + name,
           "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
env = os.environ.copy()
env["TENEBRA_BENCH_TRANSACTIONS"] = str(args.transactions)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
output = ROOT / "docs" / "performance"
output.mkdir(parents=True, exist_ok=True)
base = output / ("confirmed-tps-" + args.mode + "-" + stamp)
metadata = {
    "started_utc": stamp, "mode": args.mode, "command": command,
    "platform": platform.platform(), "processor": platform.processor(),
    "logical_cpus": os.cpu_count(),
    "scope": "single host, controlled chain, actual TCP/disk/PoW/ten successor blocks",
    "limitations": [
        "Not a public-network or independent-server measurement.",
        "Client proof construction and initial chain preparation are outside the timed section.",
        "Accelerated mode does not measure sustained wall-clock confirmations.",
        "Sustained mode deliberately paces four workload blocks at real 30-second intervals.",
        "This benchmark does not establish anonymity strength or consensus security.",
    ],
    "source_sha256": {},
}
for path in sorted((ROOT / "src").rglob("*.rs")):
    metadata["source_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
for name in ("Cargo.toml", "Cargo.lock", "config/mainnet-genesis.hex"):
    metadata["source_sha256"][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
meta_path = base.with_suffix(".json")
meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
metrics = {}
print("Logging to", base.with_suffix(".log"), flush=True)
try:
    with base.with_suffix(".log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
            log.flush()
            for key, value in re.findall(r"([a-z_]+)=([0-9]+(?:\.[0-9]+)?)", line):
                metrics[key] = float(value)
        code = process.wait()
except OSError as error:
    metadata["runner_error"] = str(error)
    code = 1
metadata["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
metadata["exit_code"] = code
metadata["metrics"] = metrics
metadata["local_150_tps_gate_passed"] = (
    args.mode == "sustained" and code == 0
    and metrics.get("steady_confirmed_tps", 0) >= 150
    and metrics.get("minimum_window_confirmed_tps", 0) >= 150
)
metadata["public_mainnet_verified"] = False
meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
sys.exit(code)
