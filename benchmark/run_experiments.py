#!/usr/bin/env python3
"""
SecLab DoS Mitigation - Benchmark Orchestrator & Telemetry Sampler
Module: benchmark.run_experiments

Automates:
  1. High-frequency PostgreSQL resource telemetry sampling (CPU %, RAM) via docker stats
  2. Execution of Scenario A (Direct Unprotected Backend on :8000)
  3. Cooldown and buffer flush period (30s)
  4. Execution of Scenario B (Protected Reverse Proxy Gateway on :8080)
  5. Persistence of datasets into benchmark/data/ for academic plotting
"""

from __future__ import annotations

import csv
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("orchestrator")

BENCHMARK_DIR = Path(__file__).resolve().parent
DATA_DIR = BENCHMARK_DIR / "data"
LOAD_TEST_SCRIPT = BENCHMARK_DIR / "load_test.js"

CONTAINER_NAME = "seclab-postgres"
SAMPLE_INTERVAL_S = 1.0


class DockerStatsSampler:
    """Samples PostgreSQL container resource consumption in background thread."""

    def __init__(self, output_csv: Path, container_name: str = CONTAINER_NAME) -> None:
        self.output_csv = output_csv
        self.container_name = container_name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Started docker stats sampler -> %s", self.output_csv.name)

    def stop(self) -> None:
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=5.0)
            logger.info("Stopped docker stats sampler.")

    def _run(self) -> None:
        t_start = time.perf_counter()
        self.output_csv.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["time_s", "cpu_percent", "memory_mb", "raw_mem"])

            while not self._stop_event.is_set():
                t_rel = round(time.perf_counter() - t_start, 2)
                try:
                    # Run docker stats without streaming
                    res = subprocess.run(
                        ["docker", "stats", self.container_name, "--no-stream", "--format", "{{.CPUPerc}},{{.MemUsage}}"],
                        capture_output=True,
                        text=True,
                        timeout=2.0,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        parts = res.stdout.strip().split(",")
                        if len(parts) >= 2:
                            cpu_str = parts[0].replace("%", "").strip()
                            mem_str = parts[1].strip()

                            cpu_val = float(cpu_str) if cpu_str else 0.0

                            # Parse memory string e.g. "312.4MiB / 512MiB"
                            mem_mb = 0.0
                            mem_match = re.match(r"([0-9.]+)\s*([A-Za-z]+)", mem_str)
                            if mem_match:
                                val = float(mem_match.group(1))
                                unit = mem_match.group(2).upper()
                                if "G" in unit:
                                    mem_mb = val * 1024.0
                                elif "M" in unit:
                                    mem_mb = val
                                elif "K" in unit:
                                    mem_mb = val / 1024.0

                            writer.writerow([t_rel, cpu_val, round(mem_mb, 2), mem_str])
                            f.flush()
                except Exception as exc:
                    logger.debug("Sampling tick exception: %s", exc)

                time.sleep(SAMPLE_INTERVAL_S)


def run_k6(target_url: str, summary_file: Path) -> bool:
    """Invokes k6 benchmark scenario."""
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if k6 is installed
    k6_bin = shutil.which("k6")
    env = os.environ.copy()
    env["TARGET_URL"] = target_url
    env["SUMMARY_FILE"] = str(summary_file)

    if k6_bin:
        cmd = ["k6", "run", str(LOAD_TEST_SCRIPT)]
    else:
        logger.warning(
            "k6 CLI not found in system PATH. Attempting fallback via docker container (grafana/k6)..."
        )
        docker_bin = shutil.which("docker")
        if not docker_bin:
            logger.error("Neither k6 nor docker CLI found. Please install k6 or Docker.")
            return False

        # Map local benchmark directory into container
        cmd = [
            "docker", "run", "--rm",
            "--network", "host",
            "-v", f"{BENCHMARK_DIR}:/benchmark",
            "-e", f"TARGET_URL={target_url}",
            "-e", f"SUMMARY_FILE=/benchmark/data/{summary_file.name}",
            "grafana/k6:latest",
            "run", "/benchmark/load_test.js",
        ]

    logger.info("Executing Benchmark: %s (Target: %s)", " ".join(cmd), target_url)
    try:
        proc = subprocess.run(cmd, env=env, text=True)
        return proc.returncode == 0
    except Exception as exc:
        logger.error("Failed to execute k6 benchmark: %s", exc)
        return False


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SecLab DoS Mitigation - Automated Empirical Experimentation Suite")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # Scenario A: Unprotected Direct Backend (Port 8000)
    # -------------------------------------------------------------------------
    print("\n>>> [1/4] Running Scenario A: Unprotected Baseline (Direct Backend :8000) <<<")
    stats_a = DATA_DIR / "stats_direct_docker.csv"
    summary_a = DATA_DIR / "k6_direct_summary.json"

    sampler_a = DockerStatsSampler(output_csv=stats_a)
    sampler_a.start()

    success_a = run_k6("http://localhost:8000", summary_a)
    sampler_a.stop()

    if not success_a:
        logger.warning("Scenario A encountered errors or was interrupted.")

    # -------------------------------------------------------------------------
    # Cooldown & Buffer Pool Normalization
    # -------------------------------------------------------------------------
    cooldown_s = 30
    print(f"\n>>> [2/4] Cooling down infrastructure for {cooldown_s}s (flushing DB locks & queues)... <<<")
    for sec in range(cooldown_s, 0, -5):
        print(f"  Waiting... {sec}s remaining")
        time.sleep(5)

    # -------------------------------------------------------------------------
    # Scenario B: Protected Reverse Proxy Gateway (Port 8080)
    # -------------------------------------------------------------------------
    print("\n>>> [3/4] Running Scenario B: Protected Architecture (Reverse Proxy Gateway :8080) <<<")
    stats_b = DATA_DIR / "stats_proxy_docker.csv"
    summary_b = DATA_DIR / "k6_proxy_summary.json"

    sampler_b = DockerStatsSampler(output_csv=stats_b)
    sampler_b.start()

    success_b = run_k6("http://localhost:8080", summary_b)
    sampler_b.stop()

    if not success_b:
        logger.warning("Scenario B encountered errors or was interrupted.")

    # -------------------------------------------------------------------------
    # Completion & Next Steps
    # -------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print(">>> [4/4] Experiments Finished Successfully! <<<")
    print(f"Data saved to: {DATA_DIR}")
    print("  - Direct Docker Stats: stats_direct_docker.csv")
    print("  - Direct k6 Summary:   k6_direct_summary.json")
    print("  - Proxy Docker Stats:  stats_proxy_docker.csv")
    print("  - Proxy k6 Summary:    k6_proxy_summary.json")
    print("\nGenerate publication plots by running:")
    print("  python3 benchmark/plot_results.py")
    print("=" * 80)


if __name__ == "__main__":
    main()
