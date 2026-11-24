import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def run_once(engine_path, log_file, threads, io_limit):
    cmd = [
        engine_path,
        log_file,
        "--threads", str(threads),
        "--io-limit", str(io_limit),
        "--csv", os.devnull,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError("No RESULT line received from engine.")


def run_suite(engine_path, log_file, configs, runs):
    results = []
    for threads, io_limit in configs:
        singles, multis, verified_all = [], [], True
        print(f"Testing threads={threads}, io_limit={io_limit} ({runs} runs)...", flush=True)
        for _ in range(runs):
            res = run_once(engine_path, log_file, threads, io_limit)
            singles.append(res["single_ms"])
            multis.append(res["multi_ms"])
            verified_all = verified_all and res["verified"]

        avg_single = statistics.mean(singles)
        avg_multi = statistics.mean(multis)
        std_multi = statistics.stdev(multis) if runs > 1 else 0.0
        speedup = avg_single / avg_multi if avg_multi > 0 else 0.0

        results.append({
            "threads": threads,
            "io_limit": io_limit,
            "runs": runs,
            "avg_single_ms": round(avg_single, 2),
            "avg_multi_ms": round(avg_multi, 2),
            "std_multi_ms": round(std_multi, 2),
            "speedup": round(speedup, 2),
            "verified": verified_all,
        })
    return results


def print_table(title, rows):
    print(f"\n=== {title} ===")
    header = f"{'Threads':>7} | {'I/O Lim':>7} | {'Single (ms)':>11} | {'Multi (ms)':>10} | {'Std (ms)':>8} | {'Speedup':>7} | {'Verified':>8}"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r['threads']:>7} | {r['io_limit']:>7} | {r['avg_single_ms']:>11.2f} | "
            f"{r['avg_multi_ms']:>10.2f} | {r['std_multi_ms']:>8.2f} | "
            f"{r['speedup']:>6.2f}x | {str(r['verified']):>8}"
        )


def save_csv(path, scaling_rows, io_rows):
    fields = ["suite", "threads", "io_limit", "runs", "avg_single_ms", "avg_multi_ms", "std_multi_ms", "speedup", "verified"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in scaling_rows:
            writer.writerow({"suite": "thread_scaling", **r})
        for r in io_rows:
            writer.writerow({"suite": "io_semaphore", **r})


def plot_scaling(rows, out_path):
    threads = [r["threads"] for r in rows]
    multi_ms = [r["avg_multi_ms"] for r in rows]
    stds = [r["std_multi_ms"] for r in rows]
    speedups = [r["speedup"] for r in rows]
    baseline = statistics.mean(r["avg_single_ms"] for r in rows)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5), dpi=150)

    # Execution time vs threads
    ax1.errorbar(threads, multi_ms, yerr=stds, fmt="-o", color="#2563eb", capsize=4, linewidth=2, label="Multithreaded")
    ax1.axhline(baseline, color="#64748b", linestyle="--", linewidth=1.5, label=f"Single-Threaded ({baseline:.1f} ms)")
    ax1.set_title("Execution Time vs. Thread Count", fontweight="bold")
    ax1.set_xlabel("Worker Threads")
    ax1.set_ylabel("Average Time (ms)")
    ax1.set_xticks(threads)
    ax1.grid(True, linestyle="--", alpha=0.4)
    ax1.legend()

    # Speedup vs ideal linear speedup
    ax2.plot(threads, speedups, "-o", color="#16a34a", linewidth=2, label="Measured Speedup")
    ax2.plot(threads, threads, "--", color="#94a3b8", linewidth=1.5, label="Ideal Linear Speedup")
    for x, y in zip(threads, speedups):
        ax2.annotate(f"{y:.2f}x", (x, y), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8, fontweight="bold")
    ax2.set_title("Parallel Speedup vs. Ideal Scaling", fontweight="bold")
    ax2.set_xlabel("Worker Threads")
    ax2.set_ylabel("Speedup (x)")
    ax2.set_xticks(threads)
    ax2.grid(True, linestyle="--", alpha=0.4)
    ax2.legend()

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_io_limit(rows, out_path):
    labels = [str(r["io_limit"]) for r in rows]
    times = [r["avg_multi_ms"] for r in rows]
    stds = [r["std_multi_ms"] for r in rows]
    fixed_threads = rows[0]["threads"]

    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=150)
    bars = ax.bar(labels, times, yerr=stds, capsize=5, color="#0ea5e9", width=0.5)
    ax.set_title(f"I/O Semaphore Limit Impact ({fixed_threads} Threads)", fontweight="bold")
    ax.set_xlabel("Semaphore Permit Limit (--io-limit)")
    ax.set_ylabel("Average Execution Time (ms)")
    ax.set_ylim(0, max(times) * 1.25)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    for bar, t in zip(bars, times):
        ax.text(bar.get_x() + bar.get_width() / 2, t, f"{t:.1f} ms", ha="center", va="bottom", fontsize=9, fontweight="bold")

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Benchmark the Parallel Log Processing Engine.")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("--runs", type=int, default=5, help="Runs per configuration (default: 5)")
    parser.add_argument("--threads", default="1,2,3,4,5,6,7,8", help="Comma-separated thread counts")
    parser.add_argument("--io-limits", default="1,2,4", help="Comma-separated I/O semaphore limits")
    parser.add_argument("--io-threads", type=int, default=4, help="Fixed thread count for I/O limit test")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(base_dir, "engine")
    if not os.path.isfile(engine_path):
        sys.exit(f"Error: compiled binary not found at {engine_path}")
    if not os.path.isfile(args.logfile):
        sys.exit(f"Error: log file not found at {args.logfile}")

    thread_list = [int(x) for x in args.threads.split(",")]
    io_list = [int(x) for x in args.io_limits.split(",")]

    scaling_rows = run_suite(engine_path, args.logfile, [(t, 2) for t in thread_list], args.runs)
    io_rows = run_suite(engine_path, args.logfile, [(args.io_threads, k) for k in io_list], args.runs)

    print_table("Thread Scaling Benchmark (io_limit=2)", scaling_rows)
    print_table(f"I/O Semaphore Benchmark (threads={args.io_threads})", io_rows)

    results_dir = os.path.join(base_dir, "results")
    os.makedirs(results_dir, exist_ok=True)

    csv_out = os.path.join(results_dir, "benchmark_results.csv")
    scaling_png = os.path.join(results_dir, "benchmark_scaling.png")
    io_png = os.path.join(results_dir, "benchmark_io_limit.png")

    save_csv(csv_out, scaling_rows, io_rows)
    plot_scaling(scaling_rows, scaling_png)
    plot_io_limit(io_rows, io_png)

    print(f"\nSaved:\n  - {csv_out}\n  - {scaling_png}\n  - {io_png}")

if __name__ == "__main__":
    main()