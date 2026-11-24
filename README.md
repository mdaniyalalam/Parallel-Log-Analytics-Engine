# Parallel Log Processing & Analytics Engine

A high-performance, multithreaded log analysis engine written in **C++11** using native POSIX concurrency primitives (`pthreads`, counting semaphores, mutexes, and `pread()`), paired with a decoupled **Python** (`tkinter` + `matplotlib`) real-time analytics dashboard and an automated benchmarking suite.

Built as a final project for **Operating Systems (CS2006)** at FAST-NUCES Karachi.

---

## Features

- **Newline-Aligned Log Segmentation:** Divides large log files into byte-offset chunks aligned to `\n` boundaries so no entry is split or double-counted across threads.
- **Thread-Safe Concurrent I/O:** Uses POSIX `pread()` for offset-based reads without a shared file cursor, throttled by a counting semaphore (`sem_t io_sem`) scoped strictly around disk reads.
- **Low-Contention Multithreading:** Worker threads dynamically claim chunks via `queue_mutex`, parse completely lock-free into thread-local `Stats` structures, and merge into global counters once per chunk under `stats_mutex`.
- **Severity & Threat Detection:** Classifies every line (`INFO`, `WARNING`, `ERROR`, `CRITICAL`), detects failed logins, invalid users, break-in attempts, and `sudo` failures, extracts IPv4 addresses, and flags brute-force sources (`>= 5` suspicious events).
- **Built-In Integrity Verification:** Warms the OS page cache and compares every multithreaded counter and IP frequency map against a single-threaded baseline (`verified: true`).
- **Real-Time GUI & CSV Export:** Streams `PHASE`, `PROGRESS`, `STATS`, and `RESULT` updates over `stdout` to a live Python dashboard and exports structured summaries to `report.csv`.

---

## Architecture

```text
Log File ──▶ engine.cpp (C++11 POSIX Threads) ──▶ stdout (PHASE / PROGRESS / STATS / RESULT) ──▶ gui.py (Tkinter + Matplotlib)
