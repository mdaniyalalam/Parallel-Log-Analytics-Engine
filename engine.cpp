#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

struct Segment {
    off_t start;
    off_t end;
};

struct Stats {
    uint64_t total_lines = 0;
    uint64_t info = 0;
    uint64_t warning = 0;
    uint64_t error = 0;
    uint64_t critical = 0;
    uint64_t failed_logins = 0;
    uint64_t invalid_users = 0;
    uint64_t breakin_attempts = 0;
    uint64_t sudo_failures = 0;

    std::unordered_map<std::string, uint64_t> ip_counts;

    void merge(const Stats& other) {
        total_lines += other.total_lines;
        info += other.info;
        warning += other.warning;
        error += other.error;
        critical += other.critical;
        failed_logins += other.failed_logins;
        invalid_users += other.invalid_users;
        breakin_attempts += other.breakin_attempts;
        sudo_failures += other.sudo_failures;
        for (const auto& kv : other.ip_counts) {
            ip_counts[kv.first] += kv.second;
        }
    }
};

struct SharedContext {
    int fd;
    const std::vector<Segment>* segments;
    int next_segment;
    int completed_segments;
    int last_progress;
    bool read_failed;

    sem_t io_sem;                 // limits concurrent disk reads
    pthread_mutex_t queue_mutex;  // protects dynamic segment assignment
    pthread_mutex_t stats_mutex;  // protects global stats aggregation

    Stats global_stats;
};

// Extract the first valid IPv4 address from a log line
static std::string extract_ip(const std::string& line) {
    size_t n = line.size();
    for (int i = 0; i < n; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(line[i]))) continue;
        if (i > 0 && (std::isdigit(static_cast<unsigned char>(line[i - 1])) || line[i - 1] == '.')) continue;

        size_t pos = i;
        int octets = 0;
        bool valid = true;

        while (octets < 4) {
            if (pos >= n || !std::isdigit(static_cast<unsigned char>(line[pos]))) {
                valid = false;
                break;
            }
            int val = 0, digits = 0;
            while (pos < n && std::isdigit(static_cast<unsigned char>(line[pos]))) {
                val = val * 10 + (line[pos] - '0');
                ++pos;
                if (++digits > 3) { valid = false; break; }
            }
            if (!valid || val > 255) { valid = false; break; }
            ++octets;
            if (octets < 4) {
                if (pos >= n || line[pos] != '.') { valid = false; break; }
                ++pos;
            }
        }

        if (valid && (pos == n || (!std::isdigit(static_cast<unsigned char>(line[pos])) && line[pos] != '.'))) {
            return line.substr(i, pos - i);
        }
    }
    return "";
}

// Classify one line and update local stats (lock-free)
static void process_line(const std::string& line, std::string& lower, Stats& local) {
    if (line.empty()) return;
    local.total_lines++;

    lower.resize(line.size());
    for (int i = 0; i < line.size(); ++i) {
        lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(line[i])));
    }

    // 1. Severity classification (highest severity wins)
    if (lower.find("critical") != std::string::npos ||
        lower.find("fatal") != std::string::npos ||
        lower.find("panic") != std::string::npos ||
        lower.find("emerg") != std::string::npos ||
        lower.find("possible break-in") != std::string::npos ||
        lower.find("segfault") != std::string::npos) {
        local.critical++;
    } else if (lower.find("error") != std::string::npos ||
               lower.find("failed") != std::string::npos ||
               lower.find("failure") != std::string::npos ||
               lower.find("invalid user") != std::string::npos ||
               lower.find("denied") != std::string::npos ||
               lower.find("refused") != std::string::npos) {
        local.error++;
    } else if (lower.find("warning") != std::string::npos ||
               lower.find("warn") != std::string::npos ||
               lower.find("timeout") != std::string::npos ||
               lower.find("timed out") != std::string::npos ||
               lower.find("connection closed") != std::string::npos ||
               lower.find("did not receive identification") != std::string::npos) {
        local.warning++;
    } else {
        local.info++;
    }

    // 2. Security pattern detection
    bool suspicious = false;
    if (lower.find("failed password") != std::string::npos ||
        lower.find("authentication failure") != std::string::npos) {
        local.failed_logins++;
        suspicious = true;
    }
    if (lower.find("invalid user") != std::string::npos) {
        local.invalid_users++;
        suspicious = true;
    }
    if (lower.find("possible break-in") != std::string::npos) {
        local.breakin_attempts++;
        suspicious = true;
    }
    if (lower.find("sudo") != std::string::npos &&
        (lower.find("incorrect password") != std::string::npos ||
         lower.find("authentication failure") != std::string::npos ||
         lower.find("not in sudoers") != std::string::npos)) {
        local.sudo_failures++;
        suspicious = true;
    }

    if (suspicious) {
        std::string ip = extract_ip(line);
        if (!ip.empty()) {
            local.ip_counts[ip]++;
        }
    }
}

// Parse an in-memory buffer line by line
static void parse_buffer(const std::string& buffer, Stats& local) {
    std::string line, lower;
    line.reserve(256);
    lower.reserve(256);

    size_t start = 0;
    while (start < buffer.size()) {
        size_t nl = buffer.find('\n', start);
        if (nl == std::string::npos) {
            line.assign(buffer, start, buffer.size() - start);
            start = buffer.size();
        } else {
            size_t len = nl - start;
            if (len > 0 && buffer[start + len - 1] == '\r') len--;
            line.assign(buffer, start, len);
            start = nl + 1;
        }
        process_line(line, lower, local);
    }
}

// Read exact byte range using thread-safe pread()
static bool read_segment(int fd, const Segment& seg, std::string& out) {
    size_t len = static_cast<size_t>(seg.end - seg.start);
    out.resize(len);
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = pread(fd, &out[offset], len - offset, seg.start + static_cast<off_t>(offset));
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

// Split file into newline-aligned byte segments
static std::vector<Segment> create_segments(int fd, off_t file_size, int num_chunks) {
    std::vector<Segment> segments;
    if (file_size <= 0) return segments;

    off_t start = 0;
    char scan_buf[4096];

    for (int i = 0; i < num_chunks && start < file_size; ++i) {
        off_t end = file_size;
        if (i < num_chunks - 1) {
            off_t target = (file_size * (i + 1)) / num_chunks;
            if (target < start) target = start;

            // Nudge boundary forward to the next newline
            off_t pos = target;
            bool found = false;
            while (pos < file_size && !found) {
                ssize_t n = pread(fd, scan_buf, sizeof(scan_buf), pos);
                if (n <= 0) break;
                for (ssize_t k = 0; k < n; ++k) {
                    if (scan_buf[k] == '\n') {
                        end = pos + k + 1;
                        found = true;
                        break;
                    }
                }
                pos += n;
            }
        }
        if (end > start) {
            segments.push_back({start, end});
            start = end;
        }
    }
    return segments;
}

static void emit_live_stats(const Stats& g, int pct);

// Worker thread routine
static void* worker_thread(void* arg) {
    auto* ctx = static_cast<SharedContext*>(arg);
    std::string buffer;

    while (true) {
        int idx = 0;
        pthread_mutex_lock(&ctx->queue_mutex);
        if (ctx->next_segment >= ctx->segments->size()) {
            pthread_mutex_unlock(&ctx->queue_mutex);
            break;
        }
        idx = ctx->next_segment++;
        pthread_mutex_unlock(&ctx->queue_mutex);

        // Acquire I/O semaphore only for the disk read
        sem_wait(&ctx->io_sem);
        bool ok = read_segment(ctx->fd, (*ctx->segments)[idx], buffer);
        sem_post(&ctx->io_sem);
        if (!ok) {
            pthread_mutex_lock(&ctx->stats_mutex);
            ctx->read_failed = true;
            pthread_mutex_unlock(&ctx->stats_mutex);
            buffer.clear();
        }

        // Parse locally without holding any locks
        Stats local_stats;
        parse_buffer(buffer, local_stats);

        // Merge into global stats in a short critical section
        pthread_mutex_lock(&ctx->stats_mutex);
        ctx->global_stats.merge(local_stats);
        ctx->completed_segments++;
        int pct = static_cast<int>((ctx->completed_segments * 100) / ctx->segments->size());
        if (pct > ctx->last_progress) {
            ctx->last_progress = pct;
            std::cout << "PROGRESS " << pct << "\n" << std::flush;
            emit_live_stats(ctx->global_stats, pct);
        }
        pthread_mutex_unlock(&ctx->stats_mutex);
    }
    return nullptr;
}

// Single-threaded baseline for verification and speedup comparison
static Stats run_single_threaded(int fd, const std::vector<Segment>& segments) {
    Stats total;
    std::string buffer;
    for (const auto& seg : segments) {
        read_segment(fd, seg, buffer);
        parse_buffer(buffer, total);
    }
    return total;
}

static std::string json_escape(const std::string& s);

// Emit a live snapshot of the global counters (caller must hold stats_mutex)
static void emit_live_stats(const Stats& g, int pct) {
    std::cout << "STATS {"
              << "\"progress\":" << pct << ","
              << "\"lines\":" << g.total_lines << ","
              << "\"info\":" << g.info << ","
              << "\"warning\":" << g.warning << ","
              << "\"error\":" << g.error << ","
              << "\"critical\":" << g.critical << ","
              << "\"failed_logins\":" << g.failed_logins << ","
              << "\"invalid_users\":" << g.invalid_users << ","
              << "\"breakin_attempts\":" << g.breakin_attempts << ","
              << "\"sudo_failures\":" << g.sudo_failures << "}\n" << std::flush;
}

static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    return out;
}

static void write_csv(const std::string& path, const std::string& log_file, double size_mb,
                      int threads, int io_limit, double single_ms, double multi_ms,
                      double speedup, bool verified, const Stats& s,
                      const std::vector<std::pair<std::string, uint64_t>>& top_ips) {
    std::ofstream out(path);
    if (!out) return;

    out << "Section,Metric,Value\n";
    out << "Run,Log File,\"" << log_file << "\"\n";
    out << "Run,File Size (MB)," << std::fixed << std::setprecision(2) << size_mb << "\n";
    out << "Run,Threads," << threads << "\n";
    out << "Run,IO Semaphore Limit," << io_limit << "\n";
    out << "Run,Total Lines," << s.total_lines << "\n";
    out << "Performance,Single-Threaded (ms)," << single_ms << "\n";
    out << "Performance,Multithreaded (ms)," << multi_ms << "\n";
    out << "Performance,Speedup (x)," << speedup << "\n";
    out << "Validation,Counts Match Baseline," << (verified ? "TRUE" : "FALSE") << "\n";
    out << "Severity,INFO," << s.info << "\n";
    out << "Severity,WARNING," << s.warning << "\n";
    out << "Severity,ERROR," << s.error << "\n";
    out << "Severity,CRITICAL," << s.critical << "\n";
    out << "Patterns,Failed Logins," << s.failed_logins << "\n";
    out << "Patterns,Invalid Users," << s.invalid_users << "\n";
    out << "Patterns,Break-in Attempts," << s.breakin_attempts << "\n";
    out << "Patterns,Sudo Failures," << s.sudo_failures << "\n";

    out << "\nSuspicious IP,Event Count,Brute-Force Flag (>=5)\n";
    for (const auto& kv : top_ips) {
        out << kv.first << "," << kv.second << "," << (kv.second >= 5 ? "YES" : "NO") << "\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <logfile> [--threads N] [--io-limit K] [--csv report.csv]\n";
        return 1;
    }

    std::string log_file = argv[1];
    int num_threads = 4;
    int io_limit = 2;
    std::string csv_path = "report.csv";

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--threads" && i + 1 < argc) num_threads = std::max(1, std::atoi(argv[++i]));
        else if (arg == "--io-limit" && i + 1 < argc) io_limit = std::max(1, std::atoi(argv[++i]));
        else if (arg == "--csv" && i + 1 < argc) csv_path = argv[++i];
    }

    int fd = open(log_file.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "ERROR: Cannot open file: " << log_file << "\n";
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        std::cerr << "ERROR: Cannot stat file.\n";
        return 1;
    }

    off_t file_size = st.st_size;
    double size_mb = static_cast<double>(file_size) / (1024.0 * 1024.0);
    int num_chunks = (file_size > 1024 * 1024) ? std::max(num_threads * 4, 20) : num_threads;
    std::vector<Segment> segments = create_segments(fd, file_size, num_chunks);

    // 0. Warm the OS page cache to avoid cold reads
    {
        std::string warm;
        for (const auto& seg : segments) read_segment(fd, seg, warm);
    }

    // 1. Run single-threaded baseline
    std::cout << "PHASE baseline\n" << std::flush;
    auto t0 = std::chrono::steady_clock::now();
    Stats single_stats = run_single_threaded(fd, segments);
    auto t1 = std::chrono::steady_clock::now();
    double single_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // 2. Run multithreaded engine
    SharedContext ctx{};
    ctx.fd = fd;
    ctx.segments = &segments;
    ctx.next_segment = 0;
    ctx.completed_segments = 0;
    ctx.last_progress = 0;
    ctx.read_failed = false;

    sem_init(&ctx.io_sem, 0, static_cast<unsigned int>(io_limit));
    pthread_mutex_init(&ctx.queue_mutex, nullptr);
    pthread_mutex_init(&ctx.stats_mutex, nullptr);

    std::vector<pthread_t> threads(num_threads);
    std::cout << "PHASE multithreaded\n" << std::flush;
    auto t2 = std::chrono::steady_clock::now();
    for (int i = 0; i < num_threads; ++i) {
        if (pthread_create(&threads[i], nullptr, worker_thread, &ctx) != 0) {
            std::cerr << "ERROR: pthread_create failed\n";
            return 1;
        }
    }
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], nullptr);
    }
    auto t3 = std::chrono::steady_clock::now();
    double multi_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    sem_destroy(&ctx.io_sem);
    pthread_mutex_destroy(&ctx.queue_mutex);
    pthread_mutex_destroy(&ctx.stats_mutex);
    close(fd);

    // 3. Verify exact match against single-threaded baseline
    const Stats& ms = ctx.global_stats;
    bool verified = (single_stats.total_lines == ms.total_lines &&
                     single_stats.info == ms.info &&
                     single_stats.warning == ms.warning &&
                     single_stats.error == ms.error &&
                     single_stats.critical == ms.critical &&
                     single_stats.failed_logins == ms.failed_logins &&
                     single_stats.invalid_users == ms.invalid_users &&
                     single_stats.breakin_attempts == ms.breakin_attempts &&
                     single_stats.sudo_failures == ms.sudo_failures &&
                     single_stats.ip_counts == ms.ip_counts &&
                     !ctx.read_failed);

    double speedup = (multi_ms > 0.0) ? (single_ms / multi_ms) : 0.0;

    // 4. Rank top 10 suspicious IPs and count brute-force sources (>= 5 events)
    std::vector<std::pair<std::string, uint64_t>> ranked_ips(ms.ip_counts.begin(), ms.ip_counts.end());
    std::sort(ranked_ips.begin(), ranked_ips.end(),
              [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b) {
                  return a.second > b.second;
              });

    uint64_t brute_force_ips = 0;
    for (const auto& kv : ranked_ips) {
        if (kv.second >= 5) brute_force_ips++;
    }
    if (ranked_ips.size() > 10) ranked_ips.resize(10);

    // 5. Export CSV report
    write_csv(csv_path, log_file, size_mb, num_threads, io_limit,
              single_ms, multi_ms, speedup, verified, ms, ranked_ips);

    // 6. Emit final JSON payload for the Python GUI
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "\nRESULT {"
              << "\"file\":\"" << json_escape(log_file) << "\","
              << "\"file_size_mb\":" << size_mb << ","
              << "\"threads\":" << num_threads << ","
              << "\"io_limit\":" << io_limit << ","
              << "\"total_lines\":" << ms.total_lines << ","
              << "\"single_ms\":" << single_ms << ","
              << "\"multi_ms\":" << multi_ms << ","
              << "\"speedup\":" << speedup << ","
              << "\"verified\":" << (verified ? "true" : "false") << ","
              << "\"csv_path\":\"" << json_escape(csv_path) << "\","
              << "\"severity\":{"
              << "\"info\":" << ms.info << ","
              << "\"warning\":" << ms.warning << ","
              << "\"error\":" << ms.error << ","
              << "\"critical\":" << ms.critical << "},"
              << "\"patterns\":{"
              << "\"failed_logins\":" << ms.failed_logins << ","
              << "\"invalid_users\":" << ms.invalid_users << ","
              << "\"breakin_attempts\":" << ms.breakin_attempts << ","
              << "\"sudo_failures\":" << ms.sudo_failures << ","
              << "\"brute_force_ips\":" << brute_force_ips << "},"
              << "\"top_ips\":[";

    for (int i = 0; i < ranked_ips.size(); ++i) {
        if (i > 0) std::cout << ",";
        std::cout << "{\"ip\":\"" << ranked_ips[i].first << "\",\"count\":" << ranked_ips[i].second << "}";
    }
    std::cout << "]}\n" << std::flush;

    return 0;
}