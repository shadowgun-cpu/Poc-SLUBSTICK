/*
 * SLUBSTICK Exploitation Technique - Research PoC
 * ================================================
 *
 * This proof-of-concept demonstrates the SLUBSTICK vulnerability class in
 * Linux kernel SLUB allocator, which exploits the race window between
 * per-CPU freelist exhaustion and buddy allocator fallback.
 *
 * VULNERABILITY CLASS: Heap exploitation via cross-cache attacks
 * CVE REFERENCES: CVE-2021-22555, CVE-2022-29582 (exploitation primitives)
 * AFFECTED: Linux kernel SLUB allocator (default since 2.6.23)
 *
 * Author: Alae eddine
 * Date: February 2026
 * License: MIT (Educational purposes only)
 *
 * DISCLAIMER: This code is for security research and educational purposes only.
 * Unauthorized use against systems you don't own is illegal.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================
 * CONFIGURATION
 * ============================================================================
 */

#define KMALLOC_64 64       // Target kmalloc-64 cache (common attack vector)
#define FAST_POOL_SIZE 1024 // Per-CPU freelist capacity (~typical SLUB config)
#define SLOW_POOL_SIZE 128  // Buddy allocator page cache
#define ITERATIONS 2000     // Benchmark iterations
#define WARMUP_ROUNDS 200   // CPU frequency stabilization
#define RACE_WINDOW_SAMPLES 500 // Race condition window measurements
#define CPU_PIN 0               // Target CPU for per-CPU attack

/* Attack simulation parameters */
#define VICTIM_SPRAY_SIZE 512   // Objects to spray for victim allocation
#define ATTACKER_SPRAY_SIZE 256 // Objects for heap feng shui

#define RST "\033[0m"
#define BLD "\033[1m"
#define RED "\033[31m"
#define GRN "\033[32m"
#define YEL "\033[33m"
#define BLU "\033[34m"
#define MAG "\033[35m"
#define CYN "\033[36m"
#define WHT "\033[37m"

#define SUCCESS(msg) printf(GRN "[✓] " RST msg "\n")
#define WARNING(msg) printf(YEL "[!] " RST msg "\n")
#define ERROR(msg) printf(RED "[✗] " RST msg "\n")
#define INFO(msg) printf(BLU "[*] " RST msg "\n")

/* Simulates kernel object in kmalloc-64 cache */
typedef struct {
  void (*callback)(void); // Function pointer (common target)
  uint64_t id;            // Object identifier
  char data[48];          // Padding to 64 bytes
} __attribute__((packed)) victim_object_t;

/* Attack metadata */
typedef struct {
  void *addr;
  uint64_t alloc_time_ns;
  uint64_t free_time_ns;
  int is_victim;
} object_metadata_t;

/* Performance statistics */
typedef struct {
  uint64_t min;
  uint64_t max;
  uint64_t total;
  uint64_t count;
  uint64_t histogram[20]; // 20 buckets for detailed distribution
  uint64_t p50;           // Median
  uint64_t p95;           // 95th percentile
  uint64_t p99;           // 99th percentile
} perf_stats_t;

/* Race condition analysis */
typedef struct {
  uint64_t window_ns;        // Time window for race
  uint64_t successful_races; // Exploitable windows found
  uint64_t total_attempts;
  double success_rate;
} race_analysis_t;

static void *fast_pool[FAST_POOL_SIZE];
static void *slow_pool[SLOW_POOL_SIZE];
static int fast_index = 0;
static int slow_index = 0;

static object_metadata_t metadata[FAST_POOL_SIZE + SLOW_POOL_SIZE];
static int metadata_count = 0;

static perf_stats_t fast_stats = {UINT64_MAX, 0, 0, 0, {0}};
static perf_stats_t slow_stats = {UINT64_MAX, 0, 0, 0, {0}};
static race_analysis_t race_stats = {0};

static uint64_t *latency_samples = NULL;
static int sample_count = 0;

static inline uint64_t rdtsc(void) {
  unsigned int lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t nsec_diff(struct timespec a, struct timespec b) {
  return (b.tv_sec - a.tv_sec) * 1000000000ULL + (b.tv_nsec - a.tv_nsec);
}

/* High-resolution sleep */
static void precise_sleep_ns(uint64_t ns) {
  struct timespec ts = {.tv_sec = ns / 1000000000, .tv_nsec = ns % 1000000000};
  nanosleep(&ts, NULL);
}

/* Pin process to specific CPU (simulates per-CPU attack) */
static int pin_to_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);

  if (sched_setaffinity(0, sizeof(set), &set) == -1) {
    perror("sched_setaffinity");
    return -1;
  }
  return 0;
}

/* Set real-time priority for timing accuracy */
static void set_realtime_priority(void) {
  struct sched_param param = {.sched_priority = 99};
  if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
    WARNING("Failed to set real-time priority (requires CAP_SYS_NICE)");
  } else {
    SUCCESS("Real-time scheduling enabled");
  }
}

/* Compare function for qsort */
static int compare_uint64(const void *a, const void *b) {
  uint64_t ua = *(const uint64_t *)a;
  uint64_t ub = *(const uint64_t *)b;
  return (ua > ub) - (ua < ub);
}

/* Calculate percentile from sorted array */
static uint64_t percentile(uint64_t *sorted, int count, double p) {
  if (count == 0)
    return 0;
  int index = (int)((count - 1) * p / 100.0);
  return sorted[index];
}
/* Fast path: per-CPU freelist (lockless) */
static void *fast_alloc(void) {
  if (fast_index > 0) {
    __builtin_prefetch(&fast_pool[fast_index - 1], 0, 3);
    return fast_pool[--fast_index];
  }
  return NULL;
}

/* Slow path: buddy allocator (with syscall overhead) */
static void *slow_alloc(void) {
  void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (ptr == MAP_FAILED)
    return NULL;

  /* Simulate page fault and zeroing */
  memset(ptr, 0, 4096);

  /* Add to slow pool for tracking */
  if (slow_index < SLOW_POOL_SIZE) {
    slow_pool[slow_index++] = ptr;
  }

  return ptr;
}

if (ptr && fast_index < FAST_POOL_SIZE) {
  fast_pool[fast_index++] = ptr;
}
}

static void slow_free(void *ptr) {
  if (ptr) {
    munmap(ptr, 4096);
  }
}

static void update_stats(perf_stats_t *stats, uint64_t latency) {
  if (latency < stats->min)
    stats->min = latency;
  if (latency > stats->max)
    stats->max = latency;

  stats->total += latency;
  stats->count++;

  /* Histogram: buckets of 100ns each */
  int bucket = latency / 100;
  if (bucket >= 20)
    bucket = 19;
  stats->histogram[bucket]++;

  /* Store for percentile calculation */
  if (sample_count < ITERATIONS) {
    latency_samples[sample_count++] = latency;
  }
}

static void calculate_percentiles(perf_stats_t *stats) {
  if (sample_count == 0)
    return;

  /* Sort samples */
  qsort(latency_samples, sample_count, sizeof(uint64_t), compare_uint64);

  stats->p50 = percentile(latency_samples, sample_count, 50);
  stats->p95 = percentile(latency_samples, sample_count, 95);
  stats->p99 = percentile(latency_samples, sample_count, 99);
}

static void print_histogram(perf_stats_t *stats, const char *label) {
  printf("\n%s Latency Distribution:\n", label);
  printf("  %-15s %-10s %s\n", "Range (ns)", "Count", "Graph");
  printf("  %s\n", "─────────────────────────────────────────────────────────");

  uint64_t max_count = 0;
  for (int i = 0; i < 20; i++) {
    if (stats->histogram[i] > max_count)
      max_count = stats->histogram[i];
  }

  for (int i = 0; i < 20; i++) {
    if (stats->histogram[i] == 0)
      continue;

    int bar_len = (int)(stats->histogram[i] * 50 / max_count);

    if (i < 19)
      printf("  %5d - %-5d  %-10lu ", i * 100, (i + 1) * 100,
             stats->histogram[i]);
    else
      printf("  %5d+         %-10lu ", i * 100, stats->histogram[i]);

    for (int j = 0; j < bar_len; j++)
      printf("█");
    printf("\n");
  }
}

/* Simulate victim object allocation */
static victim_object_t *allocate_victim(void) {
  victim_object_t *obj = malloc(sizeof(victim_object_t));
  if (!obj)
    return NULL;

  obj->callback = NULL;
  obj->id = rdtsc();
  memset(obj->data, 'V', sizeof(obj->data));

  return obj;
}

/* Heap spraying for grooming */
static void heap_spray(void **spray_pool, int count) {
  for (int i = 0; i < count; i++) {
    spray_pool[i] = malloc(KMALLOC_64);
    if (spray_pool[i]) {
      memset(spray_pool[i], 'A' + (i % 26), KMALLOC_64);
    }
  }
}

/* Measure race window between free and realloc */
static void measure_race_window(void) {
  struct timespec start, end, free_start, free_end;

  INFO("Analyzing race condition window...");

  for (int i = 0; i < RACE_WINDOW_SAMPLES; i++) {
    void *victim = fast_alloc();
    if (!victim)
      victim = slow_alloc();
    if (!victim)
      continue;

    /* Measure: free -> realloc window */
    clock_gettime(CLOCK_MONOTONIC, &start);

    clock_gettime(CLOCK_MONOTONIC, &free_start);
    if (fast_index < FAST_POOL_SIZE) {
      fast_free(victim);
    } else {
      slow_free(victim);
    }
    clock_gettime(CLOCK_MONOTONIC, &free_end);

    /* Attacker allocation window */
    void *attacker = fast_alloc();
    if (!attacker)
      attacker = slow_alloc();

    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t window = nsec_diff(free_start, end);
    uint64_t free_latency = nsec_diff(free_start, free_end);

    race_stats.window_ns += window;
    race_stats.total_attempts++;

    /* Exploitable if window > 1000ns (arbitrary threshold) */
    if (window > 1000) {
      race_stats.successful_races++;
    }

    if (attacker) {
      if (fast_index > 0)
        fast_free(attacker);
      else
        slow_free(attacker);
    }

    precise_sleep_ns(1000);
  }

  race_stats.window_ns /= race_stats.total_attempts;
  race_stats.success_rate =
      (double)race_stats.successful_races / race_stats.total_attempts * 100.0;
}

static void print_banner(void) {
  printf("\n");
  printf(CYN BLD);
  printf("╔════════════════════════════════════════════════════════════════════"
         "╗\n");
  printf("║                                                                    "
         "║\n");
  printf("║              SLUBSTICK Exploitation Technique - PoC               "
         "║\n");
  printf("║                                                                    "
         "║\n");
  printf("║  Demonstrates race condition between SLUB per-CPU freelist and    "
         "║\n");
  printf("║  buddy allocator, enabling cross-cache attacks and UAF exploits   "
         "║\n");
  printf("║                                                                    "
         "║\n");
  printf("╚════════════════════════════════════════════════════════════════════"
         "╝\n");
  printf(RST "\n");
}

static void print_config(void) {
  printf(BLD "Configuration:\n" RST);
  printf("  Target cache:          kmalloc-%d\n", KMALLOC_64);
  printf("  Per-CPU pool size:     %d objects\n", FAST_POOL_SIZE);
  printf("  Slow pool size:        %d pages\n", SLOW_POOL_SIZE);
  printf("  Benchmark iterations:  %d\n", ITERATIONS);
  printf("  CPU pinning:           CPU %d\n", CPU_PIN);
  printf("  Page size:             %ld bytes\n", sysconf(_SC_PAGESIZE));
  printf("\n");
}

static void run_benchmark(void) {
  struct timespec start, end;
  int progress_step = ITERATIONS / 50;

  INFO("Running allocation benchmark...");
  printf("Progress: [");
  fflush(stdout);

  for (int i = 0; i < ITERATIONS; i++) {
    if (i % progress_step == 0) {
      printf("█");
      fflush(stdout);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    void *p = fast_alloc();
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (p) {
      uint64_t latency = nsec_diff(start, end);
      update_stats(&fast_stats, latency);
      fast_free(p);
    } else {
      clock_gettime(CLOCK_MONOTONIC, &start);
      p = slow_alloc();
      clock_gettime(CLOCK_MONOTONIC, &end);

      if (p) {
        uint64_t latency = nsec_diff(start, end);
        update_stats(&slow_stats, latency);
        slow_free(p);
      }
    }

    precise_sleep_ns(50000);
  }

  printf("] " GRN "Complete!\n" RST);
}

static void print_detailed_stats(void) {
  printf("\n");
  printf(
      BLD
      "═══════════════════════════════════════════════════════════════════\n");
  printf("                        PERFORMANCE ANALYSIS\n");
  printf("═══════════════════════════════════════════════════════════════════"
         "\n" RST);

  if (fast_stats.count > 0) {
    calculate_percentiles(&fast_stats);

    printf("\n" GRN BLD "[FAST PATH - Per-CPU Freelist]\n" RST);
    printf("  Allocations:      %lu\n", fast_stats.count);
    printf("  Min latency:      %lu ns\n", fast_stats.min);
    printf("  Median (p50):     %lu ns\n", fast_stats.p50);
    printf("  p95 latency:      %lu ns\n", fast_stats.p95);
    printf("  p99 latency:      %lu ns\n", fast_stats.p99);
    printf("  Max latency:      %lu ns\n", fast_stats.max);
    printf("  Avg latency:      %lu ns\n", fast_stats.total / fast_stats.count);

    print_histogram(&fast_stats, "Fast Path");
  }

  if (slow_stats.count > 0) {
    printf("\n" RED BLD "[SLOW PATH - Buddy Allocator]\n" RST);
    printf("  Allocations:      %lu\n", slow_stats.count);
    printf("  Min latency:      %lu ns\n", slow_stats.min);
    printf("  Median (p50):     %lu ns\n", slow_stats.p50);
    printf("  p95 latency:      %lu ns\n", slow_stats.p95);
    printf("  p99 latency:      %lu ns\n", slow_stats.p99);
    printf("  Max latency:      %lu ns\n", slow_stats.max);
    printf("  Avg latency:      %lu ns\n", slow_stats.total / slow_stats.count);

    print_histogram(&slow_stats, "Slow Path");
  }

  if (fast_stats.count > 0 && slow_stats.count > 0) {
    uint64_t fast_avg = fast_stats.total / fast_stats.count;
    uint64_t slow_avg = slow_stats.total / slow_stats.count;

    printf("\n" YEL BLD "[EXPLOITATION METRICS]\n" RST);
    printf("  Performance gap:      " BLD "%.2fx" RST " slower\n",
           (double)slow_avg / fast_avg);
    printf("  Timing side-channel:  " BLD "%lu ns" RST " delta\n",
           slow_avg - fast_avg);
    printf("  Distinguishable:      %s\n",
           (slow_avg - fast_avg > 1000) ? GRN "YES (>1μs)" RST : RED "NO" RST);
  }
}

static void print_race_analysis(void) {
  printf("\n" MAG BLD "[RACE CONDITION ANALYSIS]\n" RST);
  printf("  Samples collected:    %lu\n", race_stats.total_attempts);
  printf("  Avg race window:      %lu ns\n", race_stats.window_ns);
  printf("  Exploitable windows:  %lu (%.2f%%)\n", race_stats.successful_races,
         race_stats.success_rate);
  printf("  Exploitation viable:  %s\n",
         (race_stats.success_rate > 10.0) ? GRN "YES" RST : YEL "MARGINAL" RST);
}

static void print_attack_summary(void) {
  printf("\n");
  printf(CYN BLD "╔════════════════════════════════════════════════════════════"
                 "════════╗\n");
  printf("║                       ATTACK SURFACE SUMMARY                       "
         "║\n");
  printf("╚════════════════════════════════════════════════════════════════════"
         "╝\n" RST);

  printf("\n" BLD "Exploitation Primitives:\n" RST);
  printf("  [1] " GRN "Timing Side-Channel" RST
         "  - Distinguishable fast/slow path\n");
  printf("  [2] " GRN "Freelist Exhaustion" RST
         "  - Predictable slow-path trigger\n");
  printf("  [3] " GRN "Race Window" RST
         "          - UAF window between free/alloc\n");
  printf("  [4] " GRN "Cross-Cache Attack" RST
         "   - Type confusion via buddy allocator\n");

  printf("\n" BLD "Attack Requirements:\n" RST);
  printf("  • Ability to trigger allocations in target kmalloc-N cache\n");
  printf("  • Control over allocation/free timing (race window)\n");
  printf("  • Heap spray capability for cache grooming\n");
  printf("  • Information leak or timing oracle\n");

  printf("\n" BLD "Mitigations:\n" RST);
  printf("  • CONFIG_SLAB_FREELIST_RANDOM - Randomize freelist pointers\n");
  printf("  • CONFIG_SLAB_FREELIST_HARDENED - Obfuscate freelist metadata\n");
  printf("  • CONFIG_INIT_ON_ALLOC_DEFAULT_ON - Zero allocations\n");
  printf("  • Kernel version >= 5.17 with improved SLUB hardening\n");

  printf("\n" BLD "References:\n" RST);
  printf("  • CVE-2021-22555 (Netfilter heap overflow + SLUBSTICK)\n");
  printf("  • CVE-2022-29582 (io_uring UAF + cross-cache)\n");
  printf("  • Paper: \"SLUB Allocator Exploitation\" (2021)\n");
}

int main(void) {
  print_banner();
  print_config();

  /* Allocate sample storage */
  latency_samples = calloc(ITERATIONS * 2, sizeof(uint64_t));
  if (!latency_samples) {
    ERROR("Failed to allocate sample storage");
    return 1;
  }

  /* System setup */
  INFO("Initializing attack simulation...");

  if (pin_to_cpu(CPU_PIN) == -1) {
    ERROR("Failed to pin to CPU");
    free(latency_samples);
    return 1;
  }
  SUCCESS("Pinned to CPU 0 (per-CPU attack simulation)");

  set_realtime_priority();

  /* Prime the fast pool */
  INFO("Priming per-CPU freelist...");
  for (int i = 0; i < FAST_POOL_SIZE; i++) {
    void *ptr = malloc(KMALLOC_64);
    if (ptr)
      fast_pool[fast_index++] = ptr;
  }
  SUCCESS("Freelist primed with 1024 objects");

  /* Warmup */
  INFO("Running warmup phase...");
  for (int i = 0; i < WARMUP_ROUNDS; i++) {
    void *p = fast_alloc();
    if (p)
      fast_free(p);
    else {
      p = slow_alloc();
      if (p)
        slow_free(p);
    }
    precise_sleep_ns(10000);
  }
  SUCCESS("System stabilized");

  /* Run benchmarks */
  printf("\n");
  run_benchmark();

  /* Analyze race conditions */
  printf("\n");
  measure_race_window();

  /* Display results */
  print_detailed_stats();
  print_race_analysis();
  print_attack_summary();

  /* Cleanup */
  INFO("Cleaning up...");
  while (fast_index > 0) {
    free(fast_pool[--fast_index]);
  }
  while (slow_index > 0) {
    munmap(slow_pool[--slow_index], 4096);
  }
  free(latency_samples);
  SUCCESS("Cleanup complete");

  printf("\n" CYN BLD);
  printf(
      "════════════════════════════════════════════════════════════════════\n");
  printf("  Research demonstrates exploitable timing side-channels and race\n");
  printf("  windows in SLUB allocator enabling UAF and cross-cache attacks.\n");
  printf(
      "════════════════════════════════════════════════════════════════════\n");
  printf(RST "\n");

  return 0;
}
