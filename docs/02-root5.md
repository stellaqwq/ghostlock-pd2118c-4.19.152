# 02 · ROOT5：跨进程换 cred + per-task SELinux 绕过

这是本仓库与「只拿到 uid 0 就停下」的实现之间真正的分叉点。

## 为什么不能原地改自己的 cred

若在写者自己的 syscall 里把 `current->cred` 指向 `init_cred`，返回路径会
重新读 `cred` 做各种检查/记账，直接在内核里崩。解法是**写者不改自己**：

1. 父进程 `slide`，然后 fork 子进程；
2. 子进程用 `perf_task_from_sched()` 泄漏自己的 task，写入共享页，然后
   **在用户态自旋**（不在任何 syscall 里）；父进程用读原语校验
   `comm = root5child`；
3. 父进程用 configfs 写把**子进程**的 `task->real_cred/cred` 指向
   `&init_cred`；
4. 父进程再设子进程的 `thread_info.flags` bit63，然后放行；
5. 子进程 mount tmpfs → 写内嵌 su → 起 `su --daemon`。

真机闭环：

```
[+] root5: verdict=[ROOT5_OK uid=0 mount=0 sock=1]
[*] root5: client connect=0 errno=0 out=[uid=0(root)]
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

## per-task 绕过位（决定性的一步）

`avc_has_perm` 的拒绝路径（本机 `0x4a3440`）：

```
0x4a3440: ldr  x8, [x25]        ; x25 = current, i.e. task->thread_info.flags
0x4a3444: asr  x8, x8, #63
0x4a3448: bic  w25, w0, w8      ; rc = denied & ~(signbit ? -1 : 0)
```

vendor 自己加的分支：`bit63 = 1` 时该任务的 SELinux 拒绝被忽略
（per-task permissive），**不需要**改全局 `selinux_state.enforcing`。
后者在本机落在 `ro_after_init [0xa54f180, 0xa554431]` 里，强写会 page fault；
之前试过 `policydb->permissive_map` 的 22 个窗口也无法放行 mount —— 位在这里。

这一位同时解决了三件看似无解的事：

| 看似的结构性限制 | 实际情况 |
|---|---|
| `kernel` 域无 `dac_override` | AVC 拒绝被 bit63 忽略 |
| `system_file` 无 `entrypoint` | exec 的 AVC 拒绝同样被忽略 |
| 全域 0 条 `(security (setenforce))` | 不需要 setenforce；全局保持 Enforcing |

## su socket 的三个坑

daemon 起来之后，从 `adb shell` 连不上，原因是 socket 相关的 SELinux 细节：

1. **socket 标签**：daemon 在 `socket()` 之前把 `u:r:shell:s0` 写进
   `/proc/self/attr/sockcreate`（靠 bit63 让拒绝被忽略），并读回确认；
   否则 socket 在 `kernel` 域，shell 连不上。
2. **必须用 abstract unix socket**：文件系统 socket 会额外检查
   `sock_file { write }`（tcontext 为 `shell_data_file`），shell 没有该权限；
   改成 `sun_path[0]=0` + 名字 `ghostlock_su` 后只剩 `connectto` 检查，
   同域（shell → shell）放行。
3. **客户端二进制必须由 shell 新建**：老流程里子进程（kernel 域）写过
   `/data/local/tmp/su`，inode 带上了非 shell 标签，之后 shell exec 一律 EPERM。
   预写前先 `unlink(/data/local/tmp/su)`，让新 inode 拿到 `shell_data_file`。

## 构建注意

zig 的 cache 不把 `.incbin` 当依赖：改了 `build/embed/su_daemon_aarch64_pie`
之后 touch `su_blob.S` 也不会重编（缓存按内容哈希）。`build_953.sh` 因此每次
用带时间戳的注释重写 `src/su_blob.S`，否则会一直嵌旧 blob。
