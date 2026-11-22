# tools/ — 配套脚本

这些脚本用于**分发前**的模块指纹替换、APK 重打包/换签和源码打包。
提权本体（`ghostlock`）不依赖它们，只跑 root 的话不需要执行这里任何脚本。

| 脚本 | 用途 |
|---|---|
| `apk_cert_probe.py` | 读 APK 的签名证书信息（证书大小、指纹、v1/v2/v3 签名块） |
| `patch_ksu_expected.py` | 把内核模块里期望的证书指纹改成指定调试/发布证书 |
| `patch_manager_hash.py` | 修补管理器里校验用的哈希 |
| `repack_apk_asset.py` | 原位替换 APK 内某个 asset（按 stock 指纹定位，等长替换） |
| `release_sign.py` | 端到端发布：生成密钥 → 打模块补丁 → 替换内嵌模块 → 重签两个 APK → 复核 |
| `pack_source.py` / `SOURCE-README.md` | 生成随 APK 分发的 GPL 源码包（那份包是独立产物，不在本仓库内） |

## 换自己的签名

分发前**务必**换成自己的密钥，否则任何人都能用公开密钥伪造更新
（内核模块认的就是证书指纹）：

```bash
python tools/release_sign.py --storepass <你的口令> \
  --manager  <原始管理器.apk> \
  --ghostlock <原始 Ghostlock.apk> \
  --outdir release
```

两个硬约束（脚本已处理）：

- 密钥必须 **RSA-2048**：内核对证书的栈缓冲上限 1024 字节，4096 位证书约
  1.4 KB 会被直接拒绝。
- 管理器必须**只带 v2 签名块**：`apksigner` 默认会加 v3，内核遇到 v3 block id
  会整包拒绝，脚本已强制关闭 v1/v3 并复核。

## 自解压器里的内嵌模块

`RootService.extractAssets()` 每次运行都会 `exists → delete → 解压`，
所以手工 push 到设备的补丁模块下次一定会被内嵌的 stock 模块覆盖。
`release_sign.py` 会按 stock 指纹定位并原位替换
`assets/pd2055_exploit` 里的那份等长模块，这才是一次性修好的做法。
