# Application Toolchain Add-on 2026.11.27 candidate.1

> 独立签名、不可变的应用工具链增量，绑定已发布 Platform 候选
> `platform-development-2026.11.24-candidate.1`（签名描述符
> `sha256:2385cdbb84ccb2894ae8c89ba7a7cbb09d8c087039c6f2047407e6ce81c652af`，
> sysroot 资产 `sha256:26d950688d6cc1657ae73323e16e74e7afc3fe2e3cd581dc21a0115e4b36a6f5`）。
> 基础 Platform 的固件/sysroot 字节与描述符不变；本 Add-on 只声明兼容的工具链身份。
> 候选资格：`UNQUALIFIED_NO_BOOT`；App Builder `hardwareValidation: NOT_RUN`。

## 资产

| 文件 | 作用 | 摘要 |
|---|---|---|
| `application-toolchain-addon.json` | 签名信封 `{descriptor, signature}`（Ed25519, keyId `platform-release-2026-11`）；Gitee 同步此文件为签名索引 | 见发布页 |
| `application-toolchain-addon-input.json` | 组装输入清单（CI 验证后签名的依据） | 见发布页 |
| `app-builder.tar` | 兼容的新 App Builder 镜像（generic packageMode + 应用私有库机制） | `sha256:83cb0d81c7ff96c4a9f88d9b0bea4a553af5f9dd3ca2ea65e991cc1df59b8e98`（567,282,688 B） |
| `profiles-manifest.json` | 能力 profile 清单（10 profile，绑定目标与 Platform 摘要） | 文件 `sha256:ef9d31ae8593a8a889d0ab794f02645e5c5aba54e1c437e0d01d79dc3f3e13b4`；canonical `sha256:9f5b891102a9cde395371e7c09b8d1cb8dfc5824389b26a392042567eca9c6b1` |
| `zlib-capability-pack.tar.gz` | zlib 1.3.1 能力包（应用私有库；含 pack.json/headers/library/provenance/构建证据） | `sha256:5bacc81459b5ee5a9c2d65d23bafc620d2ee77b53014194a68bfc9c529245602`（94,567 B） |
| `reassembly.json` | Gitee 分片重组清单 | 见发布页 |

## 验签与绑定

SDK（及任何客户端）按以下顺序校验：

1. 下载 `application-toolchain-addon.json`，文件 SHA-256 必须等于 Catalog
   `platform-development.json` 的 `applicationToolchainAddon.envelopeDigest` 钉扎值。
2. Ed25519 验签（canonical `{"descriptor": …}`，公钥
   `trust/platform-release-2026-11.pub`）。
3. 身份全绑定核对：`target == ws-e2/rk3588j-evm/1`、
   `platformDescriptorDigest == 2385cdbb…`、`sysrootDigest == 26d95068…`、
   `appBuilderDigest == 83cb0d81…`、`profileManifestDigest == 9f5b8911…`（canonical）、
   `capabilityPackDigests == {"zlib": "5bacc814…"}`。
4. 二进制资产按字节 SHA-256 入内容缓存后使用； mismatches quarantine。

## 资格边界

- 固件烧录、启动、板端应用与 NPU 执行均 `NOT_RUN / NO_BOARD`。
- zlib 能力包为软件数据压缩（应用私有部署），不声称任何硬件加速。
- ISP/音频/媒体编解码/硬件加密保持 `NEEDS_CUSTOM_PLATFORM`；ROS 2/实时保持
  `NOT_INSTALLED`（见 profiles-manifest 证据字段）。
- 旧 App Builder（`ff01a438…`）仍由基础 Platform 描述符发布、不删除；
  SDK 仅在 Add-on 验签通过后才选用新 Builder。
