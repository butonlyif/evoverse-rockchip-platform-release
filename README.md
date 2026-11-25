# EvoVerse RK3588 Platform Development releases

This repository is the public delivery channel for signed Platform Development assets. Platform source and private BSP material are not distributed here.

The first candidate is `platform-development-2026.11.24-candidate.1`. Its [signed descriptor](releases/candidates/2026.11.24/platform-development-release.json) is mirrored to Gitee. Download the five descriptor-bound assets from the [GitHub candidate Release](https://github.com/butonlyif/evoverse-rockchip-platform-release/releases/tag/platform-development-2026.11.24-candidate.1) and follow the bilingual release notes to verify them. Gitee's ordinary repository has a 1 GB total attachment quota, so this approximately 3.8 GB candidate has no complete Gitee binary mirror.

The candidate carries `UNQUALIFIED_NO_BOOT`: software qualification passed, while board flash, boot, target execution and NPU execution remain `NOT_RUN / NO_BOARD`. This state does not qualify the image for production deployment. A later hardware-qualified promotion requires separate boot and hardware evidence.

Release assets are immutable. The descriptor's SHA-256 digest and target board identity are the authority; the tag or URL alone is not.

The release-signing public key is in `trust/platform-release-2026-11.pub` (raw Ed25519 public key, hex). Its private counterpart is held only as the `PLATFORM_RELEASE_SIGN_KEY` Actions secret in this repository. The candidate descriptor is signed with this key.
