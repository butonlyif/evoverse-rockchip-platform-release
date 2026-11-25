# EvoVerse RK3588 Platform Development releases

This repository is the public delivery channel for signed Platform Development assets. Platform source and private BSP material are not distributed here.

No release is available yet. A release is usable only when its signed descriptor, checksums, SBOM, license and corresponding-source records, qualification receipt, and all referenced assets have been uploaded and independently downloaded and verified from both GitHub and the Gitee mirror.

The first candidate may carry `UNQUALIFIED_NO_BOOT`: software qualification passed, while board flash, boot, target execution and NPU execution remain `NOT_RUN / NO_BOARD`. This state does not qualify the image for production deployment. A later hardware-qualified promotion requires separate boot and hardware evidence.

Release assets are immutable. The descriptor's SHA-256 digest and target board identity are the authority; the tag or URL alone is not.
