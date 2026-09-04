# MassDNS 离线源码包

网络受限时，可将固定 commit 的源码压缩包放在本目录，并通过 `ARL_MASSDNS_OFFLINE_ARCHIVE` 指定文件名。

默认文件名：

```text
massdns-6bfa47197d78e68b79041d494e280174cb2d6ae1.tar.gz
```

压缩包解压后顶层应包含 `Makefile` 和 `bin/` 目录。源码包仅作本地构建缓存，不进入 Git。
