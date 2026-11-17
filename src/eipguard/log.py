from __future__ import annotations

import logging
import sys
import warnings


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    # 第三方库降噪
    noisy = ("httpx", "httpcore", "telegram.ext.Application", "apscheduler")
    for name in noisy:
        logging.getLogger(name).setLevel(logging.WARNING)
    # 阿里云 SDK 自带日志会重复打印错误，我们自己的 AliyunError 已经带了 requestId
    logging.getLogger("aliyunsdkcore").setLevel(logging.CRITICAL)
    # SDK 内部 vendored 的旧 urllib3 会报 SNIMissingWarning，实际请求是正常的
    warnings.filterwarnings("ignore", message=".*SNI.*")
    warnings.filterwarnings("ignore", message=".*SubjectAltNameWarning.*")
