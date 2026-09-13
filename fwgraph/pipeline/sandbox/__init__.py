"""Docker 沙箱执行层（Phase 2）：fuzz / frida / trace 三处不可信固件
代码执行的统一容器后端。纯标准库，无第三方依赖。"""

from pipeline.sandbox.docker_backend import (
    DEFAULT_LIMITS,
    backend_for,
    configured_backend,
    docker_available,
    host_mount_path,
    resolved_host_data_prefix,
    run_sandboxed,
    sandbox_image_present,
)
from pipeline.sandbox.image import BUILD_HINT, SANDBOX_IMAGE, ensure_image

__all__ = [
    "BUILD_HINT",
    "DEFAULT_LIMITS",
    "SANDBOX_IMAGE",
    "backend_for",
    "configured_backend",
    "docker_available",
    "ensure_image",
    "host_mount_path",
    "resolved_host_data_prefix",
    "run_sandboxed",
    "sandbox_image_present",
]
