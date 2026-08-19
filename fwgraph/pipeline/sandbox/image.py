"""沙箱镜像定义与存在性检查（Phase 2）。

镜像由 deploy/docker/Dockerfile.sandbox 构建；缺失时各沙箱路径回退到
原有宿主/userns 执行并写中文警告，平台不假装有隔离。
"""

import os
import sys

from pipeline.sandbox.docker_backend import docker_available, sandbox_image_present

SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "fwgraph-sandbox:local")

# 镜像缺失时给运维的构建提示（仓库根目录下执行）
BUILD_HINT = ("docker build -f deploy/docker/Dockerfile.sandbox "
              "-t fwgraph-sandbox:local .")


def ensure_image(image: str | None = None) -> bool:
    """沙箱镜像是否就绪；缺失时在 stderr 给出构建命令提示并返回 False。"""
    image = image or SANDBOX_IMAGE
    if docker_available() and sandbox_image_present(image):
        return True
    print(f"[sandbox] 沙箱镜像 {image} 不可用（docker 未就绪或镜像未构建），"
          f"相关动态分析将回退非容器路径。构建：{BUILD_HINT}",
          file=sys.stderr)
    return False
