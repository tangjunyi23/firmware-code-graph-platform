"""Docker 沙箱后端（Phase 2）：不可信固件代码的容器化执行。

薄封装原则：run_sandboxed() 只负责把调用方的命令包装成一条带隔离参数的
`docker run` 并返回 Popen，等待/杀进程逻辑仍由各调用方沿用。统一隔离基线：
`--network <mode> --read-only --cap-drop ALL --security-opt no-new-privileges`
+ pids/memory/cpus 限额 + 可写 /tmp tmpfs（容器 rootfs 只读）。

后端选择：SANDBOX_BACKEND（docker|userns|none，默认 docker），组件可用
<COMPONENT>_SANDBOX_BACKEND 覆盖（如 FUZZ_SANDBOX_BACKEND）。请求 docker 但
docker 不可用时的兜底：fuzz/frida -> none（宿主直跑，调用方写中文警告）；
trace -> userns（原有 unshare 路径）。

兄弟容器路径（Phase 3）：编排器自身容器化后，docker run -v 的源路径由宿主
daemon 解析，与容器内路径不一致；设置 SANDBOX_HOST_PREFIX 后，run_sandboxed
把挂载源中以容器内 FWGRAPH_DATA 开头的前缀改写为宿主侧路径（host_mount_path）。
"""

import os
import shutil
import signal
import subprocess
import threading

# 统一资源限额；调用方写 meta 时引用同一组常量，避免漂移
DEFAULT_LIMITS = {"memory": "2g", "cpus": 2, "pids": 256}

VALID_BACKENDS = ("docker", "userns", "none")

_DOCKER_OK = None


def host_mount_path(path) -> str:
    """docker run -v 挂载源的宿主侧路径（兄弟容器路径改写，Phase 3）。

    编排器自身跑在容器里、经挂载的 docker.sock 起兄弟沙箱容器时，-v 的源
    路径由宿主 docker daemon 解析——容器内路径在宿主上通常不存在。此时设置
    SANDBOX_HOST_PREFIX 为宿主侧数据目录绝对路径，本函数把源路径中以容器内
    FWGRAPH_DATA（默认 /data）开头的前缀替换为它。默认空 = 宿主直跑，不改写。
    """
    path = str(path)
    prefix = os.getenv("SANDBOX_HOST_PREFIX", "").strip().rstrip("/")
    if not prefix:
        return path
    data = os.getenv("FWGRAPH_DATA", "/data").strip().rstrip("/") or "/data"
    if path == data or path.startswith(data + "/"):
        return prefix + path[len(data):]
    return path


def docker_available() -> bool:
    """docker CLI 存在且 daemon 可达（结果按进程缓存）。

    快检过程中的任何异常都视为不可用——包括测试把 subprocess.Popen
    全局 mock 掉的情形（探针绝不向调用方抛异常）。
    """
    global _DOCKER_OK
    if _DOCKER_OK is None:
        if not shutil.which("docker"):
            _DOCKER_OK = False
        else:
            try:
                _DOCKER_OK = subprocess.run(
                    ["docker", "info"], capture_output=True,
                    timeout=10).returncode == 0
            except Exception:  # noqa: BLE001 - 探针语义：出错即不可用
                _DOCKER_OK = False
    return _DOCKER_OK


def sandbox_image_present(image: str) -> bool:
    """镜像是否已在本地（不缓存，镜像可能随时被 build/prune）。"""
    try:
        return subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001 - 同上，探针不抛异常
        return False


def configured_backend(component: str) -> str:
    """env 里为组件配置的后端（docker|userns|none，默认 docker），不做可用性回退。"""
    key = f"{component.strip().upper()}_SANDBOX_BACKEND"
    raw = (os.getenv(key) or os.getenv("SANDBOX_BACKEND") or "docker")
    raw = raw.strip().lower()
    return raw if raw in VALID_BACKENDS else "docker"


def backend_for(component: str) -> str:
    """组件实际生效的后端：配置为 docker 但 docker 不可用时按组件兜底
    （trace -> userns 原有路径；其余 -> none 即宿主直跑）。"""
    backend = configured_backend(component)
    if backend == "docker" and not docker_available():
        return "userns" if component == "trace" else "none"
    return backend


def run_sandboxed(cmd, *, image, mounts, workdir=None, network="none",
                  extra_hosts=None, ports=None, env=None,
                  mem=DEFAULT_LIMITS["memory"], cpus=DEFAULT_LIMITS["cpus"],
                  pids=DEFAULT_LIMITS["pids"], timeout=None, log_path=None,
                  name=None, sysctls=None, user=None, cap_add=None):
    """以隔离容器运行 cmd，返回 docker run 客户端的 Popen。

    cmd            容器内执行的 argv（调用方负责容器内路径的正确性）
    mounts         [(host_path, container_path, mode)]，mode 如 "ro"/"rw"；
                   host_path 经 host_mount_path() 改写为宿主侧路径（仅当
                   SANDBOX_HOST_PREFIX 非空且源路径在 FWGRAPH_DATA 下）
    ports          需发布到宿主 127.0.0.1 的端口列表（service 型 trace 用）
    sysctls        docker --sysctl 键值（service 型 trace 把
                   net.ipv4.ip_unprivileged_port_start=0，让 uid 1000 能
                   bind 80；否则 docker-proxy 接上后 RST，覆盖无差分）
    timeout        硬上限（秒）：到期由看门狗线程 docker rm -f 容器并
                   SIGKILL 客户端进程组；None 则完全交给调用方控制生命周期
    log_path       给定时容器 stdout/stderr 追加写入该文件，否则
                   stdout=DEVNULL、stderr=PIPE(text)（对齐 fuzz 现有用法）
    name           容器名（默认 fwgraph-sbx-<rand>）；调用方可经返回 Popen 的
                   sandbox_container 属性取回，用于自行 docker rm -f
    user           docker --user（trace chroot 用 0）
    cap_add        docker --cap-add 列表（chroot 需要 SYS_CHROOT；root 绑 80
                   需要 NET_BIND_SERVICE，因为 --cap-drop ALL 会拿掉它）
    """
    name = name or f"fwgraph-sbx-{os.urandom(4).hex()}"
    docker_cmd = ["docker", "run", "--rm", "--name", name,
                  "--network", network, "--read-only",
                  "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges",
                  "--pids-limit", str(pids),
                  "--memory", str(mem), "--cpus", str(cpus),
                  "--tmpfs", "/tmp:rw,size=512m"]
    for host_path, container_path, mode in mounts or []:
        docker_cmd += ["-v", f"{host_mount_path(host_path)}:"
                             f"{container_path}:{mode}"]
    for spec in ports or []:
        if isinstance(spec, (tuple, list)) and len(spec) == 2:
            host_p, guest_p = spec
            docker_cmd += ["-p", f"127.0.0.1:{host_p}:{guest_p}"]
        else:
            docker_cmd += ["-p", f"127.0.0.1:{spec}:{spec}"]
    for key, value in (sysctls or {}).items():
        docker_cmd += ["--sysctl", f"{key}={value}"]
    if user is not None:
        docker_cmd += ["--user", str(user)]
    for cap in cap_add or []:
        docker_cmd += ["--cap-add", cap]
    for host in extra_hosts or []:
        docker_cmd += ["--add-host", host]
    for key, value in (env or {}).items():
        docker_cmd += ["--env", f"{key}={value}"]
    if workdir:
        docker_cmd += ["-w", str(workdir)]
    docker_cmd.append(image)
    docker_cmd += [str(a) for a in cmd]

    log_fh = None
    if log_path:
        log_fh = open(log_path, "ab")
        stdout, stderr = log_fh, subprocess.STDOUT
    else:
        stdout, stderr = subprocess.DEVNULL, subprocess.PIPE
    proc = subprocess.Popen(docker_cmd, stdin=subprocess.DEVNULL,
                            stdout=stdout, stderr=stderr,
                            start_new_session=True, text=True)
    proc.sandbox_container = name
    if log_fh is not None:
        # Popen 已持有 fd；watchdog/调用方不再触碰此句柄，进程退出即随 GC 关闭
        log_fh.close()

    if timeout:
        def _watchdog():
            try:
                proc.wait(timeout=timeout)
                return
            except subprocess.TimeoutExpired:
                pass
            # 先 rm -f 容器（kill 客户端本身不会停容器），再杀客户端进程组兜底
            subprocess.run(["docker", "rm", "-f", name],
                           capture_output=True, check=False)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

        threading.Thread(target=_watchdog, daemon=True).start()
    return proc
