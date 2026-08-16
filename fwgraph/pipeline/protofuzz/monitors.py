"""监视器：fuzz 过程中判定被测设备存活状态（M-ICS-1）。

纯软件探针（对应博智的 ARP/ICMP/TCP/协议监视器子集）：
  tcp_probe      —— TCP 建连探活
  icmp_ping      —— ICMP ping（调系统 ping，无需 root）
  protocol_probe —— 发送未变异种子报文，期待任意响应
DI/AI/继电器类物理监视器依赖硬件，不在软件实现范围内。
"""

import socket
import subprocess


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"monitor": "tcp_probe", "alive": True, "detail": "connect ok"}
    except OSError as exc:
        return {"monitor": "tcp_probe", "alive": False,
                "detail": f"{type(exc).__name__}: {exc}"}


def icmp_ping(host: str, timeout: float = 2.0) -> dict:
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host],
            capture_output=True, timeout=timeout + 2)
        alive = proc.returncode == 0
        return {"monitor": "icmp_ping", "alive": alive,
                "detail": "reply" if alive else f"rc={proc.returncode}"}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"monitor": "icmp_ping", "alive": None,
                "detail": f"ping unavailable: {exc}"}


def protocol_probe(host: str, port: int, transport: str, seed: bytes,
                   timeout: float = 2.0) -> dict:
    try:
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(seed, (host, port))
                data, _ = sock.recvfrom(2048)
                return {"monitor": "protocol_probe", "alive": True,
                        "detail": f"response {len(data)}B"}
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(seed)
            data = sock.recv(2048)
            return {"monitor": "protocol_probe", "alive": bool(data),
                    "detail": f"response {len(data)}B" if data
                              else "connected, empty response"}
    except OSError as exc:
        return {"monitor": "protocol_probe", "alive": False,
                "detail": f"{type(exc).__name__}: {exc}"}


MONITOR_FUNCS = {"tcp_probe": tcp_probe, "icmp_ping": icmp_ping}


def run_monitors(names, host, port, transport, seed, timeout=2.0) -> list:
    """执行选中的监视器，返回结果列表。protocol_probe 需要种子报文。"""
    out = []
    for name in names:
        if name == "protocol_probe":
            out.append(protocol_probe(host, port, transport, seed, timeout))
        elif name in MONITOR_FUNCS:
            if name == "tcp_probe":
                out.append(tcp_probe(host, port, timeout))
            else:
                out.append(MONITOR_FUNCS[name](host, timeout))
    return out
