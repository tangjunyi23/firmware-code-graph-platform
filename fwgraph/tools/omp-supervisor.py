#!/usr/bin/env python3
"""omp-supervisor：fwgraph 会话深度监督器（旁路只读，持久部署版）。

部署：fwgraph/tools/omp-supervisor.py（/tmp 是 tmpfs，重启即清）。
启动：setsid nohup python3 <本文件> > /tmp/omp-supervisor.log 2>&1 < /dev/null &

每 60s 检查：
- running 挖掘/模拟会话的 journal 最后事件年龄（>6 分钟即 ALERT_STALL）
- host runner.pid 存活（死而 state=running → ALERT_HOSTDEAD）
- 服务进程 autopilot 线程存在性（running 挖掘会话应有，无则 ALERT_NOPILOT）
- orchestrator 实例数（>1 → ALERT_MULTIINSTANCE；cmdline 含 python 才计数）
ALERT 行即时输出；正常心跳每 10 轮一行。只读不干预。
"""
import glob
import json
import subprocess
import time

BASE = '/home/tankuku/src/firmware-code-graph-platform'
SID_ROOTS = [
    (BASE + '/vulnagent/sessions', 'miner'),
    (BASE + '/vulnagent/emul-sessions', 'emul'),
]


def journal_last_age(sdir):
    for z in glob.glob('/home/tankuku/.dsh/sessions/*'
                       + sdir.split('/')[-1] + '*/session-*/session.v3.jsonl.zstd'):
        try:
            out = subprocess.run(['zstdcat', z], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            if not out:
                continue
            last = json.loads(out.split('\n')[-1])
            return (time.time() * 1000 - (last.get('time') or 0)) / 1000, last
        except Exception:
            continue
    return None, None


def pid_alive(pid):
    try:
        open(f'/proc/{pid}/cmdline').read()
        return True
    except OSError:
        return False


def autopilot_count():
    orch = []
    for p in subprocess.run(['pgrep', '-f', 'uvicorn orchestrator'],
                            capture_output=True, text=True).stdout.split():
        try:
            if 'python' in open(f'/proc/{p}/cmdline', 'rb').read().decode(
                    errors='replace'):
                orch.append(p)
        except OSError:
            pass
    n = 0
    for p in orch:
        try:
            n += int(subprocess.run(
                f'cat /proc/{p}/task/*/comm 2>/dev/null | grep -c autopilot',
                shell=True, capture_output=True, text=True).stdout.strip() or 0)
        except Exception:
            pass
    return n, len(orch)


beat = 0
while True:
    alerts = []
    running_miners = 0
    for root, kind in SID_ROOTS:
        for sdir in glob.glob(root + '/*'):
            try:
                st = json.load(open(sdir + '/state.json'))
            except Exception:
                continue
            if st.get('status') != 'running':
                continue
            sid = st.get('session_id') or sdir.split('/')[-1]
            if kind == 'miner':
                running_miners += 1
            age, last = journal_last_age(sdir)
            if age is not None and age > 360:
                alerts.append(f'ALERT_STALL {sid} last={last.get("type")} age={int(age)}s')
            try:
                pid = open(sdir + '/runner.pid').read().strip()
                if not pid_alive(pid):
                    alerts.append(f'ALERT_HOSTDEAD {sid} pid={pid}')
            except OSError:
                pass
    n_pilot, n_orch = autopilot_count()
    if running_miners and n_pilot < running_miners:
        alerts.append(f'ALERT_NOPILOT running_miners={running_miners} pilots={n_pilot}')
    if n_orch > 1:
        alerts.append(f'ALERT_MULTIINSTANCE orchestrators={n_orch}')
    now = time.strftime('%H:%M:%S')
    if alerts:
        for a in alerts:
            print(now, a, flush=True)
    else:
        beat += 1
        if beat % 10 == 1:
            print(now, 'ok miners=%d pilots=%d orch=%d' %
                  (running_miners, n_pilot, n_orch), flush=True)
    time.sleep(60)
