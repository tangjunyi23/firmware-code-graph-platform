#!/usr/bin/env python3
"""
vuln-hunt 漏洞挖掘实时监控
灵感来自 edict 三省六部制监控系统
"""
import json
import time
import os
from pathlib import Path
from datetime import datetime

class VulnHuntMonitor:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.state = {}

    def scan_state(self):
        """扫描当前项目状态"""
        state = {
            'timestamp': datetime.now().isoformat(),
            'project': str(self.project_path),
            'phase': self._detect_phase(),
            'round': self._detect_round(),
            'candidates': self._parse_candidates(),
            'coverage': self._parse_coverage(),
            'verdict': self._parse_verdict()
        }
        return state

    def _detect_phase(self):
        """检测当前阶段"""
        progress = self.project_path / 'progress.md'
        if not progress.exists():
            return 'Phase 0: Initializing'

        content = progress.read_text()
        if 'Phase 5' in content or 'Reporting' in content:
            return 'Phase 5: Reporting'
        elif 'Phase 4' in content or 'Challenge' in content:
            return 'Phase 4: Challenge Review'
        elif 'Phase 3' in content or 'Verification' in content:
            return 'Phase 3: Verification'
        elif 'Phase 2' in content or 'Hunting' in content:
            return 'Phase 2: Vulnerability Hunt'
        elif 'Phase 1' in content or 'Attack' in content:
            return 'Phase 1: Attack Surface'
        return 'Phase 0: Memory Bootstrap'

    def _detect_round(self):
        """检测当前轮次"""
        snapshot = self.project_path / 'context_snapshot.json'
        if snapshot.exists():
            data = json.loads(snapshot.read_text())
            return data.get('round', 0)
        return 0

    def _parse_candidates(self):
        """解析候选漏洞"""
        final_md = self.project_path / 'FINAL.md'
        if not final_md.exists():
            return []

        candidates = []
        content = final_md.read_text()

        # 简单解析 CAND-XX
        for line in content.split('\n'):
            if line.startswith('### CAND-') or line.startswith('## CAND-'):
                cand_id = line.split()[1].rstrip(':')
                candidates.append({'id': cand_id, 'status': 'unknown'})

        return candidates

    def _parse_coverage(self):
        """解析攻击面覆盖率"""
        attack_surface = self.project_path / 'attack-surface.md'
        if not attack_surface.exists():
            return {'p0': 0, 'analyzed': 0, 'percent': 0}

        content = attack_surface.read_text()
        # 简单统计 P0 数量
        p0_count = content.count('| P0 |')

        return {
            'p0': p0_count,
            'analyzed': p0_count,
            'percent': 100 if p0_count > 0 else 0
        }

    def _parse_verdict(self):
        """解析当前判定"""
        verdict_file = self.project_path / 'challenge_verdict.md'
        if not verdict_file.exists():
            return 'UNKNOWN'

        content = verdict_file.read_text()
        if 'verdict: PASS' in content or 'Verdict: PASS' in content:
            return 'PASS'
        elif 'verdict: LOOP' in content or 'Verdict: LOOP' in content:
            return 'LOOP'
        return 'UNKNOWN'

    def format_status(self, state):
        """格式化状态输出"""
        lines = [
            "=" * 60,
            f"vuln-hunt 漏洞挖掘监控 - {state['timestamp'][:19]}",
            "=" * 60,
            f"项目: {Path(state['project']).name}",
            f"轮次: Round {state['round']}",
            f"阶段: {state['phase']}",
            f"判定: {state['verdict']}",
            "",
            f"攻击面覆盖: {state['coverage']['analyzed']}/{state['coverage']['p0']} ({state['coverage']['percent']}%)",
            f"候选漏洞: {len(state['candidates'])} 个",
        ]

        if state['candidates']:
            lines.append("")
            lines.append("候选列表:")
            for cand in state['candidates']:
                lines.append(f"  - {cand['id']}")

        lines.append("=" * 60)
        return '\n'.join(lines)

def monitor_loop(project_path, interval=15):
    """监控循环"""
    monitor = VulnHuntMonitor(project_path)

    try:
        while True:
            state = monitor.scan_state()
            print('\033[2J\033[H')  # 清屏
            print(monitor.format_status(state))

            # 如果已完成，退出
            if state['verdict'] in ['PASS', 'LOOP'] and state['phase'] == 'Phase 5: Reporting':
                print("\n扫描已完成！")
                break

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n监控已停止")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("用法: python monitor.py <project_path>")
        sys.exit(1)

    project_path = sys.argv[1]
    monitor_loop(project_path)
