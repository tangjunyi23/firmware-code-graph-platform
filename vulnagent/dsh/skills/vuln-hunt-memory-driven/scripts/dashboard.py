#!/usr/bin/env python3
"""
vuln-hunt Dashboard Server - 轻量级 Web 监控
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path
from monitor import VulnHuntMonitor

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path.startswith('/api/status'):
            project = self.server.project_path
            monitor = VulnHuntMonitor(project)
            state = monitor.scan_state()

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(state).encode())

HTML = '''<!DOCTYPE html>
<html>
<head>
    <title>vuln-hunt Dashboard</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { border-bottom: 2px solid #569cd6; padding-bottom: 10px; margin-bottom: 20px; }
        .card { background: #252526; border: 1px solid #3e3e42; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .status { display: inline-block; padding: 4px 8px; border-radius: 3px; font-weight: bold; }
        .status.PASS { background: #4ec9b0; color: #000; }
        .status.LOOP { background: #ce9178; color: #000; }
        .progress { background: #3e3e42; height: 20px; border-radius: 3px; overflow: hidden; }
        .progress-bar { background: #569cd6; height: 100%; transition: width 0.3s; }
        .candidate { padding: 8px; margin: 5px 0; background: #2d2d30; border-left: 3px solid #569cd6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 vuln-hunt 漏洞挖掘监控</h1>
            <p id="timestamp">加载中...</p>
        </div>

        <div class="card">
            <h2>扫描状态</h2>
            <p><strong>项目:</strong> <span id="project">-</span></p>
            <p><strong>轮次:</strong> Round <span id="round">0</span></p>
            <p><strong>阶段:</strong> <span id="phase">-</span></p>
            <p><strong>判定:</strong> <span id="verdict" class="status">-</span></p>
        </div>

        <div class="card">
            <h2>攻击面覆盖</h2>
            <div class="progress">
                <div class="progress-bar" id="coverage-bar" style="width: 0%"></div>
            </div>
            <p id="coverage-text">0/0 (0%)</p>
        </div>

        <div class="card">
            <h2>候选漏洞 (<span id="cand-count">0</span>)</h2>
            <div id="candidates"></div>
        </div>
    </div>

    <script>
        function updateDashboard() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('timestamp').textContent = data.timestamp;
                    document.getElementById('project').textContent = data.project.split('/').pop();
                    document.getElementById('round').textContent = data.round;
                    document.getElementById('phase').textContent = data.phase;

                    const verdict = document.getElementById('verdict');
                    verdict.textContent = data.verdict;
                    verdict.className = 'status ' + data.verdict;

                    const percent = data.coverage.percent;
                    document.getElementById('coverage-bar').style.width = percent + '%';
                    document.getElementById('coverage-text').textContent =
                        `${data.coverage.analyzed}/${data.coverage.p0} (${percent}%)`;

                    document.getElementById('cand-count').textContent = data.candidates.length;

                    const candDiv = document.getElementById('candidates');
                    if (data.candidates.length > 0) {
                        candDiv.innerHTML = data.candidates.map(c =>
                            `<div class="candidate">${c.id}</div>`
                        ).join('');
                    } else {
                        candDiv.innerHTML = '<p>暂无候选</p>';
                    }
                });
        }

        updateDashboard();
        setInterval(updateDashboard, 15000);
    </script>
</body>
</html>
'''

def run_server(project_path, port=8080):
    server = HTTPServer(('0.0.0.0', port), DashboardHandler)
    server.project_path = project_path
    print(f"Dashboard 运行在 http://localhost:{port}")
    server.serve_forever()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("用法: python dashboard.py <project_path> [port]")
        sys.exit(1)

    project = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    run_server(project, port)
