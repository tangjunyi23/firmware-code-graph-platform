#!/usr/bin/env bash
# Launch the fwgraph MCP bridge (tools/artex_mcp.py) with creds from .env.
set -euo pipefail
cd "$(dirname "$0")"

TOKEN=$(grep '^ORCH_TOKEN=' .env | cut -d= -f2-)
export FWGRAPH_BASE_URL=http://127.0.0.1:8000
export FWGRAPH_TOKEN="${TOKEN}"
export FWGRAPH_JOB_ID="${FWGRAPH_JOB_ID:-60ca28d897cf}"
export FWGRAPH_MCP_PORT="${FWGRAPH_MCP_PORT:-8900}"

exec .venv/bin/python tools/artex_mcp.py
