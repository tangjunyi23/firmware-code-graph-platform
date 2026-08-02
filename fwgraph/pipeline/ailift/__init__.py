"""AI symbol recovery & renaming (M3).

Pure-Python package (runs in the venv, no IDA modules). Pipeline:

  funnel.py   three-layer funnel: symbols.json -> candidate functions for AI
  llm.py      async DeepSeek client (httpx + semaphore + tenacity retry)
  registry.py SQLite name registry + naming_spec.yaml validator/arbitration
  runner.py   funnel -> LLM -> validate -> renames.json -> IDA apply ->
              second-pass export -> symbols.json update (resumable)
  ida_apply_renames.py  IDAPython script (separate; runs inside IDA, applies
              renames into the .i64)
"""
