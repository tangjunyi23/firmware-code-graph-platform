#!/usr/bin/env python3
"""Update memory confidence in insights.jsonl based on verdict and snapshot.

Usage: update_feedback.py <snapshot_file> <verdict> <memory_file>

verdict: PASS or LOOP
- PASS: all applied_memory_ids confidence +0.05
- LOOP: all applied_memory_ids confidence +0.02
- LOOP + excluded candidates: influencing_memory_ids confidence -0.03
"""

import json
import sys
import os
import tempfile
import datetime


def main():
    if len(sys.argv) < 4:
        print("Usage: update_feedback.py <snapshot_file> <verdict> <memory_file>",
              file=sys.stderr)
        sys.exit(1)

    snapshot_file = sys.argv[1]
    verdict = sys.argv[2]
    memory_file = sys.argv[3]
    today = datetime.date.today().isoformat()

    # Read snapshot
    try:
        with open(snapshot_file) as f:
            snapshot = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        sys.exit(0)

    # Get applied_memory_ids
    applied_ids = set()
    mem_filter = snapshot.get('memory_filter', {})
    applied_ids.update(mem_filter.get('applied_memory_ids', []))

    if not applied_ids:
        sys.exit(0)

    # Get penalize IDs from excluded candidates (LOOP only)
    penalize_ids = set()
    if verdict == 'LOOP':
        candidates = snapshot.get('candidates', {})
        for exc in candidates.get('excluded', []):
            penalize_ids.update(exc.get('influencing_memory_ids', []))

    # Update insights.jsonl line by line
    updated_lines = []
    try:
        with open(memory_file) as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    updated_lines.append(line)
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    updated_lines.append(line)
                    continue

                eid = entry.get('id', '')
                modified = False

                if eid in applied_ids:
                    # Initialize fields for backward compatibility
                    if 'confidence' not in entry:
                        entry['confidence'] = 0.5
                    if 'hit_count' not in entry:
                        entry['hit_count'] = 0

                    entry['hit_count'] = entry['hit_count'] + 1
                    entry['last_accessed'] = today

                    if verdict == 'PASS':
                        entry['confidence'] = min(1.0, entry['confidence'] + 0.05)
                    elif verdict == 'LOOP':
                        entry['confidence'] = min(1.0, entry['confidence'] + 0.02)
                    modified = True

                # LOOP: penalize excluded candidate memories
                if eid in penalize_ids and verdict == 'LOOP':
                    if 'confidence' not in entry:
                        entry['confidence'] = 0.5
                    entry['confidence'] = max(0.1, entry['confidence'] - 0.03)
                    if 'last_accessed' not in entry:
                        entry['last_accessed'] = today
                    modified = True

                if modified:
                    updated_lines.append(json.dumps(entry, ensure_ascii=False) + '\n')
                else:
                    updated_lines.append(line)
    except FileNotFoundError:
        sys.exit(0)

    # Atomic write: temp file then mv
    dir_name = os.path.dirname(memory_file)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.jsonl.tmp')
    try:
        with os.fdopen(fd, 'w') as tmp_f:
            tmp_f.writelines(updated_lines)
        os.replace(tmp_path, memory_file)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


if __name__ == '__main__':
    main()
