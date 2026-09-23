#!/usr/bin/env python3
"""Filter memory entries from insights.jsonl by vulnerability type tags.

Usage: filter_memory.py <memory_file> <tags_space_separated> [max_extra=20]

Outputs space-separated memory IDs, ordered by confidence (descending).
meta_rule and failure_pattern entries are always included first.
"""

import json
import sys
import datetime


def main():
    if len(sys.argv) < 3:
        print("Usage: filter_memory.py <memory_file> <tags> [max_extra]", file=sys.stderr)
        sys.exit(1)

    memory_file = sys.argv[1]
    tags = sys.argv[2].split()
    max_extra = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    today = datetime.date.today()

    must_include = []  # meta_rule / failure_pattern — always included
    ranked = []        # others sorted by confidence

    try:
        with open(memory_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eid = entry.get('id', '')
                etype = entry.get('type', '')

                if entry.get('deprecated', False):
                    continue

                # meta_rule / failure_pattern always included with confidence 1.0
                if etype in ('meta_rule', 'failure_pattern'):
                    must_include.append((1.0, eid))
                    continue

                # Tag matching
                matched = any(tag in eid.upper() for tag in tags)
                if not matched:
                    continue

                # Read confidence (default 0.5) and last_accessed
                confidence = float(entry.get('confidence', 0.5))
                last_accessed = entry.get('last_accessed', entry.get('timestamp', ''))

                # Time decay: -0.01 per 7 days, floor 0.1
                if last_accessed:
                    try:
                        la = datetime.date.fromisoformat(last_accessed[:10])
                        days_since = (today - la).days
                        if days_since > 0:
                            decay = (days_since // 7) * 0.01
                            confidence = max(0.1, confidence - decay)
                    except (ValueError, TypeError):
                        pass

                confidence = max(0.1, min(1.0, confidence))
                ranked.append((confidence, eid))

    except FileNotFoundError:
        sys.exit(0)

    # Sort by confidence descending, take top N
    ranked.sort(key=lambda x: -x[0])
    ranked = ranked[:max_extra]

    # must_include first, then ranked
    result = must_include + ranked
    print(' '.join(eid for _, eid in result))


if __name__ == '__main__':
    main()
