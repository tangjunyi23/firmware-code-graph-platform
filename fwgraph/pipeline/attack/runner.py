"""Run AS-1 classification, path generation, and CBM injection."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline import profiles as analysis_profiles
from pipeline.attack import ai_review, cross, inject, paths, surface
from pipeline.graph import ingest as graph_ingest

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _profile_spec(job_id, data_dir):
    path = Path(data_dir) / "firmware" / job_id / "job.json"
    name = None
    if path.is_file():
        try:
            name = json.loads(path.read_text(encoding="utf-8")).get("profile")
        except (OSError, json.JSONDecodeError):
            name = None
    try:
        return analysis_profiles.spec(name)
    except analysis_profiles.UnknownProfile:
        return analysis_profiles.spec(None)


def run_job(job_id, data_dir, config_path=None, dry_run=False):
    data_dir = Path(data_dir)
    started = time.time()
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols_path = pseudo_root / "symbols.json"
    symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
    config = surface.load_config(config_path)
    spec = _profile_spec(job_id, data_dir)
    config.setdefault("scoring", {}).update(spec.get("scoring") or {})
    analysis = surface.analyze(
        symbols, pseudo_root, config, job_id=job_id, data_dir=data_dir)
    result = paths.compute(analysis, config)
    cross_stats = cross.apply(analysis, result, data_dir / "traces" / job_id)
    if dry_run:
        return {"job_id": job_id, "status": "dry_run",
                "analysis": result["summary"],
                "cross_validation": cross_stats,
                "top_paths": result["paths"][:5],
                "elapsed_seconds": round(time.time() - started, 2)}
    project = graph_ingest.project_name(job_id)
    database = graph_ingest.db_path(project)
    if not database.is_file():
        raise FileNotFoundError(
            f"CBM database not found for {project}: {database}")
    surface.apply_annotations(symbols, analysis, result["path_ids_by_key"])
    surface.write_symbols(symbols_path, symbols)

    attack_dir = data_dir / "attack" / job_id
    attack_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "job_id": job_id, "generated_at": _now(),
        "config_version": config.get("version"),
        "summary": result["summary"], "paths": result["paths"],
        "cross_validation": cross_stats,
    }
    if spec.get("attack_ai") and ai_review.enabled():
        try:
            artifact["summary"]["ai_review"] = ai_review.review(
                job_id, data_dir, artifact, pseudo_root,
                max_paths=spec.get("attack_ai_max_paths"))
        except Exception as exc:  # noqa: BLE001 - review must not fail attack
            artifact["summary"]["ai_review"] = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "reviewed": 0,
            }
    elif not spec.get("attack_ai"):
        artifact["summary"]["ai_review"] = {
            "status": "skipped", "reason": "profile_low", "reviewed": 0,
        }
    else:
        artifact["summary"]["ai_review"] = {
            "status": "skipped", "reason": "disabled_or_no_key", "reviewed": 0,
        }
    (attack_dir / "attack_paths.json").write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False), encoding="utf-8")

    injection = inject.inject_metadata(database, symbols, project)
    summary = {
        "job_id": job_id, "status": "ok",
        "started_at": artifact["generated_at"], "finished_at": _now(),
        "analysis": result["summary"], "injection": injection,
        "cross_validation": cross_stats,
        "elapsed_seconds": round(time.time() - started, 2),
    }
    (attack_dir / "attack_done.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(run_job(argv[1], data_dir, dry_run="--dry-run" in argv[2:]),
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
