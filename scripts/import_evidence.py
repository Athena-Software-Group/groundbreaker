"""Index a folder of case evidence into a case's evidence register (originals are never modified).

    python -m scripts.import_evidence --case DEMO-2026-001 --source /path/outside/repo/evidence --dry-run
    python -m scripts.import_evidence --case DEMO-2026-001 --source /path/outside/repo/evidence --mode reference
    python -m scripts.import_evidence --case REF --source DIR --map mapping.json --received-from "victim"
    python -m scripts.import_evidence --case DEMO-2026-001 --source data/fixtures/demo_evidence --mode inline \
        --exclude '*.json'

Walks DIR, hashes every file (sha256, read-only), maps it to an evidence folder by rules and registers
it. Modes: ``reference`` (default; metadata + hash, the original stays where it is), ``inline`` (small
UTF-8 text files only, e.g. the synthetic demo artifacts) and ``vault`` (a copy into AEGIS_VAULT_DIR).

* .zip archives are indexed by member (``archive.zip!member``) without extracting anything to disk.
  Member names without the zip UTF-8 flag are repaired (cp437 -> UTF-8 when that decodes, else cp437).
  Loose files are walked first and archives last, so a loose original is the canonical item and its
  copy inside an archive is recorded as the duplicate.
* .rtfd bundles are one item, hashed as their TXT.rtf (inside a zip only when the archive holds the
  bundle directory; a flat member named ``*.rtfd`` is read as itself). .DS_Store and other OS litter
  are skipped.
* Duplicates (bytes already registered in the case) are not registered twice: the existing item is
  tagged ``has-duplicate`` and lists the extra path in ``meta.duplicates``. Re-runs are idempotent.
* Default folder rules: 'Stop Orders' -> stop_orders_correspondence, 'Legal Docs' -> legal,
  '*Due Diligence*' -> financial, police / IC3 / statement / power-of-attorney / agent -> law_enforcement,
  WhatsApp / chat / transcript / meeting / .mp4 / e-mail images -> digital_artifacts, invoice / work
  product / intelligence report / fund flow graph -> investigator_reports, other images -> digital
  artifacts (screenshots), the rest -> other.
* ``--map mapping.json`` adds rules (checked before the defaults):

    {"rules": [{"glob": "*Bank*", "folder": "financial"},
               {"keyword": ["kyc"], "folder": "financial", "classification": "R3", "tags": ["kyc"]},
               {"dir": "Exchange replies", "folder": "stop_orders_correspondence"},
               {"ext": [".eml"], "folder": "digital_artifacts", "section": "emails"}],
     "replace_defaults": false, "default_folder": "other", "classification": "R3", "exclude": ["*.tmp"]}

The output lists file paths, which are case data (R2): run it in a private terminal and do not paste
it into tickets or chats. Nothing is written with --dry-run.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True, metavar="REFERENCE", help="case reference, e.g. DEMO-2026-001")
    ap.add_argument("--source", required=True, metavar="DIR", help="folder to index (kept read-only)")
    ap.add_argument("--mode", default="reference", choices=["reference", "inline", "vault"])
    ap.add_argument("--map", metavar="mapping.json", help="extra folder-mapping rules (JSON)")
    ap.add_argument("--dry-run", action="store_true", help="show the plan; write nothing")
    ap.add_argument("--received-from", metavar="TEXT", help="who supplied this material (stored on every item)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip file names matching GLOB")
    ap.add_argument("--quiet", action="store_true", help="print the summary only")
    args = ap.parse_args(argv)

    from sqlalchemy import select

    from app.core.audit import CREATE, audit
    from app.db.models import Case
    from app.db.session import SessionLocal
    from app.domain import evidence as ev

    try:
        mapping = ev.load_mapping(args.map)
    except (OSError, ValueError) as e:
        sys.exit(f"--map: {e}")
    if args.exclude:
        mapping.exclude = (*mapping.exclude, *args.exclude)

    with SessionLocal() as db:
        case = db.scalar(select(Case).where(Case.reference == args.case))
        if case is None:
            sys.exit(f"no case with reference {args.case!r}")
        try:
            report = ev.import_directory(db, case, args.source, mode=args.mode, mapping=mapping,
                                         dry_run=args.dry_run, received_from=args.received_from)
        except ev.EvidenceError as e:
            db.rollback()
            sys.exit(str(e))

        if not args.quiet:
            for r in report.rows:
                c = r.candidate
                where = f"{r.folder.value}" + (f"/{r.section}" if r.section else "")
                note = f"  ({c.error})" if c.error else (f"  -> item #{r.item_id}" if r.item_id else "")
                print(f"{r.action:<9} {where:<36} {(c.sha256 or '-')[:12]:<12} {c.size:>10}  {c.rel}{note}")
        actions = Counter(r.action for r in report.rows)
        print(f"\n{len(report.rows)} file(s): " + ", ".join(f"{n} {a}" for a, n in sorted(actions.items())))
        if report.by_folder():
            print("new by folder: " + ", ".join(f"{f}={n}" for f, n in sorted(report.by_folder().items())))

        if args.dry_run:
            db.rollback()
            print("dry run: nothing written")
            return 0
        db.flush()
        audit(db, None, CREATE, case, ("evidence_items", None), via="import_evidence", mode=args.mode,
              created=len(report.created), duplicates=actions.get("duplicate", 0),
              unchanged=actions.get("unchanged", 0), changed=actions.get("changed", 0),
              errors=actions.get("error", 0), item_ids=[i.id for i in report.created][:100])
        ev.notify_added(db, case, report.created)
        print(f"registered {len(report.created)} new item(s) in {case.reference}")
        if actions.get("changed"):
            print("WARNING: registered originals changed since they were hashed (integrity mismatch recorded)")
        return 1 if actions.get("changed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
