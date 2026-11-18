"""Retention constants, dependency-free.

Separated from `retention.py` so the halt reasons and the version can be
imported by tests, tools and the API without pulling in the ORM. These strings
are stored on purge_runs rows and asserted by the I12 tests, so they are part
of the contract rather than internal detail.
"""
from __future__ import annotations

RETENTION_VERSION = "1.0.0"

# Halt reasons. Each is a disagreement between what the database claims and
# what the filesystem shows; none can be resolved by guessing, so the run stops.
HALT_BLOB_FILE_MISSING = "blob_file_missing"
HALT_BLOB_INTEGRITY = "blob_integrity_failed"
HALT_REFERENCE_APPEARED = "reference_appeared_during_delete"
HALT_ORPHAN_REFERENCE = "evidence_references_a_missing_blob"
HALT_DELETE_FAILED = "delete_failed"

HALT_REASONS = (HALT_BLOB_FILE_MISSING, HALT_BLOB_INTEGRITY, HALT_REFERENCE_APPEARED,
                HALT_ORPHAN_REFERENCE, HALT_DELETE_FAILED)

PURGE_SCOPE = ("unredacted evidence blobs only. Findings, raw observations, evidence rows, "
               "provenance digests and the audit log are never purged.")
PURGE_ELIGIBILITY = ("A blob is eligible only when every evidence row referencing it is older "
                     "than the window AND it has zero active references — evidence rows, report "
                     "pins, raw observations and report artifacts all count.")
