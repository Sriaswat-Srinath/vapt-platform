"""scan_jobs.mode — fixture (no network contact) vs live (full gate chain).

NOTE: autogenerate also proposed dropping `uq_one_held_lease_per_adapter`,
because that partial unique index is created with raw SQL and is invisible to
the model metadata. Dropping it would remove the database-level guarantee that
only one job can hold the scanner daemon. The drop is deliberately NOT included
here, and `migrations/env.py` now excludes the index from autogenerate so the
proposal cannot recur.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "8baf8636071a"
down_revision = "c4000000lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs",
                  sa.Column("mode", sa.String(length=10), nullable=False,
                            server_default="live"))
    op.create_check_constraint("ck_scan_job_mode", "scan_jobs", "mode in ('fixture','live')")


def downgrade() -> None:
    op.drop_constraint("ck_scan_job_mode", "scan_jobs", type_="check")
    op.drop_column("scan_jobs", "mode")
