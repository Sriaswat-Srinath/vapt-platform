"""Server-side defaults for the daemon state/lease flags.

These rows are touched by operators during incident recovery (a stuck lease, a
dirty daemon). A NOT NULL boolean whose default exists only in Python means any
non-ORM insert fails, so the defaults belong in the database too.
"""
from __future__ import annotations
from alembic import op

revision = "c5000000srvdef"
down_revision = "8baf8636071a"
branch_labels = None
depends_on = None

COLUMNS = [
    ("scanner_daemon_state", "is_dirty", "false"),
    ("scanner_daemon_state", "requires_operator_restart", "false"),
    ("scanner_daemon_leases", "daemon_dirty_on_release", "false"),
    ("scanner_resets", "cleared_dirty", "false"),
]


def upgrade() -> None:
    for table, column, default in COLUMNS:
        op.execute(f"alter table {table} alter column {column} set default {default}")


def downgrade() -> None:
    for table, column, _ in COLUMNS:
        op.execute(f"alter table {table} alter column {column} drop default")
