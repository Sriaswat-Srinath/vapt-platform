"""One `held` lease per adapter — the global exclusivity guarantee (ADR-0008 R2).

A partial unique index, so the database itself refuses a second concurrent
holder even if the application logic were wrong.
"""
from __future__ import annotations
from alembic import op

revision = "c4000000lease"
down_revision = "634cfcbb33f5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        create unique index uq_one_held_lease_per_adapter
        on scanner_daemon_leases (adapter_name)
        where lease_state = 'held';
    """)
    # raw_observations are immutable: block UPDATE and DELETE at the database level.
    op.execute("""
        create or replace function vapt_raw_observations_immutable() returns trigger as $$
        begin
          raise exception 'raw_observations are immutable (ADR-0002)' using errcode = 'check_violation';
        end;
        $$ language plpgsql;
    """)
    op.execute("""
        create trigger trg_raw_observations_immutable
        before update or delete on raw_observations
        for each row execute function vapt_raw_observations_immutable();
    """)


def downgrade() -> None:
    op.execute("drop trigger if exists trg_raw_observations_immutable on raw_observations")
    op.execute("drop function if exists vapt_raw_observations_immutable()")
    op.execute("drop index if exists uq_one_held_lease_per_adapter")
