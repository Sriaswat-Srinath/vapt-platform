"""Evidence integrity guards (ADR-0002, ADR-0003, ADR-0011 R2 §7).

  * validation_events is append-only: no UPDATE, no DELETE. A human override
    therefore coexists with the automated result rather than replacing it.
  * a blob reference may only be created while the blob is `present`, which is
    what makes the pre-unlink reference recount durable.
"""
from __future__ import annotations
from alembic import op

revision = "d5000000guard"
down_revision = "8ac2ddcce77e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        create or replace function vapt_validation_events_append_only() returns trigger as $$
        begin
          raise exception 'validation_events is append-only: the automated result is preserved'
            using errcode = 'check_violation';
        end;
        $$ language plpgsql;
    """)
    op.execute("""
        create trigger trg_validation_events_append_only
        before update or delete on validation_events
        for each row execute function vapt_validation_events_append_only();
    """)
    op.execute("""
        create or replace function vapt_blob_reference_guard() returns trigger as $$
        declare blob_state text;
        begin
          if new.blob_id is null then return new; end if;
          select state into blob_state from evidence_blobs where id = new.blob_id;
          if blob_state is distinct from 'present' then
            raise exception 'cannot reference evidence blob in state %: a purge is in flight',
              coalesce(blob_state, 'missing') using errcode = 'check_violation';
          end if;
          return new;
        end;
        $$ language plpgsql;
    """)
    op.execute("""
        create trigger trg_evidence_blob_reference_guard
        before insert or update on evidence
        for each row execute function vapt_blob_reference_guard();
    """)


def downgrade() -> None:
    op.execute("drop trigger if exists trg_evidence_blob_reference_guard on evidence")
    op.execute("drop function if exists vapt_blob_reference_guard()")
    op.execute("drop trigger if exists trg_validation_events_append_only on validation_events")
    op.execute("drop function if exists vapt_validation_events_append_only()")
