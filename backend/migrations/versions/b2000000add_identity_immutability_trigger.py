"""Asset identity immutability + audit append-only hardening (invariant I14).

Expressed in the database so it holds under direct SQL, not only through the API.
"""
from __future__ import annotations
from alembic import op

revision = "b2000000add"
down_revision = "40d82117bfaf"
branch_labels = None
depends_on = None

TRIGGER_FN = """
create or replace function vapt_assets_identity_immutable() returns trigger as $$
begin
  if new.environment is distinct from old.environment
     or new.hostname   is distinct from old.hostname
     or new.protocol   is distinct from old.protocol
     or new.port       is distinct from old.port
     or new.asset_identifier is distinct from old.asset_identifier then
    raise exception
      'asset identity is immutable (environment, hostname, protocol, port, asset_identifier); re-register instead'
      using errcode = 'check_violation';
  end if;
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;
"""


def upgrade() -> None:
    op.execute(TRIGGER_FN)
    op.execute("""
        create trigger trg_assets_identity_immutable
        before update on assets
        for each row execute function vapt_assets_identity_immutable();
    """)
    # audit_log is append-only: block UPDATE and DELETE at the database level.
    op.execute("""
        create or replace function vapt_audit_append_only() returns trigger as $$
        begin
          raise exception 'audit_log is append-only' using errcode = 'check_violation';
        end;
        $$ language plpgsql;
    """)
    op.execute("""
        create trigger trg_audit_append_only
        before update or delete on audit_log
        for each row execute function vapt_audit_append_only();
    """)


def downgrade() -> None:
    op.execute("drop trigger if exists trg_audit_append_only on audit_log")
    op.execute("drop function if exists vapt_audit_append_only()")
    op.execute("drop trigger if exists trg_assets_identity_immutable on assets")
    op.execute("drop function if exists vapt_assets_identity_immutable()")
