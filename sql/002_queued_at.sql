-- Fixes the sweep's staleness check. last_seen is bumped by record_signal on
-- EVERY occurrence, including while a signature is stranded in 'queued' and
-- actively recurring — the case that matters most, and the one the original
-- sweep (keyed on last_seen) could never catch, since a live bug's last_seen
-- is always recent. queued_at is stamped exactly once, on the transition
-- INTO 'queued', and left untouched by every occurrence after that — so its
-- age genuinely reflects how long the row has been stuck, not how recently
-- the underlying bug last fired.
-- Run in the Supabase SQL editor, after 001_error_signatures.sql.

alter table error_signatures add column if not exists queued_at timestamptz;

-- One-time correction: any row already sitting in 'queued' when this
-- migration runs has no queued_at yet, which would make it invisible to the
-- sweep's `queued_at < cutoff` filter forever. last_seen is a safe
-- approximation for these — it's already an underestimate of how long
-- they've actually been queued, so the sweep will treat them as strictly
-- more urgent than they truly are, never less.
update error_signatures
   set queued_at = last_seen
 where status = 'queued'
   and queued_at is null;

create or replace function record_signal(
  p_hash             text,
  p_sample           jsonb,
  p_session          text,
  p_min_occurrences  int      default 3,
  p_min_sessions     int      default 2,
  p_regression_grace interval default interval '30 minutes'
)
returns table (
  out_status         text,
  out_occurrences    int,
  out_sessions       int,
  out_should_enqueue boolean,
  out_is_regression  boolean
)
language plpgsql
security definer
as $$
declare
  v_new_session boolean := false;
  v_row         error_signatures%rowtype;
  v_next_status text;
  v_occ         int;
  v_ses         int;
begin
  insert into error_signatures (signature_hash, raw_sample, status, occurrence_count, session_count)
  values (p_hash, p_sample, 'watching', 0, 0)
  on conflict (signature_hash) do nothing;

  insert into error_signature_sessions (signature_hash, session_id)
  values (p_hash, p_session)
  on conflict do nothing;
  v_new_session := found;

  select * into v_row from error_signatures
   where signature_hash = p_hash
   for update;

  v_occ := v_row.occurrence_count + 1;
  v_ses := v_row.session_count + (case when v_new_session then 1 else 0 end);
  v_next_status := v_row.status;

  out_is_regression  := false;
  out_should_enqueue := false;

  -- Regression is measured from when the fix shipped, not from the last hit.
  -- A fix that never held keeps firing continuously, so last_seen is always
  -- recent and a last_seen-based check would never trip.
  if v_row.status = 'fix_shipped'
     and v_row.fix_shipped_at is not null
     and now() - v_row.fix_shipped_at > p_regression_grace then
    v_next_status     := 'regressed';
    out_is_regression := true;

  elsif v_row.status = 'watching'
        and v_occ >= p_min_occurrences
        and v_ses >= p_min_sessions then
    v_next_status      := 'queued';
    out_should_enqueue := true;
  end if;

  update error_signatures
     set occurrence_count = v_occ,
         session_count    = v_ses,
         last_seen        = now(),
         status           = v_next_status,
         -- Stamped ONLY on the actual transition into 'queued' (status
         -- wasn't already 'queued' coming in). A row that's already queued
         -- and keeps recurring must not have this refreshed, or the sweep
         -- is measuring the wrong thing again.
         queued_at        = case
                               when v_next_status = 'queued' and v_row.status <> 'queued' then now()
                               else v_row.queued_at
                             end,
         raw_sample       = case when v_row.occurrence_count = 0 then p_sample else raw_sample end
   where signature_hash = p_hash;

  out_status      := v_next_status;
  out_occurrences := v_occ;
  out_sessions    := v_ses;
  return next;
end;
$$;
