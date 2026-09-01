-- TestPilot proactive support: signature store
-- Run in the Supabase SQL editor.

create table if not exists error_signatures (
  signature_hash    text primary key,
  raw_sample        jsonb       not null,
  status            text        not null default 'watching'
                      check (status in ('watching','queued','fix_in_progress',
                                        'fix_shipped','regressed','ignored')),
  occurrence_count  int         not null default 0,
  session_count     int         not null default 0,
  first_seen        timestamptz not null default now(),
  last_seen         timestamptz not null default now(),
  fix_shipped_at    timestamptz,          -- set on deploy, NOT on last hit
  pr_url            text,
  job_id            text
);

create index if not exists error_signatures_status_idx on error_signatures (status, last_seen desc);

-- Distinct-session tracking. This is what stops one person hammering F5
-- from looking like a widespread bug.
create table if not exists error_signature_sessions (
  signature_hash text not null references error_signatures(signature_hash) on delete cascade,
  session_id     text not null,
  first_seen     timestamptz not null default now(),
  primary key (signature_hash, session_id)
);

create table if not exists approval_tokens (
  token           text primary key,
  pr_url          text not null,
  signature_hash  text not null,
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null,
  used_at         timestamptz
);


-- One round trip, one row lock. Concurrent sessions hitting the same brand-new
-- signature serialise here, so exactly one caller can ever get should_enqueue=true.
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
         raw_sample       = case when v_row.occurrence_count = 0 then p_sample else raw_sample end
   where signature_hash = p_hash;

  out_status      := v_next_status;
  out_occurrences := v_occ;
  out_sessions    := v_ses;
  return next;
end;
$$;


-- Called by the bridge's GitHub-merge webhook after a fix PR actually merges.
create or replace function mark_fix_shipped(p_hash text, p_pr_url text default null)
returns void
language sql
as $$
  update error_signatures
     set status = 'fix_shipped',
         fix_shipped_at = now(),
         pr_url = coalesce(p_pr_url, pr_url)
   where signature_hash = p_hash;
$$;

-- No anon access: everything goes through the service key from routes/signal.js.
alter table error_signatures          enable row level security;
alter table error_signature_sessions  enable row level security;
alter table approval_tokens           enable row level security;
