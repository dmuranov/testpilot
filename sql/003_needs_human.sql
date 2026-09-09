-- TestPilot proactive support: terminal 'needs_human' status
-- Run in the Supabase SQL editor.
--
-- A fix job that exhausts every auto-fix attempt (orchestrator.js's retry
-- loop in testpilot-support-bridge) previously had no way to tell TestPilot
-- it gave up: the row stayed at 'fix_in_progress' forever, and the support
-- widget kept telling users "a fix is already underway" for a job nothing
-- was actually working on. This adds a terminal status for that outcome,
-- mirroring 'ignored' -- record_signal's 'watching' branch never touches
-- it, so it stays until a human resets it by hand.

alter table error_signatures drop constraint if exists error_signatures_status_check;
alter table error_signatures add constraint error_signatures_status_check
  check (status in ('watching','queued','fix_in_progress','fix_shipped',
                     'regressed','ignored','needs_human'));

-- Called by the bridge (via POST /api/internal/fix-failed) when a fix job
-- exhausts every retry and falls back to emailing a human. Only fires from
-- 'fix_in_progress' so it can't clobber a row that already moved on (e.g. a
-- race with mark_fix_shipped, or a status a human already reset by hand).
create or replace function mark_fix_needs_human(p_hash text)
returns void
language sql
as $$
  update error_signatures
     set status = 'needs_human'
   where signature_hash = p_hash
     and status = 'fix_in_progress';
$$;
