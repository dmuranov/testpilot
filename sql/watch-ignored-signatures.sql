-- This is now sent automatically — see sendIgnoredDigestIfDue() in
-- routes/signal.js, which runs the same query on a weekly interval and
-- emails it via sendAdminAlert when the worst offender's occurrence_count
-- crosses CFG.IGNORED_DIGEST_THRESHOLD. Kept here for manual, ad-hoc digging
-- (raw_sample, checking sooner than the weekly cadence, etc.) — a query
-- nobody is scheduled to run was the actual problem, not the query itself.
--
-- 'ignored' is terminal (see routes/signal.js) — a 4xx that crosses the
-- enqueue threshold is written off permanently and the RPC never revisits
-- it. That's correct for a typo'd URL, but a shipped validation regression
-- that starts rejecting previously-valid input is a real bug wearing a 4xx,
-- and it would land here too, silently.
--
-- The occurrence_count is what tells them apart: a validation guard doing
-- its job produces a slow trickle across many DIFFERENT signatures (many
-- distinct typos, few hits each). A regression produces a cliff on ONE
-- signature (every affected user hits the exact same rejected input shape).
-- A row with a high count relative to the others is the one worth opening
-- raw_sample on.

select
  signature_hash,
  status,
  occurrence_count,
  session_count,
  first_seen,
  last_seen,
  raw_sample -> 'event' ->> 'path' as path,
  raw_sample -> 'event' ->> 'status' as http_status,
  raw_sample
from error_signatures
where status = 'ignored'
order by occurrence_count desc
limit 50;
