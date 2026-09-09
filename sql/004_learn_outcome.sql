-- TestPilot: persist the actual learn/crawl OUTCOME, not just the URL claim
-- Run in the Supabase SQL editor.
--
-- app_ownership previously only recorded that a URL was claimed
-- (url_normalized, owner_email, created_at) -- never whether the crawl that
-- followed actually succeeded. The real result (login required? succeeded?
-- how many pages?) lived only in a JSON file on the app VM's disk, so
-- answering "did this signup's onboarding actually work" had no database
-- answer at all, only an SSH-in-and-read-the-file one.

alter table app_ownership
  add column if not exists learn_status text check (learn_status in ('success','failed')),
  add column if not exists login_required boolean,
  add column if not exists login_success boolean,
  add column if not exists login_message text,
  add column if not exists pages_crawled integer,
  add column if not exists failure_message text,
  add column if not exists failure_category text,
  add column if not exists learned_at timestamptz;
