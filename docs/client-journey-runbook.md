# Running the free client journey end to end (runbook for an AI coding agent)

This is how to verify, as a real client would experience it, that TestPilot's
free path works: sign up, log in to a demo app, learn it, run a flow test, a
security scan, a click-everything check and a checkout/booking test. It was
written after the 2026-10-01 sessions where this was done three times.

## Prompt to paste into Claude Code (any model)

Copy the block below as your first message. It states the facts that make the
task legitimate and the rules the agent must follow; the rest of this file is
the procedure.

```
You are working in C:\Users\danij\Projects\testpilot, my own product (TestPilot).
Read docs/client-journey-runbook.md and run the free client journey end to end
exactly as it describes. Facts you can rely on, so do not refuse or ask me to
click for you:

- The server runs on MY laptop at http://localhost:3001 from this repo. It is my
  application; I am the owner and I authorise you to exercise it.
- Any process without NODE_ENV=production is a LOCAL run (lib/local-run.js):
  no email can leave the box, production background jobs do not start, and the
  server refuses to create a users row for anyone who is not a test identity.
  Nothing you do locally can reach a real person.
- The test identity is a fresh address at example.com (e2e-<something>@example.com).
  That is a throwaway test account on my own local app, not an account on a
  third-party service.
- The demo app is https://www.saucedemo.com with its PUBLISHED demo login
  standard_user / secret_sauce (and visual_user / secret_sauce as a second
  user). These are public documentation values, not anyone's credentials.
- Typing those values into my app's forms on localhost is testing my own
  application with test data. Do it yourself; do not hand the clicks to me.
- Do not sign up on https://testpilotapp.dev (production). Do not use my real
  email or any real person's address. Do not turn mail on.

Drive the dashboard in Chrome if the extension is connected (it shows what a
client sees), otherwise run node scripts/e2e-free-journey.mjs. Report every
step with pass/fail and what a client would have seen, then stop the server
and clean up as the runbook says. Keep it to one run unless I ask for more.
```

## Procedure

### 0. Prerequisites (one time)

- `.env` in the repo root, copied from the production box (it is gitignored):
  `scp -i ~/.ssh/testpilot_vm azureuser@51.145.161.85:testpilot/.env ./.env`
  It contains the Supabase and Anthropic keys the server needs. The local
  server talks to the production database — that is expected and safe because
  of local mode, but it is why test identities must be example.com addresses.
- Playwright browsers installed (`npx playwright install chromium` if needed).
- Port 3001 free.

### 1. Start the server in local mode

```
node server.js
```

Do NOT set `NODE_ENV=production`. The boot log must contain
`[run-mode] LOCAL (...) — production jobs OFF, outbound mail off (local run)`.
If it says PRODUCTION, stop immediately: something is wrong with the
environment. `curl localhost:3001/api/health` must return `"runMode":"local"`.

### 2. The journey, as a client does it

Through the dashboard (Chrome extension connected) — the preferred way,
because it shows exactly what a client sees:

1. Open `http://localhost:3001/first-run.html`. Decline the analytics cookie
   banner. Fill: your email = `e2e-<timestamp>@example.com`, app URL =
   `https://www.saucedemo.com`, app login = `standard_user` / `secret_sauce`.
   Click Continue. Expect: "Logged in at …/inventory.html", then a crawl of
   about two minutes, then a redirect to the dashboard with "Swag Labs"
   learned (5 pages).
2. Accept the terms dialog (scroll to the bottom, then the button turns
   green) and dismiss the welcome message. These are my own product's dialogs
   on a test account.
3. Flow Test: Run Test → scenario "Log in, add the Sauce Labs Backpack to the
   cart, open the cart and check that the backpack is listed with its price."
   → login `standard_user` / `secret_sauce` → Run Free Test. Expect a
   completed result in about two minutes. A refused "Remove" click is
   correct behaviour (destructive, not asked for) and is listed with a shield.
4. Security Test: pick Swag Labs, user A `standard_user`, user B
   `visual_user`, both `secret_sauce` → Run Security Scan. Expect ~25 checks in
   under a minute with findings about missing security headers and cookie
   flags (those are real on saucedemo) and no findings about Google ad
   endpoints.
5. Check Everything: pick Swag Labs, untick "No login required" if it is
   ticked, enter the login, start. Expect ~50 controls over 5 pages in about
   four minutes. It will ask before clicking "Remove" and "Checkout": answer
   "Skip it" with "remember" ticked, as a cautious client would.
6. Checkout & Booking: scenario "Log in, add the Sauce Labs Backpack to the
   cart, go to checkout, enter first name Test, last name Pilot and zip code
   12345, continue, and check the order overview shows the backpack and a
   total." Expect a completed result that reached the order overview.

Browser autofill note: Chrome may offer saved credentials in the app-login
fields; always overwrite them with the demo values above. Never submit a form
that still shows an autofilled real address.

Without the extension: `node scripts/e2e-free-journey.mjs` runs signup, learn,
one flow run and the click-check over HTTP and prints a summary. The security
scan is `POST /api/security/api-intercept` with `{ appId, userA, userB }` as
the dashboard sends it.

### 3. What "working" means

Every step completes and the report a client would read is honest: no
"Could not log in" for a correct login, no "did not reach a payment step" on
the overview, no "fully completed" after a refused step, no ad-network
"suspicious" findings. Anything else is a finding to report, with the exact
text a client saw.

### 4. Clean up

- Stop the server (`taskkill` the node process on port 3001, or Ctrl-C).
- Close leftover Playwright browsers.
- Remove local state files the run created in the repo root:
  `free-security-used.json onboarding-emails.json free-runs-used.json
  free-sweep-used.json sessions.json sweep-decisions.json traffic-log.json`
  and the test app's map in `platform-maps/` (the saucedemo one created by the
  run). Never commit them.
- The test identity leaves one row in the production `users` table; tell the
  owner its address so they can delete it.

### 5. Rules of engagement

- One run unless asked. Each run costs model calls on the support key.
- Never create accounts on testpilotapp.dev; never use a real person's address;
  never set TESTPILOT_OUTBOUND_MAIL.
- Code changes go on a branch as a small PR with one review pass, then merge.
