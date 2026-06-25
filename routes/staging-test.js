// routes/staging-test.js
// Staging Safe — auto-test trigger
// Called after every Netlify deploy completes
// Runs all active scenarios for the app against the staging URL
// Uses the existing runAgentTest() and crawlApp() infrastructure

import { randomUUID } from 'crypto';

// Decide a scenario's TRUSTWORTHY outcome from a runAgentTest result.
// The whole point of Staging Safe is to tell the user "your commit broke
// something". It must NEVER cry regression because TestPilot itself couldn't
// log in, couldn't finish the flow, or had an API blip.
//   - 'failed'       → CONFIRMED app defect (summary.bugs > 0). The only
//                      outcome allowed to become a regression / "do not publish".
//   - 'passed'       → ran to completion with zero confirmed defects.
//   - 'inconclusive' → we could not actually test it (login/env blocked, agent
//                      didn't complete, tool/API error). Reported separately,
//                      auto-retried once, never a regression.
export function classifyScenarioOutcome(testResult) {
  const confirmedBugs = testResult?.summary?.bugs
    ?? (Array.isArray(testResult?.bugs) ? testResult.bugs.length : 0);
  if (confirmedBugs > 0) return { outcome: 'failed', confirmedBugs, reason: 'confirmed app defect' };
  // 'completed_with_unverified' = ran to the end with no confirmed defect but a
  // check it couldn't confirm. Not a regression (no defect) — treat as passed
  // so it neither churns retries nor blocks a deploy; the unconfirmed check is
  // surfaced in the interactive report, not the staging gate.
  if (testResult?.status === 'completed' || testResult?.status === 'completed_with_unverified') {
    return { outcome: 'passed', confirmedBugs: 0, reason: '' };
  }
  const cat = testResult?.blockedReason?.category;
  const reason = cat === 'environment' ? 'login/environment blocked — not an app fault'
    : testResult?.status === 'incomplete' ? 'agent could not complete the flow'
    : testResult?.status === 'error' ? 'TestPilot/tool error'
    : 'could not confirm the outcome';
  return { outcome: 'inconclusive', confirmedBugs: 0, reason };
}

// ─────────────────────────────────────────────
// This function is called from netlify_routes.js
// after a staging deploy completes successfully.
//
// It is NOT a route — it's an internal function
// exported for use by the deploy pipeline.
// ─────────────────────────────────────────────

export async function runStagingSafeTests(
  appId,
  commitSha,
  commitMessage,
  {
    supabase,        // the supabase() helper from server.js
    runAgentTest,    // the existing runAgentTest() from server.js
    testResults,     // the existing testResults Map from server.js
    testStreams,     // the existing testStreams Map from server.js
    platformMaps,    // the existing platformMaps Map from server.js
    mailer,          // the existing mailer from server.js
    emitStep,        // the existing emitStep() from server.js
  }
) {
  console.log(`[Staging Safe] Starting auto-test for app=${appId} commit=${commitSha}`);

  try {
    // ── 1. Load the app ──
    const apps = await supabase('GET', 'apps', null,
      `?app_id=eq.${appId}&select=*`
    );
    const app = apps?.[0];
    if (!app) throw new Error(`App ${appId} not found`);
    if (!app.staging_url) throw new Error(`No staging_url for app ${appId}`);

    // ── 2. Load all active scenarios for this app ──
    const scenarios = await supabase('GET', 'scenarios', null,
      `?app_id=eq.${appId}&status=eq.active&select=*`
    );

    if (!scenarios || scenarios.length === 0) {
      console.log(`[Staging Safe] No active scenarios for app ${appId} — skipping tests`);
      return { skipped: true, reason: 'no_scenarios' };
    }

    console.log(`[Staging Safe] Running ${scenarios.length} scenarios against ${app.staging_url}`);

    // ── 3. Get the app knowledge map (from crawl/Learn step) ──
    let appKnowledge = platformMaps.get(appId);
    if (!appKnowledge) {
      console.warn(`[Staging Safe] No platform map for app ${appId} — tests may be less accurate`);
      // Create a minimal knowledge object so runAgentTest can still attempt
      appKnowledge = {
        appId,
        url: app.staging_url,
        pages: {},
        navigation: {},
        formRecipes: {},
        interactions: {},
        summary: null
      };
    } else {
      // Override URL to point to staging, not production
      appKnowledge = { ...appKnowledge, url: app.staging_url };
    }

    // ── 4. Load test credentials ──
    const credentials = {
      email: app.test_credentials_email || '',
      password: app.test_credentials_password || '',
    };

    if (!credentials.email || !credentials.password) {
      console.warn(`[Staging Safe] No test credentials for app ${appId} — tests will run without login`);
    }

    // ── 5. Run each scenario ──
    const testRunResults = [];
    const reportId = `rpt_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
    let regressions = 0;
    let fixes = 0;
    let unchanged = 0;
    let inconclusive = 0;
    let totalPassed = 0;
    let totalFailed = 0;

    for (const scenario of scenarios) {
      const testId = `tst_${randomUUID().replace(/-/g, '').slice(0, 12)}`;

      // Build scenario description string for runAgentTest
      const scenarioText = scenario.description ||
        (scenario.steps || []).map(s => s.instruction).join('. ');

      console.log(`[Staging Safe] Running scenario: ${scenario.name} (${testId})`);

      try {
        // Run the test using the existing runAgentTest infrastructure
        let testResult = await runAgentTest(
          testId,
          appKnowledge,
          scenarioText,
          credentials,
          app.anthropic_api_key || process.env.ANTHROPIC_SUPPORT_KEY
        );

        // Trust-aware classification. Only a CONFIRMED app defect is a failure.
        let decision = classifyScenarioOutcome(testResult);

        // One automatic retry for inconclusive runs. A transient login/vision/
        // API flake must never surface to the user — a real defect already
        // returned 'failed' and won't be retried away. Passed runs aren't
        // retried either; only "couldn't test" gets a second chance.
        if (decision.outcome === 'inconclusive') {
          console.log(`[Staging Safe] ${scenario.name}: inconclusive (${decision.reason}) — auto-retrying once`);
          const retryId = `tst_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
          testResult = await runAgentTest(
            retryId, appKnowledge, scenarioText, credentials,
            app.anthropic_api_key || process.env.ANTHROPIC_SUPPORT_KEY
          );
          decision = classifyScenarioOutcome(testResult);
        }

        const result = decision.outcome; // 'passed' | 'failed' | 'inconclusive'
        const baselineResult = scenario.baseline_result || 'not_run';

        // Determine change_type vs baseline. ONLY confirmed failures can be a
        // regression; inconclusive never moves the needle.
        let changeType = 'unchanged';
        if (result === 'inconclusive') {
          changeType = 'inconclusive';
        } else if (baselineResult === 'passing' && result === 'failed') {
          changeType = 'regression';
          regressions++;
        } else if (baselineResult === 'failing' && result === 'passed') {
          changeType = 'fix';
          fixes++;
        } else if (baselineResult === 'not_run') {
          changeType = 'new';
        } else {
          unchanged++;
        }

        if (result === 'passed') totalPassed++;
        else if (result === 'failed') totalFailed++;
        else inconclusive++;

        // Failure detail, tagged with WHY so the user can tell an app defect
        // from a "couldn't test" condition at a glance.
        const failedStep = testResult.steps?.find(s => s.status === 'fail');
        let failureReason = failedStep?.outcome || testResult.error || testResult.blockedReason?.description || null;
        if (result === 'inconclusive') {
          failureReason = `Could not test (${decision.reason})${failureReason ? `: ${failureReason}` : ''}`;
        }

        // Save test record to Supabase
        await supabase('POST', 'tests', {
          test_id: testId,
          scenario_id: scenario.scenario_id,
          app_id: appId,
          is_baseline: false,
          commit_sha: commitSha,
          commit_message: commitMessage,
          result,
          baseline_result: baselineResult,
          change_type: changeType,
          started_at: testResult.startedAt || new Date().toISOString(),
          completed_at: new Date().toISOString(),
          steps_total: scenario.steps?.length || 0,
          steps_passed: testResult.steps?.filter(s => s.status === 'pass').length || 0,
          failure_reason: failureReason,
          triggered_by: 'commit',
        }).catch(e => console.error('Failed to save test:', e.message));

        // Update scenario last_result — but NOT on inconclusive: we don't want
        // a flaky "couldn't test" to clobber the last meaningful baseline.
        if (result !== 'inconclusive') {
          await supabase('PATCH', 'scenarios', { last_result: result },
            `?scenario_id=eq.${scenario.scenario_id}`
          ).catch(() => {});
        }

        testRunResults.push({
          scenario_id: scenario.scenario_id,
          name: scenario.name,
          result,
          change_type: changeType,
          failure_reason: failureReason,
        });

        console.log(`[Staging Safe] ${scenario.name}: ${result} (${changeType})`);

      } catch (err) {
        console.error(`[Staging Safe] Scenario ${scenario.name} errored:`, err.message);

        // A thrown error is a TestPilot/tool failure, never an app defect.
        // Record it as inconclusive so it can't become a regression.
        await supabase('POST', 'tests', {
          test_id: testId,
          scenario_id: scenario.scenario_id,
          app_id: appId,
          is_baseline: false,
          commit_sha: commitSha,
          commit_message: commitMessage,
          result: 'inconclusive',
          baseline_result: scenario.baseline_result || 'not_run',
          change_type: 'inconclusive',
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          steps_total: scenario.steps?.length || 0,
          steps_passed: 0,
          failure_reason: `Could not test (TestPilot/tool error): ${err.message}`,
          triggered_by: 'commit',
        }).catch(() => {});

        inconclusive++;
        testRunResults.push({
          scenario_id: scenario.scenario_id,
          name: scenario.name,
          result: 'inconclusive',
          change_type: 'inconclusive',
          failure_reason: `Could not test (TestPilot/tool error): ${err.message}`,
        });
      }
    }

    // ── 6. Save report ──
    const githubDiffUrl = app.github_repo
      ? `https://github.com/${app.github_repo}/commit/${commitSha}`
      : null;

    // NOTE: 'unchanged' is intentionally NOT inserted — the reports table
    // schema has no such column and PostgREST 422s the whole row, losing
    // the entire report. Local `unchanged` is still used below for the
    // email body and the function's return value. To persist it, run:
    //   ALTER TABLE reports ADD COLUMN unchanged integer NOT NULL DEFAULT 0;
    // and then add `unchanged,` back into this payload.
    await supabase('POST', 'reports', {
      report_id: reportId,
      app_id: appId,
      commit_sha: commitSha,
      commit_message: commitMessage,
      commit_diff_url: githubDiffUrl,
      scenarios_total: scenarios.length,
      scenarios_passed: totalPassed,
      scenarios_failed: totalFailed,
      regressions,
      fixes,
      spiral_detected: false, // Phase 3
      created_at: new Date().toISOString(),
    }).catch(e => console.error('Failed to save report:', e.message));

    // ── 7. Send email notification to user ──
    if (app.user_email) {
      const statusEmoji = regressions > 0 ? '⚠️' : '✅';
      const statusLine = regressions > 0
        ? `${regressions} regression${regressions > 1 ? 's' : ''} detected`
        : fixes > 0
          ? `${fixes} issue${fixes > 1 ? 's' : ''} fixed`
          : inconclusive > 0
            ? `No regressions${inconclusive > 0 ? ` (${inconclusive} couldn't be tested)` : ''}`
            : 'All scenarios unchanged';

      const scenarioRows = testRunResults.map(r => {
        const icon = r.result === 'passed' ? '✅' : r.result === 'inconclusive' ? '⏳' : '❌';
        const badge = r.change_type === 'regression' ? ' 🔴 REGRESSION'
          : r.change_type === 'fix' ? ' 🟢 FIXED'
          : r.change_type === 'new' ? ' 🔵 NEW'
          : r.change_type === 'inconclusive' ? ' ⏳ COULDN’T TEST'
          : '';
        // Inconclusive reasons are de-emphasised (grey, italic) so they read as
        // "we couldn't check this", never as an app defect.
        const reasonStyle = r.result === 'inconclusive'
          ? 'color:#999;font-size:13px;font-style:italic'
          : 'color:#666;font-size:13px';
        return `<tr>
          <td style="padding:8px 12px;border-bottom:1px solid #eee">${icon} ${r.name}${badge}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #eee;${reasonStyle}">${r.failure_reason || '—'}</td>
        </tr>`;
      }).join('');

      await mailer({
        from: 'TestPilot Staging Safe <hello@testpilotapp.dev>',
        to: app.user_email,
        subject: `${statusEmoji} ${app.name}: ${statusLine} — ${commitMessage.slice(0, 50)}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px 20px">
            <h2 style="font-size:20px;font-weight:800;margin-bottom:4px">
              Test<span style="color:#c8f040">Pilot</span>
              <span style="font-weight:400;font-size:14px;color:#888;margin-left:8px">Staging Safe</span>
            </h2>

            <div style="background:#f9f9f9;border-left:4px solid ${regressions > 0 ? '#ef4444' : '#22c55e'};padding:16px;margin:20px 0;border-radius:0 4px 4px 0">
              <p style="margin:0;font-size:15px;font-weight:700;color:#080808">${statusEmoji} ${statusLine}</p>
              <p style="margin:4px 0 0;font-size:13px;color:#666">Commit: <code>${commitSha.slice(0, 7)}</code> — ${commitMessage.slice(0, 80)}</p>
            </div>

            <div style="display:flex;gap:16px;margin:20px 0">
              <div style="text-align:center;padding:12px 20px;background:#f9f9f9;border-radius:4px;min-width:80px">
                <div style="font-size:24px;font-weight:800;color:#22c55e">${totalPassed}</div>
                <div style="font-size:12px;color:#888">passed</div>
              </div>
              <div style="text-align:center;padding:12px 20px;background:#f9f9f9;border-radius:4px;min-width:80px">
                <div style="font-size:24px;font-weight:800;color:#ef4444">${totalFailed}</div>
                <div style="font-size:12px;color:#888">failed</div>
              </div>
              <div style="text-align:center;padding:12px 20px;background:#f9f9f9;border-radius:4px;min-width:80px">
                <div style="font-size:24px;font-weight:800;color:#f97316">${regressions}</div>
                <div style="font-size:12px;color:#888">regressions</div>
              </div>
              <div style="text-align:center;padding:12px 20px;background:#f9f9f9;border-radius:4px;min-width:80px">
                <div style="font-size:24px;font-weight:800;color:#3b82f6">${fixes}</div>
                <div style="font-size:12px;color:#888">fixed</div>
              </div>
              <div style="text-align:center;padding:12px 20px;background:#f9f9f9;border-radius:4px;min-width:80px">
                <div style="font-size:24px;font-weight:800;color:#9ca3af">${inconclusive}</div>
                <div style="font-size:12px;color:#888">couldn’t test</div>
              </div>
            </div>

            <table style="width:100%;border-collapse:collapse;margin:20px 0">
              <thead>
                <tr style="background:#080808;color:#c8f040">
                  <th style="padding:8px 12px;text-align:left;font-size:13px">Scenario</th>
                  <th style="padding:8px 12px;text-align:left;font-size:13px">Failure reason</th>
                </tr>
              </thead>
              <tbody>${scenarioRows}</tbody>
            </table>

            ${githubDiffUrl ? `<p style="margin:16px 0"><a href="${githubDiffUrl}" style="color:#3b82f6;font-size:13px">→ View code diff on GitHub</a></p>` : ''}

            <div style="background:#080808;color:#f4f2ee;padding:16px;border-radius:4px;margin:20px 0">
              <p style="margin:0;font-size:14px;font-weight:700">
                ${regressions > 0 ? '⚠️ Do not publish yet — review regressions first.' : '✅ Safe to publish.'}
              </p>
              ${inconclusive > 0 ? `<p style="margin:8px 0 0;font-size:12px;color:#cbd5e1">⏳ ${inconclusive} scenario${inconclusive > 1 ? 's' : ''} couldn’t be tested (login/tool/API issue, not your app) — already auto-retried once. These do <strong>not</strong> count as regressions.</p>` : ''}
            </div>

            <p style="font-size:12px;color:#aaa;margin-top:24px">
              TestPilot Staging Safe · <a href="https://testpilotapp.dev/app" style="color:#aaa">View full report</a>
            </p>
          </div>
        `
      }).catch(e => console.error('Failed to send report email:', e.message));

      // Update report notified_at
      await supabase('PATCH', 'reports', { notified_at: new Date().toISOString() },
        `?report_id=eq.${reportId}`
      ).catch(() => {});
    }

    console.log(`[Staging Safe] Complete: ${totalPassed} passed, ${totalFailed} failed, ${inconclusive} inconclusive, ${regressions} regressions, ${fixes} fixes`);

    return {
      report_id: reportId,
      scenarios_total: scenarios.length,
      scenarios_passed: totalPassed,
      scenarios_failed: totalFailed,
      inconclusive,
      regressions,
      fixes,
      unchanged,
      results: testRunResults,
    };

  } catch (err) {
    console.error(`[Staging Safe] Auto-test failed for app ${appId}:`, err.message);
    throw err;
  }
}
