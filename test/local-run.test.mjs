import { test } from 'node:test';
import assert from 'node:assert/strict';
process.env.TESTPILOT_TESTER_EMAILS = 'tester.one@company.com, Second@Company.com';
const { runMode, isInternalAddress, canonicalForCompare } = await import('../lib/local-run.js');

test('production pm2 process: jobs and mail on', () => {
  const m = runMode({ NODE_ENV: 'production' });
  assert.equal(m.isProd, true);
  assert.equal(m.prodJobs, true);
  assert.equal(m.mailEnabled, true);
});

test('plain `node server.js` on a laptop: local, no jobs, no mail', () => {
  for (const env of [{}, { NODE_ENV: 'development' }, { NODE_ENV: 'test' }]) {
    const m = runMode(env);
    assert.equal(m.local, true, JSON.stringify(env));
    assert.equal(m.prodJobs, false);
    assert.equal(m.mailEnabled, false);
  }
});

test('TESTPILOT_LOCAL forces local mode even with NODE_ENV=production, any truthy spelling', () => {
  for (const v of ['1', 'true', 'TRUE', 'yes']) {
    const m = runMode({ NODE_ENV: 'production', TESTPILOT_LOCAL: v });
    assert.equal(m.local, true, v);
    assert.equal(m.prodJobs, false, v);
    assert.equal(m.mailEnabled, false, v);
  }
  const off = runMode({ NODE_ENV: 'production', TESTPILOT_LOCAL: 'no' });
  assert.equal(off.isProd, true);
});

test('TESTPILOT_OUTBOUND_MAIL turns mail on for a local run WITHOUT re-arming production jobs', () => {
  const m = runMode({ TESTPILOT_OUTBOUND_MAIL: '1' });
  assert.equal(m.local, true);
  assert.equal(m.mailEnabled, true);
  assert.equal(m.prodJobs, false);
});

test('pm2 on the production path counts as production even without NODE_ENV (first deploy safety net)', () => {
  const m = runMode({ pm_id: '0', name: 'testpilot' }, '/home/azureuser/testpilot');
  assert.equal(m.isProd, true);
  assert.equal(m.mailEnabled, true);
  assert.match(m.reason, /pm2 process "testpilot" on \/home\/azureuser\/testpilot/);
  // pm2 elsewhere, the path without pm2, or another pm2 process name there, is still local
  assert.equal(runMode({ pm_id: '0', name: 'testpilot' }, '/home/dev/testpilot').isProd, false);
  assert.equal(runMode({}, '/home/azureuser/testpilot').isProd, false);
  assert.equal(runMode({ pm_id: '1', name: 'tp-experiment' }, '/home/azureuser/testpilot').isProd, false);
  // a sibling checkout whose path merely starts the same is not production; a sub-path is
  assert.equal(runMode({ pm_id: '0', name: 'testpilot' }, '/home/azureuser/testpilot-staging').isProd, false);
  assert.equal(runMode({ pm_id: '0', name: 'testpilot' }, '/home/azureuser/testpilot/').isProd, true);
  // pm2 without an injected name still counts (older pm2)
  assert.equal(runMode({ pm_id: '0' }, '/home/azureuser/testpilot').isProd, true);
  // TESTPILOT_LOCAL still wins on the box, but the box is still "the production box" for log hygiene
  const forced = runMode({ pm_id: '0', name: 'testpilot', TESTPILOT_LOCAL: '1' }, '/home/azureuser/testpilot');
  assert.equal(forced.isProd, false);
  assert.equal(forced.onProductionBox, true);
});

test('internal addresses: admin in any gmail spelling, @example.*, TESTPILOT_TESTER_EMAILS; nobody else', () => {
  for (const a of ['danijel.muranovic@gmail.com', 'DanijelMuranovic@gmail.com', 'danijel.muranovic+demo@gmail.com', 'x@example.com', 'tester.one@company.com', 'second@company.com', 'Second+qa@company.com', '']) {
    assert.equal(isInternalAddress(a), true, a);
  }
  for (const a of ['bob@acme.com', 'admin@facilitlabs.com', 'danijel.muranovic@proton.me']) {
    assert.equal(isInternalAddress(a), false, a);
  }
  assert.equal(canonicalForCompare('A.B+c@GoogleMail.com'), 'ab@gmail.com');
});

test('reasons name the deciding input', () => {
  assert.equal(runMode({ NODE_ENV: 'production' }).reason, 'NODE_ENV=production');
  assert.equal(runMode({ NODE_ENV: 'production', TESTPILOT_LOCAL: '1' }).reason, 'TESTPILOT_LOCAL is set');
  assert.match(runMode({}, '/tmp').reason, /^NODE_ENV=\(unset\)/);
});
