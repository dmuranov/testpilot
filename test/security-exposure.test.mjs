// Regression tests for the URL-only leak checker (security-exposure.js).
// Real hosts: express.static / nginx / CDNs answer the probe's Range request
// with 206 — that response IS the file and must be judged, not skipped.
// SPA hosts: every unknown path is 200 + index.html — must yield no finding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { scanExposedFiles } from '../security-exposure.js';

function serve(app) {
  return new Promise(resolve => {
    const srv = app.listen(0, () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}` }));
  });
}

test('leak check: a published .env behind a Range-honouring static server is found', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tp-leak-'));
  fs.writeFileSync(path.join(dir, '.env'), 'DATABASE_URL=postgres://x\nSECRET_KEY=abc\n');
  fs.writeFileSync(path.join(dir, 'index.html'), '<html>ok</html>');
  const app = express();
  app.use(express.static(dir, { dotfiles: 'allow' }));
  const { srv, origin } = await serve(app);
  try {
    const probe = await fetch(origin + '/.env', { headers: { Range: 'bytes=0-1000' } });
    assert.equal(probe.status, 206, 'precondition: express.static honours Range with 206');
    const res = await scanExposedFiles(origin);
    const env = res.findings.find(f => f.path === '/.env');
    assert.ok(env, 'the .env must be reported');
    assert.equal(env.severity, 'critical');
    assert.match(env.evidence, /DATABASE_URL, SECRET_KEY/);
    assert.ok(!/postgres:\/\/x|abc/.test(JSON.stringify(res)), 'values are never reported, only key names');
  } finally { srv.close(); }
});

test('leak check: an SPA host answering every path with 200 + index.html yields no finding', async () => {
  const app = express();
  app.use((req, res) => res.status(200).type('html').send('<!doctype html><html><body>app shell ' + req.path + '</body></html>'));
  const { srv, origin } = await serve(app);
  try {
    const res = await scanExposedFiles(origin);
    assert.equal(res.hostAnswersEverythingWith200, true);
    assert.equal(res.findings.length, 0);
  } finally { srv.close(); }
});

test('leak check: a clean static host with no sensitive files yields no finding', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tp-clean-'));
  fs.writeFileSync(path.join(dir, 'index.html'), '<html>ok</html>');
  const app = express();
  app.use(express.static(dir));
  const { srv, origin } = await serve(app);
  try {
    const res = await scanExposedFiles(origin);
    assert.equal(res.findings.length, 0);
  } finally { srv.close(); }
});
