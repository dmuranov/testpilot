import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFreeRunAllowance } from '../lib/free-runs.js';

const canonicalEmail = (e) => String(e || '').trim().toLowerCase().replace(/\+[^@]*@/, '@');
const quiet = { log() {}, warn() {} };
const tick = () => new Promise(r => setImmediate(r));

// The only thing the module touches on a response is end(); res.json/send go
// through it. Track whether the handler answered.
function fakeRes() { return { ended: false, end() { this.ended = true; return this; } }; }

// In-memory fs: `files` is what is on disk.
function fakeFs(files) {
  return {
    files,
    readFile: async (f) => {
      if (!(f in files)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return files[f];
    },
    writeFile: async (f, body) => { files[f] = body; },
    rename: async (a, b) => { if (!(a in files)) throw new Error('ENOENT'); files[b] = files[a]; delete files[a]; },
  };
}

async function make({ runs = 3, files = {}, load = true, holdTtlMs, now } = {}) {
  const fs = fakeFs(files);
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => runs, file: 'x.json', fs, log: quiet, holdTtlMs, now });
  if (load) await a.load();
  return { a, files };
}

test('extras = runs - 1; identity is canonical (plus-alias is the same person)', async () => {
  const { a } = await make({ runs: 3 });
  assert.equal(a.left('a@x.com'), 2);
  assert.equal(a.available('a@x.com'), true);
  assert.equal(a.available(''), false);
  a.reserve(fakeRes(), 'a+demo@x.com').commit();
  assert.equal(a.left('a@x.com'), 1);
});

test('runs = 1 (today\'s free tier) means no extras for anyone', async () => {
  const { a } = await make({ runs: 1 });
  assert.equal(a.left('a@x.com'), 0);
  assert.equal(a.available('a@x.com'), false);
});

test('fail closed until the file has been read — gates AND reporting', async () => {
  const { a } = await make({ runs: 3, load: false });
  assert.equal(a.loaded, false);
  assert.equal(a.available('a@x.com'), false);
  assert.equal(a.left('a@x.com'), 0);
  assert.equal(a.remaining('a@x.com'), 0);
  await a.load();
  assert.equal(a.available('a@x.com'), true);
  assert.equal(a.remaining('a@x.com'), 2);
});

test('reserve is synchronous: the last extra can be taken only once', async () => {
  const { a } = await make({ runs: 2 });
  assert.equal(a.available('a@x.com'), true);
  a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.available('a@x.com'), false);   // a parallel request is denied
  assert.equal(a.left('a@x.com'), 0);
});

test('remaining() ignores in-flight holds; left() counts them', async () => {
  const { a } = await make({ runs: 2 });
  const hold = a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.left('a@x.com'), 0);          // another request would be denied
  assert.equal(a.remaining('a@x.com'), 1);     // but the user is not told they are out
  hold.commit();
  assert.equal(a.remaining('a@x.com'), 0);
});

test('answering without commit (early 4xx) gives the run back, even to a dead client', async () => {
  const { a } = await make({ runs: 3 });
  const res = fakeRes();
  a.reserve(res, 'a@x.com');
  assert.equal(a.left('a@x.com'), 1);
  res.end('{"error":"App not found"}');            // no socket involved: still releases
  assert.equal(res.ended, true);
  assert.equal(a.left('a@x.com'), 2);
  res.end();                                       // idempotent
  assert.equal(a.left('a@x.com'), 2);
});

test('commit before the response keeps the charge', async () => {
  const { a } = await make({ runs: 3 });
  const res = fakeRes();
  const hold = a.reserve(res, 'a@x.com');
  hold.commit();
  res.end();
  assert.equal(a.left('a@x.com'), 1);
  hold.commit();                                   // idempotent
  assert.equal(a.left('a@x.com'), 1);
});

test('commit after the handler already answered is a no-op (nothing started)', async () => {
  const { a } = await make({ runs: 3 });
  const res = fakeRes();
  const hold = a.reserve(res, 'a@x.com');
  res.end();                                       // 4xx went out
  hold.commit();
  assert.equal(a.left('a@x.com'), 2);
});

test('refund() after commit gives the extra back, at most once, and persists', async () => {
  const { a, files } = await make({ runs: 3 });
  const hold = a.reserve(fakeRes(), 'a@x.com');
  hold.commit();
  await tick();
  assert.equal(files['x.json'], '[["a@x.com",1]]');
  hold.refund();                                   // run ended without a verdict
  assert.equal(a.left('a@x.com'), 2);
  hold.refund();                                   // idempotent
  assert.equal(a.left('a@x.com'), 2);
  await tick();
  assert.equal(files['x.json'], '[]');
});

test('refund() before commit is a no-op (nothing was charged)', async () => {
  const { a } = await make({ runs: 3 });
  const hold = a.reserve(fakeRes(), 'a@x.com');
  hold.refund();
  assert.equal(a.left('a@x.com'), 1);              // still held
});

test('a handler that never answers releases the hold after the TTL', async () => {
  const { a } = await make({ runs: 3, holdTtlMs: 5 });
  a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.left('a@x.com'), 1);
  await new Promise(r => setTimeout(r, 20));
  assert.equal(a.left('a@x.com'), 2);
});

test('a commit that arrives after the TTL still charges (the run IS starting)', async () => {
  const { a } = await make({ runs: 2, holdTtlMs: 5 });
  const slow = a.reserve(fakeRes(), 'a@x.com');
  await new Promise(r => setTimeout(r, 20));       // TTL released it
  assert.equal(a.left('a@x.com'), 1);
  a.reserve(fakeRes(), 'a@x.com').commit();        // someone else took the freed extra
  assert.equal(a.left('a@x.com'), 0);
  slow.commit();                                   // slow handler finally starts its run
  assert.equal(a.remaining('a@x.com'), 0);         // charged, not silently free
  slow.refund();                                   // and can still be refunded on no-verdict
  assert.equal(a.remaining('a@x.com'), 0);         // (clamped: 2 spent - 1 = 1 spent of 1 extra)
});

test('a released hold does not fire its TTL later (timer cleared)', async () => {
  const { a } = await make({ runs: 3, holdTtlMs: 5 });
  const res = fakeRes();
  a.reserve(res, 'a@x.com');
  res.end();                                       // released
  a.reserve(fakeRes(), 'a@x.com').commit();        // a real spend afterwards
  assert.equal(a.left('a@x.com'), 1);
  await new Promise(r => setTimeout(r, 20));
  assert.equal(a.left('a@x.com'), 1);              // stale timer did not double-release
});

test('the wrapped end() still calls the original with its arguments and this', async () => {
  const { a } = await make({ runs: 3 });
  const calls = [];
  const res = { end(...args) { calls.push([this === res, ...args]); return 'orig'; } };
  a.reserve(res, 'a@x.com');
  assert.equal(res.end('body', 'utf8'), 'orig');
  assert.deepEqual(calls, [[true, 'body', 'utf8']]);
});

test('only committed spends are persisted; a hold alone writes nothing', async () => {
  const { a, files } = await make({ runs: 3 });
  assert.equal(files['x.json'], '[]');
  const res = fakeRes();
  const hold = a.reserve(res, 'a@x.com');
  assert.equal(files['x.json'], '[]');             // reservation not on disk
  hold.commit();
  await tick();
  assert.equal(files['x.json'], '[["a@x.com",1]]');
  assert.equal(files['x.json.tmp'], undefined);   // tmp+rename left no temp file
});

test('load is additive and nothing is written before it completes', async () => {
  const { a, files } = await make({ runs: 5, files: { 'x.json': '[["b@x.com",1]]' }, load: false });
  // available() is false before load, but a caller holding a reference from
  // elsewhere could still commit — make sure that survives the load.
  a.reserve(fakeRes(), 'b@x.com').commit();
  assert.equal(files['x.json'], '[["b@x.com",1]]');   // save() guarded until loaded
  await a.load();
  assert.equal(a.left('b@x.com'), 5 - 1 - 2);      // disk 1 + in-memory 1
  assert.equal(files['x.json'], '[["b@x.com",2]]');
});

test('a corrupt or wrong-shape file is moved aside in full, nothing applied, earlier samples kept', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const bads = ['{not json', '[["a@x.com",2],5,["b@x.com",2]]', '{"a@x.com":2}', '[["a@x.com",-100]]', '[["a@x.com",0.5]]'];
  let t = 0;
  const now = () => new Date(1700000000000 + (t++) * 1000);
  for (const bad of bads) {
    const files = { 'x.json': bad, 'x.json.corrupt-earlier': 'keep me' };
    const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x.json', fs: fakeFs(files), log, now });
    await a.load();
    const aside = Object.keys(files).filter(k => k.startsWith('x.json.corrupt-') && k !== 'x.json.corrupt-earlier');
    assert.equal(aside.length, 1, bad);
    assert.equal(files[aside[0]], bad);
    assert.equal(files['x.json.corrupt-earlier'], 'keep me');
    assert.equal(files['x.json'], '[]');
    assert.equal(a.left('a@x.com'), 2, bad);       // nothing from the file was applied
  }
  assert.equal(warned.length, bads.length);
});

test('an UNREADABLE file (not missing) is left alone and extras stay disabled', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const files = { 'x.json': '[["a@x.com",2]]' };
  const fs = fakeFs(files);
  fs.readFile = async () => { throw Object.assign(new Error('EBUSY'), { code: 'EBUSY' }); };
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x.json', fs, log });
  await a.load();
  assert.equal(a.loaded, false);
  assert.equal(a.available('a@x.com'), false);          // fail closed
  assert.deepEqual(Object.keys(files), ['x.json']);     // nothing moved, nothing written
  assert.equal(files['x.json'], '[["a@x.com",2]]');
  assert.equal(warned.length, 1);
});

test('the hold restores res.end and lets go of the response once it settles', async () => {
  const { a } = await make({ runs: 3 });
  const orig = function () { return 'orig'; };
  const res1 = { end: orig }, res2 = { end: orig };
  const h1 = a.reserve(res1, 'a@x.com');
  assert.notEqual(res1.end, orig);                      // wrapped while held
  h1.commit();
  assert.equal(res1.end, orig);                         // restored on commit
  a.reserve(res2, 'a@x.com');
  res2.end();                                           // released by the response
  assert.equal(res2.end, orig);                         // restored on release
  assert.equal(a.left('a@x.com'), 1);
});

test('a missing file is not an error', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const files = {};
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x.json', fs: fakeFs(files), log });
  await a.load();
  assert.equal(warned.length, 0);
  assert.equal(files['x.json'], '[]');
});
