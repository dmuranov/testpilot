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

async function make({ runs = 3, files = {}, load = true, holdTtlMs } = {}) {
  const fs = fakeFs(files);
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => runs, file: 'x.json', fs, log: quiet, holdTtlMs });
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

test('fail closed until the file has been read', async () => {
  const { a } = await make({ runs: 3, load: false });
  assert.equal(a.loaded, false);
  assert.equal(a.available('a@x.com'), false);
  await a.load();
  assert.equal(a.available('a@x.com'), true);
});

test('reserve is synchronous: the last extra can be taken only once', async () => {
  const { a } = await make({ runs: 2 });
  assert.equal(a.available('a@x.com'), true);
  a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.available('a@x.com'), false);   // a parallel request is denied
  assert.equal(a.left('a@x.com'), 0);
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

test('a handler that never answers releases the hold after the TTL', async () => {
  const { a } = await make({ runs: 3, holdTtlMs: 5 });
  const hold = a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.left('a@x.com'), 1);
  await new Promise(r => setTimeout(r, 20));
  assert.equal(a.left('a@x.com'), 2);
  hold.commit();                                   // too late: nothing to charge
  assert.equal(a.left('a@x.com'), 2);
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

test('a corrupt file is moved aside, never overwritten', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const files = { 'x.json': '{not json' };
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x.json', fs: fakeFs(files), log });
  await a.load();
  assert.equal(files['x.json.corrupt'], '{not json');
  assert.equal(files['x.json'], '[]');
  assert.equal(warned.length, 1);
  assert.equal(a.available('a@x.com'), true);
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
