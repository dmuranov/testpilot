import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFreeRunAllowance } from '../lib/free-runs.js';

const canonicalEmail = (e) => String(e || '').trim().toLowerCase().replace(/\+[^@]*@/, '@');
const quiet = { log() {}, warn() {} };

// The only thing the module touches on a response is end(); res.json/send go
// through it. Track whether the handler answered.
function fakeRes() { return { ended: false, end() { this.ended = true; return this; } }; }

function make({ runs = 3, stored = [] } = {}) {
  const files = {};
  const fs = {
    readFile: async () => JSON.stringify(stored),
    writeFile: async (f, body) => { files[f] = body; },
    rename: async (a, b) => { files[b] = files[a]; delete files[a]; },
  };
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => runs, file: 'x.json', fs, log: quiet });
  return { a, files };
}

test('extras = runs - 1; identity is canonical (plus-alias is the same person)', () => {
  const { a } = make({ runs: 3 });
  assert.equal(a.left('a@x.com'), 2);
  assert.equal(a.available('a@x.com'), true);
  assert.equal(a.available(''), false);
  a.reserve(fakeRes(), 'a+demo@x.com').commit();
  assert.equal(a.left('a@x.com'), 1);
});

test('runs = 1 (today\'s free tier) means no extras for anyone', () => {
  const { a } = make({ runs: 1 });
  assert.equal(a.left('a@x.com'), 0);
  assert.equal(a.available('a@x.com'), false);
});

test('reserve is synchronous: the last extra can be taken only once', () => {
  const { a } = make({ runs: 2 });
  assert.equal(a.available('a@x.com'), true);
  a.reserve(fakeRes(), 'a@x.com');
  assert.equal(a.available('a@x.com'), false);   // a parallel request is denied
  assert.equal(a.left('a@x.com'), 0);
});

test('answering without commit (early 4xx) gives the run back, even to a dead client', () => {
  const { a } = make({ runs: 3 });
  const res = fakeRes();
  a.reserve(res, 'a@x.com');
  assert.equal(a.left('a@x.com'), 1);
  res.end('{"error":"App not found"}');            // no socket involved: still releases
  assert.equal(res.ended, true);
  assert.equal(a.left('a@x.com'), 2);
  res.end();                                       // idempotent
  assert.equal(a.left('a@x.com'), 2);
});

test('commit before the response keeps the charge', () => {
  const { a } = make({ runs: 3 });
  const res = fakeRes();
  const hold = a.reserve(res, 'a@x.com');
  hold.commit();
  res.end();
  assert.equal(a.left('a@x.com'), 1);
  hold.commit();                                   // idempotent
  assert.equal(a.left('a@x.com'), 1);
});

test('the wrapped end() still calls the original with its arguments and this', () => {
  const { a } = make({ runs: 3 });
  const calls = [];
  const res = { end(...args) { calls.push([this === res, ...args]); return 'orig'; } };
  a.reserve(res, 'a@x.com');
  assert.equal(res.end('body', 'utf8'), 'orig');
  assert.deepEqual(calls, [[true, 'body', 'utf8']]);
});

test('only committed spends are persisted; a hold alone writes nothing', async () => {
  const { a, files } = make({ runs: 3 });
  await a.load();
  const res = fakeRes();
  const hold = a.reserve(res, 'a@x.com');
  assert.equal(files['x.json'], '[]');             // reservation not on disk
  hold.commit();
  await new Promise(r => setImmediate(r));
  assert.equal(files['x.json'], '[["a@x.com",1]]');
  assert.equal(files['x.json.tmp'], undefined);   // tmp+rename left no temp file
});

test('load is additive and nothing is written before it completes', async () => {
  const { a, files } = make({ runs: 5, stored: [['b@x.com', 1]] });
  a.reserve(fakeRes(), 'b@x.com').commit();        // committed before the file was read
  assert.equal(files['x.json'], undefined);       // save() guarded until loaded
  await a.load();
  assert.equal(a.left('b@x.com'), 5 - 1 - 2);      // disk 1 + in-memory 1
  await new Promise(r => setImmediate(r));
  assert.equal(files['x.json'], '[["b@x.com",2]]');
});

test('load tolerates a missing file and warns on anything else', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const enoent = Object.assign(new Error('nope'), { code: 'ENOENT' });
  const fsOk = { writeFile: async () => {}, rename: async () => {} };
  const a1 = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x', fs: { ...fsOk, readFile: async () => { throw enoent; } }, log });
  await a1.load();
  assert.equal(warned.length, 0);
  const a2 = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x', fs: { ...fsOk, readFile: async () => { throw new Error('disk'); } }, log });
  await a2.load();
  assert.equal(warned.length, 1);
});
