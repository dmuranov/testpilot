import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createFreeRunAllowance } from '../lib/free-runs.js';

const canonicalEmail = (e) => String(e || '').trim().toLowerCase().replace(/\+[^@]*@/, '@');
const quiet = { log() {}, warn() {} };

function make({ runs = 3, stored = [] } = {}) {
  const writes = [];
  const fs = {
    readFile: async () => JSON.stringify(stored),
    writeFile: async (_f, body) => { writes.push(JSON.parse(body)); },
  };
  const a = createFreeRunAllowance({ canonicalEmail, runsFor: () => runs, file: 'x.json', fs, log: quiet });
  return { a, writes };
}

test('extras = runs - 1; identity is canonical (plus-alias is the same person)', async () => {
  const { a } = make({ runs: 3 });
  assert.equal(a.left('a@x.com'), 2);
  assert.equal(a.available('a@x.com'), true);
  assert.equal(a.available(''), false);
  a.reserve(new EventEmitter(), 'a+demo@x.com').commit();
  assert.equal(a.left('a@x.com'), 1);
});

test('runs = 1 (today\'s free tier) means no extras for anyone', () => {
  const { a } = make({ runs: 1 });
  assert.equal(a.left('a@x.com'), 0);
  assert.equal(a.available('a@x.com'), false);
});

test('reserve is synchronous: the last extra can be taken only once', () => {
  const { a } = make({ runs: 2 });
  const r1 = new EventEmitter(), r2 = new EventEmitter();
  assert.equal(a.available('a@x.com'), true);
  a.reserve(r1, 'a@x.com');
  assert.equal(a.available('a@x.com'), false);   // second parallel request is denied
  assert.equal(a.left('a@x.com'), 0);
  void r2;
});

test('response finishing without commit gives the run back (early 4xx)', () => {
  const { a } = make({ runs: 3 });
  const res = new EventEmitter();
  a.reserve(res, 'a@x.com');
  assert.equal(a.left('a@x.com'), 1);
  res.emit('finish');
  assert.equal(a.left('a@x.com'), 2);
  res.emit('finish');                              // idempotent
  assert.equal(a.left('a@x.com'), 2);
});

test('commit before the response keeps the charge through finish', () => {
  const { a } = make({ runs: 3 });
  const res = new EventEmitter();
  const hold = a.reserve(res, 'a@x.com');
  hold.commit();
  res.emit('finish');
  assert.equal(a.left('a@x.com'), 1);
  hold.commit();                                   // idempotent
  assert.equal(a.left('a@x.com'), 1);
});

test('a client that goes away before the response does NOT release the run', () => {
  const { a } = make({ runs: 3 });
  const res = new EventEmitter();
  const hold = a.reserve(res, 'a@x.com');
  res.emit('close');                               // abort: no finish
  assert.equal(a.left('a@x.com'), 1);              // still charged
  hold.commit();                                   // handler went on and started the run
  assert.equal(a.left('a@x.com'), 1);
});

test('counter is persisted on reserve and on release, and loaded back', async () => {
  const { a, writes } = make({ runs: 3, stored: [['b@x.com', 1]] });
  await a.load();
  assert.equal(a.left('b@x.com'), 1);
  const res = new EventEmitter();
  a.reserve(res, 'b@x.com');
  assert.deepEqual(writes.at(-1), [['b@x.com', 2]]);
  res.emit('finish');
  assert.deepEqual(writes.at(-1), [['b@x.com', 1]]);
});

test('load tolerates a missing file and warns on anything else', async () => {
  const warned = [];
  const log = { log() {}, warn: (...m) => warned.push(m.join(' ')) };
  const enoent = Object.assign(new Error('nope'), { code: 'ENOENT' });
  const a1 = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x', fs: { readFile: async () => { throw enoent; }, writeFile: async () => {} }, log });
  await a1.load();
  assert.equal(warned.length, 0);
  const a2 = createFreeRunAllowance({ canonicalEmail, runsFor: () => 3, file: 'x', fs: { readFile: async () => { throw new Error('disk'); }, writeFile: async () => {} }, log });
  await a2.load();
  assert.equal(warned.length, 1);
});
