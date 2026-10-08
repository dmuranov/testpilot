import { test } from 'node:test';
import assert from 'node:assert/strict';
import { userScenarioWords, FREE_RUN_WORD_LIMIT } from '../lib/scenario-words.js';

const words = (n) => Array.from({ length: n }, (_, i) => `w${i}`).join(' ');
const REPEATABLE = ' \n\n(Repeatable run: if this flow needs specific starting data that is not already present, create it first and tag anything you create with a "TP-TEST" prefix; at the very end, delete ONLY the records you created during this run.)';
const READ_ONLY = ' \n\n(Read-only run: do not create, edit, or delete any data - navigate and verify only.)';

test('only the client\'s own words count, not the instruction the dashboard appends', () => {
  assert.equal(userScenarioWords(words(80) + REPEATABLE), 80);
  assert.equal(userScenarioWords(words(80) + READ_ONLY), 80);
  assert.ok(userScenarioWords(words(80) + REPEATABLE) <= FREE_RUN_WORD_LIMIT, 'an 80-word description is allowed');
});

test('a description over the limit is still over it', () => {
  assert.equal(userScenarioWords(words(101) + REPEATABLE), 101);
  assert.ok(userScenarioWords(words(101)) > FREE_RUN_WORD_LIMIT);
});

test('plain text with no appended instruction, and empty input', () => {
  assert.equal(userScenarioWords('  open the page   and check it  '), 6);
  assert.equal(userScenarioWords(''), 0);
  assert.equal(userScenarioWords(undefined), 0);
});
