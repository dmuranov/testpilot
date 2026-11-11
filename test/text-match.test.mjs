import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesText } from '../lib/text-match.js';

test('text with brackets is matched as written, not as a pattern', () => {
  // Seen 2026-11-11: "Cart (1)" was compiled as a regex and looked for "Cart 1".
  assert.equal(matchesText('Cart (1)', 'Shop Cart (1) My orders'), true);
  assert.equal(matchesText('Cart (1)', 'ShopCart (1)My orders'), true);
  assert.equal(matchesText('Cart (1)', 'Shop Cart (0) My orders'), false);
});

test('prices and other punctuation match as written', () => {
  assert.equal(matchesText('$24.00', 'Total: $24.00'), true);       // "$" used to mean "end of text"
  assert.equal(matchesText('Total: €48.00', 'Total: €48.00'), true);
  assert.equal(matchesText('Total: €48.00', 'Total: €24.00'), false);
  assert.equal(matchesText('Is this ok?', 'Is this ok? Yes'), true);
  assert.equal(matchesText('[draft]', 'Invoice [draft]'), true);
  assert.equal(matchesText('2 + 2', 'Sum: 2 + 2'), true);
});

test('case and whitespace do not matter', () => {
  assert.equal(matchesText('my orders', 'MY ORDERS'), true);
  assert.equal(matchesText('Order placed', 'Order\n   placed'), true);
  assert.equal(matchesText('Order placed', 'Order placed'), true);
});

test('a deliberate pattern still works when the words as written are not there', () => {
  assert.equal(matchesText('Order #\\d+', 'Order #1234 confirmed'), true);
  assert.equal(matchesText('Order #\\d+', 'Order pending'), false);
  assert.equal(matchesText('paid|settled', 'Invoice settled'), true);
});

test('a broken pattern never throws', () => {
  assert.equal(matchesText('Total (incl. VAT', 'Total (incl. VAT) €10'), true);
  assert.equal(matchesText('Total (incl. VAT', 'Subtotal €10'), false);
});

test('an empty expectation matches (unchanged behaviour); a real one does not match an empty page', () => {
  assert.equal(matchesText('', 'anything'), true);
  assert.equal(matchesText('Order placed', ''), false);
});
