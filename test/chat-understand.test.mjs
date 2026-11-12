import { test } from 'node:test';
import assert from 'node:assert/strict';
import { quickRead, parseUnderstanding, parseScenario, understandPrompt, scenarioPrompt, appDigest, handsBack, refersToKnown, makeLimiter } from '../lib/chat-understand.js';

test('"use the one I gave you" is the email already known', () => {
  const known = { email: 'dan@example.com' };
  for (const t of ['use the one i gave you', 'the same', 'same as before', 'I already gave it', 'my email', 'you have it', 'yes'])
    assert.deepEqual(quickRead('email', t, { known }), { action: 'use_known' }, t);
  // Nothing known: there is nothing to point at.
  assert.equal(quickRead('email', 'use the one i gave you', {}), null);
});

test('an email inside a sentence is found', () => {
  assert.deepEqual(quickRead('email', "it's Dan@Example.com, thanks", {}), { action: 'value', value: 'dan@example.com' });
  assert.equal(quickRead('email', 'what do you need it for?', {}), null);
});

test('a link inside a sentence is found, an email is not a link', () => {
  assert.deepEqual(quickRead('url', 'here: https://my-shop.lovable.app/ ok?', {}), { action: 'value', value: 'https://my-shop.lovable.app/' });
  assert.deepEqual(quickRead('url', 'my-shop.lovable.app', {}), { action: 'value', value: 'my-shop.lovable.app' });
  assert.equal(quickRead('url', 'dan@example.com', {}), null);
  assert.equal(quickRead('url', 'which link do you mean', {}), null);
});

test('"you create the scenario" hands the choice back', () => {
  for (const t of ['you create scenario', 'you create the scenario', 'you decide', 'suggest one', 'up to you', "I don't know", 'surprise me', 'create one for me', 'whatever you think'])
    assert.equal(handsBack(t), true, t);
  for (const t of ['a customer books a table for Saturday', 'buy the blue bowl and check the total'])
    assert.equal(handsBack(t), false, t);
});

test('a list is answered by number, by name, by position, by yes or no', () => {
  const options = [{ label: 'Suggest flows' }, { label: 'I will describe it' }];
  assert.deepEqual(quickRead('menu', '2', { options }), { action: 'choose', index: 2 });
  assert.deepEqual(quickRead('menu', 'suggest flows', { options }), { action: 'choose', index: 1 });
  assert.deepEqual(quickRead('menu', 'the second', { options }), { action: 'choose', index: 2 });
  assert.deepEqual(quickRead('menu', 'yes', { options: [{ label: 'Start' }, { label: 'Not now' }] }), { action: 'choose', index: 1 });
  assert.deepEqual(quickRead('menu', 'no', { options: [{ label: 'Start' }, { label: 'Not now' }] }), { action: 'choose', index: 2 });
  assert.equal(quickRead('menu', '9', { options }), null);
  assert.equal(quickRead('menu', 'what is a flow?', { options }), null);
  // "yes" says nothing on a list of three.
  assert.equal(quickRead('menu', 'yes', { options: [{ label: 'a' }, { label: 'b' }, { label: 'c' }] }), null);
});

test('only whitelisted actions come back from Claude', () => {
  const ctx = { known: { email: 'dan@example.com' }, options: [{ label: 'a' }, { label: 'b' }] };
  assert.deepEqual(parseUnderstanding('email', '{"action":"use_known"}', ctx), { action: 'use_known' });
  assert.deepEqual(parseUnderstanding('email', '{"action":"use_known"}', {}), { action: 'unclear' });
  assert.deepEqual(parseUnderstanding('email', '{"action":"value","value":"not an email"}', ctx), { action: 'unclear' });
  assert.deepEqual(parseUnderstanding('menu', 'Sure! {"action":"choose","index":2}', ctx), { action: 'choose', index: 2 });
  assert.deepEqual(parseUnderstanding('menu', '{"action":"choose","index":7}', ctx), { action: 'unclear' });
  assert.deepEqual(parseUnderstanding('menu', '{"action":"run_shell","value":"rm"}', ctx), { action: 'unclear' });
  assert.deepEqual(parseUnderstanding('email', '{"action":"choose","index":1}', ctx), { action: 'unclear' });
  assert.deepEqual(parseUnderstanding('url', 'no json here', ctx), { action: 'unclear' });
  assert.equal(parseUnderstanding('url', '{"action":"answer","reply":"The link your customers open."}', ctx).reply, 'The link your customers open.');
});

test('a written scenario must be a real one', () => {
  assert.deepEqual(parseScenario('{"scenario":"Open the shop, add the Ciotola in maiolica to the cart and check the cart lists it."}'),
    { scenario: 'Open the shop, add the Ciotola in maiolica to the cart and check the cart lists it.' });
  assert.equal(parseScenario('{"scenario":"Test it."}').none, true);
  assert.deepEqual(parseScenario('{"none":true,"reply":"I did not see a purchase or a booking. What does a customer buy?"}'),
    { none: true, reply: 'I did not see a purchase or a booking. What does a customer buy?' });
  assert.equal(parseScenario('garbage').none, true);
});

test('prompts carry the question, the list and what is known', () => {
  const p = understandPrompt('menu', 'the booking one', { title: 'Which test?', options: [{ label: 'Flow Test', desc: 'one journey' }], known: { email: 'dan@example.com' } });
  assert.match(p, /1\. Flow Test — one journey/);
  assert.match(p, /the booking one/);
  assert.match(p, /dan@example\.com/);
  const s = scenarioPrompt('checkout', '{"app":"Shop"}', 'a haircut');
  assert.match(s, /BEFORE paying/);
  assert.match(s, /a haircut/);
});

test('the app digest is small and has the names a scenario needs', () => {
  const d = appDigest({ summary: { appName: 'Shop', appType: 'E-commerce', sections: [{ name: 'Cart', purpose: 'Review' }], crossSectionFlows: [{ name: 'Add to cart', description: 'x' }] },
    pages: { '/shop': { name: 'Shop', headings: ['Handmade'], buttons: [{ label: 'Add to cart' }, { label: 'Add to cart' }, { label: 'Menu', inNav: true }], inputs: [{ placeholder: 'Search' }] } } });
  const j = JSON.parse(d);
  assert.deepEqual(j.pages[0].buttons, ['Add to cart']);
  assert.deepEqual(j.pages[0].fields, ['Search']);
  assert.equal(j.flows[0].name, 'Add to cart');
});

test('the limiter lets a few through and then stops', () => {
  const ok = makeLimiter(2, 1000);
  assert.equal(ok('a', 0), true);
  assert.equal(ok('a', 10), true);
  assert.equal(ok('a', 20), false);
  assert.equal(ok('b', 20), true);
  assert.equal(ok('a', 1500), true);
});

test('refersToKnown does not fire on ordinary sentences', () => {
  assert.equal(refersToKnown('a customer books a table'), false);
  assert.equal(refersToKnown('the same as before'), true);
});
