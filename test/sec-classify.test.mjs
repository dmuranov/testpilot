import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isReadRequest, extractRecordIdentity, findLeakedIdentity, crossTenantVerdict,
  requestKey, endpointKey, isPublicPath, isConfirmedPublic, prioritizeEndpoints,
  fabricateLoginBody, isIdorCandidate, hasRecordIdInBody, bodyHasData, noAuthVerdict,
} from '../routes/sec-classify.js';

const B44 = 'https://base44.app/api/apps/f002-6059/functions/secure';

test('isReadRequest: GET/HEAD are always reads, PUT/PATCH/DELETE never', () => {
  assert.equal(isReadRequest({ method: 'GET', url: 'https://x/api/jobs' }), true);
  assert.equal(isReadRequest({ method: 'HEAD', url: 'https://x/api/jobs' }), true);
  assert.equal(isReadRequest({ method: 'PUT', url: 'https://x/api/getJob' }), false);
  assert.equal(isReadRequest({ method: 'DELETE', url: 'https://x/api/jobs/1' }), false);
});

test('isReadRequest: Base44 POST reads are reads', () => {
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Job"}' }), true);
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/getMyOrg`, postData: '{}' }), true);
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/me/context`, postData: '{}' }), true);
  assert.equal(isReadRequest({ method: 'POST', url: 'https://x/trpc/job.list?batch=1', postData: '{}' }), true);
});

test('isReadRequest: POST writes and ambiguous POSTs are writes', () => {
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/updateEntity`, postData: '{"id":"abc"}' }), false);
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/deleteJob`, postData: '{}' }), false);
  assert.equal(isReadRequest({ method: 'POST', url: 'https://x/api/jobs', postData: '{"name":"new"}' }), false);
  assert.equal(isReadRequest({ method: 'POST', url: `${B44}/getAndUpdateCounter`, postData: '{}' }), false);
});

test('isReadRequest: GraphQL query is a read, mutation is a write', () => {
  assert.equal(isReadRequest({ method: 'POST', url: 'https://x/graphql', postData: '{"query":"query { jobs { id } }"}' }), true);
  assert.equal(isReadRequest({ method: 'POST', url: 'https://x/graphql', postData: '{"query":"{ jobs { id } }"}' }), true);
  assert.equal(isReadRequest({ method: 'POST', url: 'https://x/graphql', postData: '{"query":"mutation { deleteJob(id:1) }"}' }), false);
});

test('extractRecordIdentity: collects ids, references and owner fields', () => {
  const body = JSON.stringify({ data: [
    { id: 'job-aaaa1111', created_by: 'user-a@example.com', client_id: 'cli-9999', title: 'Roof' },
    { id: 'job-bbbb2222', owner_id: 'u-77', nested: { _id: 'n-0001' } },
  ] });
  const r = extractRecordIdentity(body);
  assert.deepEqual([...r.ids].sort(), ['cli-9999', 'job-aaaa1111', 'job-bbbb2222', 'n-0001']);
  assert.deepEqual([...r.owners].sort(), ['u-77', 'user-a@example.com']);
});

test('extractRecordIdentity: non-JSON, short values and enum-like references yield nothing', () => {
  assert.deepEqual(extractRecordIdentity('<!DOCTYPE html>'), { ids: [], owners: [] });
  assert.deepEqual(extractRecordIdentity('{"id":"ab"}'), { ids: [], owners: [] });
  assert.deepEqual(extractRecordIdentity('{"status_id":1,"type_id":"A","PAID":"yes","valid":"true"}'), { ids: [], owners: [] });
  assert.deepEqual(extractRecordIdentity('{"id":7,"job_id":123456}').ids.sort(), ['123456', '7']);
});

test('findLeakedIdentity: only EXCLUSIVE identifiers count', () => {
  const body = '{"data":[{"id":"job-aaaa1111","created_by":"user-a@example.com"},{"id":"shared-cfg-1"}]}';
  const r = findLeakedIdentity({ body, exclusiveIds: ['job-aaaa1111', 'job-zzzz'], exclusiveOwners: ['user-a@example.com'], markers: ['user-a'] });
  assert.deepEqual(r.idMatches, ['job-aaaa1111']);
  assert.deepEqual(r.ownerMatches, ['user-a@example.com']);
  assert.deepEqual(r.markerMatches, ['user-a']);
  const clean = findLeakedIdentity({ body: '{"data":[{"id":"job-bbbb2222","created_by":"user-b@example.com"}]}', exclusiveIds: ['job-aaaa1111'], exclusiveOwners: ['user-a@example.com'], markers: ['user-a'] });
  assert.deepEqual(clean, { idMatches: [], ownerMatches: [], markerMatches: [] });
});

test('crossTenantVerdict: a request that never reached the app is never SAFE', () => {
  assert.equal(crossTenantVerdict({ reached: false, status: 0 }).verdict, 'INCONCLUSIVE');
});

test('crossTenantVerdict: genuine refusal is SAFE', () => {
  assert.equal(crossTenantVerdict({ reached: true, status: 401 }).verdict, 'SAFE');
  assert.equal(crossTenantVerdict({ reached: true, status: 403 }).verdict, 'SAFE');
  assert.equal(crossTenantVerdict({ reached: true, status: 404, aStatus: 200 }).verdict, 'SAFE');
  assert.equal(crossTenantVerdict({ reached: true, status: 404, aStatus: 404 }).verdict, 'INCONCLUSIVE');
  assert.equal(crossTenantVerdict({ reached: true, status: 500 }).verdict, 'INCONCLUSIVE');
  assert.equal(crossTenantVerdict({ reached: true, status: 400 }).verdict, 'INCONCLUSIVE');
});

test('crossTenantVerdict: ownership match is a confirmed leak even on a public path', () => {
  const v = crossTenantVerdict({ reached: true, status: 200, hasRealData: true, comparable: true, ownerMatches: ['a@x'], isPublic: true });
  assert.deepEqual([v.verdict, v.severity], ['VULNERABLE', 'critical']);
  const v2 = crossTenantVerdict({ reached: true, status: 200, hasRealData: true, comparable: true, idMatches: ['job-1'] });
  assert.deepEqual([v2.verdict, v2.severity], ['VULNERABLE', 'high']);
});

test('crossTenantVerdict: User B got data but none of User A records â†’ SAFE only when comparable', () => {
  assert.equal(crossTenantVerdict({ reached: true, status: 200, hasRealData: true, comparable: true }).verdict, 'SAFE');
  assert.equal(crossTenantVerdict({ reached: true, status: 200, hasRealData: true, comparable: false }).verdict, 'INCONCLUSIVE');
  assert.equal(crossTenantVerdict({ reached: true, status: 200, hasRealData: true, comparable: false, responsesMatch: true }).verdict, 'SUSPICIOUS');
  assert.equal(crossTenantVerdict({ reached: true, status: 200, hasRealData: false, comparable: true }).verdict, 'SAFE');
  assert.equal(crossTenantVerdict({ reached: true, status: 200, hasRealData: false, comparable: false }).verdict, 'INCONCLUSIVE');
});

test('requestKey separates same-url POSTs by body; endpointKey collapses ids', () => {
  const a = requestKey({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Job"}' });
  const b = requestKey({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Invoice"}' });
  assert.notEqual(a, b);
  assert.equal(endpointKey({ method: 'GET', url: 'https://x/api/jobs/12345?t=1' }), endpointKey({ method: 'GET', url: 'https://x/api/jobs/67890?t=2' }));
  assert.equal(endpointKey({ method: 'GET', url: 'https://x/api/jobs/3fa85f64-5717-4562-b3fc-2c963f66afa6' }), endpointKey({ method: 'GET', url: 'https://x/api/jobs/9fa85f64-5717-4562-b3fc-2c963f66afa7' }));
  assert.notEqual(endpointKey({ method: 'GET', url: 'https://x/api/jobs?entity=Job' }), endpointKey({ method: 'GET', url: 'https://x/api/jobs?entity=Invoice' }));
  assert.equal(endpointKey({ method: 'POST', url: `${B44}/getEntity`, postData: '{"id":"aaaaaaaaaaaaaaaaaaaaaaaa"}' }), endpointKey({ method: 'POST', url: `${B44}/getEntity`, postData: '{"id":"bbbbbbbbbbbbbbbbbbbbbbbb"}' }));
  assert.notEqual(endpointKey({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Job"}' }), endpointKey({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Invoice"}' }));
});

test('isPublicPath: whole segment only; isConfirmedPublic needs the logged-out probe', () => {
  assert.equal(isPublicPath('https://x/api/public/config'), true);
  assert.equal(isPublicPath('https://x/publications/1'), false);
  assert.equal(isPublicPath('https://x/api/jobs?scope=public/'), false);
  assert.equal(isConfirmedPublic('https://x/api/public/config', { status: 200, hasData: true }), true);
  assert.equal(isConfirmedPublic('https://x/api/public/config', { status: 401, hasData: false }), false);
  assert.equal(isConfirmedPublic('https://x/api/public/config', null), false);
});

test('prioritizeEndpoints: authed data reads first, auth endpoints last', () => {
  const out = prioritizeEndpoints([
    { name: 'login', isAuthEndpoint: true, authed: false, isRead: false, aStatus: 200, aHasRecords: true },
    { name: 'static', authed: false, isRead: true, aStatus: 200, aHasRecords: false },
    { name: 'jobs', authed: true, isRead: true, aStatus: 200, aHasRecords: true },
    { name: 'write', authed: true, isRead: false, aStatus: 200, aHasRecords: false },
  ]);
  assert.deepEqual(out.map(e => e.name), ['jobs', 'write', 'static', 'login']);
});

test('fabricateLoginBody: swaps identity and password, never keeps the real email', () => {
  const r = fabricateLoginBody('{"email":"user-a@example.com","password":"real"}');
  assert.equal(r.ok, true);
  const parsed = JSON.parse(r.body);
  assert.match(parsed.email, /^tp-probe-[a-z0-9]+@example\.com$/);
  assert.notEqual(parsed.password, 'real');
  assert.equal(r.body.includes('user-a'), false);
  const form = fabricateLoginBody('username=dado&password=x');
  assert.equal(form.ok, true);
  assert.equal(form.body.includes('dado'), false);
  assert.equal(fabricateLoginBody('{"refresh_token":"abc"}').ok, false);
  assert.equal(fabricateLoginBody('garbage').ok, false);
});

test('isIdorCandidate: GET id urls and POST reads carrying a record id', () => {
  assert.equal(isIdorCandidate({ method: 'GET', url: 'https://x/api/jobs/12345' }), true);
  assert.equal(isIdorCandidate({ method: 'GET', url: 'https://x/api/jobs' }), false);
  assert.equal(isIdorCandidate({ method: 'POST', url: `${B44}/getEntity`, postData: '{"entity_type":"Job","id":"3fa85f6457174562b3fc"}' }), true);
  assert.equal(isIdorCandidate({ method: 'POST', url: `${B44}/listEntity`, postData: '{"entity_type":"Job"}' }), false);
  assert.equal(isIdorCandidate({ method: 'POST', url: `${B44}/deleteEntity`, postData: '{"id":"3fa85f6457174562b3fc"}' }), false);
  assert.equal(isIdorCandidate({ method: 'POST', url: 'https://x/api/auth/login', postData: '{"password":"x","id":"3fa85f6457174562b3fc"}' }), false);
  assert.equal(hasRecordIdInBody('{"entity_type":"Job"}'), false);
});

test('noAuthVerdict: SAFE only for a genuine refusal', () => {
  assert.equal(noAuthVerdict({ hasData: false, reached: false, status: 0 }).verdict, 'INCONCLUSIVE');
  assert.equal(noAuthVerdict({ hasData: false, status: 401 }).verdict, 'SAFE');
  assert.equal(noAuthVerdict({ hasData: false, status: 404, aStatus: 200 }).verdict, 'SAFE');
  assert.equal(noAuthVerdict({ hasData: false, status: 404, aStatus: 404 }).verdict, 'INCONCLUSIVE');
  assert.equal(noAuthVerdict({ hasData: false, status: 500 }).verdict, 'INCONCLUSIVE');
  assert.equal(noAuthVerdict({ hasData: false, status: 400 }).verdict, 'INCONCLUSIVE');
  assert.equal(noAuthVerdict({ hasData: false, status: 200 }).verdict, 'SAFE');
  assert.deepEqual(noAuthVerdict({ hasData: true, isPublic: false }).verdict, 'VULNERABLE');
  assert.deepEqual(noAuthVerdict({ hasData: true, isPublic: true }).verdict, 'SUSPICIOUS');
  assert.deepEqual(noAuthVerdict({ hasData: true, isPublic: true, leaksPrivateData: true }).severity, 'critical');
});

test('bodyHasData: empty collections and HTML shells are not data', () => {
  assert.equal(bodyHasData(200, '{"data":[]}'), false);
  assert.equal(bodyHasData(200, '[]'), false);
  assert.equal(bodyHasData(200, '<!DOCTYPE html><html>â€¦</html>'), false);
  assert.equal(bodyHasData(401, '{"data":[{"id":"abc123456"}]}'), false);
  assert.equal(bodyHasData(200, '{"data":[{"id":"abc123456","title":"Roof"}]}'), true);
});
