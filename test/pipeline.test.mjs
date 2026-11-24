import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { openStore, snapshot } from '../server/store.mjs';
import { syncSources } from '../server/sources.mjs';
import { deliver } from '../server/wechat.mjs';
import { digestSignals, telegramPosts } from '../server/digest.mjs';

const testedId = 'CVE-2026-999999';
const tryDate = '2026-11-24';
const patch = {
  ...snapshot.items.find(item => item.id === 'CVE-2026-123007'), id:testedId, date:tryDate
};
const entry = {
  id:testedId, published:tryDate + 'T01:00:00Z',
  references:[{ url:'https://nginx.org/en/security_advisories.html' }],
  metrics:{ cvssMetricV40:[{ cvssData:{ baseScore:9.2,version:'4.0' } }] }
};
const now = new Date(tryDate + 'T06:12:00Z');
const emptyDigest = { status:{}, cursors:{}, signals:[] };

function catalog() {
  return {
    dateReleased:'2026-11-24T05:00:00Z', catalogVersion:'2026.11.24',
    vulnerabilities: snapshot.items.filter(item => item.kev).map(item => ({
      cveID:item.id, dateAdded:item.kev, notes:''
    }))
  };
}

test('the reviewed snapshot covers the requested products and has no initial notifications', t => {
  const store = openStore(':memory:');
  t.after(() => store.db.close());
  const products = new Set(store.feed().items.flatMap(item => item.products));
  assert.ok(['PHP','Nginx','Node.js','Java','Windows','macOS','iOS','Android'].every(p => products.has(p)));
  assert.ok(store.feed().items.some(item => item.category === 'incident'));
  assert.equal(store.lookup('CVE-2026-109619').id,'CVE-2026-109618');
  assert.equal(store.q('SELECT count(*) AS count FROM events').get().count,0);
});

test('severity distribution and pagination use the same grades and keep every alert accessible', () => {
  const sandbox = { module: { exports: {} } };
  runInNewContext(readFileSync(new URL('../miniprogram/shared/catalog.js', import.meta.url), 'utf8'), sandbox);
  const alertCatalog = sandbox.module.exports;
  const initial = alertCatalog.display(snapshot, { tab: 'home' });
  const displayedIds = new Set();
  const shownGrades = [];
  for (let page = 1; page <= initial.pageCount; page++) {
    const view = alertCatalog.display(snapshot, { tab: 'home', page });
    assert.ok(view.pageItems.length <= 5);
    for (const item of view.pageItems) {
      displayedIds.add(item.id);
      shownGrades.push(initial.severityCounts.findIndex(level => level.id === item.severity));
    }
  }
  assert.equal(displayedIds.size, snapshot.items.length);
  assert.deepEqual(shownGrades, [...shownGrades].sort((a, b) => a - b));
  assert.equal(initial.severityCounts.reduce((sum, level) => sum + level.count, 0), initial.count);
  for (const level of initial.severityCounts) {
    const view = alertCatalog.display(snapshot, { tab: 'home', severity: level.id });
    assert.equal(view.count, level.count);
    assert.ok(view.pageItems.every(item => item.severity === level.id));
  }
  const sap = alertCatalog.display(snapshot, { tab: 'home', id: 'CVE-2025-42884' }).detail;
  assert.equal(sap.severity, 'medium');
  assert.ok(sap.kev);
  const windows = alertCatalog.display(snapshot, { tab: 'home', id: 'WIN11-2026-11' }).detail;
  assert.equal(windows.severity, 'critical');
  const patch = alertCatalog.display(snapshot, { tab: 'home', id: 'KB5132061' }).detail;
  assert.equal(patch.severity, 'unrated');
  const scores = [0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10];
  const expected = ['none', 'low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical'];
  const scoreFeed = { items: scores.map((score, index) => ({
    ...snapshot.items[0], id: 'TEST-' + index, kev: null, score, metric: 'CVSS 4.0'
  })) };
  for (const [index, severity] of expected.entries()) {
    const view = alertCatalog.display(scoreFeed, { tab: 'home', id: 'TEST-' + index });
    assert.equal(view.detail.severity, severity);
  }

  assert.ok(initial.home.feature.kev);
  assert.equal(initial.count, snapshot.items.length);
  assert.equal(initial.pageItems.length, 5);
  const homePageTwo = alertCatalog.display(snapshot, { tab: 'home', page: 2 });
  assert.ok(homePageTwo.pageItems.every(item => !initial.pageItems.some(first => first.id === item.id)));
  const homeRuntime = alertCatalog.display(snapshot, { tab: 'home', category: 'runtime' });
  assert.equal(homeRuntime.count, snapshot.items.filter(item => item.category === 'runtime').length);
  assert.ok(homeRuntime.pageItems.every(item => item.category === 'runtime'));
  const personalized = alertCatalog.display(snapshot, { tab: 'home', following: ['PHP'] }).home;
  assert.ok(personalized.featureFollowed);
  assert.ok(personalized.feature.products.includes('PHP'));

  const id = snapshot.items.find(item => item.id === 'WIN11-2026-11').aliases[0];
  const emptySearch = alertCatalog.display(snapshot, { tab: 'search', query: ' ' });
  assert.equal(emptySearch.queryActive, false);
  assert.equal(emptySearch.count, 0);
  assert.ok(emptySearch.popularTopics.some(topic => topic.name === 'Windows'));
  const search = alertCatalog.display(snapshot, { tab: 'search', query: id, id });
  assert.equal(search.pageItems[0].matchedId, id);
  assert.equal(search.detail.id, 'WIN11-2026-11');
  const nginx = alertCatalog.display(snapshot, { tab: 'search', query: 'Nginx' });
  assert.ok(nginx.count > 5);
  assert.equal(nginx.pageItems.length, nginx.count);
  assert.equal(nginx.nextSearchLimit, 0);
  const broadQuery = { tab: 'search', query: '漏洞' };
  const broad = alertCatalog.display(snapshot, broadQuery);
  assert.equal(broad.pageCount, 1);
  assert.ok(broad.nextSearchLimit > broad.pageItems.length);
  const more = alertCatalog.display(snapshot, { ...broadQuery, searchLimit: broad.nextSearchLimit });
  assert.equal(more.pageItems.length, broad.nextSearchLimit);
  assert.equal(more.pageItems.slice(0, broad.pageItems.length).map(item => item.id).join(), broad.pageItems.map(item => item.id).join());
});

test('verified CVEs publish once, unverified leads wait, and withdrawals remain hidden', async t => {
  const store = openStore(':memory:');
  t.after(() => store.db.close());
  const sources = { kev:catalog(),nvd:[entry],cisa:[],vendor:[],digest:emptyDigest,now };
  await syncSources(store,{ ...sources, draft:async () => null });
  assert.equal(store.lookup(testedId), undefined);
  assert.ok(store.candidates().some(item => item.id === testedId));
  const first = await syncSources(store,{ ...sources, draft:async () => patch });
  assert.equal(first.published,1);
  assert.ok(store.lookup(testedId));
  const second = await syncSources(store,{ ...sources, draft:async () => patch });
  assert.equal(second.published,0);
  assert.equal(store.q('SELECT count(*) AS count FROM events').get().count,1);
  await syncSources(store,{ ...sources, nvd:[{ ...entry,vulnStatus:'Rejected' }], draft:async () => patch });
  assert.equal(store.lookup(testedId),undefined);
  await syncSources(store,{ ...sources, draft:async () => patch });
  assert.equal(store.lookup(testedId),undefined);
});

test('public channel posts generate deduplicated private leads without republishing text', async t => {
  const store = openStore(':memory:');
  t.after(() => store.db.close());
  const chunk = (handle,id,text) => `<div class="tgme_widget_message" data-post="${handle}/${id}">
    <div class="tgme_widget_message_text js-message_text">${text}</div>
    <time datetime="2026-11-24T04:00:00Z"></time></div>`;
  const posts = telegramPosts([
    chunk('IntCyberDigest',1,`Private marker CVE-2026-999999 <a href="https://nginx.org/en/security_advisories.html?utm_source=social">官方页面</a>`),
    chunk('IntCyberDigest',2,'A second mention of CVE-2026-999999.'),
    chunk('IntCyberDigest',3,'The vendor announced a security incident.'),
    chunk('IntCyberDigest',4,'A hardware product was announced.'),
    chunk('AnotherAccount',5,'A security update for CVE-2026-123456.')
  ].join(''));
  const signals = digestSignals(posts);
  assert.equal(posts.length,4);
  assert.equal(signals.length,3);
  const digest = { status:{ telegram:{state:'ok',posts:4} },cursors:{digestTelegramCursor:'4'},signals };
  const base = { kev:catalog(),nvd:[entry],cisa:[],vendor:[],now,draft:async () => null };
  const first = await syncSources(store,{ ...base,digest });
  assert.equal(first.digest.candidates,2);
  const cve = store.candidates().find(item => item.id === testedId);
  assert.equal(cve.origin,'NVD');
  assert.equal(cve.leads.length,2);
  assert.ok(cve.links.every(link => !link.url.includes('utm_')));
  assert.equal(store.meta('digestTelegramCursor'),'4');
  assert.equal(store.lookup(testedId),undefined);
  assert.equal(JSON.stringify(store.candidates()).includes('Private marker'),false);

  await syncSources(store,{ ...base,digest:emptyDigest });
  assert.equal(store.candidates().find(item => item.id === testedId).leads.length,2);
});

test('grouped CVEs remain searchable and new KEV evidence reopens individual review', async t => {
  const store = openStore(':memory:');
  t.after(() => store.db.close());
  const bundle = {
    ...patch, id:'PATCH-GROUP-2026', aliases:[
      testedId, ...Array.from({ length:33 },(_,index) => 'CVE-2026-' + (990000 + index))
    ]
  };
  store.transact(() => {
    store.candidate({ id:testedId });
    store.save(bundle,'review',false);
  });
  assert.equal(store.lookup(testedId).id,bundle.id);
  assert.equal(store.lookup(bundle.aliases.at(-1)).aliases.length,34);
  const status = store.q('SELECT state FROM candidates WHERE id=?');
  assert.equal(status.get(testedId).state,'published');
  const kev = catalog();
  kev.vulnerabilities.push({ cveID:testedId,dateAdded:tryDate,notes:'' });
  const sources = { kev,nvd:[],cisa:[],vendor:[],digest:emptyDigest,now };
  await syncSources(store,sources);
  assert.equal(status.get(testedId).state,'pending');
  assert.equal(store.candidates().find(item => item.id === testedId).kev,tryDate);
  await syncSources(store,{ ...sources,nvd:[{ ...entry,vulnStatus:'Rejected' }] });
  assert.equal(store.lookup(testedId),undefined);
  assert.equal(status.get(testedId).state,'withdrawn');
  assert.equal(store.lookup(bundle.id).aliases.length,33);
});

test('a single opted-in matching recipient receives the new alert only once', async t => {
  const store = openStore(':memory:');
  t.after(() => store.db.close());
  const old = new Date(Date.now() - 5000).toISOString();
  const register = store.q('INSERT INTO recipients VALUES(?,?,?,?)');
  register.run('matches','abc','["Nginx"]',old);
  register.run('other','def','["Java"]',old);
  register.run('cancelled','xyz','["Nginx"]',null);
  store.transact(() => store.save(patch));
  const calls = [];
  const transport = async (item,openid) => { calls.push([item.id,openid]); return { errcode:0 }; };
  await Promise.all([deliver(store,{},transport),deliver(store,{},transport)]);
  assert.deepEqual(calls,[[testedId,'matches']]);
  assert.equal(store.q('SELECT state FROM deliveries WHERE openid=?').get('matches').state,'sent');
  assert.equal(store.q('SELECT registered FROM recipients WHERE openid=?').get('matches').registered,null);
});
