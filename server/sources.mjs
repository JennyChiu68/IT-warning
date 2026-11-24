import { CVE_ID, KEV_SOURCE, validSource } from './store.mjs';
import { readDigest } from './digest.mjs';

const KEV_FEED = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
];
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_RSS = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';
const CVE_BASE = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/';
const NGINX_ADVISORIES = 'https://nginx.org/en/security_advisories.html';
const PHP_CHANGELOG = 'https://www.php.net/ChangeLog-8.php';
const APPEARANCE = [
  { key: 'PHP', category: 'runtime', designation: /^PHP(?: Group)?$/i, names: /^PHP(?: Interpreter)?$/i, path: /^https:\/\/(?:(?:www\.)?php\.net\/(?:ChangeLog-8\.php|releases\/)|github\.com\/php\/php-src\/security\/advisories\/GHSA-[a-z0-9-]+$)/i },
  { key: 'Nginx', category: 'server', designation: /^(?:F5(?:, Inc\.)?|nginx)$/i, names: /^(?:NGINX(?: Open Source| Plus)?|nginx)$/i, path: /^https:\/\/(?:nginx\.org\/en\/security_advisories\.html|my\.f5\.com\/manage\/s\/article\/K\d+)/i },
  { key: 'Node.js', category: 'runtime', designation: /^(?:Node\.js|OpenJS(?: Foundation)?|NodeJS)$/i, names: /^Node(?:\.js|JS)?$/i, path: /^https:\/\/nodejs\.org\/en\/blog\/vulnerability\//i },
  { key: 'Java', category: 'runtime', designation: /^Oracle(?: Corporation)?$/i, names: /^(?:Oracle )?(?:Java SE|JDK|OpenJDK)(?: .+)?$/i, path: /^https:\/\/www\.oracle\.com\/security-alerts\//i },
  { key: 'Windows', category: 'system', designation: /^Microsoft(?: Corporation)?$/i, names: /^Windows(?:$| (?:10|11|Server|8|7|Vista|RT)\b)/i, path: /^https:\/\/msrc\.microsoft\.com\/(?:update-guide\/vulnerability|en-US\/security-guidance\/advisory)\/CVE-/i },
  { key: 'macOS', category: 'system', designation: /^Apple(?: Inc\.?)?$/i, names: /^macOS(?:$| )/i, path: /^https:\/\/support\.apple\.com\/(?:[\w-]+\/)?\d+(?:\?|$)/i },
  { key: 'iOS', category: 'mobile', designation: /^Apple(?: Inc\.?)?$/i, names: /^iOS(?:$| |\/)/i, path: /^https:\/\/support\.apple\.com\/(?:[\w-]+\/)?\d+(?:\?|$)/i },
  { key: 'Android', category: 'mobile', designation: /^Google(?: LLC)?$/i, names: /^Android(?:$| (?:[\d]+|OS)(?:$| ))/i, path: /^https:\/\/source\.android\.com\/docs\/security\/bulletin\//i },
  { key: 'VMware', category: 'server', designation: /^(?:Broadcom(?: Inc\.?)?|VMware(?:, Inc\.)?)$/i, names: /^(?:VMware )?vCenter(?: Server)?$/i, path: /^https:\/\/support\.broadcom\.com\/web\/ecx\/support-content-notification\//i },
  { key: 'MONAI Label', category: 'server', designation: /^Project MONAI$/i, names: /^MONAI ?Label$/i, path: /^https:\/\/github\.com\/Project-MONAI\/MONAILabel\/releases\//i }
];
const DAY = 86400000;

export async function fetchSource(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(16000) });
  if (!response.ok) throw new Error(new URL(url).hostname + ' HTTP ' + response.status);
  return response;
}

async function getKEV() {
  const errors = [];
  for (const url of KEV_FEED) {
    try {
      const data = await (await fetchSource(url)).json();
      if (!Array.isArray(data.vulnerabilities) || data.count !== data.vulnerabilities.length ||
          !/^\d{4}\.\d{2}\.\d{2}$/.test(data.catalogVersion) ||
          !Number.isFinite(Date.parse(data.dateReleased)) ||
          !data.vulnerabilities.every(item => CVE_ID.test(item.cveID) && /^\d{4}-\d{2}-\d{2}$/.test(item.dateAdded))) throw new Error('目录格式不符');
      return data;
    } catch (error) { errors.push(error.message); }
  }
  throw new Error(errors.join(' / '));
}

function nvdRange(start,end,index) {
  const url = new URL(NVD);
  url.search = new URLSearchParams({
    lastModStartDate: start.toISOString(), lastModEndDate: end.toISOString(),
    startIndex: String(index), resultsPerPage: '2000'
  });
  return url;
}

async function getNVD(store, now) {
  const last = Date.parse(store.meta('nvdCursor'));
  const start = new Date(Number.isFinite(last) ? Math.max(last - 300000, now - 7 * DAY) : now - DAY);
  const end = new Date(Math.min(now, +start + DAY));
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const rows = [];
  let index = 0;
  for (;;) {
    const page = await (await fetchSource(nvdRange(start,end,index), { headers })).json();
    if (!Array.isArray(page.vulnerabilities) || !Number.isInteger(page.totalResults) ||
        (page.vulnerabilities.length === 0 && page.totalResults > index)) throw new Error('NVD 分页数据不完整');
    rows.push(...page.vulnerabilities.map(entry => entry.cve));
    index += page.vulnerabilities.length;
    if (index >= page.totalResults) break;
    if (page.vulnerabilities.length === 0 || index >= 10000) throw new Error('NVD 分页超出预期');
    await new Promise(resolve => setTimeout(resolve, 6000));
  }
  return { end, rows };
}

function vendorMatch(reference) {
  if (!validSource({ name: '厂商', url: reference.url })) return [];
  return APPEARANCE.filter(profile => profile.path.test(reference.url));
}

function risk(metrics) {
  const fields = [['cvssV4_0','cvssMetricV40'], ['cvssV3_1','cvssMetricV31'], ['cvssV3_0','cvssMetricV30']];
  for (const [cna,nvd] of fields) {
    const direct = Array.isArray(metrics) ? metrics.find(m => m[cna])?.[cna] : null;
    const values = metrics?.[nvd] || [];
    const value = direct || (values.find(v => v.type === 'Primary') || values[0])?.cvssData;
    if (value && Number.isFinite(value.baseScore) && /^\d\.\d$/.test(value.version)) {
      return { score: value.baseScore, metric: 'CVSS ' + value.version };
    }
  }
  return { score: null, metric: null };
}

function readNVD(cve) {
  const links = [];
  const products = new Set();
  for (const reference of cve.references || []) {
    const vendors = vendorMatch(reference);
    if (!vendors.length || reference.tags?.includes('Exploit')) continue;
    links.push({ name: vendors[0].key, url: reference.url });
    for (const vendor of vendors) products.add(vendor.key);
  }
  const rating = risk(cve.metrics);
  return {
    id: cve.id, date: cve.published?.slice(0,10), products: [...products],
    links: links.slice(0,5), ...rating, origin: 'NVD',
    rejected: cve.vulnStatus === 'Rejected'
  };
}

function officialRecordUrl(id) {
  const [,year,number] = id.split('-');
  return CVE_BASE + year + '/' + number.slice(0,-3) + 'xxx/' + id + '.json';
}

function publishedSolution(cna) {
  const texts = (cna.solutions || []).filter(entry => /^en(?:-|$)/i.test(entry.lang || '')).map(entry => entry.value);
  for (const text of texts) {
    if (typeof text !== 'string' || !/\b(?:upgrade|update|fixed|patched|install)\b/i.test(text)) continue;
    const versions = [...new Set(text.match(/\bv?\d{1,3}\.\d{1,3}\.\d{1,4}(?:\.\d{1,4})?\b/g) || [])];
    if (versions.length && versions.length <= 8) return true;
  }
  return false;
}

function memoizedPages() {
  const pending = new Map();
  return url => {
    if (!pending.has(url)) pending.set(url,(async () => (await fetchSource(url)).text())());
    return pending.get(url);
  };
}

function publishedVersions(products) {
  return [...new Set(products.flatMap(product => (product.versions || []).map(version =>
    version.status === 'affected' && /^\d{1,3}\.\d{1,3}\.\d{1,4}$/.test(version.lessThan || '') ? version.lessThan : null
  )).filter(Boolean))];
}

async function verifyPatch(profile, products, id, url, getPage) {
  if (profile.key === 'PHP') {
    const page = await getPage(PHP_CHANGELOG);
    const fixed = new Set(publishedVersions(products));
    const exact = new RegExp('\\b' + id + '\\b');
    const releases = [...page.matchAll(/<h3\b[^>]*>\s*Version\s+(\d+\.\d+\.\d+)\s*<\/h3>([\s\S]*?)(?=<h3\b|$)/gi)];
    const versions = releases.filter(([,version,notes]) => fixed.has(version) && exact.test(notes)).map(match => match[1]);
    if (versions.length) return { versions:[...new Set(versions)], official:PHP_CHANGELOG };
  }
  if (profile.key === 'Nginx') {
    const list = await getPage(NGINX_ADVISORIES);
    const exact = new RegExp('\\b' + id + '\\b');
    const entry = list.split(/<li\b[^>]*>/i).find(section => exact.test(section));
    const supported = entry?.match(/Not vulnerable:\s*([\d.]+\+[\d.,+\s]*)/i)?.[1]?.match(/\d+\.\d+\.\d+/g);
    if (supported?.length) return { versions: [...new Set(supported)], official: NGINX_ADVISORIES };
  }
  if (profile.key === 'Node.js') {
    const page = await getPage(url);
    if (!page.includes(id)) return null;
    const versions = publishedVersions(products).filter(version =>
      page.includes('/en/blog/release/v' + version + '"'));
    if (versions.length) return { versions };
  }
  return null;
}

async function directDraft(hint,getPage,now) {
  const item = await (await fetchSource(officialRecordUrl(hint.id))).json();
  if (item.cveMetadata?.state !== 'PUBLISHED' || item.cveMetadata?.cveId !== hint.id) return null;
  const date = item.cveMetadata.datePublished?.slice(0,10);
  if (!date || (!hint.kev && now - Date.parse(date) > 14 * DAY)) return null;
  const cna = item.containers?.cna;
  if (!cna) return null;
  const affected = cna.affected || [];
  const confirmed = APPEARANCE.filter(profile =>
    affected.some(product => profile.names.test(product.product || '') &&
      (profile.designation.test(product.vendor || '') || profile.designation.test(cna.providerMetadata?.shortName || ''))) &&
    (cna.references || []).some(ref => profile.path.test(ref.url || '') && !ref.tags?.includes('exploit') &&
      validSource({ name: profile.key, url: ref.url })));
  if (!confirmed.length) return null;
  const products = confirmed.map(profile => profile.key);
  const rating = risk(cna.metrics);
  const { score, metric } = rating.score != null ? rating : { score: hint.score, metric: hint.metric };
  if (!hint.kev && (score == null || score < 7)) return null;
  const lead = confirmed[0];
  const sources = [];
  let fix = '';
  for (const profile of confirmed) {
    const ref = cna.references.find(reference => profile.path.test(reference.url || '') &&
      !reference.tags?.includes('exploit') && validSource({ name: profile.key, url: reference.url }));
    const relevant = affected.filter(product => profile.names.test(product.product || ''));
    const patch = await verifyPatch(profile,relevant,hint.id,ref.url,getPage);
    if (patch?.versions.length && confirmed.length === 1) {
      fix = '按所用分支升级至 ' + patch.versions.join('、') + ' 或更新的修复版本。商业版本与发行版维护构建请参照对应厂商公告。';
    }
    if (patch?.official) sources.push({ name: profile.key + ' 安全公告',url: patch.official });
    if (!sources.some(source => source.url === ref.url)) sources.push({ name: profile.key + ' 安全公告', url: ref.url });
  }
  if (!fix && !publishedSolution(cna)) return null;
  if (hint.kev) sources.push(KEV_SOURCE);
  return {
    id: hint.id, date, products, category: lead.category,
    level: score >= 9 ? 'critical' : 'high', kev: hint.kev, score, metric, badge: lead.key,
    title: products.join(' / ') + ' 安全更新',
    summary: hint.kev ? 'CISA 已将该漏洞列入已知遭利用目录。厂商已提供修复信息。' : 'CVE 发布方已公布漏洞及修复信息，请核对设备和软件版本。',
    impact: '涉及 ' + products.join('、') + ' 的部分构建。请按所用版本、平台与厂商的受影响范围核对。',
    fix: fix || '按厂商安全公告核对修复版本，安装与当前分支匹配的安全更新。优先处理暴露面较大的设备或实例。',
    sources
  };
}

async function getCISAFeed() {
  const body = await (await fetchSource(CISA_RSS)).text();
  if (!/<rss\b/i.test(body)) throw new Error('CISA 公告 RSS 格式不符');
  return [...body.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)].slice(0,45).flatMap(([,item]) => {
    const url = (item.match(/<link>\s*(?:<!\[CDATA\[)?(https:\/\/www\.cisa\.gov\/news-events\/[^\s<\]]+)/i) || [])[1];
    const tag = (item.match(/<pubDate>([^<]+)/i) || [])[1];
    const date = Number.isFinite(Date.parse(tag)) ? new Date(tag).toISOString().slice(0,10) : '';
    if (!url || !date) return [];
    const id = 'CISA-' + url.toLowerCase().split('/').slice(-2).join('-').slice(0,100);
    return [{ id, date, products: [], links: [{ name: 'CISA 公告', url }], origin: 'CISA RSS' }];
  });
}

async function getNginxHead(getPage) {
  const text = await getPage(NGINX_ADVISORIES);
  const ids = [...new Set(text.match(/CVE-\d{4}-\d{4,}/g) || [])].slice(0,11);
  if (!ids.length) throw new Error('Nginx 安全公告格式不符');
  return ids.map(id => ({
    id, products:['Nginx'], origin:'Nginx',
    links:[{ name:'Nginx',url:NGINX_ADVISORIES }]
  }));
}

function addKEV(store, index, kev, now) {
  const known = new Set();
  for (const active of store.all()) {
    const entry = index.get(active.id);
    if (!entry) {
      if (active.kev) {
        const sources = active.sources.filter(s => s.name !== KEV_SOURCE.name);
        if (sources.length) store.save({ ...active, kev: null, sources }, store.origin(active.id), false);
        else store.withdraw(active.id);
      }
      continue;
    }
    const date = entry.dateAdded;
    known.add(active.id);
    for (const alias of active.aliases) {
      if (index.get(alias)?.dateAdded === date) known.add(alias);
    }
    if (active.kev === date) continue;
    const isRecent = now - Date.parse(date) <= 7 * DAY;
    const sources = active.sources.some(source => source.url === KEV_SOURCE.url) ? active.sources : [...active.sources, KEV_SOURCE];
    store.save({ ...active, kev: date, sources }, store.origin(active.id), isRecent);
  }
  const hints = [];
  for (const entry of kev.vulnerabilities) {
    if (known.has(entry.cveID) || now - Date.parse(entry.dateAdded) > 14 * DAY) continue;
    const links = [];
    const products = new Set();
    for (const url of (entry.notes || '').match(/https:\/\/[^\s;]+/g) || []) {
      const matches = vendorMatch({ url });
      for (const profile of matches) products.add(profile.key);
      if (matches.length) links.push({ name: matches[0].key, url });
    }
    hints.push({
      id: entry.cveID, kev: entry.dateAdded, date: entry.dateAdded,
      products: products.size ? [...products] : [entry.product].filter(Boolean),
      links: [...links.slice(0,4), KEV_SOURCE], origin: 'CISA KEV'
    });
  }
  return hints;
}

function coversHint(store,hint) {
  const alert = store.lookup(hint.id);
  return alert && (!hint.kev || alert.id === hint.id || alert.kev === hint.kev);
}

function mergeLinks(items,key,limit) {
  return [...new Map(items.map(item => [item[key],item])).values()].slice(0,limit);
}

function addDigest(store,hints,signals) {
  const getCandidate = store.q('SELECT content,state FROM candidates WHERE id=?');
  const selected = new Set();
  const covered = new Set();
  for (const signal of signals) {
    if (store.lookup(signal.id)) {
      covered.add(signal.id);
      continue;
    }
    const row = getCandidate.get(signal.id);
    if (row && row.state !== 'pending') continue;
    const previous = row ? JSON.parse(row.content) : null;
    const current = hints.get(signal.id) || previous;
    const products = new Set(current?.products || []);
    const links = [...(current?.links || [])];
    for (const url of signal.urls) {
      const vendors = vendorMatch({ url });
      for (const profile of vendors) products.add(profile.key);
      if (vendors.length) links.push({ name:vendors[0].key, url });
    }
    const leads = mergeLinks([...(current?.leads || []),...(previous?.leads || []),signal.source],'url',8);
    hints.set(signal.id,{
      ...current,
      id:signal.id,
      date:current?.date || signal.source.date.slice(0,10),
      products:[...products],
      links:mergeLinks(links,'url',8),
      origin:current?.origin || 'International Cyber Digest',
      leads
    });
    selected.add(signal.id);
  }
  return { candidates:selected.size, alreadyPublished:covered.size };
}

export async function syncSources(store, overrides = {}) {
  const now = overrides.now || new Date();
  const getPage = memoizedPages();
  const feeds = await Promise.allSettled([
    overrides.kev ? Promise.resolve(overrides.kev) : getKEV(),
    overrides.nvd ? Promise.resolve({ end: now, rows: overrides.nvd }) : getNVD(store,now),
    overrides.cisa ? Promise.resolve(overrides.cisa) : getCISAFeed(),
    overrides.vendor ? Promise.resolve(overrides.vendor) : getNginxHead(getPage),
    overrides.digest ? Promise.resolve(overrides.digest) : readDigest(store,fetchSource,now)
  ]);
  const [kevResult,nvdResult,cisaResult,vendorResult,digestResult] = feeds;
  const hints = new Map();
  const outcomes = {};
  const checked = now.toISOString();
  if (kevResult.status === 'fulfilled') {
    const kev = kevResult.value;
    const newer = !store.meta('kevReleased') || Date.parse(kev.dateReleased) >= Date.parse(store.meta('kevReleased'));
    if (newer && kev.catalogVersion >= store.meta('kevVersion')) {
      const index = new Map(kev.vulnerabilities.map(v => [v.cveID,v]));
      store.transact(() => {
        for (const hint of addKEV(store,index,kev,+now)) hints.set(hint.id,hint);
        store.setMeta('kevVersion',kev.catalogVersion);
        store.setMeta('kevReleased',kev.dateReleased);
        store.setMeta('kevOK',checked);
      });
      outcomes.kev = kev.catalogVersion;
    } else outcomes.kev = '上游目录早于本地版本';
  } else outcomes.kev = kevResult.reason.message;

  if (nvdResult.status === 'fulfilled') {
    for (const cve of nvdResult.value.rows) {
      if (!cve || !CVE_ID.test(cve.id)) continue;
      const hint = readNVD(cve);
      if (hint.rejected) {
        hints.delete(hint.id);
        store.transact(() => {
          store.candidate({ id: hint.id, origin: 'NVD 已撤回' });
          store.withdraw(hint.id);
        });
        continue;
      }
      const existing = hints.get(hint.id);
      const recent = now - Date.parse(hint.date) <= 14 * DAY;
      if (!existing && (!hint.products.length || !recent || (hint.score != null && hint.score < 7))) continue;
      hints.set(hint.id, {
        ...hint, ...existing, score: hint.score, metric: hint.metric,
        products: [...new Set([...(existing?.products || []), ...hint.products])],
        links: [...new Map([...hint.links,...(existing?.links || [])].map(link => [link.url,link])).values()],
        origin: existing ? 'CISA KEV · NVD' : 'NVD'
      });
    }
    outcomes.nvd = nvdResult.value.rows.length;
  } else outcomes.nvd = nvdResult.reason.message;

  if (cisaResult.status === 'fulfilled') {
    for (const hint of cisaResult.value) hints.set(hint.id,hint);
    outcomes.cisa = cisaResult.value.length;
  } else outcomes.cisa = cisaResult.reason.message;

  if (vendorResult.status === 'fulfilled') {
    for (const hint of vendorResult.value) if (!hints.has(hint.id)) hints.set(hint.id,hint);
    outcomes.nginx = vendorResult.value.length;
  } else outcomes.nginx = vendorResult.reason.message;

  const digest = digestResult.status === 'fulfilled' ? digestResult.value : null;
  if (digest) {
    const selected = addDigest(store,hints,digest.signals);
    outcomes.digest = { ...digest.status, ...selected };
  } else outcomes.digest = { error:digestResult.reason.message };

  const nonPublic = store.q('SELECT active,origin FROM alerts WHERE id=?');
  const reviewState = store.q('SELECT state FROM candidates WHERE id=?');
  const backlog = new Map(store.candidates().filter(hint => now - Date.parse(hint.date) <= 14 * DAY).map(hint => [hint.id,hint]));
  for (const hint of hints.values()) backlog.set(hint.id,hint);
  const eligible = [...backlog.values()].filter(hint => {
    if (!CVE_ID.test(hint.id) ||
        (!hint.leads?.length && !hint.links?.some(link => vendorMatch(link).length))) return false;
    const current = nonPublic.get(hint.id);
    const state = reviewState.get(hint.id)?.state;
    return !['dismissed','withdrawn'].includes(state) &&
      (!current ? !coversHint(store,hint) : current.active && current.origin === 'auto');
  }).sort((a,b) => Number(Boolean(b.kev)) - Number(Boolean(a.kev)) ||
    Number(b.origin === 'Nginx') - Number(a.origin === 'Nginx') ||
    Number(Boolean(b.leads?.length)) - Number(Boolean(a.leads?.length)) ||
    Number(hints.has(b.id)) - Number(hints.has(a.id)) ||
    (b.score || 0) - (a.score || 0) || (b.date || '').localeCompare(a.date || '')).slice(0,36);
  let published = 0;
  const draft = overrides.draft || directDraft;
  for (let index = 0; index < eligible.length; index += 6) {
    const results = await Promise.allSettled(eligible.slice(index,index + 6).map(hint => draft(hint,getPage,now)));
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        try {
          const item = result.value;
          const lead = backlog.get(item.id);
          if (store.transact(() => {
            if (lead?.leads?.length && !store.lookup(item.id)) store.candidate(lead);
            return store.save(item,'auto');
          })) published++;
        } catch (error) {
          console.warn('自动发布待复核', result.value.id, error.message);
        }
      }
    }
  }
  store.transact(() => {
    for (const hint of hints.values()) {
      if (coversHint(store,hint)) continue;
      const current = store.q('SELECT content,state FROM candidates WHERE id=?').get(hint.id);
      const reopen = current?.state === 'published' && Boolean(hint.kev);
      if (current && current.state !== 'pending' && !reopen) continue;
      const previous = current ? JSON.parse(current.content) : null;
      if (previous?.leads?.length) {
        hint.leads = mergeLinks([...(hint.leads || []),...previous.leads],'url',8);
      }
      store.candidate(hint,reopen);
    }
    if (nvdResult.status === 'fulfilled') {
      const next = nvdResult.value.end.toISOString();
      if (next > (store.meta('nvdCursor') || '')) store.setMeta('nvdCursor',next);
      if (+now - +nvdResult.value.end <= 75 * 60000) store.setMeta('nvdOK',checked);
    }
    if (store.meta('nvdOK') === checked && store.meta('kevOK') === checked) store.setMeta('checkedAt',checked);
    if (digest) {
      for (const [key,value] of Object.entries(digest.cursors)) {
        const old = store.meta(key);
        if (!old || BigInt(value) > BigInt(old)) store.setMeta(key,value);
      }
      for (const [provider,status] of Object.entries(digest.status)) {
        if (status.state === 'ok') store.setMeta('digest-' + provider + '-checked',checked);
      }
    }
    store.setMeta('syncOutcome',JSON.stringify(outcomes));
  });
  return { ...outcomes, pending: store.candidates().length, published };
}
