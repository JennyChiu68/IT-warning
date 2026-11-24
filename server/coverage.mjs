import { createHash } from 'node:crypto';
import { CVE_ID, publicationTime, validSource } from './store.mjs';

const dayMs = 86400000;
const incidentTitle = /incident|breach|data (?:exposure|leak)|privacy notice|security (?:notice|advisory|alert)/i;
const feeds = [
  { name: 'Chrome Releases', key: 'CHROME', products: ['Chrome'], url: 'https://chromereleases.googleblog.com/feeds/posts/default?alt=atom', path: /^\/\d{4}\/\d{2}\/.+\.html$/, title: /^(?:Stable Channel Update for Desktop|Extended Stable Update for Desktop|Chrome for Android Update)$/i, ranked: true },
  { name: 'GitLab 补丁公告', key: 'GITLAB', products: ['GitLab'], url: 'https://docs.gitlab.com/releases/patch-releases.xml', path: /^\/releases\/patches\//, title: /patch release/i },
  { name: 'Ruby 安全公告', key: 'RUBY', products: ['Ruby'], url: 'https://www.ruby-lang.org/en/feeds/news.rss', path: /^\/en\/news\//, title: /security|vulnerabilit/i, fallbackByUrl: true },
  { name: 'OpenRouter 公告', key: 'OPENROUTER', products: ['OpenRouter'], url: 'https://openrouter.ai/blog/feed.xml', path: /^\/blog\/(?:announcements|security)\//, title: incidentTitle, byUrl: true },
  { name: 'simple-git 项目发布', key: 'SIMPLE_GIT', products: ['simple-git'], url: 'https://github.com/steveukx/git-js/releases.atom', path: /^\/steveukx\/git-js\/releases\/tag\//, title: /^(?:simple-git|@simple-git\/argv-parser)@/, securityRelease: true }
];
const novita = { name: 'Novita 官方公告', key: 'NOVITA', products: ['Novita'], url: 'https://novita.ai/blog/', path: /^\/blog\/[a-z\d-]+\/?$/i };

function xmlText(value) {
  return value.replace(/^<!\[CDATA\[([\s\S]*)\]\]>$/, '$1')
    .replace(/&(?:amp|quot|apos|lt|gt|#39);/g, entity =>
      ({ '&amp;': '&', '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>', '&#39;': "'" })[entity]);
}

function field(fragment, tag) {
  const match = new RegExp('<' + tag + '\\b[^>]*>([\\s\\S]*?)</' + tag + '>', 'i').exec(fragment);
  return match ? xmlText(match[1].trim()) : '';
}

function officialFeedLink(fragment, source) {
  const links = [...fragment.matchAll(/<link\b[^>]*>/gi)]
    .filter(match => !/\brel=/i.test(match[0]) || /\brel=(["'])alternate\1/i.test(match[0]))
    .map(match => /\bhref=(["'])(.*?)\1/i.exec(match[0])?.[2]);
  const raw = links.find(Boolean) || field(fragment, 'link');
  return officialLink(raw, source);
}

function officialLink(raw, source) {
  if (!raw) return null;
  try {
    const base = new URL(source.url);
    const url = new URL(xmlText(raw), base);
    if (url.hostname !== base.hostname || !source.path.test(url.pathname)) return null;
    if (url.protocol === 'http:') url.protocol = 'https:';
    url.hash = '';
    url.search = '';
    return validSource({ name: source.name, url: url.href }) ? url.href : null;
  } catch {
    return null;
  }
}

function inWindow(date, now, days = 7) {
  const timestamp = Date.parse(date);
  return Number.isFinite(timestamp) && timestamp >= +now - days * dayMs && timestamp <= +now + dayMs;
}

function signalId(source, url) {
  return source.key + '-' + createHash('sha256').update(url).digest('hex').slice(0, 12).toUpperCase();
}

export function feedSignals(xml, source, now) {
  if (!/<(?:feed|rss)\b/i.test(xml)) throw new Error('公告订阅格式不符');
  const signals = [];
  for (const [, , entry] of xml.matchAll(/<(entry|item)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    const title = field(entry, 'title').replace(/<[^>]+>/g, '').trim();
    const original = field(entry, 'published');
    const published = original || field(entry, 'pubDate') || field(entry, 'updated');
    if (!source.title.test(title) || !inWindow(published, now, source.securityRelease ? 14 : 7)) continue;
    const url = officialFeedLink(entry, source);
    if (!url) continue;
    const content = xmlText(entry).replace(/<[^>]+>|&(?:nbsp|#160);/gi, ' ');
    if (source.securityRelease && !/\bvulnerabilit(?:y|ies)\b|\bsecurity (?:fix|patch|update)/i.test(content)) continue;
    const ids = source.ranked
      ? [...content.matchAll(/\b(?:Critical|High)\s+(CVE-\d{4}-\d{4,})\b/gi)].map(match => match[1].toUpperCase())
      : (content.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map(id => id.toUpperCase());
    const date = /^\d{4}-\d{2}-\d{2}/.test(published) ? published.slice(0, 10) : new Date(published).toISOString().slice(0, 10);
    const publication = (source.ranked && publicationTime(original)) || { date };
    const pickByUrl = source.byUrl || (!ids.length && (source.securityRelease || source.fallbackByUrl));
    const selected = pickByUrl ? [signalId(source, url)] : [...new Set(ids)].slice(0, 20);
    for (const id of selected) {
      signals.push({ id, ...publication, title: title.slice(0, 180), products: source.products, links: [{ name: source.name, url }], origin: source.name });
    }
  }
  return signals;
}

function novitaSignals(html, now) {
  const cards = [...html.matchAll(/<a\b[^>]*\bclass="post-card__link"[^>]*>([\s\S]*?)<\/a>/gi)];
  if (!cards.length) throw new Error('Novita 公告列表格式不符');
  return cards.flatMap(([card, body]) => {
    const title = xmlText(/\baria-label="([^"]*)"/i.exec(card)?.[1] || '');
    const date = /<span>([A-Z][a-z]+ \d{1,2}, \d{4})<\/span>/.exec(body)?.[1];
    const url = officialLink(/\bhref="([^"]*)"/i.exec(card)?.[1], novita);
    if (!incidentTitle.test(title) || !inWindow(date, now) || !url) return [];
    return [{ id: signalId(novita, url), date: new Date(date + ' UTC').toISOString().slice(0, 10),
      title: title.slice(0, 180), products: novita.products, links: [{ name: novita.name, url }], origin: novita.name }];
  });
}

function npmSignals(rows, now) {
  if (!Array.isArray(rows)) throw new Error('GitHub 公告格式不符');
  return rows.flatMap(row => {
    if (!CVE_ID.test(row.cve_id || '') || row.withdrawn_at || !['critical', 'high'].includes(row.severity) ||
        !inWindow(row.published_at, now) || !/^https:\/\/github\.com\/advisories\/GHSA-[a-z0-9-]+$/.test(row.html_url || '')) return [];
    const products = [...new Set((row.vulnerabilities || []).filter(v => v.package?.ecosystem === 'npm')
      .map(v => v.package.name).filter(name => typeof name === 'string' && name.length <= 40))].slice(0, 8);
    if (!products.length) return [];
    const publication = publicationTime(row.published_at) || { date: row.published_at.slice(0, 10) };
    return [{ id: row.cve_id, ...publication, title: String(row.summary || 'npm 安全公告').slice(0, 180),
      products, links: [{ name: 'GitHub Advisory Database', url: row.html_url }], origin: 'GitHub npm 公告' }];
  });
}

export async function readCoverage(fetchSource, now) {
  const github = new URL('https://api.github.com/advisories');
  github.search = new URLSearchParams({ type: 'reviewed', ecosystem: 'npm', per_page: '100',
    published: '>=' + new Date(+now - 7 * dayMs).toISOString().slice(0, 10) });
  const results = await Promise.allSettled([
    ...feeds.map(async source => feedSignals(await (await fetchSource(source.url)).text(), source, now)),
    (async () => novitaSignals(await (await fetchSource(novita.url)).text(), now))(),
    (async () => npmSignals(await (await fetchSource(github, { headers: { Accept: 'application/vnd.github+json' } })).json(), now))()
  ]);
  return {
    signals: results.flatMap(result => result.status === 'fulfilled' ? result.value : []),
    status: Object.fromEntries(results.map((result, index) => [
      [...feeds, novita][index]?.key || 'NPM', result.status === 'fulfilled'
        ? { state: 'ok', notices: result.value.length } : { state: 'error', error: result.reason.message }
    ]))
  };
}

function sourceKey(url) {
  const normalized = new URL(url);
  normalized.search = '';
  normalized.hash = '';
  return normalized.href.replace(/\/$/, '');
}

export function queueCoverage(store, signals) {
  const candidates = new Set();
  const covered = new Set();
  const publishedLinks = new Set(store.all().flatMap(item => item.sources.map(source => sourceKey(source.url))));
  const previous = store.q('SELECT content,state FROM candidates WHERE id=?');
  for (const signal of signals) {
    if (store.lookup(signal.id) || (!CVE_ID.test(signal.id) && signal.links.some(link => publishedLinks.has(sourceKey(link.url))))) {
      covered.add(signal.id);
      continue;
    }
    const row = previous.get(signal.id);
    if (row && row.state !== 'pending') continue;
    const prior = row ? JSON.parse(row.content) : {};
    const links = [...new Map([...(prior.links || []), ...signal.links].map(link => [sourceKey(link.url), link])).values()].slice(0, 8);
    const dates = [prior.publishedAt, signal.publishedAt].filter(Boolean).sort();
    const publication = publicationTime(dates[0]) || { date: prior.date || signal.date };
    store.candidate({ ...prior, ...signal, ...publication,
      products: [...new Set([...(prior.products || []), ...signal.products])].slice(0, 8), links, reviewOnly: true });
    candidates.add(signal.id);
  }
  return { candidates: candidates.size, alreadyPublished: covered.size };
}
