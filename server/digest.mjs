import { createHash } from 'node:crypto';

const ACCOUNT = 'IntCyberDigest';
const TELEGRAM = 'https://t.me/s/' + ACCOUNT;
const X_API = 'https://api.x.com/2/';
const NUMERIC_ID = /^\d{1,25}$/;
const LOOKBACK = 7 * 86400000;
const MAX_TELEGRAM_PAGES = 5;
const MAX_X_PAGES = 3;
const CVES = /\bCVE-\d{4}-\d{4,}\b/gi;
const SECURITY_NEWS = /\b(?:data breach|cyber\s?attack|ransomware|security (?:incident|advisory|update|patch|release|flaw|vulnerability)|unauthori[sz]ed access|zero[- ]day|actively exploited|critical vulnerability)\b/i;
const SAFE_ENTITIES = { amp:'&', quot:'"', apos:"'", lt:'<', gt:'>', nbsp:' ' };

function decode(value) {
  return value.replace(/&(amp|quot|apos|lt|gt|nbsp|#\d+|#x[\da-f]+);/gi,(entity,ref) => {
    if (ref[0] !== '#') return SAFE_ENTITIES[ref.toLowerCase()] || entity;
    const n = /^#x/i.test(ref) ? parseInt(ref.slice(2),16) : Number(ref.slice(1));
    return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : entity;
  });
}

function cleanUrl(value) {
  try {
    const url = new URL(decode(value));
    if (url.protocol !== 'https:' || url.username || url.password || url.port) return null;
    // Ignore lone post previews, subscription links and shortening services.
    if (['t.me','telegram.me','x.com','twitter.com','t.co','internationalcyberdigest.com'].includes(url.hostname)) return null;
    url.hash = '';
    for (const key of [...url.searchParams.keys()]) {
      if (/^utm_|^(?:ref|fbclid|gclid)$/i.test(key)) url.searchParams.delete(key);
    }
    return url.href;
  } catch {
    return null;
  }
}

export function telegramPosts(html) {
  const rows = [...html.matchAll(/<div\b[^>]*\bdata-post="([a-z0-9_]+)\/(\d+)"[^>]*>/gi)];
  if (!rows.some(row => row[1].toLowerCase() === ACCOUNT.toLowerCase())) {
    throw new Error('公开频道页面缺少可识别的帖子');
  }
  return rows.flatMap((row,index) => {
    const [,handle,id] = row;
    if (handle.toLowerCase() !== ACCOUNT.toLowerCase()) return [];
    const section = html.slice(row.index,rows[index + 1]?.index);
    const date = section.match(/<time\b[^>]*\bdatetime="([^"]+)"/i)?.[1];
    if (!NUMERIC_ID.test(id) || !Number.isFinite(Date.parse(date))) return [];
    const blocks = [...section.matchAll(/<div\b[^>]*\bclass="[^"]*\bjs-message_text\b[^"]*"[^>]*>([\s\S]*?)<\/div>/gi)]
      .map(match => match[1]);
    const text = decode(blocks.join(' ').replace(/<[^>]+>/g,' '));
    const urls = [...blocks.join(' ').matchAll(/<a\b[^>]*\bhref="([^"]+)"/gi)].map(match => match[1]);
    return [{ id, date, text, urls, platform:'Telegram', url:'https://t.me/' + ACCOUNT + '/' + id }];
  });
}

function latestId(posts) {
  return posts.reduce((max,post) => BigInt(post.id) > BigInt(max) ? post.id : max,'0');
}

function newestDate(posts) {
  const dates = posts.map(p => Date.parse(p.date)).filter(Number.isFinite);
  return dates.length ? new Date(Math.max(...dates)).toISOString() : null;
}

async function readTelegram(fetchSource, cursor, now) {
  const seen = new Map();
  let before;
  let exhausted = false;
  for (let i = 0; i < MAX_TELEGRAM_PAGES; i++) {
    const address = new URL(TELEGRAM);
    if (before) address.searchParams.set('before',before);
    const page = await telegramPosts(await (await fetchSource(address)).text());
    if (!page.length) throw new Error('公开频道帖子时间或编号缺失');
    for (const post of page) seen.set(post.id,post);
    const oldest = page.reduce((min,post) => BigInt(post.id) < BigInt(min) ? post.id : min,page[0].id);
    exhausted = cursor ? BigInt(oldest) <= BigInt(cursor)
      : newestDate(page) === null || page.some(post => now - Date.parse(post.date) >= LOOKBACK);
    if (exhausted || oldest === before || oldest === '1') break;
    before = oldest;
  }
  const posts = [...seen.values()];
  const fresh = posts.filter(post => now - Date.parse(post.date) <= LOOKBACK && (!cursor || BigInt(post.id) > BigInt(cursor)));
  return { posts:fresh, latestPostAt:newestDate(posts), cursor:latestId(posts), bounded:!exhausted };
}

async function readX(fetchSource, token, id, cursor, now) {
  const headers = { authorization:'Bearer ' + token };
  const read = async url => (await fetchSource(url,{ headers, redirect:'error' })).json();
  let account = id;
  if (!account) {
    const user = await read(new URL('users/by/username/' + ACCOUNT,X_API));
    if (user.data?.username?.toLowerCase() !== ACCOUNT.toLowerCase() || !NUMERIC_ID.test(user.data?.id || '')) {
      throw new Error('X 未返回目标账号');
    }
    account = user.data.id;
  }

  const posts = [];
  let next;
  for (let i = 0; i < MAX_X_PAGES; i++) {
    const address = new URL('users/' + account + '/tweets',X_API);
    address.search = new URLSearchParams({ 'tweet.fields':'created_at,entities,author_id,note_tweet', max_results:'50', exclude:'retweets' });
    if (cursor) address.searchParams.set('since_id',cursor);
    else address.searchParams.set('start_time',new Date(now - 86400000).toISOString().replace(/\.\d{3}Z$/,'Z'));
    if (next) address.searchParams.set('pagination_token',next);
    const page = await read(address);
    if (!page.meta || page.errors?.length) throw new Error('X 时间线响应不完整');
    for (const item of page.data || []) {
      if (item.author_id !== account || !NUMERIC_ID.test(item.id) || !Number.isFinite(Date.parse(item.created_at))) continue;
      const urls = [...(item.entities?.urls || []),...(item.note_tweet?.entities?.urls || [])]
        .flatMap(link => [link.expanded_url,link.unwound_url].filter(value => typeof value === 'string'));
      posts.push({
        id:item.id, date:item.created_at, text:item.note_tweet?.text || item.text || '', urls, platform:'X',
        url:'https://x.com/' + ACCOUNT + '/status/' + item.id
      });
    }
    next = page.meta.next_token;
    if (!next) break;
  }
  if (next && cursor) throw new Error('X 本轮有更多帖子，保留上次游标');
  return { posts, latestPostAt:newestDate(posts), cursor:latestId(posts), account, bounded:Boolean(next) };
}

export function digestSignals(posts) {
  return posts.flatMap(post => {
    const urls = [...new Set(post.urls.map(cleanUrl).filter(Boolean))].slice(0,12);
    const ids = [...new Set((post.text + ' ' + urls.join(' ')).match(CVES)?.map(id => id.toUpperCase()))].slice(0,30);
    const source = { url:post.url, platform:post.platform, date:new Date(post.date).toISOString() };
    if (ids.length) return ids.map(id => ({ id, kind:'cve', source, urls }));
    if (!SECURITY_NEWS.test(post.text)) return [];
    const fingerprint = post.text.toLowerCase().replace(/https?:\/\/\S+/g,'').replace(/[^a-z0-9 ]/g,' ').replace(/\s+/g,' ').trim().slice(0,420);
    if (!fingerprint) return [];
    const hash = createHash('sha256').update(fingerprint).digest('hex').toUpperCase().slice(0,20);
    return [{ id:'ICD-' + hash, kind:'incident', source, urls }];
  });
}

export async function readDigest(store,fetchSource,now) {
  const token = process.env.X_DIGEST_BEARER_TOKEN?.trim();
  const oldTelegram = store.meta('digestTelegramCursor');
  const oldX = store.meta('digestXCursor');
  const [telegram,x] = await Promise.allSettled([
    readTelegram(fetchSource,oldTelegram,now),
    token ? readX(fetchSource,token,store.meta('digestXAccount'),oldX,now) : Promise.resolve(null)
  ]);
  const status = {};
  const cursors = {};
  const posts = [];
  for (const [name,result] of [['telegram',telegram],['x',x]]) {
    if (result.status === 'rejected') {
      status[name] = { state:'error', error:result.reason.message };
      continue;
    }
    const feed = result.value;
    if (!feed) {
      status[name] = { state:'unconfigured' };
      continue;
    }
    status[name] = { state:'ok', posts:feed.posts.length, latestPostAt:feed.latestPostAt, bounded:feed.bounded };
    const key = name === 'telegram' ? 'digestTelegramCursor' : 'digestXCursor';
    const oldCursor = name === 'telegram' ? oldTelegram : oldX;
    if (BigInt(feed.cursor) > BigInt(oldCursor || '0')) cursors[key] = feed.cursor;
    if (feed.account) cursors.digestXAccount = feed.account;
    posts.push(...feed.posts);
  }
  return { status, cursors, signals:digestSignals(posts) };
}
