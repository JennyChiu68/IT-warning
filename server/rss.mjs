import { priority } from './store.mjs';

export const previewUrl = 'https://jennychiu68.github.io/IT-warning/';
const escapeXml = value => String(value).replace(/[<>&"']/g, char => ({ '<':'&lt;', '>':'&gt;', '&':'&amp;', '"':'&quot;', "'":'&apos;' })[char]);

export function publicUrl(value = previewUrl) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('PUBLIC_URL 必须是预警页面的 HTTPS 地址。');
  return url;
}

export function alertsRss(feed, url) {
  const items = feed.items.filter(priority).sort((a,b) => b.date.localeCompare(a.date) ||
    (b.publishedAt || '').localeCompare(a.publishedAt || '') || a.id.localeCompare(b.id));
  return `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel>
<title>IT漏洞预警 · 重点订阅</title>
<link>${escapeXml(url)}</link>
<description>严重漏洞、已知遭利用漏洞及高危安全事件</description>
<language>zh-cn</language>
${items.map(item => {
    const link = new URL(url);
    link.searchParams.set('id',item.id);
    return `<item><title>${escapeXml(item.title)}</title><link>${escapeXml(link)}</link><guid>${escapeXml(link)}</guid>` +
      `<description>${escapeXml(item.summary)}</description>${item.publishedAt ? `<pubDate>${new Date(item.publishedAt).toUTCString()}</pubDate>` : ''}</item>`;
  }).join('\n')}
</channel></rss>\n`;
}
