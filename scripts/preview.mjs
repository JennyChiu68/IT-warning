import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { alertsRss, publicUrl } from '../server/rss.mjs';
const read = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const snapshot = read('miniprogram/shared/snapshot.json').replaceAll('<', '\\u003c');
const assets = new URL('../miniprogram/assets/',import.meta.url);
const icons = Object.fromEntries(readdirSync(assets).filter(name => name.endsWith('.png')).map(name =>
  [name.slice(0,-4),'data:image/png;base64,' + readFileSync(new URL(name,assets)).toString('base64')]));
const html = read('web/index.html')
  .replace('/assets/pulse-active.png',icons['pulse-active'])
  .replace('<link rel="stylesheet" href="/styles.css">', '<style>' + read('web/styles.css') + '</style>')
  .replace(/  <script defer.*\n/g, '')
  .replace('</body>', '<script>const IT_WARNING_SNAPSHOT=' + snapshot.trim() + ';\nconst IT_WARNING_ICONS=' + JSON.stringify(icons) + ';\n' +
    read('miniprogram/shared/catalog.js') + '\n' + read('web/app.js') + '</script></body>');
writeFileSync(new URL('../preview.html', import.meta.url), html);
writeFileSync(new URL('../miniprogram/shared/snapshot.js', import.meta.url), 'module.exports = ' + snapshot.trim() + ';\n');

const pages = new URL('../docs/', import.meta.url);
mkdirSync(pages, { recursive: true });
writeFileSync(new URL('index.html', pages), html.replace('</head>', '  <link rel="license" href="./brand-icons.txt">\n</head>'));
writeFileSync(new URL('feed.xml', pages), alertsRss(JSON.parse(snapshot),publicUrl()));
writeFileSync(new URL('.nojekyll', pages), '');
for (const name of ['brand-icons.txt', 'monai-label-apache-2.0.txt']) {
  copyFileSync(new URL('../miniprogram/licenses/' + name, import.meta.url), new URL(name, pages));
}
