import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { openStore } from './store.mjs';
import { syncSources } from './sources.mjs';
import { deliver, recipient, register, remaining, validTopics, wechatConfig } from './wechat.mjs';

const store = openStore();
const wechat = wechatConfig();
const interval = Math.max(5,Number(process.env.SYNC_MINUTES) || 15) * 60000;
const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || 4173);
const mime = { html:'text/html; charset=utf-8', css:'text/css; charset=utf-8', js:'text/javascript; charset=utf-8', png:'image/png', json:'application/json; charset=utf-8' };
const project = new URL('../',import.meta.url);
const staticRoutes = new Map([
  ['/','web/index.html'], ['/app.js','web/app.js'], ['/styles.css','web/styles.css'],
  ['/shared/catalog.js','miniprogram/shared/catalog.js'], ['/shared/snapshot.json','miniprogram/shared/snapshot.json']
]);
const rate = new Map();
let syncing = false;
let delivering = false;

function json(response, status, data) {
  response.writeHead(status,{ 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' });
  response.end(JSON.stringify(data));
}

async function body(request) {
  if (!/^application\/json(?:;|$)/i.test(request.headers['content-type'] || '')) throw new Error('请求格式无效。');
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 4096) throw new Error('请求内容过长。');
    chunks.push(chunk);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('请求格式无效。');
  return parsed;
}

function allowed(ip) {
  const time = Date.now();
  if (rate.size > 1000) {
    for (const [key,item] of rate) if (item.until < time) rate.delete(key);
    if (rate.size > 5000 && !rate.has(ip)) return false;
  }
  const record = rate.get(ip);
  if (!record || record.until < time) {
    rate.set(ip,{ until:time + 60000, count:1 });
    return true;
  }
  return ++record.count <= 30;
}

function staticFile(response,path,head) {
  const extension = path.split('.').pop();
  const stream = createReadStream(fileURLToPath(new URL(path,project)));
  stream.once('open', () => {
    response.writeHead(200, { 'Content-Type':mime[extension], 'Cache-Control':'no-cache' });
    if (head) { stream.destroy(); response.end(); }
    else stream.pipe(response);
  });
  stream.once('error', () => { if (!response.headersSent) json(response,404,{ message:'页面不存在' }); });
}

const server = createServer(async (request,response) => {
  response.setHeader('X-Content-Type-Options','nosniff');
  response.setHeader('Referrer-Policy','no-referrer');
  response.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  const pathname = (request.url || '/').split('?')[0];
  const method = request.method;
  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/api/feed') return json(response,200,{ ...store.feed(), templateId:wechat?.templateId || null });
    const alert = /^\/api\/alerts\/([A-Z\d-]{4,45})$/.exec(pathname);
    if (alert) {
      const item = store.lookup(alert[1]);
      return item ? json(response,200,item) : json(response,404,{ message:'预警暂不可查看' });
    }
    if (pathname === '/api/wechat/status' && wechat) {
      const user = recipient(store,request.headers.authorization);
      return user ? json(response,200,{ remaining:remaining(user) }) : json(response,401,{ message:'会话无效' });
    }
    const assets = /^\/assets\/[a-z-]+\.png$/;
    const path = staticRoutes.get(pathname) || (assets.test(pathname) ? 'miniprogram' + pathname : '');
    if (path) return staticFile(response,path,method === 'HEAD');
  }
  if (method === 'POST' && wechat && ['/api/wechat/subscribe','/api/wechat/topics','/api/wechat/cancel'].includes(pathname)) {
    if (!allowed(request.socket.remoteAddress)) return json(response,429,{ message:'请求过于频繁' });
    try {
      if (pathname === '/api/wechat/subscribe') {
        const input = await body(request);
        const following = validTopics(input.following,store);
        if (!following.length) return json(response,400,{ message:'请先关注产品' });
        return json(response,200,await register(store,wechat,input.code,following));
      }
      const user = recipient(store,request.headers.authorization);
      if (!user) return json(response,401,{ message:'会话无效' });
      if (pathname === '/api/wechat/topics') {
        const input = await body(request);
        const following = validTopics(input.following,store);
        store.q('UPDATE recipients SET following=? WHERE openid=?').run(JSON.stringify(following),user.openid);
      } else {
        store.q("UPDATE recipients SET registered=NULL,following='[]' WHERE openid=?").run(user.openid);
      }
      return json(response,200,{ remaining:remaining(recipient(store,request.headers.authorization)) });
    } catch {
      return json(response,400,{ message:'微信服务暂不可用或参数无效' });
    }
  }
  json(response,404,{ message:'页面不存在' });
});

async function sync() {
  if (syncing) return;
  syncing = true;
  try { console.log('信源同步', await syncSources(store)); }
  catch (error) { console.warn('信源同步失败',error.message); }
  finally { syncing = false; }
}
async function notifications() {
  if (delivering) return;
  delivering = true;
  try { await deliver(store,wechat); }
  catch (error) { console.warn('通知任务失败',error.message); }
  finally { delivering = false; }
}

server.listen(port,host,() => {
  console.log('IT漏洞预警 http://' + host + ':' + port);
  if (process.env.AUTO_SYNC !== '0') {
    sync();
    setInterval(sync,interval);
  }
  if (wechat) {
    notifications();
    setInterval(notifications,30000);
  }
});
