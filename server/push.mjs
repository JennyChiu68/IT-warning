import * as webpush from 'web-push';
import { priority } from './store.mjs';

const serviceHosts = /^(?:fcm\.googleapis\.com|(?:[a-z\d-]+\.)?push\.services\.mozilla\.com|web\.push\.apple\.com|[a-z\d-]+\.notify\.windows\.com)$/i;
const twoDays = 48 * 60 * 60 * 1000;

export function pushConfig(env = process.env) {
  const { WEB_PUSH_SUBJECT:subject, WEB_PUSH_PUBLIC_KEY:publicKey, WEB_PUSH_PRIVATE_KEY:privateKey } = env;
  if (!subject || !publicKey || !privateKey) return null;
  webpush.setVapidDetails(subject,publicKey,privateKey);
  return { subject,publicKey,privateKey };
}

export function pushSubscription(input) {
  const url = typeof input.endpoint === 'string' && input.endpoint.length <= 2048 ? URL.parse(input.endpoint) : null;
  const { p256dh,auth } = input.keys || {};
  if (!url || url.protocol !== 'https:' || url.username || url.password || url.port || url.hash ||
      !serviceHosts.test(url.hostname) || !/^B[A-Za-z0-9_-]{86}$/.test(p256dh || '') || !/^[A-Za-z0-9_-]{22}$/.test(auth || '')) {
    throw new Error('浏览器通知凭证无效。');
  }
  return { endpoint:url.href, keys:JSON.stringify({ p256dh,auth }) };
}

export function managePush(store,input,action) {
  const { endpoint,keys } = pushSubscription(input);
  if (action === 'subscribe') store.q('INSERT OR IGNORE INTO push_subscriptions VALUES (?,?,?)').run(endpoint,keys,new Date().toISOString());
  if (action === 'cancel') store.q('DELETE FROM push_subscriptions WHERE endpoint=? AND keys=?').run(endpoint,keys);
  return { subscribed:Boolean(store.q('SELECT 1 FROM push_subscriptions WHERE endpoint=? AND keys=?').get(endpoint,keys)) };
}

export async function deliverPush(store,config,transport = webpush.sendNotification) {
  const now = Date.now();
  const cutoff = new Date(now - twoDays).toISOString();
  store.q(`DELETE FROM push_deliveries WHERE event IN (SELECT id FROM events WHERE created<?)`).run(cutoff);
  store.q(`INSERT OR IGNORE INTO push_deliveries (endpoint,event,next_attempt)
    SELECT push_subscriptions.endpoint,events.id,? FROM push_subscriptions
    JOIN events ON events.created>push_subscriptions.created AND events.created>=?
    JOIN alerts ON alerts.id=events.id AND alerts.active=1`).run(now,cutoff);
  const jobs = store.q(`SELECT d.endpoint,d.event,d.attempts,s.keys FROM push_deliveries d
    JOIN push_subscriptions s ON s.endpoint=d.endpoint WHERE d.done=0 AND d.next_attempt<=?
    ORDER BY d.next_attempt,d.event LIMIT 48`).all(now);
  const claim = store.q('UPDATE push_deliveries SET next_attempt=?,attempts=attempts+1 WHERE endpoint=? AND event=? AND done=0 AND next_attempt<=?');
  const done = store.q('UPDATE push_deliveries SET done=1 WHERE endpoint=? AND event=?');
  for (let i=0; i<jobs.length; i+=8) {
    await Promise.all(jobs.slice(i,i+8).map(async ({ endpoint,event,attempts,keys }) => {
      if (!claim.run(now+60000,endpoint,event,now).changes) return;
      const item = store.lookup(event);
      if (!item || item.id!==event || !priority(item)) { done.run(endpoint,event); return; }
      try {
        await transport({ endpoint,keys:JSON.parse(keys) },JSON.stringify({ id:item.id, title:item.title }),
          { TTL:3600, timeout:10000, vapidDetails:config });
        done.run(endpoint,event);
      } catch (error) {
        if ([404,410].includes(error.statusCode)) store.q('DELETE FROM push_subscriptions WHERE endpoint=?').run(endpoint);
        else if (attempts>=4 || (error.statusCode>=400 && error.statusCode<500 && error.statusCode!==429)) done.run(endpoint,event);
        else store.q('UPDATE push_deliveries SET next_attempt=? WHERE endpoint=? AND event=?').run(now + 60000 * 2 ** attempts,endpoint,event);
      }
    }));
  }
}
