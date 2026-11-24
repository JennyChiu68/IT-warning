import { randomBytes } from 'node:crypto';
import { fetchSource } from './sources.mjs';
import { priority } from './store.mjs';

const wxBase = 'https://api.weixin.qq.com/';
const levels = { critical: '严重', high: '高危', notice: '更新' };
const fieldType = /^(thing|phrase|date|time|character_string)\d+$/;
const stateNames = ['developer','trial','formal'];
const now = () => new Date().toISOString();

export function wechatConfig(env = process.env) {
  const { WECHAT_APP_ID: appid, WECHAT_APP_SECRET: secret, WECHAT_TEMPLATE_ID: templateId, WECHAT_TEMPLATE_FIELDS: raw } = env;
  if (![appid,secret,templateId,raw].some(Boolean)) return null;
  if (!appid || !secret || !templateId || !raw) return null;
  const fields = JSON.parse(raw);
  if (!fields || Array.isArray(fields) || typeof fields !== 'object' || !Object.keys(fields).length ||
      Object.entries(fields).some(([key, value]) =>
        !fieldType.test(key) || !['title','level','date','id'].includes(value) ||
        (key.startsWith('date') && value !== 'date') || (key.startsWith('time') && value !== 'date'))) {
    throw new Error('微信模板字段配置无效。');
  }
  const miniprogramState = env.WECHAT_MINIPROGRAM_STATE || 'formal';
  if (!stateNames.includes(miniprogramState)) throw new Error('微信小程序版本类型无效。');
  return { appid, secret, templateId, fields, miniprogramState };
}

export function validTopics(value, store) {
  const fixed = ['PHP','Nginx','Node.js','Java','Windows','macOS','iOS','Android','VMware','MONAI Label'];
  const known = new Set([...fixed, ...store.all().flatMap(item => item.products)]);
  if (!Array.isArray(value) || value.length > 60 || value.some(topic => !known.has(topic))) throw new Error('关注产品无效。');
  return [...new Set(value)];
}

export function recipient(store, header) {
  const token = /^Bearer ([0-9a-f]{64})$/.exec(header || '')?.[1];
  return token ? store.q('SELECT * FROM recipients WHERE token=?').get(token) : null;
}

export function remaining(row) {
  return row?.registered ? 1 : 0;
}

export async function register(store, config, code, following) {
  if (typeof code !== 'string' || !/^[a-z\d_-]{8,100}$/i.test(code)) throw new Error('微信登录凭证无效。');
  const url = new URL('sns/jscode2session',wxBase);
  url.search = new URLSearchParams({ appid: config.appid, secret: config.secret, js_code: code, grant_type: 'authorization_code' });
  const login = await (await fetchSource(url)).json();
  if (typeof login.openid !== 'string' || !login.openid || login.errcode) throw new Error('微信登录验证失败。');
  return store.transact(() => {
    const previous = store.q('SELECT * FROM recipients WHERE openid=?').get(login.openid);
    const token = previous?.token || randomBytes(32).toString('hex');
    const registered = previous?.registered || now();
    store.q(`INSERT INTO recipients VALUES(?,?,?,?) ON CONFLICT(openid) DO UPDATE SET
      following=excluded.following,registered=excluded.registered`).run(login.openid,token,JSON.stringify(following),registered);
    return { token, remaining: 1 };
  });
}

function templateData(item, fields) {
  const content = { title: item.title, level: item.kev ? '已知遭利用' : levels[item.level], date: item.kev || item.date, id: item.id };
  return Object.fromEntries(Object.entries(fields).map(([field, name]) => {
    const [,kind] = field.match(fieldType);
    let value = content[name];
    if (kind === 'phrase') value = [...value.replace(/[^\u4e00-\u9fff]/g,'')].slice(0,5).join('') || '安全提醒';
    if (kind === 'character_string') value = value.replace(/[^\w-]/g,'').slice(0,32) || item.id.slice(0,32);
    if (kind === 'thing') value = [...value].slice(0,20).join('');
    if (kind === 'time') value = value + ' 00:00';
    return [field,{ value }];
  }));
}

let cached;
async function accessToken(config) {
  if (cached?.id === config.appid && cached.expiry > Date.now()) return cached.token;
  const response = await fetchSource(new URL('cgi-bin/stable_token',wxBase), {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body:JSON.stringify({ grant_type:'client_credential', appid:config.appid, secret:config.secret, force_refresh:false })
  });
  const data = await response.json();
  if (!data.access_token) throw new Error('微信访问令牌获取失败');
  cached = { id:config.appid, token:data.access_token, expiry:Date.now() + (data.expires_in - 180) * 1000 };
  return cached.token;
}

async function send(item, openid, config, token) {
  const url = new URL('cgi-bin/message/subscribe/send',wxBase);
  url.searchParams.set('access_token',token);
  return (await fetchSource(url, {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body:JSON.stringify({
      touser:openid, template_id:config.templateId,
      page:'pages/index/index?id=' + encodeURIComponent(item.id),
      miniprogram_state:config.miniprogramState, lang:'zh_CN', data:templateData(item,config.fields)
    })
  })).json();
}

export async function deliver(store, config, transport = send) {
  if (!config) return 0;
  const cutoff = new Date(Date.now() - 48 * 3600000).toISOString();
  const events = store.q(`SELECT events.id,events.created,alerts.content FROM events
    JOIN alerts ON alerts.id=events.id AND alerts.active=1 WHERE events.created>=? ORDER BY events.created ASC,events.id`).all(cutoff)
    .map(event => ({ ...event, item: JSON.parse(event.content) })).filter(event => priority(event.item));
  if (!events.length) return 0;
  const users = store.q('SELECT * FROM recipients WHERE registered IS NOT NULL').all();
  const plans = users.flatMap(user => {
    const topics = JSON.parse(user.following);
    const event = events.find(entry => entry.created > user.registered &&
      entry.item.products.some(p => topics.includes(p)) &&
      !store.q('SELECT 1 FROM deliveries WHERE openid=? AND event=?').get(user.openid,entry.id));
    return event ? [{ user, event }] : [];
  });
  if (!plans.length) return 0;
  const token = transport === send ? await accessToken(config) : '';
  let success = 0;
  for (let index = 0; index < plans.length; index += 6) {
    await Promise.all(plans.slice(index,index + 6).map(async ({ user, event }) => {
      const claimed = store.transact(() => {
        if (!store.q('SELECT active FROM alerts WHERE id=?').get(event.id)?.active) return false;
        const changed = store.q('UPDATE recipients SET registered=NULL WHERE openid=? AND registered=? AND following=?')
          .run(user.openid,user.registered,user.following).changes;
        if (!changed) return false;
        store.q("INSERT INTO deliveries VALUES(?,?,'sending',?)").run(user.openid,event.id,now());
        return true;
      });
      if (!claimed) return;
      let state = 'unknown';
      try {
        const result = await transport(event.item,user.openid,config,token);
        state = result.errcode === 0 ? 'sent' : 'wechat-' + result.errcode;
        if ([40001,40014,42001].includes(result.errcode)) {
          cached = null;
          store.transact(() => {
            store.q('DELETE FROM deliveries WHERE openid=? AND event=?').run(user.openid,event.id);
            store.q('UPDATE recipients SET registered=? WHERE openid=? AND registered IS NULL').run(user.registered,user.openid);
          });
          return;
        }
        if (state === 'sent') success++;
        else console.warn('微信订阅投递失败',event.id,state);
      } catch {
        console.warn('微信订阅投递结果未知',event.id);
      }
      store.q('UPDATE deliveries SET state=?,updated=? WHERE openid=? AND event=?').run(state,now(),user.openid,event.id);
    }));
  }
  return success;
}
