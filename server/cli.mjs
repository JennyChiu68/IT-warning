import { readFileSync } from 'node:fs';
import { openStore, validSource } from './store.mjs';
import { syncSources } from './sources.mjs';
import { queueCoverage } from './coverage.mjs';

const [command, value, ...rest] = process.argv.slice(2);
const store = openStore();
try {
  if (command === 'sync') {
    const options = {};
    if (value === '--kev-json' && rest.length === 1) options.kev = JSON.parse(readFileSync(rest[0],'utf8'));
    else if (value) throw new Error('用法 npm run sync');
    const result = await syncSources(store,options);
    console.log(JSON.stringify(result,null,2));
    if (typeof result.nvd !== 'number' || !/^\d{4}\.\d{2}\.\d{2}$/.test(result.kev)) process.exitCode = 2;
  } else if (command === 'list') {
    const items = value === 'coverage'
      ? store.q("SELECT content FROM candidates WHERE state='pending' AND json_extract(content,'$.reviewOnly')=1 ORDER BY updated DESC,id LIMIT 150").all().map(row => JSON.parse(row.content))
      : value === 'digest'
      ? store.q(`SELECT content FROM candidates WHERE state='pending' AND json_type(content,'$.leads')='array'
        ORDER BY updated DESC,id LIMIT 150`).all().map(row => JSON.parse(row.content))
      : store.candidates();
    console.log(JSON.stringify(items,null,2));
  } else if (command === 'status') {
    const feed = store.feed();
    console.log(JSON.stringify({ checkedAt:feed.checkedAt, status:feed.status, kevVersion:feed.kevVersion,
      published:feed.items.length, sync:JSON.parse(store.meta('syncOutcome') || '{}') },null,2));
  } else if (command === 'publish' && value) {
    const data = JSON.parse(readFileSync(value,'utf8'));
    const changed = store.transact(() => store.save(data));
    console.log(changed ? '已发布 ' + data.id : '预警无变化 ' + data.id);
  } else if (command === 'backfill' && value) {
    const items = JSON.parse(readFileSync(value,'utf8'));
    if (!Array.isArray(items) || !items.length) throw new Error('补录文件须包含已核验的预警数组。');
    const changed = store.transact(() => items.filter(item => store.save(item,'review',false)).length);
    console.log(JSON.stringify({ checked:items.length, updated:changed, queuedNotifications:0 }));
  } else if (command === 'lead' && value) {
    const input = JSON.parse(readFileSync(value,'utf8'));
    if (!input || !/^[A-Z\d-]{4,45}$/.test(input.id || '') || !/^\d{4}-\d{2}-\d{2}$/.test(input.date || '') ||
        !Number.isFinite(Date.parse(input.date)) || typeof input.title !== 'string' || !input.title.trim() || input.title.length > 180 ||
        !Array.isArray(input.products) || !input.products.length || input.products.length > 8 ||
        !input.products.every(product => typeof product === 'string' && product.trim() && product.length <= 40) ||
        !Array.isArray(input.links) || !input.links.length || input.links.length > 8 || !input.links.every(validSource)) {
      throw new Error('请填写线索编号、日期、标题、产品和可信 HTTPS 来源。');
    }
    const { id, date, title, products, links } = input;
    console.log(JSON.stringify(store.transact(() => queueCoverage(store,[{ id,date,title,products,links,origin:'人工线索' }]))));
  } else if (command === 'withdraw' && value) {
    store.transact(() => store.withdraw(value));
    console.log('已撤下 ' + value);
  } else if (command === 'dismiss' && value) {
    store.q("UPDATE candidates SET state='dismissed' WHERE id=?").run(value);
    console.log('已略过 ' + value);
  } else {
    throw new Error('用法 npm run review -- list [digest|coverage] | status | lead 文件 | publish 文件 | backfill 文件 | withdraw 编号 | dismiss 编号');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally { store.db.close(); }
