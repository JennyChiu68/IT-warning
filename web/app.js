/* global AlertCatalog, IT_WARNING_SNAPSHOT, IT_WARNING_ICONS */
const app = document.getElementById('app');
const toast = document.getElementById('toast');
const embeddedIcons = typeof IT_WARNING_ICONS === 'undefined' ? {} : IT_WARNING_ICONS;
const staticPreview = typeof IT_WARNING_SNAPSHOT !== 'undefined';
const state = {
  tab: 'home', category: 'all', page: 1, severity: '', severityHelp: false,
  query: '', searchLimit: 0, following: [], topicsOpen: false, aliasesOpen: false,
  id: new URLSearchParams(location.search).get('id') || ''
};
let feed = staticPreview ? IT_WARNING_SNAPSHOT : { items: [], checkedAt: null };
let live = false;
let timer;
let detailScroll = 0;
try { state.following = JSON.parse(localStorage.getItem('it-warning-following')) || []; } catch {}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[char]);
}

function icon(name, cls = 'nav-icon') {
  const src = embeddedIcons[name] || '/assets/' + name + '.png';
  return '<img class="' + cls + '" src="' + src + '" alt="">';
}

function message(value) {
  toast.textContent = value;
  toast.hidden = false;
  clearTimeout(timer);
  timer = setTimeout(() => { toast.hidden = true; }, 2500);
}

function tags(item) {
  return '<span class="tag tag-' + esc(item.severity) + '">' + esc(item.levelName) + '</span>' +
    (item.kev ? '<span class="tag tag-kev">已知遭利用</span>' : '');
}

function header(view) {
  const home = state.tab === 'home';
  const title = home
    ? '<h1 class="title home-title">IT漏洞预警</h1>'
    : '<h1 class="title">搜索预警</h1>';
  return `<header class="masthead">${title}
    ${home && view.updateLabel ? `<span class="status"><i class="status-dot ${live ? 'live' : ''}"></i>${live ? '同步于' : '快照'} <time>${esc(view.updateLabel)}</time></span>` : ''}
  </header>`;
}

function homePage(view) {
  const { feature, featureFollowed } = view.home;
  return `<section class="home-section">
      <div class="section-head"><h2 class="heading">优先处理</h2>${featureFollowed ? '<span class="relevance">与你关注的产品有关</span>' : ''}</div>
      ${feature ? `<button class="lead-alert" data-action="detail" data-value="${esc(feature.id)}">
        <span class="lead-top"><span class="lead-product"><span class="product-symbol">${icon(feature.productIcon,'product-icon')}</span><span class="lead-flag">${feature.kev ? '已知遭利用' : esc(feature.levelName)}</span></span><span class="lead-date">${esc(feature.dateLabel)} ${feature.kev ? '收录' : '发布'}</span></span>
        <span class="lead-title">${esc(feature.title)}</span>
        <span class="lead-fix">${esc(feature.fix)}</span>
        <span class="lead-cta"><span>查看修复建议</span>${icon('arrow-white','tiny-arrow')}</span>
      </button>` : `<p class="empty">${feed.checkedAt ? '近 7 天暂无已收录的重点预警' : '正在获取预警…'}</p>`}
    </section>
    ${alertsSection(view)}`;
}

function overview(view) {
  if (!view.severityCounts.length) return '';
  return `<section class="overview" aria-label="严重程度分布">
    <div class="overview-header">
      <h2 class="overview-heading">严重程度分布</h2>
      <button class="severity-help" data-action="severity-help" aria-label="严重程度分级说明" aria-controls="severity-guide" aria-expanded="${state.severityHelp}"><span aria-hidden="true">?</span></button>
    </div>
    <div class="severity-guide" id="severity-guide" ${state.severityHelp ? '' : 'hidden'}>
      <p class="severity-guide-title">FIRST CVSS 分级</p>
      <div class="severity-guide-scale">${AlertCatalog.severityGuide.map(level => `<span>${level.name} <b>${level.range}</b></span>`).join('')}</div>
      <p>缺少评分且无明确级别时，标为未定级。</p>
    </div>
    <div class="severity-chart">${view.severityCounts.map(level => `<button class="severity-cell ${state.severity === level.id ? 'selected' : ''}"
      data-action="severity" data-value="${level.id}" aria-label="${level.name} ${level.count} 条" aria-pressed="${state.severity === level.id}" ${level.count ? '' : 'disabled'}>
      <strong class="severity-count">${level.count}</strong>
      <span class="severity-track" aria-hidden="true"><i class="severity-bar severity-${level.id}" style="height:${level.height}%"></i></span>
      <span class="severity-label">${level.name}</span>
    </button>`).join('')}
    </div>
  </section>`;
}

function rows(items, empty) {
  if (!items.length) return '<p class="empty">' + esc(empty) + '</p>';
  return `<div class="stack">${items.map(item => `<button class="row" data-action="detail" data-value="${esc(item.matchedId || item.id)}">
    <span class="product-symbol">${icon(item.productIcon,'product-icon')}</span>
    <span class="row-main"><span class="row-label">${esc(item.title)}</span>
      <span class="meta">${tags(item)} <span class="row-date">${esc(item.dateLabel)}</span>${item.matchedId ? `<span class="matched-id">${esc(item.matchedId)}</span>` : ''}</span>
    </span>${icon('arrow','row-arrow')}
  </button>`).join('')}</div>`;
}

function pager(view) {
  if (view.pageCount <= 1) return '';
  return `<nav class="pager" aria-label="预警分页">
    <button class="page-step" data-action="page" data-value="${view.page - 1}" aria-label="上一页" ${view.page === 1 ? 'disabled' : ''}>‹</button>
    <div class="page-links">${view.pageLinks.map(page => `<button class="page-number ${page === view.page ? 'selected' : ''}" data-action="page" data-value="${page}" aria-label="第 ${page} 页" ${page === view.page ? 'aria-current="page"' : ''}>${page}</button>`).join('')}</div>
    <button class="page-step" data-action="page" data-value="${view.page + 1}" aria-label="下一页" ${view.page === view.pageCount ? 'disabled' : ''}>›</button>
  </nav>`;
}

function list(view, empty) {
  return rows(view.pageItems, empty) + pager(view);
}

function alertsSection(view) {
  return `<section class="browse" id="list-start" tabindex="-1" aria-label="预警列表">
    <div class="section-head">
      <div class="heading-group"><h2 class="heading">预警列表</h2><span class="list-count">${view.count} 条</span></div>
      ${view.severityName ? `<button class="severity-filter" data-action="clear-severity" aria-label="清除严重程度筛选">${view.severityName} <b aria-hidden="true">×</b></button>` : ''}
    </div>
    ${overview(view)}
    <div class="category-list" aria-label="按类别筛选">${AlertCatalog.categories.map(category => `<button class="chip ${state.category === category.id ? 'selected' : ''}" aria-pressed="${state.category === category.id}" data-action="category" data-value="${category.id}">${category.name}</button>`).join('')}</div>
    <div class="feed-results">${list(view, feed.checkedAt ? '当前条件下暂无预警' : '正在获取预警…')}</div>
  </section>`;
}

function followTopics(entries) {
  return `<div class="chips">${entries.map(topic => `<button class="chip topic-chip ${topic.selected ? 'selected' : ''}" aria-pressed="${topic.selected}" data-action="follow" data-value="${esc(topic.name)}">${icon(topic.icon,'topic-icon')}${esc(topic.name)}</button>`).join('')}</div>`;
}

function reminderSettings(view) {
  return `<section class="panel settings-panel"><div class="section-head"><h2 class="panel-title">关注产品</h2><span class="list-count">${view.followed} 项</span></div>
    ${followTopics(view.topicList)}
    ${view.followed ? `<div class="reminder"><span>${icon('bell-active')}微信订阅提醒</span><span>在小程序内开启</span></div>` : ''}
  </section>`;
}

function searchPage(view) {
  return `<div class="searchbar">${icon('search')}<input id="query" class="search-input" type="search" aria-label="搜索预警" placeholder="搜索产品或 CVE 编号" value="${esc(state.query)}" autocomplete="off">
    <button id="clear-query" class="clear-query" data-action="clear-query" aria-label="清空搜索" ${state.query ? '' : 'hidden'}>×</button></div>
    <section class="browse secondary-browse" id="list-start" tabindex="-1">${results(view)}</section>`;
}

function results(view) {
  return view.queryActive
    ? `<div class="section-head"><div class="heading-group"><h2 class="heading">搜索结果</h2><span class="list-count">${view.count} 条</span></div></div>
      ${rows(view.pageItems,'没有搜到相关预警')}
      ${view.nextSearchLimit ? `<button class="more-results" data-action="more-results" data-value="${view.nextSearchLimit}">显示更多</button>` : ''}`
    : `<div class="section-head"><h2 class="heading">常用产品</h2></div>
      <div class="quick-products">${view.popularTopics.map(topic => `<button class="quick-product" data-action="query" data-value="${esc(topic.name)}">
        <span class="product-symbol">${icon(topic.icon,'product-icon')}</span><span class="quick-name">${esc(topic.name)}</span>${icon('arrow','tiny-arrow')}
      </button>`).join('')}</div>`;
}

function detail(view) {
  const item = view.detail;
  const back = `<button class="back" data-action="back"><span aria-hidden="true">‹</span> 返回</button>`;
  if (!item) return `<header class="detail-head">${back}<h1 class="detail-title">预警详情</h1></header><main class="main"><p class="empty">这条预警暂不可查看</p></main>`;
  return `<header class="detail-head">${back}
    <div class="detail-product"><span class="product-symbol">${icon(item.productIcon,'product-icon')}</span><span>${esc(item.products.join(' · '))}</span></div>
    <h1 class="detail-title">${esc(item.title)}</h1>
    <div class="detail-meta">${tags(item)}<span>${esc(item.dateTitle)}</span></div>
  </header>
  <main class="main detail-main">
    <section class="panel fix-panel"><h2 class="panel-title"><i aria-hidden="true">✓</i>修复建议</h2><p class="panel-text">${esc(item.fix)}</p></section>
    <section class="panel"><h2 class="panel-title">影响范围</h2><p class="panel-text">${esc(item.impact)}</p></section>
    <section class="panel"><div class="section-head"><h2 class="panel-title">漏洞信息</h2>${item.score != null ? `<span class="list-count">${esc(item.metric || 'CVSS')} · ${esc(item.score)} / 10</span>` : ''}</div>
      <button class="copy-id" data-action="copy" data-value="${esc(state.id)}"><span>${esc(state.id)}</span><span>复制编号</span></button>
      ${item.aliases.length ? `<button class="source" data-action="aliases" aria-expanded="${state.aliasesOpen}">相关编号 <span>${item.aliases.length} 项 ${state.aliasesOpen ? '⌃' : '⌄'}</span></button>${state.aliasesOpen ? `<div class="alias-grid">${item.aliases.map(id => `<button class="chip" data-action="copy" data-value="${esc(id)}" aria-label="复制 ${esc(id)}">${esc(id)}</button>`).join('')}</div>` : ''}` : ''}
      <p class="panel-text">${esc(item.summary)}</p>
    </section>
    <section class="panel"><h2 class="panel-title">官方来源</h2>${item.sources.map(source => `<a class="source" href="${esc(source.url)}" target="_blank" rel="noopener noreferrer">${esc(source.name)} ${icon('arrow','tiny-arrow')}</a>`).join('')}</section>
    <div class="actions">${item.products.map(product => `<button class="cta light" data-action="follow" data-value="${esc(product)}">${state.following.includes(product) ? '已关注 ' : '关注 '}${esc(product)}</button>`).join('')}
      <button class="cta light" data-action="topics" aria-expanded="${state.topicsOpen}">关注与提醒</button>
    </div>
    ${state.topicsOpen ? reminderSettings(view) : ''}
  </main>`;
}

function render() {
  const view = AlertCatalog.display(feed,state);
  state.page = view.page;
  app.classList.toggle('detail-page', Boolean(state.id));
  app.innerHTML = state.id ? detail(view) : header(view) + '<main class="main">' +
    (state.tab === 'search' ? searchPage(view) : homePage(view)) + '</main>' +
    '<nav class="bottom" aria-label="主导航">' + AlertCatalog.tabs.map(tab => `<button class="nav ${state.tab === tab.id ? 'active' : ''}" ${state.tab === tab.id ? 'aria-current="page"' : ''} data-action="tab" data-value="${tab.id}"><span class="nav-shape">${icon(tab.icon + (state.tab === tab.id ? '-active' : ''))}</span>${tab.name}</button>`).join('') + '</nav>';
}

function showList() {
  const element = document.getElementById('list-start');
  if (!element) return;
  element.focus({ preventScroll: true });
  element.scrollIntoView({ block: 'start' });
}

app.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const { action, value } = button.dataset;
  if (action === 'severity-help') {
    state.severityHelp = !state.severityHelp;
    button.setAttribute('aria-expanded', String(state.severityHelp));
    document.getElementById('severity-guide').hidden = !state.severityHelp;
    return;
  }
  if (action === 'copy') {
    try { await navigator.clipboard.writeText(value); message('编号已复制'); }
    catch { window.prompt('复制编号', value); }
    return;
  }
  if (action === 'back' && history.state?.alertDetail) {
    history.back();
    return;
  }
  if (action === 'tab') Object.assign(state,{ tab: value, page: 1, topicsOpen: false });
  if (action === 'clear-query') Object.assign(state,{ query: '', searchLimit: 0 });
  if (action === 'more-results') state.searchLimit = Number(value);
  if (action === 'category') Object.assign(state,{ category: value, page: 1 });
  if (action === 'severity') Object.assign(state,{ severity: state.severity === value ? '' : value, page: 1 });
  if (action === 'clear-severity') Object.assign(state,{ severity: '', page: 1 });
  if (action === 'page') state.page = Number(value);
  if (action === 'topics') state.topicsOpen = !state.topicsOpen;
  if (action === 'aliases') state.aliasesOpen = !state.aliasesOpen;
  if (action === 'query') Object.assign(state,{ tab: 'search', query: value, searchLimit: 0, topicsOpen: false });
  if (action === 'detail') {
    detailScroll = scrollY;
    Object.assign(state,{ id: value, aliasesOpen: false, topicsOpen: false });
    const url = new URL(location.href);
    url.searchParams.set('id', value);
    history.pushState({ alertDetail: true }, '', url);
  }
  if (action === 'back') {
    state.id = '';
    const url = new URL(location.href);
    url.searchParams.delete('id');
    history.replaceState({}, '', url);
  }
  if (action === 'follow') {
    state.following = AlertCatalog.toggle(state.following,value);
    try { localStorage.setItem('it-warning-following', JSON.stringify(state.following)); } catch {}
    message(state.following.includes(value) ? '已关注 '+value : '已取消关注');
  }
  render();
  if (action === 'back') window.scrollTo(0,detailScroll);
  if (['tab','detail','query'].includes(action)) window.scrollTo(0,0);
  if (action === 'clear-query') document.getElementById('query').focus();
  if (action === 'page') showList();
});

app.addEventListener('input', event => {
  if (event.target.id !== 'query') return;
  Object.assign(state,{ query: event.target.value, searchLimit: 0 });
  document.getElementById('clear-query').hidden = !state.query;
  document.getElementById('list-start').innerHTML = results(AlertCatalog.display(feed,state));
});

window.addEventListener('popstate', () => {
  state.id = new URLSearchParams(location.search).get('id') || '';
  state.aliasesOpen = false;
  state.topicsOpen = false;
  render();
  window.scrollTo(0,state.id ? 0 : detailScroll);
});

async function refresh() {
  try {
    const response = await fetch('/api/feed', { cache: 'no-store' });
    if (!response.ok) throw new Error('feed');
    feed = await response.json();
    live = feed.status === 'live';
  } catch {
    live = false;
    if (!feed.checkedAt) {
      try { feed = await (await fetch('/shared/snapshot.json')).json(); } catch {}
    }
  }
  if (document.activeElement?.id !== 'query') render();
}

render();
if (!staticPreview && location.protocol !== 'file:') {
  refresh();
  setInterval(refresh,60000);
}
