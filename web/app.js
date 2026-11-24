/* global AlertCatalog, IT_WARNING_SNAPSHOT, IT_WARNING_ICONS */
const app = document.getElementById('app');
const toast = document.getElementById('toast');
const embeddedIcons = typeof IT_WARNING_ICONS === 'undefined' ? {} : IT_WARNING_ICONS;
const staticPreview = typeof IT_WARNING_SNAPSHOT !== 'undefined';
const rssLink = staticPreview ? 'https://jennychiu68.github.io/IT-warning/feed.xml' : new URL('./feed.xml',location.href).href;
const state = {
  tab: 'home', category: 'all', page: 1, severity: '', severityHelp: false,
  query: '', searchLimit: 0, following: [], topicsOpen: false, aliasesOpen: false,
  commentAlert: '', commentDraft: '', commentBusy: false,
  id: new URLSearchParams(location.search).get('id') || ''
};
const channels = { pushKey:'', registration:null, push:false, pushBusy:false, comments:false, unread:0, items:[], readAt:0 };
let feed = staticPreview ? IT_WARNING_SNAPSHOT : { items: [], checkedAt: null };
let live = false;
let timer;
let detailScroll = 0;
try { state.following = JSON.parse(localStorage.getItem('it-warning-following')) || []; } catch {}
try { channels.readAt = Number(localStorage.getItem('it-warning-comments-read')) || 0; } catch {}

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
    : '<h1 class="title">' + (state.tab === 'search' ? '搜索预警' : AlertCatalog.tabs.find(tab => tab.id === state.tab).name) + '</h1>';
  return `<header class="masthead">${title}
    ${home && view.updateLabel ? `<span class="status"><i class="status-dot ${live ? 'live' : ''}"></i>${live ? '同步于' : '快照'} <time>${esc(view.updateLabel)}</time></span>` : ''}
  </header>`;
}

function homePage(view) {
  const { feature, featureFollowed } = view.home;
  return `<section class="home-section">
      <div class="section-head"><h2 class="heading">优先处理</h2>${featureFollowed ? '<span class="relevance">与你关注的产品有关</span>' : ''}</div>
      ${feature ? `<button class="lead-alert" data-action="detail" data-value="${esc(feature.id)}">
        <span class="lead-top"><span class="lead-product"><span class="product-symbol">${icon(feature.productIcon,'product-icon')}</span><span class="lead-flag">${feature.kev ? '已知遭利用' : esc(feature.levelName)}</span></span><span class="lead-date">${esc(feature.dateLabel)} 公布</span></span>
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

function rows(items, empty, expanded = false) {
  if (!items.length) return '<p class="empty">' + esc(empty) + '</p>';
  if (expanded) return `<div class="alert-cards">${items.map(item => `<button class="alert-card" data-action="detail" data-value="${esc(item.id)}">
    <span class="card-heading">
      <span class="product-symbol">${icon(item.productIcon,'product-icon')}</span>
      <span class="row-main"><span class="card-title">${esc(item.title)}</span>
        <span class="meta">${tags(item)} <time class="row-date" datetime="${esc(item.publishedAt || item.date)}" title="${esc(item.dateTitle)}">${esc(item.dateLabel)}</time></span>
      </span>${icon('arrow','row-arrow')}
    </span>
    <span class="card-summary">${esc(item.summary)}</span>
  </button>`).join('')}</div>`;
  return `<div class="stack">${items.map(item => `<button class="row" data-action="detail" data-value="${esc(item.matchedId || item.id)}">
    <span class="product-symbol">${icon(item.productIcon,'product-icon')}</span>
    <span class="row-main"><span class="row-label">${esc(item.title)}</span>
      <span class="meta">${tags(item)} <time class="row-date" datetime="${esc(item.publishedAt || item.date)}" title="${esc(item.dateTitle)}">${esc(item.dateLabel)}</time>${item.matchedId ? `<span class="matched-id">${esc(item.matchedId)}</span>` : ''}</span>
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
  return rows(view.pageItems, empty, true) + pager(view);
}

function alertsSection(view) {
  return `<section class="browse" id="list-start" tabindex="-1" aria-label="预警列表">
    <div class="section-head">
      <div class="heading-group"><h2 class="heading">预警列表</h2><span class="list-count">${view.count} 条</span></div>
      <div class="list-controls">
        ${view.severityName ? `<button class="severity-filter" data-action="clear-severity" aria-label="清除严重程度筛选">${view.severityName} <b aria-hidden="true">×</b></button>` : ''}
        <div class="list-sort">
          <select id="alert-sort" class="list-sort-control" aria-label="预警排序">${AlertCatalog.sortOptions.map((option, index) => `<option value="${option.id}" ${index === view.sortIndex ? 'selected' : ''}>${option.name}</option>`).join('')}</select>
          <span class="list-sort-arrow" aria-hidden="true"></span>
        </div>
      </div>
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
    ${followTopics(view.topicList)}</section>`;
}

function subscriptionPage() {
  return `<section class="panel subscription-panel">
    <span class="subscription-icon">${icon('bell-active')}</span><h2 class="heading">重点预警提醒</h2>
    <p class="panel-text">订阅严重漏洞、已知遭利用的漏洞和高危安全事件。</p>
    ${channels.registration && Notification.permission !== 'denied' ? `<button class="cta subscription-button" data-action="toggle-push" ${channels.pushBusy ? 'disabled' : ''}>${channels.push ? '取消浏览器通知' : '启用浏览器通知'}</button>` : ''}
    ${channels.registration && Notification.permission === 'denied' ? '<p class="panel-text">浏览器通知已被关闭，可在站点设置中重新允许。</p>' : ''}
  </section>
  <section class="panel subscription-panel rss-panel">
    <h2 class="panel-title">RSS 订阅</h2>
    <p class="panel-text">将链接添加到 RSS 阅读器，在预警源更新后接收提醒。</p>
    <button class="cta ${channels.registration ? 'light' : ''} subscription-button" data-action="copy-feed">复制订阅链接</button>
  </section>`;
}

function commentsPage() {
  const alerts = feed.items.slice().sort((a,b) => b.date.localeCompare(a.date) || (b.publishedAt || '').localeCompare(a.publishedAt || ''));
  const form = channels.comments && alerts.length ? `<form class="panel comment-form" id="comment-form">
    <label class="panel-title" for="comment-alert">评论预警</label>
    <select id="comment-alert" required><option value="">选择一条预警</option>${alerts.map(item => `<option value="${esc(item.id)}" ${state.commentAlert === item.id ? 'selected' : ''}>${esc(item.title)}</option>`).join('')}</select>
    <label class="visually-hidden" for="comment-content">评论内容</label>
    <textarea id="comment-content" maxlength="300" minlength="2" required placeholder="写下你的评论">${esc(state.commentDraft)}</textarea>
    <button class="cta" type="submit" ${state.commentBusy ? 'disabled' : ''}>提交审核</button>
  </form>` : '';
  const list = channels.items.length ? `<div class="alert-cards">${channels.items.map(item => `<article class="alert-card comment-item">
    <button class="comment-target" data-action="detail" data-value="${esc(item.alert)}">${esc(item.title)} ${icon('arrow','tiny-arrow')}</button>
    <p class="panel-text">${esc(item.content)}</p></article>`).join('')}</div>`
    : `<p class="empty">${staticPreview ? '评论将在正式版开放' : '暂无公开评论'}</p>`;
  return form + list;
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
    <div class="detail-meta">${tags(item)}<span>${esc(item.dateTitle)}</span>${item.kev ? `<span>KEV 收录于 ${esc(item.kev)}</span>` : ''}</div>
  </header>
  <main class="main detail-main">
    <section class="panel fix-panel"><h2 class="panel-title"><i aria-hidden="true">✓</i>修复建议</h2><p class="panel-text">${esc(item.fix)}</p></section>
    <section class="panel"><h2 class="panel-title">影响范围</h2><p class="panel-text">${esc(item.impact)}</p></section>
    <section class="panel"><div class="section-head"><h2 class="panel-title">漏洞信息</h2>${item.score != null ? `<span class="list-count">${esc(item.metric || 'CVSS')} · ${esc(item.score)} / 10</span>` : ''}</div>
      <button class="copy-id" data-action="copy" data-value="${esc(state.id)}"><span>${esc(state.id)}</span><span>复制编号</span></button>
      ${item.aliases.length ? `<button class="source" data-action="aliases" aria-expanded="${state.aliasesOpen}">相关编号 <span>${item.aliases.length} 项 ${state.aliasesOpen ? '⌃' : '⌄'}</span></button>${state.aliasesOpen ? `<div class="alias-grid">${item.aliases.map(id => `<button class="chip" data-action="copy" data-value="${esc(id)}" aria-label="复制 ${esc(id)}">${esc(id)}</button>`).join('')}</div>` : ''}` : ''}
      <p class="panel-text">${esc(item.summary)}</p>
    </section>
    <div class="actions">${item.products.map(product => `<button class="cta light" data-action="follow" data-value="${esc(product)}">${state.following.includes(product) ? '已关注 ' : '关注 '}${esc(product)}</button>`).join('')}
      <button class="cta light" data-action="topics" aria-expanded="${state.topicsOpen}">关注与提醒</button>
      ${channels.comments ? `<button class="cta light" data-action="discuss" data-value="${esc(item.id)}">评论这条预警</button>` : ''}
    </div>
    ${state.topicsOpen ? reminderSettings(view) : ''}
  </main>`;
}

function render() {
  const view = AlertCatalog.display(feed,state);
  state.page = view.page;
  app.classList.toggle('detail-page', Boolean(state.id));
  const pages = { search:searchPage, home:homePage, subscribe:subscriptionPage, comments:commentsPage };
  app.innerHTML = state.id ? detail(view) : header(view) + '<main class="main">' + pages[state.tab](view) + '</main>' +
    '<nav class="bottom" aria-label="主导航">' + AlertCatalog.tabs.map(tab => {
      const selected = state.tab === tab.id;
      const symbol = tab.id === 'subscribe' || tab.id === 'comments'
        ? `<span class="tab-symbol tab-${tab.icon}" aria-hidden="true"></span>`
        : icon(tab.icon + (selected ? '-active' : ''));
      const unread = tab.id === 'comments' && channels.unread;
      return `<button class="nav ${selected ? 'active' : ''}" ${selected ? 'aria-current="page"' : ''} data-action="tab" data-value="${tab.id}"><span class="nav-shape">${symbol}${unread ? `<span class="nav-badge" aria-label="${unread} 条未读评论">${unread > 99 ? '99+' : unread}</span>` : ''}</span>${tab.name}</button>`;
    }).join('') + '</nav>';
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
  if (action === 'tab') {
    Object.assign(state,{ tab: value, page: 1, topicsOpen: false });
    if (value === 'comments') markCommentsRead();
  }
  if (action === 'copy-feed') {
    try { await navigator.clipboard.writeText(rssLink); message('订阅链接已复制'); }
    catch { window.prompt('复制 RSS 订阅链接',rssLink); }
    return;
  }
  if (action === 'toggle-push') { await togglePush(); return; }
  if (action === 'discuss') {
    Object.assign(state,{ tab:'comments', id:'', commentAlert:value });
    const url = new URL(location.href);
    url.searchParams.delete('id');
    history.replaceState({},'',url);
    markCommentsRead();
  }
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
  if (['tab','detail','query','discuss'].includes(action)) window.scrollTo(0,0);
  if (action === 'clear-query') document.getElementById('query').focus();
  if (action === 'page') showList();
});

app.addEventListener('input', event => {
  if (event.target.id === 'comment-content') state.commentDraft = event.target.value;
  if (event.target.id !== 'query') return;
  Object.assign(state,{ query: event.target.value, searchLimit: 0 });
  document.getElementById('clear-query').hidden = !state.query;
  document.getElementById('list-start').innerHTML = results(AlertCatalog.display(feed,state));
});

app.addEventListener('change', event => {
  if (event.target.id === 'comment-alert') state.commentAlert = event.target.value;
  if (event.target.id !== 'alert-sort') return;
  Object.assign(state, { sort: event.target.value, page: 1 });
  render();
  document.getElementById('alert-sort').focus({ preventScroll: true });
});

app.addEventListener('submit', async event => {
  if (event.target.id !== 'comment-form') return;
  event.preventDefault();
  if (state.commentBusy) return;
  state.commentBusy = true;
  const submitter = event.submitter;
  if (submitter) submitter.disabled = true;
  try {
    await channelApi('/api/comments',{ id:state.commentAlert, content:state.commentDraft });
    state.commentDraft = '';
    message('评论已提交，审核通过后公开');
  } catch (error) { message(error.message); }
  finally { state.commentBusy = false; render(); }
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
  await refreshComments();
  if (!['query', 'alert-sort','comment-alert','comment-content'].includes(document.activeElement?.id)) render();
}

async function channelApi(path, data) {
  const response = await fetch(path, data ? { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify(data) } : { cache:'no-store' });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || '服务暂不可用，请稍后再试');
  return result;
}

function markCommentsRead() {
  channels.readAt = Math.max(channels.readAt,...channels.items.map(item => item.approvedAt));
  channels.unread = 0;
  try { localStorage.setItem('it-warning-comments-read',String(channels.readAt)); } catch {}
}

async function refreshComments() {
  try {
    const data = await channelApi('/api/comments?after='+channels.readAt);
    Object.assign(channels,{ unread:data.unread, items:data.items });
    if (state.tab === 'comments' && !state.id) markCommentsRead();
  } catch {}
}

async function loadChannels() {
  try {
    const { pushKey, comments } = await channelApi('/api/channels');
    Object.assign(channels,{ pushKey, comments });
    if (pushKey && isSecureContext && 'PushManager' in window && 'Notification' in window && 'serviceWorker' in navigator) {
      channels.registration = await navigator.serviceWorker.register('/push-worker.js');
      const current = await channels.registration.pushManager.getSubscription();
      if (current) channels.push = (await channelApi('/api/push/status',current.toJSON())).subscribed;
    }
  } catch {}
  if (!['query','alert-sort','comment-alert','comment-content'].includes(document.activeElement?.id)) render();
}

async function togglePush() {
  if (!channels.registration || channels.pushBusy) return;
  channels.pushBusy = true;
  try {
    const permission = channels.push || Notification.permission === 'granted' ? Promise.resolve('granted') : Notification.requestPermission();
    render();
    if (await permission !== 'granted') { message('浏览器通知未授权'); return; }
    const registration = await navigator.serviceWorker.ready;
    let subscription = await registration.pushManager.getSubscription();
    if (channels.push) {
      if (subscription) {
        await channelApi('/api/push/cancel',subscription.toJSON());
        await subscription.unsubscribe();
      }
      channels.push = false;
      message('已取消浏览器通知');
    } else {
      if (!subscription) subscription = await registration.pushManager.subscribe({ userVisibleOnly:true, applicationServerKey:channels.pushKey });
      channels.push = (await channelApi('/api/push/subscribe',subscription.toJSON())).subscribed;
      message(channels.push ? '已订阅重点预警' : '订阅暂未生效，请重试');
    }
  } catch { message('未能更新订阅，请稍后重试'); }
  finally { channels.pushBusy = false; render(); }
}

render();
if (!staticPreview && location.protocol !== 'file:') {
  loadChannels();
  refresh();
  setInterval(refresh,60000);
}
