const catalog = require('../../shared/catalog.js');
const snapshot = require('../../shared/snapshot.js');
const config = require('../../config.js');

const onSimulator = typeof wx.getDeviceInfo === 'function' && wx.getDeviceInfo().platform === 'devtools';
const apiBase = config.apiBase || (onSimulator ? config.developerApiBase : '');

function request(path, options = {}) {
  return new Promise((resolve, reject) => wx.request({
    url: apiBase.replace(/\/$/, '') + path,
    timeout: 8000,
    ...options,
    success: response => response.statusCode >= 200 && response.statusCode < 300
      ? resolve(response.data) : reject(new Error(response.data?.message || '服务暂不可用')),
    fail: reject
  }));
}

Page({
  data: {
    tab: 'home', category: 'all', page: 1, severity: '', severityHelp: false,
    query: '', searchLimit: 0, following: [], id: '', topicsOpen: false, aliasesOpen: false,
    searchFocus: false,
    categories: catalog.categories, tabs: catalog.tabs, sortOptions: catalog.sortOptions, severityGuide: catalog.severityGuide, live: false, canSubscribe: false,
    grants: 0, busy: false, message: ''
  },

  onLoad(options) {
    this.feed = wx.getStorageSync('it-warning-feed') || snapshot;
    this.session = wx.getStorageSync('it-warning-session') || '';
    const following = wx.getStorageSync('it-warning-following') || [];
    const id = typeof options.id === 'string' ? options.id : '';
    this.render({ following, id });
  },

  onShow() {
    this.refresh();
    this.refreshTimer = setInterval(() => this.refresh(), 60000);
  },

  onHide() { clearInterval(this.refreshTimer); },
  onUnload() { clearInterval(this.refreshTimer); },

  onShareAppMessage() {
    const item = this.data.detail;
    return item ? { title: item.title, path: '/pages/index/index?id=' + encodeURIComponent(this.data.id) }
      : { title: 'IT漏洞预警', path: '/pages/index/index' };
  },

  render(next = {}, callback) {
    const state = { ...this.data, ...next };
    const view = catalog.display(this.feed,state);
    if (view.detail) {
      view.detail.followingMap = {};
      for (const product of state.following) view.detail.followingMap[product] = true;
      view.detail.productsLabel = view.detail.products.join(' · ');
    }
    this.setData({ ...next, ...view }, callback);
  },

  async refresh() {
    if (!apiBase || this.refreshing) return;
    this.refreshing = true;
    try {
      const data = await request('/api/feed');
      this.feed = data;
      wx.setStorageSync('it-warning-feed', data);
      this.render({ live: data.status === 'live', canSubscribe: Boolean(data.templateId) });
      this.templateId = data.templateId;
      const missing = this.data.id;
      if (missing && !this.data.detail && /^[A-Z\d-]{4,45}$/.test(missing)) {
        try {
          const item = await request('/api/alerts/' + encodeURIComponent(missing));
          if (this.feed === data && this.data.id === missing) {
            this.feed = { ...data, items: data.items.concat(item) };
            this.render();
          }
        } catch {}
      }
      if (this.session && data.templateId) {
        try {
          const status = await request('/api/wechat/status', { header: this.authHeader() });
          this.setData({ grants: status.remaining });
        } catch {}
      }
    } catch {
      this.render({ live: false });
    } finally {
      this.refreshing = false;
    }
  },

  async onPullDownRefresh() {
    await this.refresh();
    wx.stopPullDownRefresh();
  },

  selectTab(event) {
    this.render({ tab: event.currentTarget.dataset.value, id: '', page: 1, topicsOpen: false, searchFocus: false },
      () => wx.pageScrollTo({ scrollTop: 0, duration: 0 }));
  },

  blurSearch() { this.setData({ searchFocus: false }); },

  onPageScroll(event) { this.scrollTop = event.scrollTop; },

  renderList(next) {
    this.render(next, () => wx.pageScrollTo({ selector: '#list-start', offsetTop: -12, duration: 0 }));
  },

  selectCategory(event) {
    this.render({ category: event.currentTarget.dataset.value, page: 1 });
  },
  selectSort(event) {
    const option = this.data.sortOptions[event.detail.value];
    if (option) this.render({ sort: option.id, page: 1 });
  },
  selectSeverity(event) {
    const value = event.currentTarget.dataset.value;
    this.render({ severity: this.data.severity === value ? '' : value, page: 1 });
  },
  clearSeverity() { this.render({ severity: '', page: 1 }); },
  toggleSeverityHelp() { this.setData({ severityHelp: !this.data.severityHelp }); },
  selectPage(event) { this.renderList({ page: event.currentTarget.dataset.value }); },
  toggleTopics() { this.render({ topicsOpen: !this.data.topicsOpen }); },
  toggleAliases() { this.setData({ aliasesOpen: !this.data.aliasesOpen }); },
  clearQuery() { this.render({ query: '', searchLimit: 0, searchFocus: true }); },
  queryInput(event) { this.render({ query: event.detail.value, searchLimit: 0 }); },
  showMoreResults() { this.render({ searchLimit: this.data.nextSearchLimit }); },
  queryTopic(event) {
    this.render({ query: event.currentTarget.dataset.value, searchLimit: 0, searchFocus: false },
      () => wx.pageScrollTo({ scrollTop: 0, duration: 0 }));
  },

  openDetail(event) {
    this.detailScroll = this.scrollTop || 0;
    this.render({ id: event.currentTarget.dataset.value, aliasesOpen: false, topicsOpen: false, searchFocus: false },
      () => wx.pageScrollTo({ scrollTop: 0, duration: 0 }));
  },

  closeDetail() {
    this.render({ id: '' }, () => wx.pageScrollTo({ scrollTop: this.detailScroll || 0, duration: 0 }));
  },

  copy(event) { wx.setClipboardData({ data: event.currentTarget.dataset.value }); },

  authHeader() { return { Authorization: 'Bearer ' + this.session }; },

  async follow(event) {
    const previous = this.data.following;
    const following = catalog.toggle(previous, event.currentTarget.dataset.value);
    this.render({ following, message: '' });
    wx.setStorageSync('it-warning-following', following);
    if (!this.session || !this.data.canSubscribe || !this.data.grants) return;
    try {
      const pending = (this.topicSync || Promise.resolve()).catch(() => {}).then(() => request('/api/wechat/topics', {
        method: 'POST', header: this.authHeader(), data: { following }
      }));
      this.topicSync = pending;
      const result = await pending;
      this.setData({ grants: result.remaining });
    } catch {
      this.setData({ message: '提醒偏好暂未同步，请检查网络后重试。' });
    }
  },

  async subscribe() {
    if (this.data.busy) return;
    if (!this.templateId || !this.data.following.length) {
      wx.showToast({ title: '请先关注至少一个产品', icon: 'none' });
      return;
    }
    const templateId = this.templateId;
    this.setData({ busy: true, message: '' });
    try {
      const result = await wx.requestSubscribeMessage({ tmplIds: [templateId] });
      if (result[templateId] !== 'accept') {
        this.setData({ message: '微信订阅未授权。' });
        return;
      }
      const login = await wx.login();
      const status = await request('/api/wechat/subscribe', {
        method: 'POST', data: { code: login.code, following: this.data.following }
      });
      this.session = status.token;
      wx.setStorageSync('it-warning-session', status.token);
      this.setData({ grants: status.remaining, message: '已订阅下一条相关重点预警。' });
    } catch {
      this.setData({ message: '暂未完成订阅，请稍后重试。' });
    } finally {
      this.setData({ busy: false });
    }
  },

  async cancelReminders() {
    if (!this.session || this.data.busy) return;
    this.setData({ busy: true, message: '' });
    try {
      await request('/api/wechat/cancel', { method: 'POST', header: this.authHeader() });
      this.setData({ grants: 0, message: '已取消待发送的提醒。' });
    } catch {
      this.setData({ message: '暂未取消提醒，请稍后重试。' });
    } finally {
      this.setData({ busy: false });
    }
  }
});
