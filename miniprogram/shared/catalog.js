(function expose(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.AlertCatalog = factory();
})(typeof globalThis === 'undefined' ? this : globalThis, function createCatalog() {
  const topics = [
    'PHP', 'Nginx', 'Node.js', 'Java', 'Windows', 'macOS', 'iOS', 'Android', 'VMware', 'MONAI Label'
  ];
  const categories = [
    { id: 'all', name: '全部' }, { id: 'server', name: '服务器' },
    { id: 'runtime', name: '开发栈' }, { id: 'system', name: '操作系统' },
    { id: 'mobile', name: '移动端' }, { id: 'incident', name: '安全事件' }
  ];
  const tabs = [{ id: 'home', name: '首页', icon: 'pulse' }, { id: 'search', name: '搜索', icon: 'search' }];
  const sortOptions = [{ id: 'latest', name: '最新优先' }, { id: 'risk', name: '风险优先' }];
  const levels = [
    { id: 'critical', name: '严重', range: '9.0–10.0' }, { id: 'high', name: '高危', range: '7.0–8.9' },
    { id: 'medium', name: '中危', range: '4.0–6.9' }, { id: 'low', name: '低危', range: '0.1–3.9' },
    { id: 'none', name: '无' }, { id: 'unrated', name: '未定级' }
  ];
  const severityRanks = Object.fromEntries(levels.map((level, rank) => [level.id, rank]));
  const severityGuide = levels.filter(level => level.range);
  const pageSize = 5;
  const searchBatchSize = 12;
  const dayMs = 86400000;
  const productIcons = new Map([
    ['monailabel','monai'], ['monai','monai'], ['mailassure','mailassure'], ['spamexperts','mailassure'],
    ['vmware','vmware'], ['vmwarevcenter','vmware'], ['optimizely','optimizely'],
    ['php','php'], ['nginx','nginx'], ['nodejs','node'], ['java','java'],
    ['windows','windows'], ['macos','macos'], ['ios','ios'], ['ipados','ios'],
    ['android','android'], ['apple','apple']
  ]);
  const categoryIcons = new Set(['server','runtime','system','mobile','incident']);
  const brandIcons = new Set(['android','node','php','java','monai']);

  function priority(item) {
    return item.level === 'critical' || Boolean(item.kev) ||
      (item.category === 'incident' && item.level === 'high');
  }

  function day(item) {
    return (item.kev || item.date).slice(0, 10);
  }

  function findItem(items, id) {
    return items.find(item => item.id === id) || items.find(item => (item.aliases || []).includes(id));
  }

  function productIcon(products, category) {
    const matches = products.map(product => productIcons.get(normalize(product))).filter(Boolean);
    const combinedApple = matches.includes('macos') && matches.includes('ios');
    const key = combinedApple ? 'apple' : matches[0] || (categoryIcons.has(category) ? category : 'security');
    return (brandIcons.has(key) ? 'brand-' : 'product-') + key;
  }

  function severityOf(item) {
    const score = item.score;
    if (Number.isFinite(score) && score >= 0 && score <= 10) {
      if (score >= 9) return 'critical';
      if (score >= 7) return 'high';
      if (score >= 4) return 'medium';
      return score > 0 ? 'low' : 'none';
    }
    return levels[severityRanks[item.level]]?.id || 'unrated';
  }

  function formatItems(items) {
    return items.map(item => {
      const severity = severityOf(item);
      return {
        ...item, severity,
        productIcon: productIcon(item.products, item.category),
        levelName: levels[severityRanks[severity]].name,
        dateLabel: day(item).slice(5).replace('-', '/'),
        dateTitle: item.kev ? 'KEV 收录于 ' + item.kev : '发布于 ' + item.date
      };
    }).sort((a, b) => day(b).localeCompare(day(a)) ||
      Number(priority(b)) - Number(priority(a)) || (b.score ?? 0) - (a.score ?? 0) ||
      a.title.localeCompare(b.title) || a.id.localeCompare(b.id));
  }

  function chinaTime(value) {
    if (!value) return '';
    const time = new Date(value);
    if (!Number.isFinite(time.getTime())) return '';
    return new Date(time.getTime() + 8 * 3600000).toISOString();
  }

  function severityOverview(items) {
    const counts = levels.map(() => 0);
    for (const item of items) counts[severityRanks[item.severity]]++;
    const peak = Math.max(1, ...counts);
    return levels.map((level, rank) => ({
      ...level, count: counts[rank], height: 100 * counts[rank] / peak
    })).filter(level => level.count || (level.id !== 'none' && level.id !== 'unrated'));
  }

  function homeFeature(items, following, checkedDay) {
    const end = checkedDay || (items.length ? day(items[0]) : '');
    if (!end) return { feature: null, featureFollowed: false };
    const start = new Date(Date.parse(end) - 6 * dayMs).toISOString().slice(0, 10);
    const isFollowed = item => item.products.some(product => following.includes(product));
    const candidates = items.filter(item => priority(item) && day(item) >= start && day(item) <= end);
    const feature = candidates.find(item => isFollowed(item) && item.kev)
      || candidates.find(isFollowed)
      || candidates.find(item => item.kev && item.level === 'critical')
      || candidates[0];
    return { feature: feature || null, featureFollowed: Boolean(feature && isFollowed(feature)) };
  }

  function display(feed, state) {
    const all = formatItems(feed.items);
    const searching = state.tab === 'search';
    const query = (state.query || '').toLowerCase().trim();
    const words = query.split(/\s+/).map(normalize).filter(Boolean);
    const queryId = normalize(query);
    const following = state.following || [];
    const updateTime = chinaTime(feed.checkedAt);
    const category = state.category || 'all';
    const scope = all.filter(item => category === 'all' || item.category === category ||
      (category === 'system' && item.products.includes('macOS')));
    const selectedLevel = levels[severityRanks[state.severity]];
    const sortIndex = Math.max(0, sortOptions.findIndex(option => option.id === state.sort));
    const items = searching
      ? all.filter(item => {
        const searchable = normalize([item.id, ...(item.aliases || []), ...item.products, item.title, item.summary, item.fix].join(' '));
        return words.length && words.every(word => searchable.includes(word));
      })
      : scope.filter(item => !selectedLevel || item.severity === selectedLevel.id);
    if (!searching && sortOptions[sortIndex].id === 'risk') {
      items.sort((a, b) => severityRanks[a.severity] - severityRanks[b.severity] ||
        Number(Boolean(b.kev)) - Number(Boolean(a.kev)));
    }
    const pageCount = searching ? 1 : Math.max(1, Math.ceil(items.length / pageSize));
    const page = Math.min(pageCount, Math.max(1, Math.trunc(Number(state.page)) || 1));
    const start = (page - 1) * pageSize;
    const searchLimit = state.searchLimit || searchBatchSize;
    const visibleItems = searching ? items.slice(0, searchLimit) : items.slice(start, start + pageSize);
    const pageItems = visibleItems.map(item => ({
      ...item,
      matchedId: (searching && [item.id, ...(item.aliases || [])].find(id => normalize(id) === queryId)) || ''
    }));
    const names = [...new Set([...topics, ...all.flatMap(item => item.products)])];
    const topicList = names.map(name => ({ name, selected: following.includes(name), icon: productIcon([name]) }));
    const pageStart = Math.max(1, Math.min(page - 2, pageCount - 4));
    const pageLinks = Array.from({ length: Math.min(5, pageCount) }, (_, index) => pageStart + index);
    return {
      pageItems, page, pageCount, pageLinks, sortIndex, count: items.length, queryActive: Boolean(query),
      updateLabel: updateTime ? updateTime.slice(5, 10).replace('-', '/') + ' ' + updateTime.slice(11, 16) : '',
      nextSearchLimit: searching && searchLimit < items.length ? Math.min(searchLimit + searchBatchSize, items.length) : 0,
      severityCounts: all.length ? severityOverview(scope) : [], severityName: selectedLevel?.name || '',
      home: homeFeature(all, following, updateTime.slice(0, 10)),
      topicList, popularTopics: topicList.slice(0, 8),
      detail: findItem(all, state.id) || null,
      followed: following.length
    };
  }

  function normalize(value) {
    return value.toLowerCase().replace(/[^a-z0-9\u3400-\u9fff]/g, '');
  }

  function toggle(list, value) {
    return list.includes(value) ? list.filter(item => item !== value) : list.concat(value);
  }

  return { categories, tabs, sortOptions, severityGuide, display, priority, toggle, day };
});
