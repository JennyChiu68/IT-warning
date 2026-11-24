export function readComments(store, after = 0) {
  const items = store.q(`SELECT comments.id,comments.alert,comments.content,comments.approved_at,alerts.content AS alert_data
    FROM comments JOIN alerts ON alerts.id=comments.alert AND alerts.active=1
    WHERE comments.approved_at IS NOT NULL ORDER BY comments.approved_at DESC,comments.id DESC LIMIT 50`).all();
  const cursor = Number(after);
  const lastRead = Number.isSafeInteger(cursor) && cursor > 0 ? cursor : 0;
  const { unread } = store.q(`SELECT count(*) AS unread FROM comments JOIN alerts ON alerts.id=comments.alert AND alerts.active=1
    WHERE comments.approved_at>?`).get(lastRead);
  return { unread, items:items.map(row => ({ id:row.id, alert:row.alert, content:row.content,
    approvedAt:row.approved_at, title:JSON.parse(row.alert_data).title })) };
}

export function writeComment(store, { id, content }) {
  const alert = typeof id === 'string' && store.lookup(id);
  const value = typeof content === 'string' ? content.trim() : '';
  if (!alert || value.length < 2 || value.length > 300 || /https?:\/\/|www\.|<[^>]*>/i.test(value)) {
    throw new Error('请输入 2–300 字的评论。请勿填写链接或内部信息。');
  }
  store.q('INSERT INTO comments (alert,content) VALUES (?,?)').run(alert.id,value);
}
