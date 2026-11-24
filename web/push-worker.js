self.addEventListener('push', event => {
  const item = event.data?.json();
  if (!item || !/^[A-Z\d-]{4,45}$/.test(item.id) || typeof item.title!=='string') return;
  event.waitUntil(self.registration.showNotification('IT漏洞预警', {
    body:item.title, tag:item.id, data:{ id:item.id }
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = new URL(self.registration.scope);
  url.searchParams.set('id',event.notification.data.id);
  event.waitUntil(self.clients.openWindow(url.href));
});
