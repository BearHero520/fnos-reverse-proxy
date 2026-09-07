export class WebhookNotifier {
  constructor({ store, logger }) {
    this.store = store;
    this.logger = logger;
    this.lastFailure = null;
  }

  async send(event, payload = {}, { force = false } = {}) {
    const config = this.store.webhookConfig();
    if (!config.url || !force && (!config.enabled || !config.events.includes(event))) return { skipped: true, ok: true };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    timer.unref?.();
    try {
      const response = await fetch(config.url, {
        method: 'POST',
        signal: controller.signal,
        headers: { ...config.headers, 'Content-Type': 'application/json', 'User-Agent': 'fnos-reverse-proxy/1' },
        body: JSON.stringify({ event, occurredAt: new Date().toISOString(), source: 'fnos-reverse-proxy', payload }),
      });
      await response.arrayBuffer();
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.store.recordWebhookDelivery({ ok: true });
      if (this.lastFailure) this.logger.info('Webhook 通知已恢复', { event });
      this.lastFailure = null;
      return { ok: true, status: response.status };
    } catch (error) {
      const message = error.name === 'AbortError' ? '发送超时' : error.message;
      this.store.recordWebhookDelivery({ ok: false, error: message });
      const failureKey = `${event}:${message}`;
      if (failureKey !== this.lastFailure) this.logger.warn('Webhook 通知发送失败', { event, error: message });
      this.lastFailure = failureKey;
      return { ok: false, error: message };
    } finally {
      clearTimeout(timer);
    }
  }

  test() {
    return this.send('webhook.test', { message: '反向代理 Webhook 测试通知' }, { force: true });
  }
}
