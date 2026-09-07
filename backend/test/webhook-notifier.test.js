import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ConfigStore } from '../lib/config-store.js';
import { WebhookNotifier } from '../lib/webhook-notifier.js';

const logger = { debug() {}, info() {}, warn() {}, error() {} };
const listen = (server) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const close = (server) => new Promise((resolve) => server.close(resolve));

test('sends selected webhook events with write-only custom headers', async () => {
  let received;
  const target = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      received = { headers: request.headers, body: JSON.parse(Buffer.concat(chunks).toString()) };
      response.writeHead(204).end();
    });
  });
  const port = await listen(target);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-webhook-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    const status = store.updateWebhook({ enabled: true, url: `http://127.0.0.1:${port}/hook`, events: ['rule.error'], headers: { Authorization: 'Bearer secret-value' } });
    assert.deepEqual(status.headerNames, ['Authorization']);
    assert.equal(JSON.stringify(status).includes('secret-value'), false);
    assert.equal(JSON.stringify(store.exportConfig()).includes('secret-value'), false);
    const notifier = new WebhookNotifier({ store, logger });
    assert.deepEqual(await notifier.send('rule.recovered', { rule: 'ignored' }), { skipped: true, ok: true });
    const result = await notifier.send('rule.error', { rule: 'Example', message: 'offline' });
    assert.equal(result.ok, true);
    assert.equal(received.headers.authorization, 'Bearer secret-value');
    assert.equal(received.body.event, 'rule.error');
    assert.equal(received.body.payload.rule, 'Example');
    assert.ok(store.webhookStatus().lastDeliveryAt);
    assert.equal(store.webhookStatus().lastError, null);
  } finally {
    await close(target);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
