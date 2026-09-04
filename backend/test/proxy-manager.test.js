import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { ConfigStore } from '../lib/config-store.js';
import { ProxyManager } from '../lib/proxy-manager.js';

const logger = { debug() {}, info() {}, warn() {}, error() {} };
const listen = (server, port = 0) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => resolve(server.address().port)); });
const close = (server) => new Promise((resolve) => server.close(resolve));
const bindUdp = (socket, port = 0) => new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(port, '127.0.0.1', () => resolve(socket.address().port)); });
const closeUdp = (socket) => new Promise((resolve) => { try { socket.close(resolve); } catch { resolve(); } });
const freePort = async () => { const server = net.createServer(); const port = await listen(server); await close(server); return port; };
const freeTcpUdpPort = async () => {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const server = net.createServer();
    const socket = dgram.createSocket('udp4');
    try {
      const port = await listen(server);
      await bindUdp(socket, port);
      await close(server);
      await closeUdp(socket);
      return port;
    } catch {
      if (server.listening) await close(server);
      await closeUdp(socket);
    }
  }
  throw new Error('No port available for both TCP and UDP');
};
const rawRequest = (port, request) => new Promise((resolve, reject) => {
  const socket = net.createConnection(port, '127.0.0.1', () => socket.write(request));
  socket.once('data', (chunk) => { resolve(chunk.toString()); socket.destroy(); });
  socket.once('error', reject);
});
const freePortRange = async (width = 2) => {
  for (let start = 23000; start < 64000 - width; start += width + 3) {
    const servers = [];
    try {
      for (let offset = 0; offset < width; offset += 1) { const server = net.createServer(); await listen(server, start + offset); servers.push(server); }
      await Promise.all(servers.map(close));
      return start;
    } catch { await Promise.allSettled(servers.map(close)); }
  }
  throw new Error('No free consecutive port range');
};

test('forwards HTTP requests and custom headers', async () => {
  const target = http.createServer((req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ url: req.url, header: req.headers['x-proxy-test'] })); });
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-http-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'HTTP test', protocol: 'http', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'http', targetHost: '127.0.0.1', targetPort, customHeaders: { 'X-Proxy-Test': 'working' } });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    const response = await fetch(`http://127.0.0.1:${proxyPort}/hello?value=1`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { url: '/hello?value=1', header: 'working' });
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('enforces upload limits for chunked request bodies', async () => {
  let received = 0;
  const target = http.createServer((req, res) => {
    req.on('data', (chunk) => { received += chunk.length; });
    req.on('end', () => res.end('ok'));
  });
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-upload-limit-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'Upload limit', protocol: 'http', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'http', targetHost: '127.0.0.1', targetPort, uploadLimitMb: 1 });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    const response = await fetch(`http://127.0.0.1:${proxyPort}/upload`, { method: 'POST', body: Readable.from([Buffer.alloc(1_100_000)]), duplex: 'half' });
    assert.equal(response.status, 413);
    assert.ok(received <= 1024 * 1024);
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('forwards TCP streams', async () => {
  const target = net.createServer((socket) => socket.pipe(socket));
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-tcp-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'TCP test', protocol: 'tcp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'tcp', targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    const reply = await new Promise((resolve, reject) => { const socket = net.createConnection(proxyPort, '127.0.0.1', () => socket.write('ping')); socket.once('data', (chunk) => { resolve(chunk.toString()); socket.destroy(); }); socket.once('error', reject); });
    assert.equal(reply, 'ping');
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('forwards every port in a TCP range', async () => {
  const target = net.createServer((socket) => socket.pipe(socket));
  const targetPort = await listen(target);
  const proxyPort = await freePortRange(2);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-range-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'TCP range', protocols: ['tcp'], listenHost: '127.0.0.1', listenPortStart: proxyPort, listenPortEnd: proxyPort + 1, targetProtocols: ['tcp'], targetHost: '127.0.0.1', targetPortStart: targetPort, targetPortEnd: targetPort });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    for (const port of [proxyPort, proxyPort + 1]) {
      const reply = await new Promise((resolve, reject) => { const socket = net.createConnection(port, '127.0.0.1', () => socket.write(`port-${port}`)); socket.once('data', (chunk) => { resolve(chunk.toString()); socket.destroy(); }); socket.once('error', reject); });
      assert.equal(reply, `port-${port}`);
    }
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('forwards discrete TCP ports with ordered target mapping', async () => {
  const targetA = net.createServer((socket) => socket.once('data', () => socket.end('target-a')));
  const targetB = net.createServer((socket) => socket.once('data', () => socket.end('target-b')));
  const targetPortA = await listen(targetA);
  const targetPortB = await listen(targetB);
  const proxyBase = await freePortRange(3);
  const proxyPorts = [proxyBase, proxyBase + 2];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-list-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'TCP list', protocols: ['tcp'], listenHost: '127.0.0.1', listenPorts: proxyPorts, targetProtocols: ['tcp'], targetHost: '127.0.0.1', targetPorts: [targetPortA, targetPortB] });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    for (const [index, port] of proxyPorts.entries()) {
      const reply = await new Promise((resolve, reject) => { const socket = net.createConnection(port, '127.0.0.1', () => socket.write('ping')); socket.once('data', (chunk) => { resolve(chunk.toString()); socket.destroy(); }); socket.once('error', reject); });
      assert.equal(reply, index === 0 ? 'target-a' : 'target-b');
    }
  } finally {
    await manager.stopAll(); await close(targetA); await close(targetB); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('forwards UDP datagrams', async () => {
  const target = dgram.createSocket('udp4');
  target.on('message', (message, client) => target.send(message, client.port, client.address));
  const targetPort = await new Promise((resolve) => target.bind(0, '127.0.0.1', () => resolve(target.address().port)));
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-udp-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'UDP test', protocol: 'udp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'udp', targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  const client = dgram.createSocket('udp4');
  try {
    await manager.startAll();
    const reply = await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('UDP reply timeout')), 2500); client.once('message', (message) => { clearTimeout(timer); resolve(message.toString()); }); client.send(Buffer.from('datagram'), proxyPort, '127.0.0.1'); });
    assert.equal(reply, 'datagram');
  } finally {
    client.close(); await manager.stopAll(); await new Promise((resolve) => target.close(resolve)); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('forwards TCP streams and UDP datagrams through one TCP+UDP rule on the same numeric port', async () => {
  const targetTcp = net.createServer((client) => client.on('data', (chunk) => client.write(Buffer.concat([Buffer.from('tcp:'), chunk]))));
  const targetPort = await listen(targetTcp);
  const targetUdp = dgram.createSocket('udp4');
  targetUdp.on('message', (message, client) => targetUdp.send(Buffer.concat([Buffer.from('udp:'), message]), client.port, client.address));
  await bindUdp(targetUdp, targetPort);
  const proxyPort = await freeTcpUdpPort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-tcp-udp-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({
    name: 'Universal transport',
    protocols: ['tcp', 'udp'],
    listenHost: '127.0.0.1',
    listenPort: proxyPort,
    targetProtocols: ['tcp', 'udp'],
    targetHost: '127.0.0.1',
    targetPort,
  });
  const manager = new ProxyManager({ store, logger });
  const udpClient = dgram.createSocket('udp4');
  try {
    await manager.startAll();
    const tcpReply = new Promise((resolve, reject) => {
      const client = net.createConnection(proxyPort, '127.0.0.1', () => client.write('stream'));
      client.once('data', (chunk) => { resolve(chunk.toString()); client.destroy(); });
      client.once('error', reject);
    });
    const udpReply = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('UDP reply timeout')), 2500);
      udpClient.once('message', (message) => { clearTimeout(timer); resolve(message.toString()); });
      udpClient.send(Buffer.from('datagram'), proxyPort, '127.0.0.1');
    });
    assert.deepEqual(await Promise.all([tcpReply, udpReply]), ['tcp:stream', 'udp:datagram']);
    const runtime = manager.snapshot().rules[rule.id];
    assert.equal(runtime.state, 'healthy');
    assert.equal(runtime.connections, 2);
    assert.equal(runtime.bytesIn, Buffer.byteLength('stream') + Buffer.byteLength('datagram'));
  } finally {
    await closeUdp(udpClient); await manager.stopAll(); await close(targetTcp); await closeUdp(targetUdp); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reuses a UDP client session for multiple requests and replies, then expires it when idle', async () => {
  const target = dgram.createSocket('udp4');
  const upstreamPorts = [];
  target.on('message', (message, client) => {
    upstreamPorts.push(client.port);
    target.send(Buffer.from(`ack:${message}`), client.port, client.address);
    target.send(Buffer.from(`event:${message}`), client.port, client.address);
  });
  const targetPort = await bindUdp(target);
  const proxyPort = await freeTcpUdpPort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-udp-session-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({ name: 'UDP session', protocol: 'udp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'udp', targetHost: '127.0.0.1', targetPort, timeoutMs: 1000 });
  const manager = new ProxyManager({ store, logger });
  const client = dgram.createSocket('udp4');
  try {
    await manager.startAll();
    const replies = await new Promise((resolve, reject) => {
      const values = [];
      let sentSecond = false;
      const timer = setTimeout(() => reject(new Error('UDP session replies timeout')), 2500);
      client.on('message', (message) => {
        values.push(message.toString());
        if (values.length === 2 && !sentSecond) {
          sentSecond = true;
          client.send(Buffer.from('second'), proxyPort, '127.0.0.1');
        }
        if (values.length === 4) { clearTimeout(timer); resolve(values); }
      });
      client.send(Buffer.from('first'), proxyPort, '127.0.0.1');
    });
    assert.deepEqual(new Set(replies), new Set(['ack:first', 'event:first', 'ack:second', 'event:second']));
    assert.equal(upstreamPorts.length, 2);
    assert.equal(new Set(upstreamPorts).size, 1);
    assert.equal(manager.runtimes.get(rule.id).udpSessions.size, 1);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal(manager.runtimes.get(rule.id).udpSessions.size, 0);
    const runtime = manager.snapshot().rules[rule.id];
    assert.equal(runtime.connections, 2);
    assert.equal(runtime.bytesIn, Buffer.byteLength('first') + Buffer.byteLength('second'));
    assert.equal(runtime.bytesOut, replies.reduce((total, reply) => total + Buffer.byteLength(reply), 0));
  } finally {
    await closeUdp(client); await manager.stopAll(); await closeUdp(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('closes active UDP sessions when the proxy manager stops', async () => {
  const target = dgram.createSocket('udp4');
  target.on('message', (message, client) => target.send(message, client.port, client.address));
  const targetPort = await bindUdp(target);
  const proxyPort = await freeTcpUdpPort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-udp-stop-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({ name: 'UDP stop cleanup', protocol: 'udp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'udp', targetHost: '127.0.0.1', targetPort, timeoutMs: 300000 });
  const manager = new ProxyManager({ store, logger });
  const client = dgram.createSocket('udp4');
  try {
    await manager.startAll();
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('UDP cleanup reply timeout')), 2500);
      client.once('message', () => { clearTimeout(timer); resolve(); });
      client.send(Buffer.from('keep-alive'), proxyPort, '127.0.0.1');
    });
    const runtime = manager.runtimes.get(rule.id);
    assert.equal(runtime.udpSessions.size, 1);
    assert.ok(runtime.datagramSockets.size >= 2);
    await manager.stopAll();
    assert.equal(runtime.udpSessions.size, 0);
    assert.equal(runtime.datagramSockets.size, 0);
  } finally {
    await closeUdp(client); await manager.stopAll(); await closeUdp(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('applies domain policy to WebSocket upgrades', async () => {
  const target = http.createServer();
  target.on('upgrade', (req, socket) => socket.end('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'));
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-ws-policy-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'WS policy', protocols: ['http', 'ws'], listenHost: '127.0.0.1', listenPort: proxyPort, domains: ['allowed.example'], targetProtocols: ['http', 'ws'], targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    const response = await rawRequest(proxyPort, 'GET /socket HTTP/1.1\r\nHost: blocked.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
    assert.match(response, /^HTTP\/1\.1 421 /);
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reload closes active TCP streams instead of hanging', async () => {
  const target = net.createServer(() => {});
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-active-reload-'));
  const store = new ConfigStore(directory); store.load();
  store.createRule({ name: 'Active stream', protocol: 'tcp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'tcp', targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  const client = new net.Socket();
  try {
    await manager.startAll();
    await new Promise((resolve, reject) => { client.once('error', reject); client.connect(proxyPort, '127.0.0.1', resolve); });
    const result = await Promise.race([manager.reload().then(() => 'reloaded'), new Promise((resolve) => setTimeout(() => resolve('timeout'), 1000))]);
    assert.equal(result, 'reloaded');
  } finally {
    client.destroy(); await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('serializes concurrent reloads without leaking listeners', async () => {
  const target = net.createServer((socket) => socket.end());
  const targetPort = await listen(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-concurrent-reload-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({ name: 'Concurrent reload', protocol: 'tcp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'tcp', targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  try {
    await Promise.all([manager.reload(), manager.reload()]);
    assert.equal(manager.snapshot().rules[rule.id].state, 'healthy');
    await manager.stopAll();
    const probe = net.createServer();
    await listen(probe, proxyPort);
    await close(probe);
  } finally {
    await manager.stopAll(); await close(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('uses a UDP-aware health check', async () => {
  const target = dgram.createSocket('udp4');
  const targetPort = await bindUdp(target);
  const proxyPort = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-udp-health-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({ name: 'UDP health', protocol: 'udp', listenHost: '127.0.0.1', listenPort: proxyPort, targetProtocol: 'udp', targetHost: '127.0.0.1', targetPort });
  const manager = new ProxyManager({ store, logger });
  try {
    await manager.startAll();
    const runtime = await manager.checkRule(rule);
    assert.equal(runtime.state, 'healthy');
    assert.match(runtime.message, /UDP/);
  } finally {
    await manager.stopAll(); await closeUdp(target); fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('releases UDP ports when a later endpoint fails to bind', async () => {
  const firstReservation = dgram.createSocket('udp4');
  const firstPort = await bindUdp(firstReservation);
  const occupied = dgram.createSocket('udp4');
  const occupiedPort = await bindUdp(occupied);
  await closeUdp(firstReservation);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-udp-cleanup-'));
  const store = new ConfigStore(directory); store.load();
  const rule = store.createRule({ name: 'UDP partial', protocol: 'udp', listenHost: '127.0.0.1', listenPorts: [firstPort, occupiedPort], targetProtocol: 'udp', targetHost: '127.0.0.1', targetPort: 9 });
  const manager = new ProxyManager({ store, logger });
  const probe = dgram.createSocket('udp4');
  try {
    await manager.startAll();
    assert.equal(manager.snapshot().rules[rule.id].state, 'error');
    await bindUdp(probe, firstPort);
  } finally {
    await closeUdp(probe); await manager.stopAll(); await closeUdp(occupied); fs.rmSync(directory, { recursive: true, force: true });
  }
});
