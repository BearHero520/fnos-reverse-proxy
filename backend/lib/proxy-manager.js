import dgram from 'node:dgram';
import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import { Transform } from 'node:stream';
import tls from 'node:tls';
import httpProxy from 'http-proxy';
import { isRuleScheduleOpen, listenPortsFor, sourceGroups, targetPortFor, targetPortsFor, targetProtocolFor } from './config-store.js';

const normalizeIp = (value = '') => String(value).replace(/^::ffff:/, '').split('%')[0];
const urlHost = (host) => net.isIP(String(host).replace(/^\[|\]$/g, '')) === 6 ? `[${String(host).replace(/^\[|\]$/g, '')}]` : host;
const targetUrl = (rule) => `${rule.targetProtocol === 'https' ? 'https' : 'http'}://${urlHost(rule.targetHost)}:${rule.targetPort}`;
const MAX_UDP_UPSTREAMS_PER_RULE = 1024;
const MAX_PENDING_UDP_DATAGRAMS_PER_SESSION = 64;

function certificateStateMessage(state) {
  if (!state?.exists || state.status === 'missing') return '选择的 HTTPS 证书不存在';
  if (state.status === 'expired') return '选择的 HTTPS 证书已过期';
  if (state.status === 'not-yet-valid') return '选择的 HTTPS 证书尚未生效';
  if (state.lastError) return `选择的 HTTPS 证书暂不可刷新：${state.lastError}`;
  return '选择的 HTTPS 证书当前不可用';
}

function certificateOptions(store, certificateId) {
  const state = store.certificateState(certificateId);
  if (!state.available) throw new Error(certificateStateMessage(state));
  const certificate = store.certificate(certificateId);
  if (!certificate) throw new Error('选择的 HTTPS 证书不存在');
  const cert = certificate.certificatePem || (certificate.certPath ? fs.readFileSync(certificate.certPath) : null);
  const key = certificate.privateKey || certificate.privateKeyPem || (certificate.keyPath ? fs.readFileSync(certificate.keyPath) : null);
  if (!cert || !key) throw new Error('选择的 HTTPS 证书材料不可用');
  const options = { cert, key };
  tls.createSecureContext(options);
  return { options, state };
}

function addToBlockList(blockList, entry) {
  const value = String(entry || '').trim();
  if (!value) return true;
  try {
    if (value.includes('/')) {
      const [address, prefixText] = value.split('/');
      const type = net.isIP(address) === 6 ? 'ipv6' : 'ipv4';
      blockList.addSubnet(address, Number(prefixText), type);
    } else {
      const type = net.isIP(value) === 6 ? 'ipv6' : 'ipv4';
      blockList.addAddress(value, type);
    }
    return true;
  } catch {
    return false;
  }
}

function accessGuard(rule) {
  const allow = new net.BlockList();
  const block = new net.BlockList();
  const invalid = [];
  for (const entry of rule.allowIps) if (!addToBlockList(allow, entry)) invalid.push(entry);
  for (const entry of rule.blockIps) if (!addToBlockList(block, entry)) invalid.push(entry);
  if (invalid.length) throw new Error(`IP 或 CIDR 配置无效：${invalid.join(', ')}`);
  return (address) => {
    const ip = normalizeIp(address);
    const family = net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
    if (block.check(ip, family)) return false;
    return rule.allowIps.length === 0 || allow.check(ip, family);
  };
}

function waitForListen(server, port, host) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { server.off('listening', onListen); reject(error); };
    const onListen = () => { server.off('error', onError); resolve(); };
    server.once('error', onError);
    server.once('listening', onListen);
    server.listen(port, host);
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    let settled = false;
    const done = () => { if (!settled) { settled = true; clearTimeout(timer); resolve(); } };
    const timer = setTimeout(done, 1000);
    timer.unref?.();
    try {
      server.close(done);
      server.closeAllConnections?.();
    } catch { done(); }
  });
}

function closeDatagram(socket) {
  return new Promise((resolve) => {
    if (!socket) return resolve();
    try { socket.close(resolve); } catch { resolve(); }
  });
}

function trackStream(runtime, socket) {
  runtime.sockets.add(socket);
  socket.once('close', () => runtime.sockets.delete(socket));
  return socket;
}

function trackServer(runtime, server) {
  server.on('connection', (socket) => trackStream(runtime, socket));
  return server;
}

function requestHostname(request) {
  const host = String(request.headers.host || '').trim();
  if (!host) return '';
  if (host.startsWith('[')) return host.slice(1, host.indexOf(']')).toLowerCase().replace(/\.$/, '');
  return host.replace(/:\d+$/, '').toLowerCase().replace(/\.$/, '');
}

function domainAllowed(rule, request) {
  if (!rule.domains.length) return true;
  const host = requestHostname(request);
  return rule.domains.some((domain) => domain.startsWith('*.') ? host.endsWith(domain.slice(1)) : host === domain.replace(/\.$/, ''));
}

function rejectUpgrade(socket, status, message, headers = {}) {
  const body = Buffer.from(message, 'utf8');
  const lines = [
    `HTTP/1.1 ${status}`,
    'Connection: close',
    'Content-Type: text/plain; charset=utf-8',
    `Content-Length: ${body.length}`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    '',
  ];
  socket.end(Buffer.concat([Buffer.from(lines.join('\r\n'), 'utf8'), body]));
}

function unmatchedSettings(store) {
  return store.settings().unmatchedHost || { action: 'reject', statusCode: 404, redirectUrl: '', targetUrl: '' };
}

function handleUnmatchedHttp(store, proxy, request, response) {
  const settings = unmatchedSettings(store);
  if (settings.action === 'drop') {
    request.socket.destroy();
    return;
  }
  if (settings.action === 'redirect') {
    const location = new URL(request.url || '/', settings.redirectUrl).toString();
    response.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
    response.end();
    return;
  }
  if (settings.action === 'proxy') {
    proxy.web(request, response, { target: settings.targetUrl, changeOrigin: true });
    return;
  }
  response.writeHead(settings.statusCode || 404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end('没有匹配此域名的代理规则');
}

function handleUnmatchedUpgrade(store, proxy, request, socket, head) {
  const settings = unmatchedSettings(store);
  if (settings.action === 'drop') {
    socket.destroy();
    return;
  }
  if (settings.action === 'redirect') {
    const location = new URL(request.url || '/', settings.redirectUrl).toString();
    rejectUpgrade(socket, '302 Found', '请求已重定向', { Location: location, 'Cache-Control': 'no-store' });
    return;
  }
  if (settings.action === 'proxy') {
    proxy.ws(request, socket, head, { target: settings.targetUrl, changeOrigin: true });
    return;
  }
  rejectUpgrade(socket, `${settings.statusCode || 404} Not Found`, '没有匹配此域名的代理规则', { 'Cache-Control': 'no-store' });
}

function probeTcp(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let socket;
    let settled = false;
    const finish = (ok, message = '') => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      resolve({ ok, message });
    };
    try { socket = net.createConnection({ host, port }); }
    catch (error) { finish(false, error.code || error.message); return; }
    socket.setTimeout(timeoutMs, () => finish(false, '目标连接超时'));
    socket.once('connect', () => finish(true));
    socket.once('error', (error) => finish(false, error.code || error.message));
  });
}

function lookupWithTimeout(host, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => finish(reject, new Error('目标解析超时')), timeoutMs);
    timer.unref?.();
    lookup(host).then((result) => finish(resolve, result), (error) => finish(reject, error));
  });
}

async function probeUdp(host, port, timeoutMs) {
  let socket;
  try {
    const literalFamily = net.isIP(host);
    const resolved = literalFamily ? { address: host, family: literalFamily } : await lookupWithTimeout(host, timeoutMs);
    socket = dgram.createSocket(resolved.family === 6 ? 'udp6' : 'udp4');
    return await new Promise((resolve) => {
      let settled = false;
      const finish = (ok, message = '') => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        void closeDatagram(socket);
        resolve({ ok, message });
      };
      const timer = setTimeout(() => finish(false, '目标连接超时'), timeoutMs);
      timer.unref?.();
      socket.once('error', (error) => finish(false, error.code || error.message));
      socket.connect(port, resolved.address, () => finish(true));
    });
  } catch (error) {
    if (socket) await closeDatagram(socket);
    return { ok: false, message: error.code || error.message };
  }
}

async function probeEndpoints(endpoints, timeoutMs) {
  const width = 16;
  for (let index = 0; index < endpoints.length; index += width) {
    const batch = endpoints.slice(index, index + width);
    const results = await Promise.all(batch.map(async (endpoint) => ({
      ...endpoint,
      result: endpoint.transport === 'udp'
        ? await probeUdp(endpoint.host, endpoint.port, timeoutMs)
        : await probeTcp(endpoint.host, endpoint.port, timeoutMs),
    })));
    const failed = results.find((item) => !item.result.ok);
    if (failed) return { ok: false, message: `${failed.transport.toUpperCase()} ${failed.host}:${failed.port} ${failed.result.message}` };
  }
  return { ok: true, message: endpoints.some((endpoint) => endpoint.transport === 'udp') ? '运行正常（UDP 已校验地址与路由）' : '运行正常' };
}

const metricFields = ['requests', 'connections', 'bytesIn', 'bytesOut', 'errors', 'lastActivityAt', 'lastSuccessAt', 'lastErrorAt', 'lastError'];

function runtimeFor(rule, seed = null) {
  const preserved = Object.fromEntries(metricFields.map((field) => [field, seed?.[field] ?? (field.startsWith('last') ? null : 0)]));
  return {
    ruleId: rule.id,
    state: 'starting',
    message: '正在加载',
    startedAt: null,
    lastCheckAt: null,
    latencyMs: null,
    requests: preserved.requests,
    connections: preserved.connections,
    activeConnections: 0,
    bytesIn: preserved.bytesIn,
    bytesOut: preserved.bytesOut,
    errors: preserved.errors,
    lastActivityAt: preserved.lastActivityAt,
    lastSuccessAt: preserved.lastSuccessAt,
    lastErrorAt: preserved.lastErrorAt,
    lastError: preserved.lastError,
    recentEvents: Array.isArray(seed?.recentEvents) ? seed.recentEvents.slice(0, 30) : [],
    clients: new Map(),
    servers: [],
    closers: [],
    sockets: new Set(),
    datagramSockets: new Set(),
    udpSessions: new Map(),
    tlsBindings: [],
    tlsError: null,
  };
}

function recordEvent(runtime, type, message, meta = {}) {
  const event = { id: randomUUID(), at: Date.now(), type, message, ...meta };
  runtime.recentEvents.unshift(event);
  runtime.recentEvents = runtime.recentEvents.slice(0, 30);
  runtime.lastActivityAt = event.at;
  if (type === 'success') runtime.lastSuccessAt = event.at;
  if (type === 'error') {
    runtime.lastErrorAt = event.at;
    runtime.lastError = message;
  }
  return event;
}

function touchClient(runtime, address, protocol, delta = 0) {
  const normalized = normalizeIp(address) || 'unknown';
  const key = `${protocol}:${normalized}`;
  const current = runtime.clients.get(key) || { address: normalized, protocol, active: 0, connections: 0, lastSeenAt: null };
  if (delta > 0) current.connections += delta;
  current.active = Math.max(0, current.active + delta);
  current.lastSeenAt = Date.now();
  runtime.clients.set(key, current);
  if (runtime.clients.size > 80) {
    const oldest = [...runtime.clients.entries()].sort((left, right) => left[1].lastSeenAt - right[1].lastSeenAt).slice(0, runtime.clients.size - 80);
    for (const [oldestKey] of oldest) runtime.clients.delete(oldestKey);
  }
  return () => {
    const latest = runtime.clients.get(key);
    if (!latest) return;
    latest.active = Math.max(0, latest.active - 1);
    latest.lastSeenAt = Date.now();
  };
}

function requestIdFor(request) {
  const provided = String(request.headers['x-request-id'] || '').trim();
  return provided && provided.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(provided) ? provided : randomUUID();
}

export class ProxyManager {
  constructor({ store, logger, demoMode = false, notifier = null }) {
    this.store = store;
    this.logger = logger;
    this.demoMode = demoMode;
    this.notifier = notifier;
    this.runtimes = new Map();
    this.healthTimer = null;
    this.lifecycle = Promise.resolve();
  }

  runLifecycle(operation) {
    const pending = this.lifecycle.then(operation, operation);
    this.lifecycle = pending.catch(() => {});
    return pending;
  }

  async startAllNow() {
    const seeds = new Map([...this.runtimes.entries()].map(([id, runtime]) => [id, runtime]));
    await this.stopAllNow();
    const failures = [];
    for (const rule of this.store.rules()) {
      if (rule.enabled) {
        const runtime = await this.startRule(rule, seeds.get(rule.id));
        if (runtime.state === 'error') failures.push({ ruleId: rule.id, rule: rule.name, message: runtime.message });
      }
      else this.runtimes.set(rule.id, { ...runtimeFor(rule, seeds.get(rule.id)), state: 'disabled', message: '已停用' });
    }
    this.scheduleHealthChecks();
    return { ok: failures.length === 0, failures, runtime: this.snapshot() };
  }

  startAll() { return this.runLifecycle(() => this.startAllNow()); }

  reload() { return this.startAll(); }

  async reloadTlsCertificatesNow(certificateIds = null) {
    const selectedIds = certificateIds ? new Set(certificateIds) : null;
    const results = [];
    const failures = [];
    const rules = this.store.rules().filter((rule) => rule.enabled
      && rule.tls?.certId
      && rule.protocols.some((protocol) => protocol === 'https' || protocol === 'wss')
      && (!selectedIds || selectedIds.has(rule.tls.certId)));

    for (const rule of rules) {
      let runtime = this.runtimes.get(rule.id);
      const bindings = runtime?.tlsBindings || [];
      try {
        const state = this.store.certificateState(rule.tls.certId);
        if (state.stale) throw new Error(state.lastError || '系统证书刷新失败，当前为上一份可用版本');
        const { options } = certificateOptions(this.store, rule.tls.certId);
        if (!bindings.length) {
          if (runtime) await this.closeRuntime(runtime);
           runtime = await this.startRule(rule, runtime);
          if (runtime.state === 'error') throw new Error(runtime.message);
          results.push({ ruleId: rule.id, rule: rule.name, certificateId: rule.tls.certId, action: 'started' });
          continue;
        }
        for (const binding of bindings) binding.server.setSecureContext(options);
        const hadTlsError = Boolean(runtime.tlsError);
        runtime.tlsError = null;
        if (hadTlsError && runtime.state === 'warning') {
          runtime.state = 'healthy';
          runtime.message = '运行正常';
        }
        results.push({ ruleId: rule.id, rule: rule.name, certificateId: rule.tls.certId, action: 'updated' });
      } catch (error) {
        const retainedContext = bindings.length > 0;
        if (runtime) {
          runtime.tlsError = error.message;
          runtime.errors += 1;
          recordEvent(runtime, 'error', `证书热更新失败：${error.message}`, { protocol: 'tls' });
          runtime.state = retainedContext ? 'warning' : 'error';
          runtime.message = retainedContext
            ? `证书更新失败，继续使用上一 TLS 上下文：${error.message}`
            : `证书加载失败：${error.message}`;
        }
        const failure = { ruleId: rule.id, rule: rule.name, certificateId: rule.tls.certId, message: error.message, retainedContext };
        failures.push(failure);
        this.logger.warn('HTTPS / WSS 证书热更新失败', failure);
      }
    }
    return {
      ok: failures.length === 0,
      updated: results.length,
      message: failures.length
        ? `${failures.length} 条 HTTPS / WSS 规则未能应用新证书`
        : results.length ? `${results.length} 条 HTTPS / WSS 规则已热更新` : '没有需要更新的 HTTPS / WSS 规则',
      results,
      failures,
      runtime: this.snapshot(),
    };
  }

  reloadTlsCertificates(certificateIds = null) {
    return this.runLifecycle(() => this.reloadTlsCertificatesNow(certificateIds));
  }

  scheduleHealthChecks() {
    clearInterval(this.healthTimer);
    const seconds = this.store.settings().healthCheckInterval || 30;
    this.healthTimer = setInterval(() => void this.checkAll(), seconds * 1000);
    this.healthTimer.unref?.();
    void this.checkAll();
  }

  async closeRuntime(runtime) {
    const closingServers = (runtime.servers || []).map((server) => closeServer(server));
    for (const socket of runtime.sockets || []) {
      try { socket.destroy(); } catch {}
    }
    const udpSessions = [...(runtime.udpSessions?.values() || [])];
    const sessionSockets = new Set(udpSessions.map((session) => session.socket));
    const closingSessions = udpSessions.map((session) => session.close());
    const closingDatagrams = [...(runtime.datagramSockets || [])].filter((socket) => !sessionSockets.has(socket)).map((socket) => closeDatagram(socket));
    const customClosers = (runtime.closers || []).map((closer) => Promise.resolve().then(closer).catch(() => {}));
    await Promise.allSettled([...closingServers, ...closingSessions, ...closingDatagrams, ...customClosers]);
    runtime.servers = [];
    runtime.closers = [];
    runtime.sockets?.clear();
    runtime.datagramSockets?.clear();
    runtime.udpSessions?.clear();
    runtime.tlsBindings = [];
  }

  async stopAllNow() {
    clearInterval(this.healthTimer);
    this.healthTimer = null;
    await Promise.allSettled([...this.runtimes.values()].map((runtime) => this.closeRuntime(runtime)));
    this.runtimes.clear();
  }

  stopAll() { return this.runLifecycle(() => this.stopAllNow()); }

  async startRule(rule, seed = null) {
    const runtime = runtimeFor(rule, seed);
    this.runtimes.set(rule.id, runtime);
    if (this.demoMode) {
      runtime.state = isRuleScheduleOpen(rule) ? 'healthy' : 'scheduled';
      runtime.message = runtime.state === 'scheduled' ? '当前不在计划运行时段' : '运行正常';
      runtime.startedAt = Date.now();
      runtime.latencyMs = rule.protocols.includes('tcp') ? 12 : 7;
      runtime.connections = Math.max(runtime.connections, rule.protocols.includes('udp') && rule.protocols.includes('tcp') ? 28 : rule.protocols.some((protocol) => protocol === 'http' || protocol === 'ws') ? 146 : 9);
      runtime.requests = Math.max(runtime.requests, rule.protocols.some((protocol) => protocol === 'http' || protocol === 'ws' || protocol === 'https' || protocol === 'wss') ? 483 : 0);
      runtime.bytesIn = Math.max(runtime.bytesIn, runtime.connections * 9234);
      runtime.bytesOut = Math.max(runtime.bytesOut, runtime.connections * 18240);
      runtime.lastActivityAt ||= Date.now() - 45_000;
      runtime.lastSuccessAt ||= Date.now() - 45_000;
      if (!runtime.recentEvents.length) runtime.recentEvents = [{ id: randomUUID(), at: runtime.lastSuccessAt, type: 'success', message: '目标连接成功', client: '192.168.50.24', protocol: rule.protocols[0], traceId: rule.protocols.some((protocol) => ['http', 'ws', 'https', 'wss'].includes(protocol)) ? randomUUID() : undefined }];
      return runtime;
    }
    try {
      for (const sourceProtocol of sourceGroups(rule.protocols)) {
        const targetProtocol = targetProtocolFor(sourceProtocol, rule.targetProtocols);
        for (const listenPort of listenPortsFor(rule)) {
          const endpointRule = { ...rule, protocol: sourceProtocol, targetProtocol, listenPort, targetPort: targetPortFor(rule, listenPort) };
          if (sourceProtocol === 'http' || sourceProtocol === 'https') await this.startHttp(endpointRule, runtime);
          if (sourceProtocol === 'tcp') await this.startTcp(endpointRule, runtime);
          if (sourceProtocol === 'udp') await this.startUdp(endpointRule, runtime);
        }
      }
      runtime.state = isRuleScheduleOpen(rule) ? 'healthy' : 'scheduled';
      runtime.message = runtime.state === 'scheduled' ? '当前不在计划运行时段' : '运行正常';
      runtime.startedAt = Date.now();
      this.logger.info('代理规则已启动', { ruleId: rule.id, rule: rule.name, listen: `${rule.listenHost}:${listenPortsFor(rule).join(',')}`, protocols: rule.protocols });
    } catch (error) {
      runtime.state = 'error';
      runtime.message = error.code === 'EADDRINUSE' ? '监听端口已被占用' : error.message;
      runtime.errors += 1;
      recordEvent(runtime, 'error', `规则启动失败：${runtime.message}`, { protocol: rule.protocols.join('+') });
      this.logger.error('代理规则启动失败', { ruleId: rule.id, rule: rule.name, error: error.message, code: error.code });
      void this.notifier?.send('rule.error', { ruleId: rule.id, rule: rule.name, state: runtime.state, message: runtime.message });
      await this.closeRuntime(runtime);
    }
    return runtime;
  }

  async startHttp(rule, runtime) {
    const allowed = accessGuard(rule);
    const outboundRequests = new WeakMap();
    const requestIds = new WeakMap();
    const rejectedUploads = new WeakSet();
    const proxy = httpProxy.createProxyServer({
      target: targetUrl(rule),
      ws: true,
      xfwd: rule.realIp.enabled,
      changeOrigin: !rule.preserveHost,
      secure: rule.rejectUnauthorized,
      proxyTimeout: rule.timeoutMs,
      timeout: rule.timeoutMs,
    });
    proxy.on('proxyReq', (proxyReq, request) => {
      outboundRequests.set(request, proxyReq);
      if (rejectedUploads.has(request)) { proxyReq.destroy(); return; }
      try {
        for (const [name, value] of Object.entries(rule.customHeaders)) proxyReq.setHeader(name, value);
        proxyReq.setHeader('X-Request-ID', requestIds.get(request) || requestIdFor(request));
        if (rule.realIp.enabled && rule.realIp.header) proxyReq.setHeader(rule.realIp.header, normalizeIp(request.socket.remoteAddress));
      } catch (error) {
        this.logger.error('请求头配置无效', { ruleId: rule.id, error: error.message });
        proxyReq.destroy(error);
      }
    });
    proxy.on('proxyRes', (proxyRes, request, response) => {
      if (rule.hsts && rule.protocol === 'https') proxyRes.headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
      const traceId = requestIds.get(request);
      if (traceId && response && !response.headersSent) response.setHeader('X-Request-ID', traceId);
    });
    proxy.on('error', (error, req, res) => {
      runtime.errors += 1;
      const traceId = requestIds.get(req);
      recordEvent(runtime, 'error', `HTTP 转发失败：${error.message}`, { client: normalizeIp(req?.socket?.remoteAddress), protocol: rule.protocol, traceId });
      this.logger.warn('HTTP 转发失败', { ruleId: rule.id, error: error.message, traceId });
      if (rejectedUploads.has(req)) {
        if (res && typeof res.writeHead === 'function' && !res.headersSent) res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
        if (res && typeof res.end === 'function' && !res.writableEnded) res.end(JSON.stringify({ error: '请求体超过规则限制' }));
        return;
      }
      if (res && typeof res.writeHead === 'function') {
        if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        if (!res.writableEnded) res.end(JSON.stringify({ error: '目标服务暂时不可用' }));
      } else if (res && typeof res.end === 'function' && !res.destroyed) {
        rejectUpgrade(res, '502 Bad Gateway', '目标服务暂时不可用');
      }
    });
    const handler = (req, res) => {
      const traceId = requestIdFor(req);
      requestIds.set(req, traceId);
      req.headers['x-request-id'] = traceId;
      res.setHeader('X-Request-ID', traceId);
      if (!isRuleScheduleOpen(rule)) { res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '60' }); res.end('代理规则当前处于计划暂停时段'); return; }
      const remote = req.socket.remoteAddress;
      if (!allowed(remote)) { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('访问被代理规则拒绝'); return; }
      if (!domainAllowed(rule, req)) { handleUnmatchedHttp(this.store, proxy, req, res); return; }
      const requiredProtocol = rule.protocol === 'https' ? 'https' : 'http';
      if (!rule.protocols.includes(requiredProtocol)) { res.writeHead(426, { 'Content-Type': 'text/plain; charset=utf-8', Upgrade: 'websocket' }); res.end('此入口仅允许 WebSocket 升级'); return; }
      if (rule.forceHttps && rule.protocol === 'http') {
        const host = String(req.headers.host || '').replace(/:\d+$/, '');
        res.writeHead(308, { Location: `https://${host}${req.url}` }); res.end(); return;
      }
      const contentLength = Number(req.headers['content-length'] || 0);
      if (rule.uploadLimitMb > 0 && contentLength > rule.uploadLimitMb * 1024 * 1024) {
        res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify({ error: '请求体超过规则限制' })); return;
      }
      runtime.requests += 1;
      runtime.connections += 1;
      runtime.activeConnections += 1;
      runtime.bytesIn += contentLength;
      const releaseClient = touchClient(runtime, remote, rule.protocol, 1);
      recordEvent(runtime, 'activity', `${req.method} ${req.url}`, { client: normalizeIp(remote), protocol: rule.protocol, traceId });
      let released = false;
      const finish = () => {
        if (released) return;
        released = true;
        releaseClient();
        runtime.activeConnections = Math.max(0, runtime.activeConnections - 1);
        runtime.bytesOut += Number(res.getHeader('content-length') || 0);
        if (res.statusCode < 500) recordEvent(runtime, 'success', `HTTP ${res.statusCode} ${req.method} ${req.url}`, { client: normalizeIp(remote), protocol: rule.protocol, traceId });
      };
      res.once('finish', finish);
      res.once('close', finish);
      if (rule.uploadLimitMb > 0) {
        const limitBytes = rule.uploadLimitMb * 1024 * 1024;
        let received = 0;
        const rejectUpload = () => {
          rejectedUploads.add(req);
          if (!res.headersSent) res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
          if (!res.writableEnded) res.end(JSON.stringify({ error: '请求体超过规则限制' }));
        };
        const limiter = new Transform({
          transform(chunk, encoding, callback) {
            received += chunk.length;
            if (received > limitBytes) { rejectUpload(); callback(Object.assign(new Error('请求体超过规则限制'), { code: 'UPLOAD_LIMIT' })); }
            else callback(null, chunk);
          },
        });
        limiter.once('error', () => {
          rejectUpload();
          req.unpipe(limiter);
          req.resume();
          limiter.unpipe();
          outboundRequests.get(req)?.destroy();
        });
        proxy.web(req, res, { buffer: limiter });
        req.pipe(limiter);
      } else {
        proxy.web(req, res);
      }
    };
    let server;
    if (rule.protocol === 'https') {
      const { options } = certificateOptions(this.store, rule.tls.certId);
      server = https.createServer(options, handler);
    } else {
      server = http.createServer(handler);
    }
    trackServer(runtime, server);
    server.on('upgrade', (req, socket, head) => {
      const traceId = requestIdFor(req);
      requestIds.set(req, traceId);
      req.headers['x-request-id'] = traceId;
      if (!isRuleScheduleOpen(rule)) { rejectUpgrade(socket, '503 Service Unavailable', '代理规则当前处于计划暂停时段', { 'Retry-After': '60' }); return; }
      if (!allowed(req.socket.remoteAddress)) { rejectUpgrade(socket, '403 Forbidden', '访问被代理规则拒绝'); return; }
      if (!domainAllowed(rule, req)) { handleUnmatchedUpgrade(this.store, proxy, req, socket, head); return; }
      const requiredProtocol = rule.protocol === 'https' ? 'wss' : 'ws';
      if (!rule.protocols.includes(requiredProtocol)) { rejectUpgrade(socket, '426 Upgrade Required', '此入口未启用 WebSocket'); return; }
      if (rule.forceHttps && rule.protocol === 'http') {
        const host = String(req.headers.host || '').replace(/:\d+$/, '');
        rejectUpgrade(socket, '308 Permanent Redirect', '请使用 WSS 安全连接', { Location: `https://${host}${req.url}` });
        return;
      }
      runtime.connections += 1;
      runtime.activeConnections += 1;
      const releaseClient = touchClient(runtime, req.socket.remoteAddress, rule.protocol === 'https' ? 'wss' : 'ws', 1);
      recordEvent(runtime, 'activity', `WebSocket ${req.url}`, { client: normalizeIp(req.socket.remoteAddress), protocol: rule.protocol === 'https' ? 'wss' : 'ws', traceId });
      socket.on('close', () => { runtime.activeConnections = Math.max(0, runtime.activeConnections - 1); releaseClient(); });
      proxy.ws(req, socket, head);
    });
    await waitForListen(server, rule.listenPort, rule.listenHost);
    runtime.servers.push(server);
    if (rule.protocol === 'https') runtime.tlsBindings.push({ server, certificateId: rule.tls.certId, listenPort: rule.listenPort });
  }

  async startTcp(rule, runtime) {
    const allowed = accessGuard(rule);
    const server = net.createServer((client) => {
      if (!isRuleScheduleOpen(rule)) { client.destroy(); return; }
      if (!allowed(client.remoteAddress)) { client.destroy(); return; }
      runtime.connections += 1;
      runtime.activeConnections += 1;
      const releaseClient = touchClient(runtime, client.remoteAddress, 'tcp', 1);
      recordEvent(runtime, 'activity', `TCP 连接 ${normalizeIp(client.remoteAddress)}`, { client: normalizeIp(client.remoteAddress), protocol: 'tcp' });
      const upstream = trackStream(runtime, net.createConnection({ host: rule.targetHost, port: rule.targetPort }));
      client.setTimeout(rule.timeoutMs, () => client.destroy());
      upstream.setTimeout(rule.timeoutMs, () => upstream.destroy());
      client.on('data', (chunk) => { runtime.bytesIn += chunk.length; });
      upstream.on('data', (chunk) => { runtime.bytesOut += chunk.length; });
      upstream.once('connect', () => recordEvent(runtime, 'success', `TCP 已连接目标 ${rule.targetHost}:${rule.targetPort}`, { client: normalizeIp(client.remoteAddress), protocol: 'tcp' }));
      upstream.on('error', (error) => { runtime.errors += 1; recordEvent(runtime, 'error', `TCP 目标连接失败：${error.message}`, { client: normalizeIp(client.remoteAddress), protocol: 'tcp' }); this.logger.warn('TCP 目标连接失败', { ruleId: rule.id, error: error.message }); client.destroy(); });
      client.on('error', () => {});
      client.on('close', () => { runtime.activeConnections = Math.max(0, runtime.activeConnections - 1); releaseClient(); upstream.destroy(); });
      client.pipe(upstream).pipe(client);
    });
    trackServer(runtime, server);
    await waitForListen(server, rule.listenPort, rule.listenHost);
    runtime.servers.push(server);
  }

  async startUdp(rule, runtime) {
    const allowed = accessGuard(rule);
    const socket = dgram.createSocket(net.isIP(rule.listenHost) === 6 ? 'udp6' : 'udp4');
    const listenerId = `${rule.listenHost}:${rule.listenPort}`;
    const sessionKeyFor = (client) => JSON.stringify([
      listenerId,
      client.family,
      normalizeIp(client.address),
      client.port,
      rule.targetHost,
      rule.targetPort,
    ]);
    const touchSession = (session) => {
      clearTimeout(session.timer);
      session.timer = setTimeout(() => { void session.close(); }, rule.timeoutMs);
      session.timer.unref?.();
    };
    const createSession = (client, key) => {
      const upstream = dgram.createSocket(net.isIP(rule.targetHost) === 6 ? 'udp6' : 'udp4');
      let closed = false;
      let closePromise = null;
      let connected = false;
      let pending = [];
      runtime.activeConnections += 1;
      const releaseClient = touchClient(runtime, client.address, 'udp', 1);
      recordEvent(runtime, 'activity', `UDP 会话 ${normalizeIp(client.address)}:${client.port}`, { client: normalizeIp(client.address), protocol: 'udp' });
      const session = {
        socket: upstream,
        timer: null,
        close: () => {
          if (closePromise) return closePromise;
          closed = true;
          clearTimeout(session.timer);
          pending = [];
          closePromise = closeDatagram(upstream).finally(() => {
            if (runtime.udpSessions.get(key) === session) runtime.udpSessions.delete(key);
            runtime.datagramSockets.delete(upstream);
            runtime.activeConnections = Math.max(0, runtime.activeConnections - 1);
            releaseClient();
          });
          return closePromise;
        },
        send: (message) => {
          if (closed) return;
          touchSession(session);
          if (!connected) {
            if (pending.length >= MAX_PENDING_UDP_DATAGRAMS_PER_SESSION) {
              runtime.errors += 1;
              recordEvent(runtime, 'error', 'UDP 会话等待队列已满', { client: normalizeIp(client.address), protocol: 'udp' });
              this.logger.warn('UDP 会话等待队列已满', { ruleId: rule.id, client: `${client.address}:${client.port}`, limit: MAX_PENDING_UDP_DATAGRAMS_PER_SESSION });
              return;
            }
            pending.push(Buffer.from(message));
            return;
          }
          upstream.send(message, (error) => {
            if (!error || closed) return;
            runtime.errors += 1;
            recordEvent(runtime, 'error', `UDP 数据报发送失败：${error.message}`, { client: normalizeIp(client.address), protocol: 'udp' });
            this.logger.warn('UDP 数据报发送失败', { ruleId: rule.id, error: error.message });
            void session.close();
          });
        },
      };
      const failSession = (message, error) => {
        if (closed) return;
        runtime.errors += 1;
        recordEvent(runtime, 'error', `${message}：${error.message}`, { client: normalizeIp(client.address), protocol: 'udp' });
        this.logger.warn(message, { ruleId: rule.id, error: error.message });
        void session.close();
      };
      runtime.udpSessions.set(key, session);
      runtime.datagramSockets.add(upstream);
      upstream.once('close', () => {
        runtime.datagramSockets.delete(upstream);
        if (runtime.udpSessions.get(key) === session) runtime.udpSessions.delete(key);
        if (!closed) {
          closed = true;
          clearTimeout(session.timer);
          pending = [];
        }
      });
      upstream.once('error', (error) => failSession('UDP 目标连接失败', error));
      upstream.on('message', (reply) => {
        if (closed) return;
        touchSession(session);
        runtime.bytesOut += reply.length;
        recordEvent(runtime, 'success', `UDP 收到目标回复（${reply.length} B）`, { client: normalizeIp(client.address), protocol: 'udp' });
        try {
          socket.send(reply, client.port, client.address, (error) => {
            if (!error || closed) return;
            runtime.errors += 1;
            recordEvent(runtime, 'error', `UDP 回复发送失败：${error.message}`, { client: normalizeIp(client.address), protocol: 'udp' });
            this.logger.warn('UDP 回复发送失败', { ruleId: rule.id, error: error.message });
            void session.close();
          });
        } catch (error) {
          failSession('UDP 回复发送失败', error);
        }
      });
      touchSession(session);
      try {
        upstream.connect(rule.targetPort, rule.targetHost, () => {
          if (closed) return;
          connected = true;
          const queued = pending;
          pending = [];
          for (const message of queued) session.send(message);
        });
      } catch (error) {
        failSession('UDP 目标连接失败', error);
        return null;
      }
      return session;
    };
    runtime.datagramSockets.add(socket);
    socket.once('close', () => runtime.datagramSockets.delete(socket));
    socket.on('message', (message, client) => {
      if (!isRuleScheduleOpen(rule)) return;
      if (!allowed(client.address)) return;
      const key = sessionKeyFor(client);
      let session = runtime.udpSessions.get(key);
      if (!session && runtime.udpSessions.size >= MAX_UDP_UPSTREAMS_PER_RULE) {
        runtime.errors += 1;
        recordEvent(runtime, 'error', 'UDP 转发资源已达上限', { client: normalizeIp(client.address), protocol: 'udp' });
        this.logger.warn('UDP 转发资源已达上限', { ruleId: rule.id, limit: MAX_UDP_UPSTREAMS_PER_RULE });
        return;
      }
      if (!session) session = createSession(client, key);
      if (!session) return;
      runtime.connections += 1;
      runtime.bytesIn += message.length;
      runtime.lastActivityAt = Date.now();
      session.send(message);
    });
    socket.on('error', (error) => { runtime.errors += 1; recordEvent(runtime, 'error', `UDP 监听异常：${error.message}`, { protocol: 'udp' }); this.logger.warn('UDP 监听异常', { ruleId: rule.id, error: error.message }); });
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.bind(rule.listenPort, rule.listenHost, () => { socket.off('error', reject); resolve(); });
    });
  }

  async checkRule(rule) {
    const runtime = this.runtimes.get(rule.id);
    if (!rule.enabled || !runtime || runtime.state === 'error') return runtime;
    if (!isRuleScheduleOpen(rule)) {
      runtime.lastCheckAt = Date.now();
      runtime.state = 'scheduled';
      runtime.message = '当前不在计划运行时段';
      return runtime;
    }
    if (this.demoMode) {
      runtime.lastCheckAt = Date.now();
      runtime.state = 'healthy';
      runtime.message = '运行正常';
      return runtime;
    }
    const started = performance.now();
    const endpoints = [];
    const seen = new Set();
    for (const sourceProtocol of sourceGroups(rule.protocols)) {
      const targetProtocol = targetProtocolFor(sourceProtocol, rule.targetProtocols);
      const transport = targetProtocol === 'udp' ? 'udp' : 'tcp';
      for (const port of targetPortsFor(rule)) {
        const key = `${transport}:${rule.targetHost}:${port}`;
        if (!seen.has(key)) { seen.add(key); endpoints.push({ transport, host: rule.targetHost, port }); }
      }
    }
    const result = await probeEndpoints(endpoints, Math.min(rule.timeoutMs, 5000));
    const previousState = runtime.state;
    runtime.lastCheckAt = Date.now();
    runtime.latencyMs = Math.max(1, Math.round(performance.now() - started));
    if (runtime.tlsError) {
      runtime.state = 'warning';
      runtime.message = `证书异常：${runtime.tlsError}`;
    } else {
      runtime.state = result.ok ? 'healthy' : 'warning';
      runtime.message = result.ok ? result.message : `目标异常：${result.message}`;
    }
    if (runtime.state !== previousState) {
      recordEvent(runtime, runtime.state === 'healthy' ? 'success' : 'error', runtime.message, { protocol: rule.targetProtocols.join('+') });
      if (runtime.state === 'warning') void this.notifier?.send('rule.error', { ruleId: rule.id, rule: rule.name, state: runtime.state, message: runtime.message });
      if (runtime.state === 'healthy' && ['warning', 'error'].includes(previousState)) void this.notifier?.send('rule.recovered', { ruleId: rule.id, rule: rule.name, state: runtime.state, message: runtime.message });
    }
    return runtime;
  }

  async checkAll() {
    await Promise.allSettled(this.store.rules().map((rule) => this.checkRule(rule)));
  }

  snapshot() {
    const rules = Object.fromEntries([...this.runtimes.entries()].map(([id, runtime]) => [id, this.publicRuntime(runtime)]));
    const values = Object.values(rules);
    const totals = values.reduce((acc, item) => {
      acc.connections += item.connections;
      acc.activeConnections += item.activeConnections;
      acc.requests += item.requests;
      acc.bytesIn += item.bytesIn;
      acc.bytesOut += item.bytesOut;
      acc.errors += item.errors;
      return acc;
    }, { connections: 0, activeConnections: 0, requests: 0, bytesIn: 0, bytesOut: 0, errors: 0 });
    return { rules, totals };
  }

  publicRuntime(runtime) {
    const { servers, closers, sockets, datagramSockets, udpSessions, tlsBindings, clients, ...publicData } = runtime;
    return {
      ...publicData,
      clients: [...(clients?.values?.() || [])]
        .sort((left, right) => right.active - left.active || right.lastSeenAt - left.lastSeenAt)
        .slice(0, 20),
    };
  }
}
