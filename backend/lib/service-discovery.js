import { execFile } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const COMMON_PORTS = [22, 53, 80, 81, 443, 445, 3000, 5000, 5001, 8080, 8081, 8123, 8443, 9000, 9090, 32400];
const SERVICE_NAMES = new Map([
  [22, ['SSH', ['tcp']]],
  [53, ['DNS', ['tcp', 'udp']]],
  [80, ['Web 服务', ['http', 'ws']]],
  [81, ['Web 服务', ['http', 'ws']]],
  [443, ['安全 Web 服务', ['https', 'wss']]],
  [445, ['SMB 文件服务', ['tcp']]],
  [3000, ['开发服务', ['http', 'ws']]],
  [5000, ['应用服务', ['http', 'ws']]],
  [5001, ['安全应用服务', ['https', 'wss']]],
  [8080, ['Web 服务', ['http', 'ws']]],
  [8081, ['Web 服务', ['http', 'ws']]],
  [8123, ['Home Assistant', ['http', 'ws']]],
  [8443, ['安全 Web 服务', ['https', 'wss']]],
  [9000, ['管理服务', ['http', 'ws']]],
  [9090, ['应用服务', ['http', 'ws']]],
  [32400, ['媒体服务', ['http', 'ws']]],
]);

export function localHostAliases() {
  const values = new Set(['localhost', '127.0.0.1', '::1', os.hostname().toLowerCase()]);
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses || []) values.add(String(address.address).split('%')[0].toLowerCase());
  }
  return [...values];
}

function neighborAddresses(output) {
  return [...new Set(String(output || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])]
    .filter((address) => address.split('.').every((part) => Number(part) <= 255));
}

async function readNeighbors() {
  try {
    if (process.platform === 'win32') return neighborAddresses((await execFileAsync('arp', ['-a'], { timeout: 2500, windowsHide: true })).stdout);
    return neighborAddresses((await execFileAsync('ip', ['neigh', 'show'], { timeout: 2500 })).stdout);
  } catch {
    return [];
  }
}

function probe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = performance.now();
    let settled = false;
    let socket;
    const finish = (available) => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      resolve({ available, latencyMs: available ? Math.max(1, Math.round(performance.now() - started)) : null });
    };
    try { socket = net.createConnection({ host, port }); }
    catch { finish(false); return; }
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

const serviceFor = (host, port, source, latencyMs = null) => {
  const [name, protocols] = SERVICE_NAMES.get(port) || [`TCP ${port}`, ['tcp']];
  return { id: `${host}:${port}`, host, port, name, protocols, source, latencyMs };
};

function demoServices() {
  return [
    serviceFor('192.168.50.121', 80, 'scan', 3),
    serviceFor('192.168.50.121', 22, 'scan', 4),
    serviceFor('192.168.50.18', 8123, 'scan', 7),
    serviceFor('192.168.50.32', 32400, 'scan', 9),
    serviceFor('192.168.50.8', 443, 'scan', 5),
  ];
}

export async function discoverServices({ rules = [], demoMode = false, timeoutMs = 350, reservedPorts = [] } = {}) {
  if (demoMode) return { services: demoServices(), scannedHosts: 5, scannedPorts: COMMON_PORTS.length, completedAt: new Date().toISOString() };
  const neighbors = await readNeighbors();
  const hosts = [...new Set([
    ...rules.map((rule) => String(rule.targetHost || '').trim()),
    ...neighbors,
  ].filter(Boolean))].slice(0, 64);
  const blockedPorts = new Set(reservedPorts.map(Number));
  const ports = [...new Set([
    ...rules.flatMap((rule) => rule.targetPorts || [rule.targetPort]).map(Number),
    ...COMMON_PORTS,
  ].filter((port) => Number.isInteger(port) && port > 0 && port <= 65535 && !blockedPorts.has(port)))].slice(0, 32);
  const tasks = hosts.flatMap((host) => ports.map((port) => ({ host, port })));
  const services = [];
  const width = 40;
  for (let index = 0; index < tasks.length; index += width) {
    const results = await Promise.all(tasks.slice(index, index + width).map(async (endpoint) => ({ ...endpoint, ...(await probe(endpoint.host, endpoint.port, timeoutMs)) })));
    for (const result of results) if (result.available) services.push(serviceFor(result.host, result.port, 'scan', result.latencyMs));
  }
  return {
    services: services.sort((left, right) => left.host.localeCompare(right.host, 'zh-CN', { numeric: true }) || left.port - right.port),
    scannedHosts: hosts.length,
    scannedPorts: ports.length,
    completedAt: new Date().toISOString(),
  };
}
