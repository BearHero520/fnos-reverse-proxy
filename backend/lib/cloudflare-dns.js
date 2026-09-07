const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
const clean = (value) => String(value ?? '').trim();
const integrationError = (message, status = 502) => Object.assign(new Error(message), { status });
const errorMessage = (error) => clean(error?.message) || '未知错误';

export function publicIpEndpoint(recordType) {
  return recordType === 'AAAA' ? 'https://api6.ipify.org?format=json' : 'https://api.ipify.org?format=json';
}

export class CloudflareDnsClient {
  constructor({ zoneId, apiToken, fetchFn = globalThis.fetch }) {
    this.zoneId = zoneId;
    this.apiToken = apiToken;
    this.fetchFn = fetchFn;
  }

  async request(path, { method = 'GET', body } = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    timeout.unref?.();
    try {
      const response = await this.fetchFn(`${CLOUDFLARE_API}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          Accept: 'application/json',
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      const payload = await response.json();
      if (!response.ok || payload?.success !== true) {
        const detail = payload?.errors?.map((item) => clean(item?.message)).filter(Boolean).join('；');
        throw integrationError(`Cloudflare API 返回 ${response.status}${detail ? `：${detail}` : '：响应无效'}`, 502);
      }
      return payload.result;
    } catch (error) {
      if (error.status) throw error;
      throw integrationError(error?.name === 'AbortError' ? 'Cloudflare API 请求超时' : `无法连接 Cloudflare API：${errorMessage(error)}`, 502);
    } finally {
      clearTimeout(timeout);
    }
  }

  recordPath(suffix = '') {
    return `/zones/${encodeURIComponent(this.zoneId)}/dns_records${suffix}`;
  }

  async findRecords(type, name) {
    const query = new URLSearchParams({ ...(type ? { type } : {}), name, per_page: '500' });
    const result = await this.request(`${this.recordPath()}?${query}`);
    if (!Array.isArray(result) || result.length >= 500 || result.some((record) => !record?.id || !record?.name || !record?.type)) throw integrationError('Cloudflare DNS 查询响应不完整，已停止写入');
    return result;
  }

  async inspect({ type, name }) {
    const records = (await this.findRecords(undefined, name)).filter((record) => record.name.toLowerCase().replace(/\.$/, '') === name.toLowerCase().replace(/\.$/, ''));
    if (records.some((record) => ['CNAME', 'NS'].includes(record.type))) throw integrationError('同名 DNS 记录存在 CNAME 或委派冲突，不会覆盖原记录', 409);
    const matching = records.filter((record) => record.type === type);
    if (matching.length > 1) throw integrationError('同名、同类型存在多条解析，请先在云端整理；不会任选一条覆盖', 409);
    return matching[0] || null;
  }

  async upsert({ type, name, content, ttl = 1, proxied = false }) {
    const record = await this.inspect({ type, name });
    const effectiveTtl = proxied ? 1 : ttl;
    const unchanged = record && record.content === content && Number(record.ttl) === Number(effectiveTtl) && Boolean(record.proxied) === Boolean(proxied);
    if (unchanged) return { changed: false, record };
    const body = { type, name, content, ttl: effectiveTtl, proxied };
    const saved = record
      ? await this.request(this.recordPath(`/${encodeURIComponent(record.id)}`), { method: 'PATCH', body })
      : await this.request(this.recordPath(), { method: 'POST', body });
    if (!saved?.id || record && saved.id !== record.id) throw integrationError('Cloudflare 未确认目标记录已更新，下次同步将先核对现有记录');
    return { changed: true, record: saved };
  }

  async createTxt(name, content) {
    return this.request(this.recordPath(), { method: 'POST', body: { type: 'TXT', name, content, ttl: 60, proxied: false } });
  }

  async deleteRecord(id) {
    if (!id) return;
    await this.request(this.recordPath(`/${encodeURIComponent(id)}`), { method: 'DELETE' });
  }
}
