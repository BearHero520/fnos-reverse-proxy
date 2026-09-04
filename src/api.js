const prefix = `${import.meta.env.BASE_URL.replace(/\/$/, '')}/api`;
const DEFAULT_TIMEOUT_MS = 12000;
const DEFAULT_MUTATION_TIMEOUT_MS = 60000;

export class ApiError extends Error {
  constructor(message, { status = 0, details = null, payload = null, uncertain = false } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
    this.payload = payload;
    this.uncertain = uncertain;
  }
}

export async function api(path, options = {}) {
  const { timeoutMs: requestedTimeout, signal, idempotent = false, ...requestOptions } = options;
  const method = String(requestOptions.method || 'GET').toUpperCase();
  const readOnly = ['GET', 'HEAD'].includes(method);
  const timeoutMs = requestedTimeout ?? (readOnly ? DEFAULT_TIMEOUT_MS : DEFAULT_MUTATION_TIMEOUT_MS);
  const controller = new AbortController();
  let timedOut = false;
  const abortFromCaller = () => controller.abort(signal?.reason);
  if (signal?.aborted) abortFromCaller();
  else signal?.addEventListener('abort', abortFromCaller, { once: true });
  const timer = timeoutMs > 0 ? window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs) : null;

  try {
    const response = await fetch(`${prefix}${path}`, {
      ...requestOptions,
      signal: controller.signal,
      headers: {
        ...(requestOptions.body && !(requestOptions.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}),
        ...requestOptions.headers,
      },
      body: requestOptions.body && !(requestOptions.body instanceof FormData) && typeof requestOptions.body !== 'string'
        ? JSON.stringify(requestOptions.body)
        : requestOptions.body,
    });
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) {
      const textPayload = typeof payload === 'string' ? payload.trim() : '';
      const safeText = textPayload && !/<(?:!doctype|html|head|body|pre)\b/i.test(textPayload)
        ? textPayload.slice(0, 300)
        : '';
      const backendMessage = typeof payload?.error === 'string' ? payload.error : payload?.error?.message;
      const message = backendMessage || safeText || `请求失败（${response.status}）`;
      if (!readOnly && !idempotent && [502, 503, 504].includes(response.status)) {
        throw new ApiError('网关未能确认操作结果；请勿立即重复提交', {
          status: response.status,
          details: [message, '界面将自动重新同步当前数据'],
          payload,
          uncertain: true,
        });
      }
      throw new ApiError(message, { status: response.status, details: payload?.details || payload?.error?.details || null, payload });
    }
    return payload;
  } catch (error) {
    if (error?.name === 'AbortError') {
      if (!readOnly && !idempotent) throw new ApiError(timedOut ? '服务器响应超时，操作结果尚不确定；请勿立即重复提交' : '请求中断，操作结果尚不确定；请勿立即重复提交', { details: ['界面将自动重新同步当前数据'], uncertain: true });
      throw new ApiError(timedOut ? '请求超时，请检查服务状态后重试' : '请求已取消');
    }
    if (!readOnly && !idempotent && !(error instanceof ApiError)) {
      throw new ApiError('网络连接中断，操作结果尚不确定；请勿立即重复提交', {
        details: [error?.message, '界面将自动重新同步当前数据'].filter(Boolean),
        uncertain: true,
      });
    }
    throw error;
  } finally {
    if (timer) window.clearTimeout(timer);
    signal?.removeEventListener('abort', abortFromCaller);
  }
}

export const apiUrl = (path) => `${prefix}${path}`;
