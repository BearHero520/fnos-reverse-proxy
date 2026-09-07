import { useEffect, useId, useRef, useState } from 'react';
import { api } from './api.js';

const cleanDomain = (value) => String(value || '').trim().toLowerCase().replace(/\.$/, '');
const ordinaryDomain = (value) => value.length <= 253 && value.includes('.') && !/^\d+(?:\.\d+){3}$/.test(value) && value.split('.').every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part));

export function AliyunZoneField({ value = '', onChange, domain, credentials, savedAccessKeyId, scope, active, locked = false, onBusy }) {
  const id = useId();
  const [state, setState] = useState({ phase: 'idle', message: '' });
  const [edit, setEdit] = useState(0);
  const request = useRef(null);
  const debounce = useRef(null);
  const automatic = useRef(null);
  const manual = useRef(Boolean(value));
  const latest = useRef(null);
  const name = cleanDomain(domain);
  const accessKeyId = String(credentials.accessKeyId || '').trim();
  const accessKeySecret = String(credentials.accessKeySecret || '').trim();
  const clearAccessKeySecret = Boolean(credentials.clearAccessKeySecret);
  const storedSecret = credentials.hasAccessKeySecret && !clearAccessKeySecret && accessKeyId === savedAccessKeyId;
  const ready = Boolean(active && !locked && ordinaryDomain(name) && accessKeyId && (accessKeySecret || storedSecret));
  // Captured identities never leave memory; only the selected feature's endpoint
  // receives its own draft credentials. No localStorage or cross-feature reuse.
  const targetIdentity = JSON.stringify([scope, name, accessKeyId, accessKeySecret, storedSecret, clearAccessKeySecret]);
  const previousTarget = useRef(targetIdentity);
  const identity = JSON.stringify([targetIdentity, active, locked]);
  latest.current = { identity, value, onChange, ready };

  const cancel = () => { clearTimeout(debounce.current); request.current?.abort(); request.current = null; };
  const lookup = async () => {
    cancel();
    if (!latest.current.ready) return;
    const controller = new AbortController();
    request.current = controller;
    const originalValue = latest.current.value;
    setState({ phase: 'loading', message: '正在查询阿里云账号中的解析区域…' });
    try {
      const { result } = await api(`/integrations/${scope}/aliyun/resolve-zone`, {
        method: 'POST', body: { domain: name, accessKeyId, accessKeySecret, clearAccessKeySecret },
        signal: controller.signal, timeoutMs: 35000, idempotent: true,
      });
      if (controller.signal.aborted || latest.current.identity !== identity || latest.current.value !== originalValue) return;
      if (result?.demoMode) { setState({ phase: 'idle', message: result.message }); return; }
      const zone = cleanDomain(result?.dnsZone);
      if (!ordinaryDomain(zone) || name !== zone && !name.endsWith(`.${zone}`) || result.domain !== name) throw new Error('解析区域响应无效，请重试或手动填写');
      automatic.current = zone;
      manual.current = false;
      latest.current.onChange(zone);
      setState({ phase: 'success', message: '已从阿里云匹配，保存设置后生效。' });
    } catch (error) {
      if (!controller.signal.aborted && latest.current.identity === identity && latest.current.value === originalValue) setState({ phase: 'error', message: error.message || '识别失败，请重试或手动填写' });
    } finally { if (request.current === controller) request.current = null; }
  };
  const lookupRef = useRef(lookup);
  lookupRef.current = lookup;

  useEffect(() => {
    cancel();
    setState({ phase: 'idle', message: '' });
    if (previousTarget.current !== targetIdentity && automatic.current !== null) {
      if (latest.current.value === automatic.current) latest.current.onChange('');
      automatic.current = null;
    }
    previousTarget.current = targetIdentity;
    debounce.current = ready && !manual.current && automatic.current === null ? setTimeout(() => void lookupRef.current(), 700) : null;
    return cancel;
  }, [identity, edit]);
  useEffect(() => { onBusy?.(state.phase === 'loading'); return () => onBusy?.(false); }, [state.phase, onBusy]);

  const change = (event) => {
    cancel();
    automatic.current = null;
    manual.current = Boolean(event.target.value.trim());
    onChange(event.target.value);
    setEdit((current) => current + 1);
  };
  const hint = locked ? '当前操作期间锁定解析区域。' : state.message || (accessKeyId && accessKeyId !== savedAccessKeyId && !accessKeySecret && credentials.hasAccessKeySecret ? '更换 AccessKey ID 后，请填写对应的新 Secret。' : manual.current ? '手动填写已保留；可点击自动识别重新匹配。' : `填写 AccessKey 和${scope === 'ddns' ? '完整记录名称' : '证书域名'}后自动识别，也可手动填写。`);
  return <div className="form-field aliyun-zone-field" data-state={state.phase}>
    <label className="field-label" htmlFor={id}>DNS 主域名</label>
    <div className="zone-input-row">
      <input id={id} value={value} onChange={change} disabled={locked} autoComplete="off" spellCheck={false} placeholder="自动识别，或填写 example.com" aria-describedby={`${id}-hint`} />
      <button type="button" className="secondary-button compact-button" disabled={!ready || state.phase === 'loading'} onClick={() => void lookup()}><i className={`bi ${state.phase === 'loading' ? 'bi-arrow-repeat' : 'bi-search'}`} aria-hidden="true" />{state.phase === 'loading' ? '识别中…' : '自动识别'}</button>
    </div>
    <small id={`${id}-hint`} aria-live="polite">{hint}</small>
  </div>;
}
