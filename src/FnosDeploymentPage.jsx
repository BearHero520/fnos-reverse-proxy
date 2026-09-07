import { UISelect } from './UISelect.jsx';
import { Dialog } from '@base-ui/react/dialog';
import { useEffect, useState } from 'react';
import { Field, Check, Notice } from './AutomationPages.jsx';

export const emptyDeployment = { certificateId: '', targetId: '', probeHost: '', probePort: 5667, autoDeploy: false, helper: { available: false, targets: [], message: '尚未检查内置部署服务' } };
const when = (value) => value ? new Date(value).toLocaleString() : '尚未部署';
export function FnosDeploymentPage({ integration, certificates, busy, onSave, onRefresh, onPrepare, onDeploy, onCertificates, onImport }) {
  const status = { ...emptyDeployment, ...integration };
  const [draft, setDraft] = useState(status);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  useEffect(() => { if (!dirty) setDraft(status); }, [integration, dirty]);
  useEffect(() => { void onRefresh(); }, []);
  const sources = certificates.filter((cert) => cert.source !== 'system' && cert.automation?.environment !== 'staging');
  const targets = status.helper?.targets || [];
  const selectTarget = (target) => { setDraft((current) => ({ ...current, targetId: target.id, certificateId: '', probeHost: target.probeHost || target.domains.find((d) => !d.startsWith('*.')) || '', probePort: target.verifiedPorts?.[0] || current.probePort })); setDirty(true); setPreview(null); setError(''); };
  const selectedTarget = targets.find((target) => target.id === draft.targetId);
  const domainKey = (values) => [...values].map((value) => value.toLowerCase()).sort().join(',');
  const matchingSources = selectedTarget ? sources.filter((cert) => domainKey(cert.subjectAltNames || []) === domainKey(selectedTarget.domains)) : sources;
  const set = (field, value) => { setDraft((current) => ({ ...current, [field]: value })); setDirty(true); setPreview(null); setError(''); };

  const prepare = async () => { setError(''); if (dirty) { const saved = await onSave({ certificateId: draft.certificateId, targetId: draft.targetId, probeHost: draft.probeHost, probePort: draft.probePort }); if (saved !== true) { setError(saved?.error?.message || '设置保存失败'); return; } setDirty(false); } const result = await onPrepare(); if (result?.preview) { setPreview(result.preview); setConfirmed(false); } else setError(result?.error?.message || '预检失败，请检查部署服务和绑定设置'); };
  const deploy = async () => { const result = await onDeploy({ token: preview.token, confirmed }); if (result === true) setPreview(null); else { setPreview(null); setError(result?.error?.message || '部署未启动，请重新预检'); } };
  const ready = status.helper?.available && !status.demoMode && draft.certificateId && draft.targetId && draft.probeHost;
  return <section className="view automation-page" aria-label="系统 HTTPS">
    <article className="matte-surface certificate-surface">
      <div className="section-heading"><div><h2>NAS 正在使用的证书</h2><p>选择系统证书，换成新签发或上传的同域名证书。</p></div><span className="state-chip warning">实验性</span></div>
      <dl className="automation-facts"><div><dt>系统连接</dt><dd>{status.helper?.available ? '已连接' : '未就绪'}</dd></div><div><dt>最近替换</dt><dd>{status.running ? '正在部署与验证…' : status.lastResult === 'verified' ? 'HTTPS 验证通过' : status.lastResult === 'rolled-back' ? '失败 · 已回退' : status.lastError ? '已停止，请检查' : '尚未部署'}</dd></div><div><dt>上次验证成功</dt><dd>{when(status.lastSuccessAt)}</dd></div></dl>
      {!status.helper?.available ? <Notice>{status.helper?.message || '内置部署服务不可用'}。证书签发和代理规则不受影响。</Notice> : null}
      {status.lastError ? <Notice error>{status.lastError}</Notice> : null}
      <div className="automation-actions"><button className="secondary-button" disabled={busy} onClick={onRefresh}><i className="bi bi-plug" aria-hidden="true" />刷新系统证书</button><button className="secondary-button" onClick={onCertificates}><i className="bi bi-shield-lock" aria-hidden="true" />打开证书库</button></div>
      <div className="system-target-list">{targets.map((target) => <article className="system-target-card" key={target.id}>
        <span className="system-target-icon" aria-hidden="true"><i className="bi bi-shield-check" /></span>
        <div className="system-target-content"><div className="system-target-heading"><strong>{target.domains[0]}</strong><span className={`system-target-state${target.bound ? ' bound' : ''}`}>{target.bound ? '系统 HTTPS 使用中' : '尚未绑定'}</span></div>
          {target.domains.length > 1 ? <p className="system-target-aliases">同时保护 {target.domains.slice(1).join('、')}</p> : null}
          <div className="system-target-meta"><span><i className="bi bi-calendar3" aria-hidden="true" />{new Date(target.validTo).toLocaleDateString()} 到期</span><span><i className="bi bi-hdd-network" aria-hidden="true" />{target.verifiedPorts?.length ? <>已验证端口 {target.verifiedPorts.map((port) => <code key={port}>{port}</code>)}</> : 'HTTPS 端口待验证'}</span></div>
        </div><button className="secondary-button system-target-replace" disabled={busy} onClick={() => selectTarget(target)}><i className="bi bi-arrow-repeat" aria-hidden="true" />替换证书</button>
      </article>)}</div>
      {status.helper?.available && !targets.length ? <Notice>尚未找到可替换的导入证书。请查看下方原因；若只有 fnOS 自带证书，可先在系统设置中导入自己的域名证书。</Notice> : null}
      {status.helper?.unavailableTargets?.length ? <details className="automation-details system-target-exclusions"><summary>不可替换的证书（{status.helper.unavailableTargets.length}）</summary>{status.helper.unavailableTargets.map((target) => <p key={target.id}>{target.domains.join('、') || 'fnOS 系统证书'}：{target.reason}</p>)}</details> : null}

    </article>
    {draft.targetId ? <article className="matte-surface certificate-surface">
      <div className="section-heading"><div><h2>替换系统证书</h2><p>先检查并备份，确认后替换；HTTPS 验证失败会恢复旧证书。</p></div></div>
      {error ? <Notice error>{error}</Notice> : null}
      {!matchingSources.length ? <Notice>证书库中没有覆盖上述全部域名的新证书，请先导入，或到“自动申请”获取证书。</Notice> : null}
      <form onSubmit={(event) => { event.preventDefault(); if (ready && !busy) void prepare(); }}><fieldset className="automation-fields" disabled={busy}>
        <div className="form-grid two"><Field label="新证书" hint="只显示覆盖相同域名的应用证书"><UISelect required value={draft.certificateId} onChange={(e) => set('certificateId', e.target.value)}><option value="">选择来源证书</option>{matchingSources.map((cert) => <option value={cert.id} key={cert.id}>{cert.name}</option>)}</UISelect></Field><Field label="fnOS 目标证书" hint={targets.length ? '新旧证书的域名必须完全一致' : '在 fnOS 首次导入后，点击检查部署服务'}><UISelect required value={draft.targetId} disabled={!targets.length} onChange={(e) => { const target = targets.find((item) => item.id === e.target.value); if (target) selectTarget(target); }}><option value="">选择系统证书</option>{targets.map((target) => <option value={target.id} key={target.id}>{target.domains.join('、')} · #{target.id}</option>)}</UISelect></Field><Field label="HTTPS 验证域名" hint="已绑定此系统证书的域名，不含协议或路径"><input required value={draft.probeHost} onChange={(e) => set('probeHost', e.target.value)} placeholder="nas.example.com" /></Field><Field label="系统 HTTPS 端口" hint="fnOS 默认 5667；如果修改过，请填写实际端口"><input required type="number" min="1" max="65535" value={draft.probePort} onChange={(e) => set('probePort', e.target.value)} /></Field></div>
        <div className="automation-actions"><button className="secondary-button" type="button" onClick={onImport}>导入新证书</button><button className="primary-button" type="button" disabled={!ready || busy} onClick={prepare}><i className="bi bi-shield-check" aria-hidden="true" />{busy ? '正在处理…' : '检查并替换'}</button><small>预检通过后会展示替换确认，当前证书不会立即改变</small></div>
      </fieldset></form>
      <fieldset className="automation-fields" disabled={busy || dirty || !status.lastSuccessAt || Boolean(status.lastError) || !status.helper?.available}><Check checked={status.autoDeploy} title="证书轮换后自动部署" description="仅在绑定证书更新时运行；失败或系统证书被外部修改时暂停。与签发、DDNS 分开控制。" onChange={async (autoDeploy) => { const result = await onSave({ autoDeploy }); if (result !== true) setError(result?.error?.message || '自动部署设置未保存'); }} /></fieldset>
      {!status.lastSuccessAt ? <p className="automation-caption">完成一次手动部署并验证 HTTPS 后，才可开启自动部署。</p> : null}
    </article> : null}
    <Dialog.Root open={Boolean(preview)} onOpenChange={(open) => { if (!open && !busy) setPreview(null); }}><Dialog.Portal><Dialog.Backdrop className="dialog-backdrop" /><Dialog.Popup className="dialog-popup automation-editor"><header className="dialog-header"><div><Dialog.Title>确认部署到 fnOS</Dialog.Title><Dialog.Description>预检已通过；下一步会替换选中的证书并重载 HTTPS 服务。</Dialog.Description></div><Dialog.Close className="dialog-close" disabled={busy} aria-label="取消部署"><i className="bi bi-x-lg" aria-hidden="true" /></Dialog.Close></header><div className="dialog-body automation-form">{preview ? <><dl className="automation-facts"><div><dt>目标证书</dt><dd>{preview.target.domains.join('、')}</dd></div><div><dt>新证书有效期至</dt><dd>{when(preview.validTo)}</dd></div><div><dt>本机 HTTPS 验证</dt><dd>{preview.probeHost}:{preview.probePort}</dd></div></dl><Notice>先备份，再替换；验证失败会尝试回退。若系统同时被外部修改，助手将停止写入并报告恢复异常。</Notice><Check checked={confirmed} onChange={setConfirmed} title="确认替换该系统证书并重载 HTTPS" description="管理后台可能短暂断开，请保留局域网备用访问方式。" /></> : null}</div><footer className="dialog-actions"><Dialog.Close className="secondary-button" disabled={busy}>取消</Dialog.Close><button className="primary-button" disabled={!confirmed || busy} onClick={deploy}>确认部署</button></footer></Dialog.Popup></Dialog.Portal></Dialog.Root>
  </section>;
}
