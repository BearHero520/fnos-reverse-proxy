import { useEffect, useRef, useState } from 'react';

export function IssuanceLog({ status, onRefresh }) {
  const [offline, setOffline] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const [follow, setFollow] = useState(true);
  const box = useRef(null);
  const refresh = useRef(onRefresh); refresh.current = onRefresh;
  useEffect(() => {
    let cancelled = false, timer;
    const poll = async () => {
      try { await refresh.current(); if (!cancelled) setOffline(false); }
      catch { if (!cancelled) setOffline(true); }
      if (!cancelled) timer = setTimeout(poll, 2000);
    };
    void poll(); const tick = setInterval(() => setClock(Date.now()), 1000);
    return () => { cancelled = true; clearTimeout(timer); clearInterval(tick); };
  }, []);
  const events = (status.progress?.events || []).filter((e) => e.provider === 'aliyun');
  const lastId = events.at(-1)?.id;
  useEffect(() => { if (follow && box.current) box.current.scrollTop = box.current.scrollHeight; }, [lastId, follow]);
  const active = status.progress?.active;
  const remaining = status.progress?.nextPollAt ? Math.max(0, Math.ceil((Date.parse(status.progress.nextPollAt) - clock) / 1000)) : null;
  return <article className="matte-surface certificate-surface issuance-terminal">
    <div className="section-heading"><div><h2>签发实时日志</h2><p>每 2 秒刷新 · 保留本次服务运行的最近 200 条记录</p></div><button className="secondary-button" onClick={() => setFollow(!follow)} aria-pressed={follow}>{follow ? '暂停滚动' : '跟随最新'}</button></div>
    <div className="issuance-console" ref={box} role="log" aria-label="阿里云签发日志" tabIndex={0} aria-live="polite" aria-relevant="additions">
      {events.length ? events.map((e) => <div key={e.id} className={`issuance-log-line ${e.level}`}><time>{new Date(e.at).toLocaleTimeString()}</time><span>{e.level === 'error' ? 'ERROR' : e.level === 'success' ? 'OK' : 'INFO'}</span><span>{e.message}</span></div>) : <p>{status.demoMode ? '演示模式不会发起真实签发。' : status.aliyun.order ? '已恢复保存的申请，等待后台继续查询。' : '等待操作；签发或查询额度后，这里显示实际执行过程。'}</p>}
    </div>
    <p className="issuance-heartbeat" role="status">{offline ? '进度连接中断，正在重试；暂时无法确认后台状态。' : active ? `${active.message} · 已等待 ${Math.max(0, Math.floor((clock - Date.parse(active.since)) / 1000))} 秒` : remaining !== null ? remaining ? `等待云端处理 · 约 ${remaining} 秒后再次检查` : '等待后台调度下一轮检查…' : status.aliyun.lastError ? '本轮未完成，请检查上方错误信息。' : '已连接 · 暂无正在执行的请求'}</p>
  </article>;
}
