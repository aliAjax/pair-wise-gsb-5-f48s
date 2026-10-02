import { useMemo, useState } from 'react';
import './attestation.css';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clock3,
  DatabaseBackup,
  FileSignature,
  Fingerprint,
  History,
  PencilLine,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Swords,
  XCircle,
} from 'lucide-react';
import * as eng from './engine';
import type { Artifact, Attestation, Result, Signature, StoreState } from './types';
import { commit, commitFailure, loadLegacyAndMigrate, resetFresh } from './store';
import { useStore } from './useStore';

type Toast = { kind: 'ok' | 'err' | 'conflict'; text: string; detail?: string } | null;

const statusStyle: Record<Attestation['status'], { cls: string; icon: typeof Check }> = {
  recomputing: { cls: 'recomputing', icon: RefreshCw },
  'awaiting-signatures': { cls: 'waiting', icon: Clock3 },
  finalized: { cls: 'finalized', icon: ShieldCheck },
  rejected: { cls: 'rejected', icon: ShieldAlert },
  superseded: { cls: 'superseded', icon: XCircle },
  historical: { cls: 'historical', icon: History },
};

function shortHash(h?: string): string {
  if (!h) return '—';
  if (h.startsWith('unknown')) return h;
  return `${h.slice(0, 13)}…`;
}

function resultToast(r: Result<unknown>, okText: string): Toast {
  return r.ok ? { kind: 'ok', text: okText } : { kind: r.conflict ? 'conflict' : 'err', text: r.error, detail: r.conflict ? JSON.stringify(r.conflict, null, 2) : undefined };
}

export default function AttestationCenter() {
  const state = useStore();
  const [selectedId, setSelectedId] = useState<string>(() => state.artifacts[0]?.id ?? '');
  const [toast, setToast] = useState<Toast>(null);
  const [showHistory, setShowHistory] = useState(false);

  const selected = state.artifacts.find((a) => a.id === selectedId);
  const chain = selected ? eng.attestationsOf(state, selected.id) : [];
  const live = chain.find((a) => a.status !== 'superseded' && a.status !== 'historical');
  const boundSet = selected ? eng.boundEvidenceVersionOf(state.evidence, selected.id) : '';
  const viewing = showHistory ? chain : live ? [live] : [];

  const stats = useMemo(() => {
    const lives = eng.liveAttestations(state);
    return {
      total: state.artifacts.length,
      valid: lives.filter((a) => a.status === 'finalized').length,
      recomputing: lives.filter((a) => a.status === 'recomputing').length,
      waiting: lives.filter((a) => a.status === 'awaiting-signatures').length,
      blocked: lives.filter((a) => a.status === 'rejected').length,
      wal: state.wal.length,
      historical: state.attestations.filter((a) => a.status === 'historical' || a.status === 'superseded').length,
    };
  }, [state]);

  const notify = (t: Toast) => {
    setToast(t);
    window.setTimeout(() => setToast(null), 5200);
  };

  // 自动阶段推进（可注入中途失败）
  const advance = (attId: string, failAt?: 'collect' | 'evaluate') => {
    const fn = failAt ? commitFailure : commit;
    const r = fn((d) => eng.advanceAutomated(d, attId, failAt ? { failAt } : {}));
    notify(resultToast(r, failAt ? '已模拟写入中途失败（WAL 已落盘）' : '自动阶段推进完成'));
  };

  const reconfirm = (attId: string) => notify(resultToast(commit((d) => eng.reconfirm(d, attId)), '确认通过'));

  const recover = (attId: string) => notify(resultToast(commit((d) => eng.recoverInterrupted(d, attId)), '已从最后完整证明恢复，仅补做未完成步骤'));

  const sign = (attId: string, reviewer: string, verdict: 'approve' | 'reject', opinion: string, slotToken?: string) => {
    if (!selected) return;
    const r = commit((d) =>
      eng.submitSignature(d, attId, {
        reviewer,
        verdict,
        opinion,
        seenFingerprint: selected.fingerprint ?? eng.LEGACY_FP,
        seenEvidenceVersion: eng.boundEvidenceVersionOf(d.evidence, selected.id),
        slotToken,
      }),
    );
    notify(resultToast(r, `${reviewer} 签署已提交`));
  };

  const replaceVersion = () => {
    if (!selected) return;
    const v = prompt('替换构件：输入新版本号', bump(selected.version)) ?? selected.version;
    const origin = selected.origin.replace(/[\d.]+\.(t?gz|jar)?$/, `${v}$1`).replace(/\/[^/]+$/, `/${v}`);
    notify(resultToast(commit((d) => eng.replaceArtifact(d, { id: selected.id, version: v, origin })), `构件已替换为 ${v}：旧证明失效，新版本开始重算`));
  };

  const supplementEvidence = () => {
    if (!selected) return;
    const body = prompt('补齐许可证证据（正文/摘要）', '法务补充：已核对完整 LICENSE 与 NOTICE，结论更新。');
    if (!body) return;
    notify(
      resultToast(
        commit((d) => eng.upsertEvidence(d, { id: `ev-${selected.id}-${Date.now()}`, artifactId: selected.id, kind: 'manual-review', body, reviewer: '当前用户' })),
        '证据已补齐：证据版本变化，旧证明失效重算',
      ),
    );
  };

  return (
    <div className="att-page">
      <header className="att-header">
        <div>
          <div className="crumb">WORKSPACE / <b>ATTESTATION LEDGER</b></div>
          <h1>合规证明流程 · 可恢复</h1>
          <p>证明绑定构件指纹与证据版本；来源一变即失效重算，分阶段写入可从最后完整证明恢复。</p>
        </div>
        <div className="head-actions">
          <button className="outline" onClick={() => loadLegacyAndMigrate()}><DatabaseBackup size={15} />载入 v1 旧数据并升级</button>
          <button className="outline" onClick={() => resetFresh()}><RefreshCw size={15} />重置演示</button>
        </div>
      </header>

      <section className="att-stats">
        <Stat icon={ShieldCheck} label="生效证明" value={stats.valid} tone="teal" />
        <Stat icon={RefreshCw} label="重算中" value={stats.recomputing} tone="blue" />
        <Stat icon={Clock3} label="待双签" value={stats.waiting} tone="orange" />
        <Stat icon={ShieldAlert} label="已拒绝" value={stats.blocked} tone="red" />
        <Stat icon={DatabaseBackup} label="未恢复写入" value={stats.wal} tone={stats.wal ? 'red' : 'muted'} />
        <Stat icon={History} label="历史/失效证明" value={stats.historical} tone="muted" />
      </section>

      {toast && (
        <div className={`toast ${toast.kind}`}>
          {toast.kind === 'ok' ? <CheckCircle2 size={16} /> : toast.kind === 'conflict' ? <Swords size={16} /> : <AlertTriangle size={16} />}
          <div><b>{toast.text}</b>{toast.detail && <pre>{toast.detail}</pre>}</div>
        </div>
      )}

      <section className="att-grid">
        <div className="att-artifacts card">
          <div className="card-head"><h2>构件清单</h2><small>指纹随来源变化</small></div>
          {state.artifacts.map((a) => {
            const atts = eng.attestationsOf(state, a.id);
            const cur = atts.find((x) => x.status !== 'superseded' && x.status !== 'historical');
            const S = cur ? statusStyle[cur.status] : null;
            return (
              <button key={a.id} className={`art-row ${a.id === selectedId ? 'sel' : ''}`} onClick={() => { setSelectedId(a.id); setShowHistory(false); }}>
                <div className="art-main">
                  <b>{a.name}</b><span>{a.version} · {a.license}</span>
                  <code className="fp"><Fingerprint size={10} /> {shortHash(a.fingerprint)}</code>
                </div>
                {S ? (
                  <span className={`pill ${S.cls}`}><S.icon size={11} /> {eng.statusLabel(cur!.status)}{cur!.stale ? ' · 来源过期' : ''}</span>
                ) : (
                  <span className="pill none">未发起</span>
                )}
              </button>
            );
          })}
        </div>

        {selected && (
          <div className="att-detail">
            <ArtifactPanel
              artifact={selected}
              state={state}
              onReplace={replaceVersion}
              onSupplement={supplementEvidence}
              live={live}
            />

            {viewing.length === 0 && (
              <div className="card empty">
                <Sparkles size={20} />
                <p>该构件还没有证明。</p>
                <button className="primary" onClick={() => notify(resultToast(commit((d) => { const a = eng.invalidateForSourceChange(d, selected.id, '手工发起证明'); return a ? { ok: true, value: a } : { ok: false, code: 'NOT_FOUND', error: '失败' }; }), '证明已创建并绑定当前指纹与证据版本'))}>
                  <FileSignature size={14} /> 发起证明（收集 → 评估 → 双签 → 出具）
                </button>
              </div>
            )}

            {viewing.map((att) => (
              <AttestationCard
                key={att.id}
                att={att}
                artifact={selected}
                currentEvidenceVersion={boundSet}
                isLive={att === live}
                onAdvance={advance}
                onReconfirm={reconfirm}
                onRecover={recover}
                onSign={sign}
              />
            ))}

            {chain.length > 0 && (
              <button className="link-btn" onClick={() => setShowHistory((v) => !v)}>
                <History size={13} /> {showHistory ? '只看当前证明' : `查看证明历史（${chain.length} 版，含失效与历史证明）`}
              </button>
            )}
          </div>
        )}
      </section>

      <section className="card audit">
        <div className="card-head"><h2>审计事件</h2><small>失效 / 拒绝 / 冲突 / 恢复 / 迁移全部留痕</small></div>
        {state.events.length === 0 && <p className="muted2">暂无事件。</p>}
        <div className="event-list">
          {state.events.slice(0, 18).map((e, i) => (
            <div key={i} className={`event ev-${e.kind}`}>
              <EventIcon kind={e.kind} />
              <span>{new Date(e.at).toLocaleTimeString('zh-CN', { hour12: false })}</span>
              <p>{e.message}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function bump(v: string): string {
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)$/);
  return m ? `${m[1]}.${Number(m[2]) + 1}.0` : '2.0.0';
}

function Stat({ icon: Icon, label, value, tone }: { icon: typeof Check; label: string; value: number; tone: string }) {
  return (
    <div className="stat">
      <span className={`stat-ic tone-${tone}`}><Icon size={15} /></span>
      <div><b>{value}</b><small>{label}</small></div>
    </div>
  );
}

function ArtifactPanel({ artifact, state, onReplace, onSupplement, live }: { artifact: Artifact; state: StoreState; onReplace: () => void; onSupplement: () => void; live?: Attestation }) {
  const evs = state.evidence.filter((e) => e.artifactId === artifact.id);
  const boundSet = eng.boundEvidenceVersionOf(state.evidence, artifact.id);
  const evidenceAhead = live ? boundSet !== live.boundEvidenceVersion : false;  return (
    <div className="card art-panel">
      <div className="card-head">
        <div>
          <h2>{artifact.name} <small>{artifact.version}</small></h2>
          <small className="lic">{artifact.license} · 来源 {artifact.source}</small>
        </div>
        <div className="row-actions">
          <button className="outline sm" onClick={onReplace}><PencilLine size={13} />替换构件</button>
          <button className="outline sm" onClick={onSupplement}><FileSignature size={13} />补齐证据</button>
        </div>
      </div>
      <div className="bind-grid">
        <div><label><Fingerprint size={11} /> 构件指纹（来源哈希）</label><code>{artifact.fingerprint ?? '缺失，待迁移回填'}</code></div>
        <div><label>绑定证据集合版本</label><code>{shortHash(boundSet)}</code>{evidenceAhead && <em className="ahead">证据已更新，证明绑定的是旧版本</em>}</div>
      </div>
      <div className="ev-list">
        {evs.length === 0 && <small className="muted2">暂无证据；请先补齐。</small>}
        {evs.map((e) => (
          <div key={e.id} className="ev-item">
            <div><b>{e.kind === 'license-file' ? 'LICENSE 文件' : e.kind === 'scan-report' ? '扫描报告' : '人工复核'}</b><span>{e.reviewer} · v {shortHash(e.version)}</span></div>
            <p>{e.body}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttestationCard({ att, artifact, currentEvidenceVersion, isLive, onAdvance, onReconfirm, onRecover, onSign }: {
  att: Attestation;
  artifact: Artifact;
  currentEvidenceVersion: string;
  isLive: boolean;
  onAdvance: (id: string, failAt?: 'collect' | 'evaluate') => void;
  onReconfirm: (id: string) => void;
  onRecover: (id: string) => void;
  onSign: (id: string, reviewer: string, verdict: 'approve' | 'reject', opinion: string, slotToken?: string) => void;
}) {
  const S = statusStyle[att.status];
  const [opinionA, setOpinionA] = useState('MIT/Apache 类条款，无异议');
  const [opinionB, setOpinionB] = useState('复核通过，义务已登记');
  const token = useMemo(() => `slot-${att.id}`, [att.id]);

  return (
    <div className={`card att-card ${S.cls} ${isLive ? '' : 'archived'}`}>
      <div className="card-head">
        <div>
          <h2>第 {att.issueNo} 版证明 {att.legacy && <span className="tag-legacy">升级前历史证明</span>}</h2>
          <small>编号 {att.id}</small>
        </div>
        <span className={`pill ${S.cls}`}><S.icon size={11} /> {eng.statusLabel(att.status)}</span>
      </div>

      <div className="bind-box">
        <div><label>绑定构件指纹</label><code className={att.boundFingerprint !== artifact.fingerprint ? 'stale-hash' : ''}>{shortHash(att.boundFingerprint)}</code></div>
        <div><label>绑定证据版本</label><code className={att.boundEvidenceVersion !== currentEvidenceVersion ? 'stale-hash' : ''}>{shortHash(att.boundEvidenceVersion)}</code></div>
        {att.finalDigest && <div><label>证明摘要</label><code>{shortHash(att.finalDigest)}</code></div>}
      </div>
      {att.invalidateReason && <p className="invalidate-reason"><AlertTriangle size={12} /> {att.invalidateReason}</p>}

      <ol className="steps">
        {att.steps.map((st) => (
          <li key={st.key} className={`step ${st.state}`}>
            <span className="step-dot">{st.state === 'done' ? <Check size={10} /> : st.state === 'failed' ? <XCircle size={10} /> : st.state === 'skipped' ? <Swords size={10} /> : st.seq}</span>
            <div><b>{st.label}</b>{st.detail && <small>{st.detail}</small>}</div>
          </li>
        ))}
      </ol>

      {att.signatures.length > 0 && (
        <div className="sigs">
          {att.signatures.map((sg: Signature) => (
            <div key={sg.reviewer} className={`sig ${sg.verdict}`}>
              <b>{sg.reviewer} · {sg.verdict === 'approve' ? '同意' : '拒绝'}</b>
              <p>{sg.opinion}</p>
              <small>签署时所见：{shortHash(sg.seenFingerprint)} / {shortHash(sg.seenEvidenceVersion)}</small>
            </div>
          ))}
        </div>
      )}

      {isLive && att.writeInterrupted && (
        <div className="recovery-box">
          <div><DatabaseBackup size={16} /><b>写入中途失败</b><small>WAL 基线：最后完整步骤序号 {Math.max(0, ...att.steps.filter((s) => s.state === 'done').map((s) => s.seq))}</small></div>
          <button className="primary" onClick={() => onRecover(att.id)}>从最后完整证明恢复（只补未完成部分）</button>
        </div>
      )}

      {isLive && (att.status === 'recomputing') && (
        <div className="actions">
          <button className="primary" onClick={() => onAdvance(att.id)}><RefreshCw size={13} />运行收集与评估</button>
          <button className="outline sm danger" onClick={() => onAdvance(att.id, 'collect')}><XCircle size={13} />模拟收集步骤写入失败</button>
          <button className="outline sm danger" onClick={() => onAdvance(att.id, 'evaluate')}><XCircle size={13} />模拟评估步骤写入失败</button>
          <button className="outline sm" onClick={() => onReconfirm(att.id)}>重算期间再次确认（应拒绝）</button>
        </div>
      )}

      {isLive && att.status === 'awaiting-signatures' && (
        <div className="sign-area">
          <div className="signer">
            <b>复核人 A</b>
            <input value={opinionA} onChange={(e) => setOpinionA(e.target.value)} />
            <div className="btnpair">
              <button onClick={() => onSign(att.id, '复核人 A', 'approve', opinionA)}><Check size={12} />同意</button>
              <button className="rej" onClick={() => onSign(att.id, '复核人 A', 'reject', opinionA)}><XCircle size={12} />拒绝</button>
            </div>
          </div>
          <div className="signer">
            <b>复核人 B</b>
            <input value={opinionB} onChange={(e) => setOpinionB(e.target.value)} />
            <div className="btnpair">
              <button onClick={() => onSign(att.id, '复核人 B', 'approve', opinionB)}><Check size={12} />同意</button>
              <button className="rej" onClick={() => onSign(att.id, '复核人 B', 'reject', opinionB)}><XCircle size={12} />拒绝</button>
            </div>
          </div>
          <div className="race">
            <small>并发竞争：两名复核人携带同一提交令牌同时签署，系统只保留先到的一份，后到者拿回先到意见与冲突。</small>
            <button className="outline sm" onClick={() => { onSign(att.id, '复核人 A', 'approve', opinionA + '（同时提交）', token); window.setTimeout(() => onSign(att.id, '复核人 B', 'approve', opinionB + '（同时提交）', token), 120); }}>
              <Swords size={13} />模拟 A、B 同时提交
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function EventIcon({ kind }: { kind: string }) {
  const map: Record<string, typeof Check> = {
    created: Sparkles, invalidated: RefreshCw, 'reconfirm-rejected': XCircle, 'step-done': Check,
    signed: FileSignature, conflict: Swords, 'write-failed': AlertTriangle, 'write-recovered': DatabaseBackup, migrated: DatabaseBackup,
  };
  const I = map[kind] ?? Check;
  return <I size={13} />;
}
