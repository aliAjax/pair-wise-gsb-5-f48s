// 纯领域逻辑：指纹绑定、失效重算、签署竞争、分阶段恢复。
// 所有函数接收 state 草稿并就地修改，持久化与 WAL 由 store.ts 负责。

import { fingerprint } from './hash';
import type {
  Artifact,
  Attestation,
  AttestationStatus,
  AuditEvent,
  ConflictInfo,
  Evidence,
  PipelineStep,
  Result,
  Signature,
  StepKey,
  StoreState,
} from './types';

export const FP_ALGORITHM = 'cyrb53/v1';
export const LEGACY_FP = 'unknown(legacy)';

// ---------------------------------------------------------------------------
// 指纹：来源一变，指纹即变
// ---------------------------------------------------------------------------

export function artifactFingerprintInput(a: Artifact) {
  return { type: 'artifact', name: a.name, version: a.version, license: a.license, source: a.source, origin: a.origin };
}

export function computeArtifactFingerprint(a: Artifact): string {
  return fingerprint(artifactFingerprintInput(a), FP_ALGORITHM);
}

/** 证据版本为内容寻址：kind/body/reviewer 任一字段变化即新版本 */
export function computeEvidenceVersion(e: Evidence): string {
  return fingerprint({ type: 'evidence', id: e.id, kind: e.kind, body: e.body, reviewer: e.reviewer }, FP_ALGORITHM);
}

/** 证明锚定的证据版本：对该构件全部证据的版本排序后再哈希 */
export function boundEvidenceVersionOf(evidence: Evidence[], artifactId: string): string {
  const versions = evidence.filter((e) => e.artifactId === artifactId).map((e) => e.version).sort();
  if (versions.length === 0) return fingerprint({ type: 'evidence-set', artifactId, empty: true }, FP_ALGORITHM);
  return fingerprint({ type: 'evidence-set', artifactId, versions }, FP_ALGORITHM);
}

export function attestationDigest(a: Attestation): string {
  return fingerprint(
    {
      type: 'attestation',
      artifactId: a.artifactId,
      boundFingerprint: a.boundFingerprint,
      boundEvidenceVersion: a.boundEvidenceVersion,
      signatures: a.signatures.map((s) => ({ reviewer: s.reviewer, verdict: s.verdict, opinion: s.opinion })),
    },
    FP_ALGORITHM,
  );
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

export function attestationsOf(state: StoreState, artifactId: string): Attestation[] {
  return state.attestations
    .filter((a) => a.artifactId === artifactId)
    .sort((x, y) => y.createdAt - x.createdAt);
}

export function liveAttestations(state: StoreState): Attestation[] {
  // 每个构件最新一份非历史、未被取代的证明
  const byArtifact = new Map<string, Attestation>();
  for (const a of [...state.attestations].sort((x, y) => x.createdAt - y.createdAt)) {
    if (a.status === 'superseded' || a.status === 'historical') continue;
    byArtifact.set(a.artifactId, a);
  }
  return [...byArtifact.values()].sort((x, y) => x.artifactId.localeCompare(y.artifactId));
}

export function currentFingerprint(state: StoreState, artifactId: string): string | undefined {
  return state.artifacts.find((a) => a.id === artifactId)?.fingerprint;
}

// ---------------------------------------------------------------------------
// 事件
// ---------------------------------------------------------------------------

function log(state: StoreState, ev: Omit<AuditEvent, 'at'> & { at?: number }): void {
  state.events.unshift({ at: ev.at ?? Date.now(), kind: ev.kind, message: ev.message, attestationId: ev.attestationId, artifactId: ev.artifactId });
  if (state.events.length > 200) state.events.length = 200;
}

function fail<T>(code: Exclude<Result<T>, { ok: true }>['code'], error: string, conflict?: ConflictInfo): Result<T> {
  return { ok: false, code, error, conflict };
}

// ---------------------------------------------------------------------------
// 失效：构件替换 / 证据补齐后，旧证明立即失效
// ---------------------------------------------------------------------------

function openSteps(): PipelineStep[] {
  const defs: { key: StepKey; label: string }[] = [
    { key: 'collect', label: '收集构件与证据' },
    { key: 'evaluate', label: '许可证策略评估' },
    { key: 'sign-primary', label: '复核人 A 签署' },
    { key: 'sign-secondary', label: '复核人 B 签署' },
    { key: 'finalize', label: '出具最终证明' },
  ];
  return defs.map((d, i) => ({ key: d.key, label: d.label, state: 'pending', seq: i + 1 }));
}

/**
 * 来源变化后的统一处理：
 * - 已生效的旧证明标记 superseded + stale，仍可查询但不再放行；
 * - 已在重算的证明把绑定更新到新来源（证明始终锚定最新来源）。
 */
export function invalidateForSourceChange(
  state: StoreState,
  artifactId: string,
  reason: string,
  now = Date.now(),
): Attestation | undefined {
  const fp = currentFingerprint(state, artifactId);
  const ev = boundEvidenceVersionOf(state.evidence, artifactId);
  const existing = state.attestations
    .filter((a) => a.artifactId === artifactId && a.status !== 'superseded' && a.status !== 'historical')
    .sort((x, y) => y.createdAt - x.createdAt);

  const newest = existing[0];
  // 正在重算且已锚定同一来源：无需重复失效
  if (newest && newest.boundFingerprint === fp && newest.boundEvidenceVersion === ev) return newest;

  let issueNo = (existing[0]?.issueNo ?? state.attestations.filter((a) => a.artifactId === artifactId).length) + 1;
  const successor: Attestation = {
    id: `att-${artifactId}-${issueNo}`,
    artifactId,
    boundFingerprint: fp ?? LEGACY_FP,
    boundEvidenceVersion: ev,
    status: 'recomputing',
    steps: openSteps(),
    signatures: [],
    issueNo,
    createdAt: now,
    updatedAt: now,
    invalidateReason: reason,
  };

  for (const old of existing) {
    old.status = 'superseded';
    old.stale = true;
    old.supersededBy = successor.id;
    old.updatedAt = now;
    old.invalidateReason = reason;
    log(state, {
      kind: 'invalidated',
      message: `第 ${old.issueNo} 版证明因「${reason}」失效，第 ${issueNo} 版开始重算`,
      attestationId: old.id,
      artifactId,
    });
  }
  state.attestations.push(successor);
  log(state, { kind: 'created', message: `第 ${issueNo} 版证明创建，绑定新来源`, attestationId: successor.id, artifactId });
  return successor;
}

// ---------------------------------------------------------------------------
// 分阶段推进：失败后只补未完成步骤
// ---------------------------------------------------------------------------

function findAtt(state: StoreState, id: string): Attestation | undefined {
  return state.attestations.find((a) => a.id === id);
}

/**
 * 执行从 collect 到 evaluate 的自动阶段，直到遇到签署门或失败步骤。
 * onStepFail：注入中途写入失败（在该步骤“计算完成、落盘之前”抛错），
 * 由 store 的 WAL 记录最后完整步骤；恢复时 done 步骤全部跳过。
 */
export function advanceAutomated(
  state: StoreState,
  attestationId: string,
  opts: { failAt?: StepKey; now?: number } = {},
): Result<Attestation> {
  const att = findAtt(state, attestationId);
  if (!att) return fail('NOT_FOUND', '证明不存在');
  if (att.status === 'superseded' || att.status === 'historical')
    return fail('ATT_NO_LONGER_OPEN', '该证明已失效，不能再推进');

  const now = opts.now ?? Date.now();
  const artifact = state.artifacts.find((a) => a.id === att.artifactId);
  if (!artifact) return fail('NOT_FOUND', '构件不存在');

  // 重算期间：收集阶段必须先确认来源仍然是证明绑定的那一份
  for (const step of att.steps) {
    if (step.state === 'done') continue; // 恢复：已完整落盘的步骤只跳过，不重算
    if (step.key === 'sign-primary' || step.key === 'sign-secondary' || step.key === 'finalize') break;

    if (step.key === 'collect') {
      if (artifact.fingerprint !== att.boundFingerprint)
        return fail('RECOMPUTING', '来源在重算期间再次变化，证明已重新锚定，请对最新版本发起确认');
      if (boundEvidenceVersionOf(state.evidence, att.artifactId) !== att.boundEvidenceVersion)
        return fail('RECOMPUTING', '证据在重算期间发生变化，证明已重新锚定，请对最新版本发起确认');
    }

    step.state = 'failed'; // 先占位：落盘失败时本步骤保持 failed，恢复时重试
    if (opts.failAt === step.key) {
      att.writeInterrupted = true;
      att.updatedAt = now;
      // WAL：记录最后完整步骤的序号，恢复时从该基线继续
      state.wal.push({
        attestationId: att.id,
        artifactId: att.artifactId,
        lastCompleteSeq: att.steps.filter((s) => s.state === 'done').reduce((m, s) => Math.max(m, s.seq), 0),
        failedStep: step.key,
        at: now,
      });
      log(state, { kind: 'write-failed', message: `步骤「${step.label}」写入中途失败（WAL 已记录基线），等待恢复`, attestationId: att.id, artifactId: att.artifactId, at: now });
      return fail('WRITE_FAILED', `写入在「${step.label}」中途失败，可从最后完整证明恢复`);
    }
    step.state = 'done';
    step.at = now;
    step.detail =
      step.key === 'collect'
        ? `指纹 ${att.boundFingerprint.slice(0, 18)}… / 证据 ${att.boundEvidenceVersion.slice(10, 22)}…`
        : policyNote(artifact, att);
    log(state, { kind: 'step-done', message: `步骤完成：${step.label}`, attestationId: att.id, artifactId: att.artifactId, at: now });
  }

  const firstPending = att.steps.find((s) => s.state !== 'done' && s.state !== 'skipped');
  if (firstPending && (firstPending.key === 'sign-primary' || firstPending.key === 'sign-secondary')) {
    if (att.status === 'recomputing') att.status = 'awaiting-signatures';
    att.updatedAt = now;
  }
  return { ok: true, value: att };
}

function policyNote(artifact: Artifact, att: Attestation): string {
  const evCount = att.boundEvidenceVersion ? 1 : 0;
  if (artifact.risk === 'risk') return `策略评估：${artifact.license} 存在分发限制，建议复核人重点核查（证据集 ${evCount ? '已绑定' : '为空'}）`;
  if (artifact.risk === 'warn') return `策略评估：${artifact.license} 需保留版权声明`;
  return `策略评估：${artifact.license} 兼容分发`;
}

/**
 * 再次确认（含签署入口的统一闸口）：
 * - 重算期间确认 → 拒绝（RECOMPUTING），防止对半成品来源放行；
 * - 对已失效旧证明确认 → 拒绝（ATT_NO_LONGER_OPEN）；
 * - 自动阶段未跑完 → 先驱动评估，不允许跳过收集/评估直接签。
 */
export function reconfirm(state: StoreState, attestationId: string): Result<Attestation> {
  const att = findAtt(state, attestationId);
  if (!att) return fail('NOT_FOUND', '证明不存在');
  if (att.status === 'recomputing')
    return fail('RECOMPUTING', '证明正在重算：来源已变，重算完成前的确认一律拒绝');
  if (att.status === 'superseded' || att.status === 'historical')
    return fail('ATT_NO_LONGER_OPEN', '该证明已失效或为历史版本，请使用最新版本');
  if (att.status === 'finalized' || att.status === 'rejected')
    return fail('ATT_NO_LONGER_OPEN', `证明已${att.status === 'finalized' ? '生效' : '被拒'}，无需再次确认`);
  return { ok: true, value: att };
}

// ---------------------------------------------------------------------------
// 签署：两人双签；并发提交保留先到的一份，后到者拿回意见与冲突
// ---------------------------------------------------------------------------

export interface SignInput {
  reviewer: string;
  verdict: 'approve' | 'reject';
  opinion: string;
  /** 乐观并发令牌：提交时复核人看到的来源。过期签署直接拒绝 */
  seenFingerprint: string;
  seenEvidenceVersion: string;
  /**
   * 并发槽令牌：两个复核人“同时”点提交时携带相同槽令牌竞争同一个签署位，
   * 模拟同一时刻的并行请求。
   */
  slotToken?: string;
}

/**
 * 并发竞争：同一槽令牌只保留先到的一份，后到者拿回先到者意见。
 * 占用记录保存在 state.slotLocks（运行时态，不参与持久化语义）。
 */

export function submitSignature(
  state: StoreState,
  attestationId: string,
  input: SignInput,
  now = Date.now(),
): Result<Attestation> {
  const gate = reconfirm(state, attestationId);
  if (!gate.ok) {
    if (gate.code === 'RECOMPUTING')
      log(state, { kind: 'reconfirm-rejected', message: `重算期间收到 ${input.reviewer} 的签署，已拒绝`, attestationId, at: now });
    return gate;
  }
  const att = gate.value;

  // 过期来源：签署所基于的构件指纹/证据版本已不是当前绑定
  if (input.seenFingerprint !== att.boundFingerprint || input.seenEvidenceVersion !== att.boundEvidenceVersion) {
    log(state, { kind: 'reconfirm-rejected', message: `${input.reviewer} 的签署基于过期来源，已拒绝`, attestationId, at: now });
    return fail('STALE_SIGNATURE', '签署基于过期的构件指纹或证据版本，请刷新来源后重新确认');
  }

  const sig: Signature = {
    reviewer: input.reviewer,
    verdict: input.verdict,
    opinion: input.opinion,
    seenFingerprint: input.seenFingerprint,
    seenEvidenceVersion: input.seenEvidenceVersion,
    at: now,
  };

  // 同一复核人重复提交：返回已有签署作为冲突
  const dup = att.signatures.find((s) => s.reviewer === input.reviewer);
  if (dup) {
    const conflict: ConflictInfo = {
      winner: dup,
      loser: sig,
      reason: `复核人 ${input.reviewer} 已经提交过签署，保留先到的一份`,
    };
    log(state, { kind: 'conflict', message: conflict.reason, attestationId, at: now });
    return fail('ALREADY_SIGNED', conflict.reason, conflict);
  }

  // 并发竞争：同一槽令牌只保留先到的一份，后到者拿回先到者意见
  if (input.slotToken) {
    state.slotLocks ??= {};
    const winnerKey = state.slotLocks[input.slotToken];
    if (winnerKey) {
      const winner = att.signatures.find((s) => `${s.reviewer}@${s.at}` === winnerKey);
      const conflict: ConflictInfo = {
        winner: winner ?? sig,
        loser: sig,
        reason: '两位复核人同时提交签署，系统只保留先到的一份；请阅读先到意见后处理冲突',
      };
      log(state, { kind: 'conflict', message: `${input.reviewer} 的并发签署落败，先到者为 ${winner?.reviewer ?? '?'}`, attestationId, at: now });
      return fail('ALREADY_SIGNED', conflict.reason, conflict);
    }
  }

  att.signatures.push(sig);
  if (input.slotToken) state.slotLocks[input.slotToken] = `${sig.reviewer}@${sig.at}`;
  const targetStep = att.steps.find(
    (s) => (s.key === 'sign-primary' || s.key === 'sign-secondary') && s.state !== 'done',
  );

  const tryFinalize = (): void => {
    if (att.signatures.length < 2) {
      att.updatedAt = now;
      log(state, { kind: 'signed', message: `${input.reviewer} 已签署（${sig.verdict === 'approve' ? '同意' : '拒绝'}），等待另一位复核人`, attestationId, at: now });
      return;
    }
    const [s1, s2] = att.signatures;
    const finStep = att.steps.find((s) => s.key === 'finalize')!;
    const remaining = att.steps.find((s) => s.key === 'sign-primary' || s.key === 'sign-secondary');
    if (remaining && remaining.state !== 'done') {
      remaining.state = 'done';
      remaining.at = now;
      remaining.detail = `${s2.reviewer} ${s2.verdict === 'approve' ? '同意' : '拒绝'}`;
    }
    if (s1.verdict === s2.verdict) {
      if (s1.verdict === 'approve') {
        att.status = 'finalized';
        att.finalDigest = attestationDigest(att);
        finStep.state = 'done';
        finStep.at = now;
        finStep.detail = `证明摘要 ${att.finalDigest.slice(0, 20)}…`;
        log(state, { kind: 'step-done', message: '两份签署一致，最终证明已出具', attestationId, at: now });
      } else {
        att.status = 'rejected';
        finStep.state = 'skipped';
        finStep.detail = '两份签署均为拒绝，不出具证明';
        log(state, { kind: 'conflict', message: '两份签署均为拒绝，证明不予出具', attestationId, at: now });
      }
    } else {
      att.status = 'rejected';
      finStep.state = 'skipped';
      finStep.detail = '签署意见冲突，证明被拒';
      log(state, {
        kind: 'conflict',
        message: `${s1.reviewer}（${s1.verdict === 'approve' ? '同意' : '拒绝'}）与 ${s2.reviewer}（${s2.verdict === 'approve' ? '同意' : '拒绝'}）意见冲突，证明被拒`,
        attestationId,
        at: now,
      });
    }
    att.updatedAt = now;
  };

  if (targetStep) {
    targetStep.state = 'done';
    targetStep.at = now;
    targetStep.detail = `${sig.reviewer} ${sig.verdict === 'approve' ? '同意' : '拒绝'}`;
  }
  tryFinalize();
  return { ok: true, value: att };
}

// ---------------------------------------------------------------------------
// 构件 / 证据维护：任何来源变更都驱动指纹重算与证明失效
// ---------------------------------------------------------------------------

export function replaceArtifact(state: StoreState, patch: Partial<Artifact> & Pick<Artifact, 'id'>, now = Date.now()): Result<Artifact> {
  const a = state.artifacts.find((x) => x.id === patch.id);
  if (!a) return fail('NOT_FOUND', '构件不存在');
  const before = computeArtifactFingerprint(a);
  Object.assign(a, patch, { updatedAt: now });
  a.fingerprint = computeArtifactFingerprint(a);
  if (a.fingerprint !== before) {
    invalidateForSourceChange(state, a.id, `构件替换：${a.name}@${a.version} 来源变化`, now);
  }
  return { ok: true, value: a };
}

export function upsertEvidence(state: StoreState, input: Omit<Evidence, 'version' | 'updatedAt'> & Partial<Pick<Evidence, 'updatedAt'>>, now = Date.now()): Result<Evidence> {
  const existing = state.evidence.find((e) => e.id === input.id);
  let ev: Evidence;
  if (existing) {
    const beforeVersion = existing.version;
    Object.assign(existing, { kind: input.kind, body: input.body, reviewer: input.reviewer });
    existing.updatedAt = now;
    existing.version = computeEvidenceVersion(existing);
    ev = existing;
    if (existing.version !== beforeVersion) {
      invalidateForSourceChange(state, existing.artifactId, `证据补齐/修订：${existing.kind}`, now);
    }
  } else {
    ev = { ...input, version: '', updatedAt: now };
    ev.version = computeEvidenceVersion(ev);
    state.evidence.push(ev);
    invalidateForSourceChange(state, ev.artifactId, `新增证据：${ev.kind}`, now);
  }
  return { ok: true, value: ev };
}

/** 从中断恢复：以最后完整证明为基线，只重试未完成步骤 */
export function recoverInterrupted(state: StoreState, attestationId: string, now = Date.now()): Result<Attestation> {
  const att = findAtt(state, attestationId);
  if (!att) return fail('NOT_FOUND', '证明不存在');
  if (!att.writeInterrupted) return { ok: true, value: att };

  const done = att.steps.filter((s) => s.state === 'done').map((s) => s.label);
  const walEntries = state.wal.filter((w) => w.attestationId === attestationId);
  // 恢复期间再次核对来源；来源又变过则交给失效流程重新锚定
  const fp = currentFingerprint(state, att.artifactId);
  const ev = boundEvidenceVersionOf(state.evidence, att.artifactId);
  if (fp !== att.boundFingerprint || ev !== att.boundEvidenceVersion) {
    state.wal = state.wal.filter((w) => w.attestationId !== attestationId);
    invalidateForSourceChange(state, att.artifactId, '恢复时发现来源已再次变化', now);
    return fail('RECOMPUTING', '恢复时发现来源已再次变化，已对最新来源重新发起重算');
  }
  att.writeInterrupted = false;
  state.wal = state.wal.filter((w) => w.attestationId !== attestationId); // 消费 WAL
  att.updatedAt = now;
  const lastSeq = walEntries.reduce((m, w) => Math.max(m, w.lastCompleteSeq), 0);
  const result = advanceAutomated(state, attestationId, { now });
  log(state, {
    kind: 'write-recovered',
    message: `从最后完整证明（步骤序号 ${lastSeq}）恢复，跳过已完成步骤（${done.join('、') || '无'}），仅补做未完成部分`,
    attestationId,
    artifactId: att.artifactId,
    at: now,
  });
  return result;
}

// ---------------------------------------------------------------------------
// 旧数据升级：回填缺失指纹；历史证明原样保留、仍可查询
// ---------------------------------------------------------------------------

export function migrate(state: StoreState, now = Date.now()): boolean {
  if (state.schemaVersion >= 2) return false;
  for (const a of state.artifacts) {
    if (!a.fingerprint) {
      a.fingerprint = computeArtifactFingerprint(a);
      if (!a.fpAlgorithm) a.fpAlgorithm = FP_ALGORITHM;
      log(state, { kind: 'migrated', message: `旧数据回填构件指纹：${a.name}`, artifactId: a.id, at: now });
    }
  }
  for (const e of state.evidence) {
    if (!e.version) {
      e.version = computeEvidenceVersion(e);
      log(state, { kind: 'migrated', message: `旧数据回填证据版本：${e.kind}`, artifactId: e.artifactId, at: now });
    }
  }
  for (const att of state.attestations) {
    if (!att.boundFingerprint || att.boundFingerprint === LEGACY_FP) {
      att.status = 'historical';
      att.legacy = true;
      att.boundFingerprint = att.boundFingerprint || LEGACY_FP;
      att.updatedAt = now;
      log(state, { kind: 'migrated', message: `第 ${att.issueNo} 版证明为升级前历史证明，保留可查询`, attestationId: att.id, artifactId: att.artifactId, at: now });
    }
  }
  state.schemaVersion = 2;
  return true;
}

export function statusLabel(s: AttestationStatus): string {
  return {
    recomputing: '重算中',
    'awaiting-signatures': '待签署',
    finalized: '已生效',
    rejected: '已拒绝',
    superseded: '已失效',
    historical: '历史证明',
  }[s];
}
