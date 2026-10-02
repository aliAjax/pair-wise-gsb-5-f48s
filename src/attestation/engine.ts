/**
 * 可恢复的合规证明引擎。
 *
 * 不变量：
 *  1. 构件清单、许可证证据、合规证明分开维护，各自独立版本化。
 *  2. 每份证明绑定「构件指纹 + 证据版本 + 绑定哈希」；
 *     构件替换（指纹变化）或证据补齐（版本递增）后，旧证明立即失效，
 *     后继证明从 computing 重新计算。
 *  3. computing 期间提交签署一律拒绝（REJECTED_RECOMPUTING）。
 *  4. 证明按 5 个检查点阶段计算，每阶段两阶段持久化；
 *     写入中途失败后重启，从上一个完整检查点恢复，只补未完成阶段。
 *  5. 两位复核人并发签署时，靠存储层 CAS 保留先到的一份，
 *     后到者拿回先到签署（意见）与冲突说明。
 *  6. 旧数据升级时回填缺失的构件指纹；历史证明标记 legacy 仍可查询，
 *     但不作为放行依据。
 */

import { DurableStore } from './store';
import {
  Artifact,
  Attestation,
  ConcurrentReviewResult,
  Evidence,
  EvidenceEntry,
  ReviewSignature,
  RiskLevel,
  STAGES,
  StageCheckpoint,
  StageName,
  SubmitReviewResult,
} from './types';
import {
  computeBindingHash,
  fingerprintArtifactInput,
  fingerprintEvidenceInput,
  sha256Hex,
} from './hash';

const K_ARTIFACT = 'artifact:';
const K_EVIDENCE = 'evidence:';
const K_ATTEST = 'attestation:';

export class AttestationStaleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AttestationStaleError';
  }
}

interface StageOutputs {
  // collect
  snapshot?: { artifact: Artifact; evidence: Evidence };
  // analyze
  findings?: string[];
  // policy
  decision?: { gating: boolean; reasons: string[] };
  // assemble
  report?: string;
  // seal
  proofHash?: string;
}

type Clock = () => number;

let seq = 0;
function defaultId(prefix: string, now: Clock): string {
  seq = (seq + 1) % 1_000_000;
  return `${prefix}_${now().toString(36)}${seq.toString(36).padStart(3, '0')}`;
}

const ACTIVE_STATES = new Set(['computing', 'ready', 'signed', 'failed']);

export interface EngineOptions {
  store: DurableStore;
  now?: Clock;
  id?: (prefix: string) => string;
  /** 阶段执行观测钩子（用于验证“只补未完成阶段”） */
  onStage?: (attestationId: string, stage: StageName, attempt: number) => void;
}

export class AttestationEngine {
  private store: DurableStore;
  private now: Clock;
  private id: (prefix: string) => string;
  private onStage?: EngineOptions['onStage'];

  constructor(opts: EngineOptions) {
    this.store = opts.store;
    this.now = opts.now ?? (() => Date.now());
    const now = this.now;
    this.id = opts.id ?? ((p) => defaultId(p, now));
    this.onStage = opts.onStage;
  }

  // ---------------------------------------------------------------- 构件清单

  /**
   * 新增或替换构件。内容（name/version/source）变化即视为“构件被替换”：
   * 指纹变化、revision +1、旧构件标记 replacedBy，全部关联证明失效。
   */
  async upsertArtifact(input: {
    id: string;
    name: string;
    version: string;
    source: string;
  }): Promise<{ artifact: Artifact; replaced: boolean }> {
    const fingerprint = await sha256Hex(fingerprintArtifactInput(input));
    const existing = this.store.get<Artifact>(K_ARTIFACT + input.id)?.value;
    const replaced = !!existing && existing.fingerprint !== fingerprint;

    const res = this.store.mutate<Artifact>(K_ARTIFACT + input.id, (prev) => {
      const a = prev?.value;
      const next: Artifact = {
        id: input.id,
        name: input.name,
        version: input.version,
        source: input.source,
        fingerprint,
        revision: a ? (a.fingerprint === fingerprint ? a.revision : a.revision + 1) : 1,
        createdAt: a ? a.createdAt : this.now(),
        updatedAt: this.now(),
      };
      return next;
    });
    if (!res.ok) throw new Error('构件写入冲突');
    const artifact = res.envelope.value;

    if (replaced) {
      this.invalidateActiveForArtifact(
        input.id,
        `构件已替换：指纹 ${fingerprint.slice(0, 12)}… 与绑定不一致`,
      );
    }
    return { artifact, replaced };
  }

  getArtifact(id: string): Artifact | undefined {
    return this.store.get<Artifact>(K_ARTIFACT + id)?.value;
  }

  listArtifacts(): Artifact[] {
    return this.store
      .list<Artifact>(K_ARTIFACT)
      .map((x) => x.envelope.value)
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  // ---------------------------------------------------------------- 许可证证据

  /** 登记构件的第一版许可证证据 */
  async createEvidence(input: {
    artifactId: string;
    license: string;
    risk: RiskLevel;
    entries: EvidenceEntry[];
  }): Promise<Evidence> {
    const id = this.id('ev');
    const ev: Evidence = {
      id,
      artifactId: input.artifactId,
      license: input.license,
      risk: input.risk,
      entries: input.entries,
      version: 1,
      createdAt: this.now(),
      updatedAt: this.now(),
    };
    const res = this.store.mutate<Evidence>(K_EVIDENCE + id, () => ev);
    if (!res.ok) throw new Error('证据写入冲突');
    return res.envelope.value;
  }

  /**
   * 补齐 / 修订证据：版本号 +1，并使所有绑定旧版本的证明失效。
   * 即便内容与旧版相同也换版——“证据补齐”本身就是新的证据版本。
   */
  async updateEvidence(
    evidenceId: string,
    patch: { license?: string; risk?: RiskLevel; entries?: EvidenceEntry[] },
  ): Promise<Evidence> {
    const cur = this.store.get<Evidence>(K_EVIDENCE + evidenceId)?.value;
    if (!cur) throw new Error(`证据不存在: ${evidenceId}`);

    const next: Evidence = {
      ...cur,
      license: patch.license ?? cur.license,
      risk: patch.risk ?? cur.risk,
      entries: patch.entries ?? cur.entries,
      version: cur.version + 1,
      updatedAt: this.now(),
    };
    const res = this.store.mutate<Evidence>(K_EVIDENCE + evidenceId, () => next);
    if (!res.ok) throw new Error('证据写入冲突');

    this.invalidateActiveForArtifact(
      cur.artifactId,
      `许可证证据已补齐：版本 v${cur.version} → v${next.version}`,
      (att) => att.evidenceId === evidenceId,
    );
    return res.envelope.value;
  }

  getEvidence(id: string): Evidence | undefined {
    return this.store.get<Evidence>(K_EVIDENCE + id)?.value;
  }

  listEvidence(): Evidence[] {
    return this.store.list<Evidence>(K_EVIDENCE).map((x) => x.envelope.value);
  }

  // ---------------------------------------------------------------- 证明失效

  /**
   * 来源一变就失效：将构件下仍处于活动态的证明置 invalidated。
   * computing 中的证明也会失效——正在跑的计算在下个检查点感知到后中止。
   */
  private invalidateActiveForArtifact(
    artifactId: string,
    reason: string,
    extra?: (att: Attestation) => boolean,
  ): string[] {
    const invalidated: string[] = [];
    for (const { key, envelope } of this.store.list<Attestation>(K_ATTEST)) {
      const att = envelope.value;
      if (att.artifactId !== artifactId) continue;
      if (!ACTIVE_STATES.has(att.state)) continue;
      if (extra && !extra(att)) continue;
      const res = this.store.mutate<Attestation>(
        key,
        (prev) => {
          const cur = prev!.value;
          if (!ACTIVE_STATES.has(cur.state)) return cur; // 并发下已被别人处理
          return {
            ...cur,
            state: 'invalidated',
            invalidatedAt: this.now(),
            invalidReason: reason,
            updatedAt: this.now(),
          };
        },
        envelope.version,
      );
      if (res.ok) invalidated.push(att.id);
    }
    return invalidated;
  }

  // ---------------------------------------------------------------- 发起证明

  /**
   * 发起（或幂等取回）某构件 + 证据的证明，并立即进入分阶段计算。
   * 已有同绑定的活动证明时直接复用（幂等）；绑定已过时则旧证明失效、
   * 新建 computing 后继证明。
   */
  async requestAttestation(artifactId: string, evidenceId: string): Promise<Attestation> {
    const artifact = this.mustHaveArtifact(artifactId);
    const evidence = this.mustHaveEvidence(evidenceId);
    if (evidence.artifactId !== artifactId) throw new Error('证据与构件不匹配');

    const evidenceFp = fingerprintEvidenceInput(evidence);
    const bindingHash = await computeBindingHash({
      artifactFingerprint: artifact.fingerprint!,
      evidenceVersion: evidence.version,
      evidenceFingerprint: evidenceFp,
    });

    // 幂等：同绑定的活动证明直接返回
    for (const { envelope } of this.store.list<Attestation>(K_ATTEST)) {
      const att = envelope.value;
      if (att.artifactId !== artifactId || att.evidenceId !== evidenceId) continue;
      if (att.binding.bindingHash === bindingHash && ACTIVE_STATES.has(att.state)) {
        return att.state === 'computing' || att.state === 'failed'
          ? this.runStages(att.id)
          : att;
      }
    }

    // 找前驱：构件维度上最近一份非 legacy 证明（可能已经被本次来源变更置为
    // invalidated——先建后继再把前驱的 successorId 补齐，演进链不能断）
    const predecessor = this.store
      .list<Attestation>(K_ATTEST)
      .map((x) => x.envelope.value)
      .filter((a) => a.artifactId === artifactId && !a.legacy)
      .sort((x, y) => y.createdAt - x.createdAt)[0];

    const id = this.id('att');
    const checkpoint: StageCheckpoint = {
      stage: STAGES[0],
      completedIndex: -1,
      stageAttempts: {},
      updatedAt: this.now(),
    };
    const att: Attestation = {
      id,
      artifactId,
      evidenceId,
      binding: {
        artifactFingerprint: artifact.fingerprint!,
        evidenceVersion: evidence.version,
        bindingHash,
      },
      state: 'computing',
      checkpoint,
      signatures: [],
      predecessorId: predecessor?.id,
      createdAt: this.now(),
      updatedAt: this.now(),
    };
    const created = this.store.mutate<Attestation>(K_ATTEST + id, () => att);
    if (!created.ok) throw new Error('证明创建冲突');

    if (predecessor) {
      for (const { key, envelope } of this.store.list<Attestation>(K_ATTEST)) {
        const a = envelope.value;
        if (a.id !== predecessor.id) continue;
        this.store.mutate<Attestation>(
          key,
          (prev) => {
            const cur = prev!.value;
            const stillActive = ACTIVE_STATES.has(cur.state);
            return {
              ...cur,
              ...(stillActive
                ? {
                    state: 'invalidated' as const,
                    invalidatedAt: this.now(),
                    invalidReason: `已由后继证明 ${id} 取代（来源发生变化）`,
                  }
                : {}),
              successorId: id,
              updatedAt: this.now(),
            };
          },
          envelope.version,
        );
      }
    }

    return this.runStages(id);
  }

  // ---------------------------------------------------------------- 分阶段计算

  /**
   * 从检查点恢复执行。崩溃重启后同样调用本方法：
   * 已落盘的阶段不会重跑，只补 completedIndex 之后的阶段。
   */
  async runStages(attestationId: string): Promise<Attestation> {
    for (let guard = 0; guard < STAGES.length + 1; guard++) {
      const env = this.store.get<Attestation>(K_ATTEST + attestationId);
      if (!env) throw new Error(`证明不存在: ${attestationId}`);
      const att = env.value;

      // 计算期间来源发生变化（构件替换 / 证据换版）：放弃本次计算
      if (att.state === 'invalidated') {
        throw new AttestationStaleError(`证明 ${attestationId} 已在重算期间失效，须重新发起`);
      }
      if (att.state !== 'computing' && att.state !== 'failed') return att;

      const idx = (att.checkpoint?.completedIndex ?? -1) + 1;
      if (idx >= STAGES.length) {
        // 所有阶段已完整落盘：把 computing/failed 置为 ready 后封存
        const done = this.store.mutate<Attestation>(
          K_ATTEST + attestationId,
          (prev) =>
            prev!.value.state === 'computing' || prev!.value.state === 'failed'
              ? { ...prev!.value, state: 'ready' as const, updatedAt: this.now() }
              : prev!.value,
          env.version,
        );
        if (!done.ok) continue; // 并发改动，重读
        return this.store.get<Attestation>(K_ATTEST + attestationId)!.value;
      }

      const stage = STAGES[idx];
      const outputs: StageOutputs = att.checkpoint?.payload ?? {};
      const prevAttempts = att.checkpoint?.stageAttempts ?? {};
      const attempt = (prevAttempts[stage] ?? 0) + 1;
      this.onStage?.(attestationId, stage, attempt);

      const nextPayload = await this.executeStage(stage, outputs, att);

      const res = this.store.mutate<Attestation>(
        K_ATTEST + attestationId,
        (prev) => {
          const cur = prev!.value;
          const cp = cur.checkpoint!;
          return {
            ...cur,
            ...(stage === 'seal' ? { proofHash: nextPayload.proofHash } : {}),
            ...(stage === 'assemble' ? { report: nextPayload.report, findings: nextPayload.findings } : {}),
            checkpoint: {
              stage: idx + 1 < STAGES.length ? STAGES[idx + 1] : stage,
              completedIndex: idx,
              stageAttempts: { ...prevAttempts, [stage]: attempt },
              payload: nextPayload,
              updatedAt: this.now(),
            } satisfies StageCheckpoint,
            updatedAt: this.now(),
          };
        },
        env.version,
        `checkpoint:${stage}`,
      );
      if (!res.ok) continue; // 阶段提交期间被失效/改动，下一轮重读裁决
    }
    throw new Error('证明计算异常：检查点推进超过阶段数');
  }

  /** 各阶段动作。幂等：同样的输入产出同样的结果，所以重放安全。
   *  载荷在检查点中逐阶段累积，恢复时整体带回，因此只要求返回“本阶段的增补”。 */
  private async executeStage(
    stage: StageName,
    out: StageOutputs,
    att: Attestation,
  ): Promise<StageOutputs> {
    const artifact = this.mustHaveArtifact(att.artifactId);
    const evidence = this.mustHaveEvidence(att.evidenceId);

    // 每个阶段执行前都重新核验绑定：无论是首跑还是崩溃恢复，
    // 只要构件指纹 / 证据版本已变，立即中止，绝不产出或封存过期证明。
    if (
      artifact.fingerprint !== att.binding.artifactFingerprint ||
      evidence.version !== att.binding.evidenceVersion
    ) {
      throw new AttestationStaleError(`${stage} 阶段发现来源已变化，本次证明作废`);
    }

    switch (stage) {
      case 'collect': {
        // “阶段执行中途失败”：阶段动作已开始，但在产出检查点前崩溃。
        // 属于本阶段的一次真实尝试（计数），检查点停在上一个完整阶段。
        this.store.mayFault(`stage:${stage}`, 'stage');
        return { ...out, snapshot: { artifact, evidence } };
      }
      default: {
        this.store.mayFault(`stage:${stage}`, 'stage');
        break;
      }
    }

    switch (stage) {
      case 'analyze': {
        const snapshot = out.snapshot!;
        const findings: string[] = [
          `构件 ${snapshot.artifact.name}@${snapshot.artifact.version} 指纹 ${snapshot.artifact.fingerprint!.slice(0, 12)}…`,
          `许可证 ${snapshot.evidence.license}（证据 v${snapshot.evidence.version}，${snapshot.evidence.entries.length} 条材料）`,
        ];
        if (snapshot.evidence.risk === 'notice') findings.push('再发布需保留版权与许可声明');
        if (snapshot.evidence.risk === 'copyleft') findings.push('Copyleft 义务可能与闭源分发冲突');
        if (snapshot.evidence.risk === 'unknown') findings.push('许可证不明，禁止放行直至补齐证据');
        return { ...out, findings };
      }
      case 'policy': {
        const snapshot = out.snapshot!;
        const reasons: string[] = [];
        if (snapshot.evidence.risk === 'copyleft') reasons.push('copyleft 分发限制');
        if (snapshot.evidence.entries.length === 0) reasons.push('缺少证据材料');
        if (snapshot.evidence.risk === 'unknown') reasons.push('许可证未知');
        return { ...out, decision: { gating: reasons.length === 0, reasons } };
      }
      case 'assemble': {
        const snapshot = out.snapshot!;
        const decision = out.decision!;
        const findings = out.findings!;
        const report = [
          `# 合规证明（计算稿）`,
          ``,
          `- 构件：${snapshot.artifact.name}@${snapshot.artifact.version}`,
          `- 构件指纹：${snapshot.artifact.fingerprint}`,
          `- 证据版本：v${snapshot.evidence.version}`,
          `- 绑定哈希：${att.binding.bindingHash}`,
          `- 策略结论：${decision.gating ? '可放行' : '不予放行：' + decision.reasons.join('、')}`,
          ``,
          ...findings.map((f) => `- ${f}`),
        ].join('\n');
        return { ...out, report };
      }
      case 'seal': {
        // 封存前最后一道闸：重新核验绑定。
        // 计算（或崩溃恢复）期间来源若已变化，绝不能封存出旧内容的“完整证明”。
        if (
          artifact.fingerprint !== att.binding.artifactFingerprint ||
          evidence.version !== att.binding.evidenceVersion
        ) {
          throw new AttestationStaleError('seal 阶段发现来源已变化，拒绝封存过期证明');
        }
        // 封存：最终证明哈希覆盖绑定、发现与策略结论。
        // 在此之前 attestation.proofHash 为空——不存在“完整证明”。
        const proofHash = await sha256Hex({
          bindingHash: att.binding.bindingHash,
          findings: out.findings!,
          decision: out.decision!,
          report: out.report!,
        });
        return { ...out, proofHash };
      }
    }
  }

  // ---------------------------------------------------------------- 双人复核签署

  /**
   * 复核人提交签署。
   * - computing（重算中）：拒绝，回执 REJECTED_RECOMPUTING
   * - 绑定哈希对不上（签的是旧内容）：拒绝
   * - 同一复核人重复签：拒绝
   * 两位不同复核人并发提交时，CAS 只保留先到的一份，
   * 后到者拿回 conflict：先到签署（含意见）+ 冲突说明。
   * 第二份签署落盘后证明自动 sealed（state=signed）。
   */
  async submitReview(input: {
    attestationId: string;
    reviewerId: string;
    opinion: 'approve' | 'reject';
    comment: string;
    /** 复核人签署时所认定的绑定哈希 */
    bindingHash: string;
  }): Promise<ConcurrentReviewResult> {
    const key = K_ATTEST + input.attestationId;
    const env = this.store.get<Attestation>(key);
    if (!env) {
      return { ok: false, code: 'NOT_FOUND', message: '证明不存在' };
    }
    const att0 = env.value;

    const rejection = this.validateReview(att0, input);
    if (rejection) return rejection;

    // 读校验 与 提交写入 是两次独立的存储访问（真实系统中跨网络 / 磁盘）。
    // 在这里让出一次事件循环，两位复核人的并发提交在此交错，
    // 最终由下面的 CAS（env.version）裁决先到者。
    await Promise.resolve();

    const signature: ReviewSignature = {
      reviewerId: input.reviewerId,
      opinion: input.opinion,
      comment: input.comment,
      bindingHash: input.bindingHash,
      signedAt: this.now(),
    };

    const res = this.store.mutate<Attestation>(
      key,
      (prev) => {
        const cur = prev!.value;
        return {
          ...cur,
          signatures: [...cur.signatures, signature],
          ...(cur.signatures.length + 1 >= 2 ? { state: 'signed' as const } : {}),
          updatedAt: this.now(),
        };
      },
      env.version,
    );

    if (!res.ok) {
      // CAS 失败：先到者已经写入。取回先到签署，形成冲突回执。
      const winner = res.current!.value;
      // 先到的那一份 = 自己读取（att0）之后新落盘的签署；取增量的最后一个
      const priorIds = new Set(att0.signatures.map((s) => s.reviewerId));
      const accepted =
        [...winner.signatures].reverse().find((s) => !priorIds.has(s.reviewerId)) ??
        winner.signatures[winner.signatures.length - 1];

      if (accepted) {
        const message = `两位复核人同时提交签署：先到的一份（复核人 ${accepted.reviewerId}，意见「${
          accepted.opinion === 'approve' ? '同意' : '驳回'
        }」）已保留；后到提交已退回，请取回先到意见、协调一致后再提交。`;
        return {
          ok: false,
          code: 'REVIEW_CONFLICT' as const,
          message,
          conflict: {
            code: 'REVIEW_CONFLICT',
            message,
            accepted,
            rejected: { reviewerId: input.reviewerId, opinion: input.opinion, comment: input.comment },
          },
        };
      }
      // 其它并发变化（例如来源变更导致失效），按当前状态重新裁决
      return this.validateReview(winner, input) ?? {
        ok: false,
        code: 'ALREADY_SIGNED',
        message: '证明签署状态已变化',
        attestation: winner,
      };
    }

    const att = res.envelope.value;
    return { ok: true, attestation: att, sealed: att.state === 'signed' };
  }

  private validateReview(
    att: Attestation,
    input: { reviewerId: string; bindingHash: string },
  ): SubmitReviewResult | null {
    if (att.state === 'computing' || att.state === 'failed') {
      return {
        ok: false,
        code: 'REJECTED_RECOMPUTING',
        message:
          att.state === 'computing'
            ? '证明正在重算，重算期间的确认已被拒绝；请等待新证明封存后再签署。'
            : '证明上一轮计算失败，请等待重算完成后再签署。',
        attestation: att,
      };
    }
    if (att.state === 'invalidated' || att.state === 'superseded') {
      return {
        ok: false,
        code: 'INVALIDATED',
        message: '证明绑定的来源已变化并失效，旧证明不再接受签署。',
        attestation: att,
      };
    }
    if (att.state === 'legacy') {
      return {
        ok: false,
        code: 'LEGACY_NOT_GATING',
        message: '该证明由旧数据迁移而来，仅供历史查询，不能作为放行依据。',
        attestation: att,
      };
    }
    if (att.state === 'signed') {
      return { ok: false, code: 'ALREADY_SIGNED', message: '两份签署已齐备。', attestation: att };
    }
    if (att.binding.bindingHash !== input.bindingHash) {
      return {
        ok: false,
        code: 'STALE_BINDING',
        message: '签署内容与证明当前绑定不一致，可能是过期页面，请刷新后重试。',
        attestation: att,
      };
    }
    if (att.signatures.some((s) => s.reviewerId === input.reviewerId)) {
      return {
        ok: false,
        code: 'DUPLICATE_REVIEWER',
        message: '同一复核人不能重复签署。',
        attestation: att,
      };
    }
    return null;
  }

  // ---------------------------------------------------------------- 查询 / 历史

  getAttestation(id: string): Attestation | undefined {
    return this.store.get<Attestation>(K_ATTEST + id)?.value;
  }

  /**
   * 历史证明查询：失效、被取代、legacy 的证明全部保留可查，
   * 沿 predecessor / successor 串成演进链。
   */
  listHistory(filter?: { artifactId?: string; includeLegacy?: boolean }): Attestation[] {
    return this.store
      .list<Attestation>(K_ATTEST)
      .map((x) => x.envelope.value)
      .filter((a) => (filter?.artifactId ? a.artifactId === filter.artifactId : true))
      .filter((a) => (filter?.includeLegacy === false ? !a.legacy : true))
      .sort((a, b) => a.createdAt - b.createdAt);
  }

  /** 当前唯一可作为放行依据的证明（signed 且绑定仍有效） */
  getGatingAttestation(artifactId: string): Attestation | undefined {
    return this.store
      .list<Attestation>(K_ATTEST)
      .map((x) => x.envelope.value)
      .find(
        (a) =>
          a.artifactId === artifactId &&
          a.state === 'signed' &&
          !a.legacy &&
          this.bindingStillFresh(a),
      );
  }

  private bindingStillFresh(att: Attestation): boolean {
    const artifact = this.getArtifact(att.artifactId);
    const evidence = this.getEvidence(att.evidenceId);
    return (
      !!artifact?.fingerprint &&
      artifact.fingerprint === att.binding.artifactFingerprint &&
      !!evidence &&
      evidence.version === att.binding.evidenceVersion
    );
  }

  // ---------------------------------------------------------------- 崩溃恢复

  /**
   * 进程重启后调用：丢弃残留临时写（store 重启时已完成），
   * 从最后一个完整检查点恢复所有未完成证明，只补未完成阶段。
   */
  async recover(): Promise<{ resumed: string[]; aborted: string[] }> {
    const resumed: string[] = [];
    const aborted: string[] = [];
    for (const { envelope } of this.store.list<Attestation>(K_ATTEST)) {
      const att = envelope.value;
      if (att.state !== 'computing') continue;
      try {
        await this.runStages(att.id);
        resumed.push(att.id);
      } catch (e) {
        if (e instanceof AttestationStaleError) {
          // 来源在崩溃期间已漂移：把这份不完整证明标记失效，避免再次被误续跑
          const key = K_ATTEST + att.id;
          const cur = this.store.get<Attestation>(key)!;
          if (cur.value.state === 'computing') {
            this.store.mutate<Attestation>(
              key,
              (prev) => ({
                ...prev!.value,
                state: 'invalidated',
                invalidatedAt: this.now(),
                invalidReason: '恢复时发现绑定来源已变化，未封存的计算结果作废',
                updatedAt: this.now(),
              }),
              cur.version,
            );
          }
          aborted.push(att.id);
        } else {
          throw e;
        }
      }
    }
    return { resumed, aborted };
  }

  // ---------------------------------------------------------------- 旧数据升级

  /**
   * 旧数据升级（幂等，可反复执行）：
   *  - 构件缺少 fingerprint 的，按当前内容回填，revision 保持不变；
   *  - 旧证明：绑定不完整的标记 legacy 保留可查，不作放行依据；
   *  - 绑定完整的历史证明，若与当前来源一致则保留其历史状态。
   */
  async migrateLegacy(
    legacyArtifacts: Array<Partial<Artifact> & { id: string; name: string; version: string; source: string }>,
    legacyAttestations: Array<{
      id: string;
      artifactId: string;
      evidenceId?: string;
      report?: string;
      signedAt: number;
    }>,
  ): Promise<{ backfilledArtifacts: string[]; legacyAttestations: string[] }> {
    const backfilledArtifacts: string[] = [];

    for (const input of legacyArtifacts) {
      const key = K_ARTIFACT + input.id;
      const existing = this.store.get<Artifact>(key)?.value;
      const fingerprint = await sha256Hex(fingerprintArtifactInput(input));
      if (existing?.fingerprint) continue; // 已回填过：迁移幂等

      const artifact: Artifact = existing ?? {
        id: input.id,
        name: input.name,
        version: input.version,
        source: input.source,
        revision: input.revision ?? 1,
        createdAt: input.createdAt ?? this.now(),
        updatedAt: this.now(),
      };
      const next: Artifact = { ...artifact, fingerprint };
      this.store.mutate(key, () => next);
      backfilledArtifacts.push(input.id);
    }

    const migrated: string[] = [];
    for (const legacy of legacyAttestations) {
      const key = K_ATTEST + legacy.id;
      if (this.store.get(key)) continue; // 迁移幂等，历史证明不覆盖

      const artifact = this.getArtifact(legacy.artifactId);
      const evidence = legacy.evidenceId ? this.getEvidence(legacy.evidenceId) : undefined;
      const hasFullBinding =
        !!artifact?.fingerprint && !!evidence && !!legacy.evidenceId;

      const att: Attestation = {
        id: legacy.id,
        artifactId: legacy.artifactId,
        evidenceId: legacy.evidenceId ?? 'legacy:unknown',
        binding: hasFullBinding
          ? {
              artifactFingerprint: artifact!.fingerprint!,
              evidenceVersion: evidence!.version,
              bindingHash: await computeBindingHash({
                artifactFingerprint: artifact!.fingerprint!,
                evidenceVersion: evidence!.version,
                evidenceFingerprint: fingerprintEvidenceInput(evidence!),
              }),
            }
          : {
              // 旧证明没有可信绑定：回填占位指纹并明确标记，不允许进入任何放行路径
              artifactFingerprint: artifact?.fingerprint ?? 'legacy:fingerprint-unavailable',
              evidenceVersion: evidence?.version ?? 0,
              bindingHash: 'legacy:binding-unavailable',
            },
        state: 'legacy',
        signatures: [],
        report: legacy.report,
        legacy: true,
        createdAt: legacy.signedAt,
        updatedAt: this.now(),
      };
      this.store.mutate(key, () => att);
      migrated.push(legacy.id);
    }

    return { backfilledArtifacts: backfilledArtifacts, legacyAttestations: migrated };
  }

  // ---------------------------------------------------------------- 内部

  private mustHaveArtifact(id: string): Artifact {
    const a = this.store.get<Artifact>(K_ARTIFACT + id)?.value;
    if (!a) throw new Error(`构件不存在: ${id}`);
    if (!a.fingerprint) throw new Error(`构件缺少指纹，请先执行旧数据迁移: ${id}`);
    return a;
  }

  private mustHaveEvidence(id: string): Evidence {
    const e = this.store.get<Evidence>(K_EVIDENCE + id)?.value;
    if (!e) throw new Error(`证据不存在: ${id}`);
    return e;
  }
}
