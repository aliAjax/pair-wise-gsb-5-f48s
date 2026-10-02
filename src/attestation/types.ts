// 可恢复合规证明流程的领域模型

/** 构件（清单中的一条，例如一个第三方依赖） */
export interface Artifact {
  id: string;
  name: string;
  version: string;
  license: string;
  source: string;
  /** 来源定位：仓库地址 / 下载地址 / 构件坐标，属于指纹输入 */
  origin: string;
  /** 构件指纹：对指纹输入做规范化哈希；旧数据迁移前为 undefined */
  fingerprint?: string;
  /** 指纹算法版本，便于日后更换算法 */
  fpAlgorithm: string;
  risk: 'ok' | 'warn' | 'risk';
  note: string;
  updatedAt: number;
}

/** 许可证证据（与构件清单分开维护，可独立补齐） */
export interface Evidence {
  id: string;
  artifactId: string;
  kind: 'license-file' | 'scan-report' | 'manual-review';
  /** 证据正文 / 摘要 */
  body: string;
  reviewer: string;
  /** 证据内容版本：内容寻址，正文一改版本立即变化 */
  version: string;
  updatedAt: number;
}

export type StepKey = 'collect' | 'evaluate' | 'sign-primary' | 'sign-secondary' | 'finalize';

export type StepState = 'pending' | 'done' | 'skipped' | 'failed';

export interface PipelineStep {
  key: StepKey;
  label: string;
  state: StepState;
  /** 写入序号，恢复时据此判断哪些步骤已经完整落盘 */
  seq: number;
  at?: number;
  detail?: string;
}

export type AttestationStatus =
  | 'recomputing' // 来源已变，旧证明失效，新证明重算中
  | 'awaiting-signatures' // 收集与评估完成，等待两名复核人签署
  | 'finalized' // 两份签署一致，证明生效
  | 'rejected' // 两份签署冲突，证明被拒
  | 'superseded' // 来源变化后失效的历史证明（仍可查询）
  | 'historical'; // 旧数据迁移而来的历史证明（回填前无指纹）

export interface Signature {
  reviewer: string;
  verdict: 'approve' | 'reject';
  opinion: string;
  /** 提交时复核人看到的来源指纹/证据版本 */
  seenFingerprint: string;
  seenEvidenceVersion: string;
  at: number;
}

export interface AuditEvent {
  at: number;
  kind:
    | 'created'
    | 'invalidated'
    | 'reconfirm-rejected'
    | 'step-done'
    | 'signed'
    | 'conflict'
    | 'write-failed'
    | 'write-recovered'
    | 'migrated';
  message: string;
  attestationId?: string;
  artifactId?: string;
}

/** 证明：绑定构件指纹 + 证据版本 */
export interface Attestation {
  id: string;
  artifactId: string;
  /** 证明锚定的构件指纹。旧历史证明为 'unknown(legacy)' */
  boundFingerprint: string;
  /** 证明锚定的证据版本（可能为多份证据，存哈希拼接） */
  boundEvidenceVersion: string;
  status: AttestationStatus;
  steps: PipelineStep[];
  signatures: Signature[];
  /** 被哪一份新证明取代（superseded 时） */
  supersededBy?: string;
  /** 使本证明失效的原因 */
  invalidateReason?: string;
  issueNo: number; // 同一构件的第几版证明
  createdAt: number;
  updatedAt: number;
  finalDigest?: string;
  legacy?: boolean;
  /** 绑定来源已落后于当前构件/证据，重算完成前不得作为放行依据 */
  stale?: boolean;
  /** 重算期间的写入是否还有未恢复的中断 */
  writeInterrupted?: boolean;
}

export interface StoreState {
  schemaVersion: number;
  artifacts: Artifact[];
  evidence: Evidence[];
  attestations: Attestation[];
  events: AuditEvent[];
  seq: number; // 全局写入序号
  /** 预写日志：记录中断的多步写入，恢复据此定位“最后完整证明” */
  wal: PendingWrite[];
  /** 并发槽占用（运行时态：同一签署位的并行请求只放行先到者，不持久化） */
  slotLocks: Record<string, string>;
}

export type Result<T = void> =
  | { ok: true; value: T }
  | { ok: false; error: string; code: ErrorCode; conflict?: ConflictInfo };

export type ErrorCode =
  | 'NOT_FOUND'
  | 'STALE_SIGNATURE' // 签署基于过期来源
  | 'RECOMPUTING' // 重算期间再次确认
  | 'ALREADY_SIGNED' // 该复核人已签
  | 'ATT_NO_LONGER_OPEN' // 证明已失效/生效，不能签
  | 'WRITE_FAILED'; // 模拟写入失败

export interface ConflictInfo {
  /** 先到的签署 */
  winner: Signature;
  /** 后到者自己的签署意见（原样退回） */
  loser: Signature;
  reason: string;
}

export interface PendingWrite {
  /** 预写日志：本次多步写入已完整落盘的最后序号 */
  lastCompleteSeq: number;
  /** 中断在哪个步骤 */
  failedStep: StepKey;
  attestationId: string;
  artifactId: string;
  at: number;
}
