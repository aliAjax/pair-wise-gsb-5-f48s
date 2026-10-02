/**
 * 合规证明领域模型。
 *
 * 三类对象分开维护：
 *  - Artifact    构件清单（可被替换，指纹随之变化）
 *  - Evidence    许可证证据（可补齐，版本号递增）
 *  - Attestation 合规证明（绑定构件指纹与证据版本，来源一变即失效）
 */

/** 构件许可证风险等级 */
export type RiskLevel = 'permissive' | 'notice' | 'copyleft' | 'unknown';

/** 构件（清单中的一项） */
export interface Artifact {
  id: string;
  name: string;
  version: string;
  source: string;
  /** 构件内容指纹；旧数据可能缺失，由迁移流程回填 */
  fingerprint?: string;
  /** 指纹对应的构件修订号，替换构件时递增 */
  revision: number;
  replacedBy?: string;
  createdAt: number;
  updatedAt: number;
}

/** 许可证证据条目（一条证据：许可证文本 / SBOM / 来源声明……） */
export interface EvidenceEntry {
  kind: string;
  ref: string;
  sha256: string;
}

/** 许可证证据包，补齐后版本号递增 */
export interface Evidence {
  id: string;
  /** 该证据适用的构件 */
  artifactId: string;
  license: string;
  risk: RiskLevel;
  entries: EvidenceEntry[];
  /** 证据版本：每次补齐 / 修订 +1 */
  version: number;
  createdAt: number;
  updatedAt: number;
}

export type AttestationState =
  | 'computing' // 正在重算（分阶段检查点），期间拒绝任何签署确认
  | 'ready' // 计算完成，等待复核人签署
  | 'signed' // 两份签署齐备，证明完整
  | 'invalidated' // 绑定来源已变化（构件替换 / 证据换版），不再放行
  | 'superseded' // 已被后继证明取代（失效后重算生成的新证明）——留给查询用的终态由 invalidated 表达
  | 'failed' // 计算阶段超过重试上限（可再次 request 重跑，仍从检查点恢复）
  | 'legacy'; // 旧数据升级而来：保留可查，但不作为放行依据

/** 单个复核人的签署 */
export interface ReviewSignature {
  reviewerId: string;
  opinion: 'approve' | 'reject';
  comment: string;
  /** 签署时证明内容（绑定哈希），防止签署的是旧内容 */
  bindingHash: string;
  signedAt: number;
}

/** 证明计算的检查点阶段；每完成一个阶段就持久化一次 */
export const STAGES = [
  'collect', // 汇总构件与证据
  'analyze', // 许可证义务分析
  'policy', // 合规策略判定
  'assemble', // 组装证明文档
  'seal', // 封存（生成最终证明哈希）
] as const;

export type StageName = (typeof STAGES)[number];

export interface StageCheckpoint {
  stage: StageName;
  /** 已完成阶段序号 0..STAGES.length-1；-1 表示尚未开始 */
  completedIndex: number;
  /**
   * 各阶段尝试次数（按阶段独立计数）。
   * 恢复重放时只有被重跑的那个阶段计数增长，已完整落盘的阶段不再执行。
   */
  stageAttempts: Partial<Record<StageName, number>>;
  /** 阶段中间产物（seal 之前证明还不完整） */
  payload?: unknown;
  updatedAt: number;
}

/** 合规证明 */
export interface Attestation {
  id: string;
  artifactId: string;
  evidenceId: string;
  /** 绑定：构件指纹 + 证据版本 + 两者内容的绑定哈希 */
  binding: {
    artifactFingerprint: string;
    evidenceVersion: number;
    /** 对 (artifactFingerprint, evidenceVersion, 证据内容) 计算的哈希 */
    bindingHash: string;
  };
  state: AttestationState;
  checkpoint?: StageCheckpoint;
  signatures: ReviewSignature[];
  /** 最终封存哈希，seal 阶段后才有值；此前没有“完整证明” */
  proofHash?: string;
  report?: string;
  findings?: string[];
  /** 失效 / 取代元数据 */
  invalidatedAt?: number;
  invalidReason?: string;
  successorId?: string;
  predecessorId?: string;
  /** 旧数据迁移标记 */
  legacy?: boolean;
  createdAt: number;
  updatedAt: number;
}

/** 签署提交结果 */
export type SubmitReviewResult =
  | {
      ok: true;
      attestation: Attestation;
      /** 两份签署是否齐备 */
      sealed: boolean;
    }
  | {
      ok: false;
      code:
        | 'NOT_FOUND'
        | 'REJECTED_RECOMPUTING' // 重算期间的确认一律拒绝
        | 'STALE_BINDING' // 签署内容与当前绑定不一致
        | 'DUPLICATE_REVIEWER' // 同一复核人重复签署
        | 'ALREADY_SIGNED'
        | 'INVALIDATED'
        | 'LEGACY_NOT_GATING';
      message: string;
      attestation?: Attestation;
    };

/** 并发签署冲突：后到者拿回先到签署与冲突说明 */
export interface ReviewConflict {
  code: 'REVIEW_CONFLICT';
  message: string;
  /** 先到并已保留的那份签署 */
  accepted: ReviewSignature;
  /** 被退回的后到签署 */
  rejected: { reviewerId: string; opinion: 'approve' | 'reject'; comment: string };
}

export type ConcurrentReviewResult =
  | (SubmitReviewResult & { conflict?: undefined })
  | {
      ok: false;
      code: 'REVIEW_CONFLICT';
      message: string;
      conflict: ReviewConflict;
    };
