/**
 * 持久层：模拟“写入中途失败”的两阶段键值存储。
 *
 * 写入协议（模拟原子改名 rename 落盘）：
 *   1. put(key, value) 先把内容写到临时键 `key + '.__tmp__'`；
 *   2. 再原子地用临时内容替换正式键，并删除临时键。
 *
 * 故障可注入在两个位置：
 *   - 'stage'  某个阶段动作本身失败（检查点尚未写入，重试该阶段）
 *   - 'commit' 检查点 / 记录落盘中途失败（临时键残留，正式键保持上一个完整版本）
 *
 * 重启（simulateCrashAndRestart）会丢弃所有残留临时键：
 * 上一个“完整证明”永远在正式键里，恢复后只补未完成阶段。
 */

export interface StoredEnvelope<T = unknown> {
  version: number; // 单调版本号，用于 CAS
  updatedAt: number;
  value: T;
}

export type FaultPoint = 'stage' | 'commit';

export interface FaultRule {
  /** 命中的键前缀或阶段名（按顺序匹配第一个） */
  match: string | RegExp;
  point: FaultPoint;
  /** 命中后剩余触发次数；默认 1 次 */
  times?: number;
}

export class CommitFaultError extends Error {
  constructor(public key: string) {
    super(`写入中途失败（提交阶段）: ${key}`);
    this.name = 'CommitFaultError';
  }
}

export class StageFaultError extends Error {
  constructor(public stage: string) {
    super(`写入中途失败（阶段执行）: ${stage}`);
    this.name = 'StageFaultError';
  }
}

const TMP_SUFFIX = '.__tmp__';

export class DurableStore {
  private data = new Map<string, StoredEnvelope>();
  private tmp = new Map<string, StoredEnvelope>();
  private faults: FaultRule[] = [];
  private now: () => number;

  /** 重启计数：引擎可据此做一次启动恢复 */
  private generation = 0;

  constructor(now: () => number = () => Date.now()) {
    this.now = now;
  }

  /** 注入一次或多次写入故障（用于测试 / 演练） */
  injectFault(rule: FaultRule): void {
    this.faults.push({ times: 1, ...rule });
  }

  private consumeFault(label: string, point: FaultPoint): boolean {
    for (let i = 0; i < this.faults.length; i++) {
      const rule = this.faults[i];
      const m = rule.match instanceof RegExp ? rule.match.test(label) : label.includes(rule.match);
      if (m && rule.point === point && (rule.times ?? 1) > 0) {
        rule.times = (rule.times ?? 1) - 1;
        if (rule.times <= 0) this.faults.splice(i, 1);
        return true;
      }
    }
    return false;
  }

  /** 在“非写入动作”（如阶段执行）上触发已注入的故障 */
  mayFault(label: string, point: FaultPoint): void {
    if (this.consumeFault(label, point)) {
      throw point === 'stage' ? new StageFaultError(label) : new CommitFaultError(label);
    }
  }

  /** 原子读改写（CAS）。
   * expectedVersion 非空时，只有当前版本号匹配才允许提交；
   * 版本号不匹配返回 {ok:false, conflict:true, current} —— 双人并发签署靠它裁决。
   */
  mutate<T>(
    key: string,
    fn: (prev: StoredEnvelope<T> | undefined) => T,
    expectedVersion?: number,
    /** 故障匹配标签：检查点提交可携带阶段名，便于把故障精确注入到“某阶段的写入” */
    faultLabel?: string,
  ): { ok: true; envelope: StoredEnvelope<T> } | { ok: false; conflict: true; current: StoredEnvelope<T> | undefined } {
    const prev = this.data.get(key) as StoredEnvelope<T> | undefined;
    if (expectedVersion !== undefined && prev && prev.version !== expectedVersion) {
      return { ok: false, conflict: true, current: prev };
    }
    if (expectedVersion !== undefined && !prev && expectedVersion !== 0) {
      return { ok: false, conflict: true, current: prev };
    }

    const label = faultLabel ?? key;

    // 阶段执行故障：发生在任何写入之前，正式数据完全不变
    if (this.consumeFault(label, 'stage')) throw new StageFaultError(label);

    const nextValue = fn(prev);
    const envelope: StoredEnvelope<T> = {
      version: prev ? prev.version + 1 : 1,
      updatedAt: this.now(),
      value: nextValue,
    };

    // 1) 写临时键
    this.tmp.set(key + TMP_SUFFIX, envelope as StoredEnvelope);
    // 2) 提交前故障：临时键残留，正式键保持旧值
    if (this.consumeFault(label, 'commit')) throw new CommitFaultError(key);
    // 3) 原子替换
    this.data.set(key, envelope as StoredEnvelope);
    this.tmp.delete(key + TMP_SUFFIX);

    return { ok: true, envelope };
  }

  get<T>(key: string): StoredEnvelope<T> | undefined {
    return this.data.get(key) as StoredEnvelope<T> | undefined;
  }

  /** 列出某前缀下全部正式键的当前值（临时键永不出现） */
  list<T>(prefix: string): { key: string; envelope: StoredEnvelope<T> }[] {
    const out: { key: string; envelope: StoredEnvelope<T> }[] = [];
    for (const [key, env] of this.data.entries()) {
      if (key.startsWith(prefix)) out.push({ key, envelope: env as StoredEnvelope<T> });
    }
    return out;
  }

  /** 有多少未提交的临时键残留（故障后可观测） */
  pendingTempKeys(): string[] {
    return [...this.tmp.keys()];
  }

  /**
   * 模拟进程崩溃后重启：
   * 丢弃所有未完成的临时写入；已提交的正式数据完好。
   */
  simulateCrashAndRestart(): void {
    this.tmp.clear();
    this.faults = [];
    this.generation += 1;
  }

  getGeneration(): number {
    return this.generation;
  }
}
