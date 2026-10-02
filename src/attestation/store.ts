// 状态容器：localStorage 持久化、启动迁移、订阅通知。
// 领域操作以事务方式执行（深拷贝草稿 -> engine 纯逻辑 -> 原子提交）。
import * as engine from './engine';
import { freshState, legacyV1State } from './seed';
import type { Result, StoreState } from './types';

const KEY = 'license-lens-attestation-v2';
const listeners = new Set<() => void>();

function clone<T>(v: T): T {
  return structuredClone(v);
}

function load(): StoreState {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as StoreState;
      if (!parsed.wal) parsed.wal = [];
      parsed.slotLocks = {}; // 并发槽为运行时态，重启后不继承
      engine.migrate(parsed);
      return parsed;
    }
  } catch {
    /* 损坏数据退回初始态 */
  }
  const init = freshState();
  engine.migrate(init);
  return init;
}

let state: StoreState = load();

function persist(): void {
  // 并发槽锁是进程内运行时态，不写入持久层
  const { slotLocks: _omit, ...rest } = state;
  localStorage.setItem(KEY, JSON.stringify(rest));
}

export function getState(): StoreState {
  return state;
}

export function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** 在草稿上执行领域操作；返回业务结果（失败不提交、不触发渲染） */
export function commit<T>(fn: (draft: StoreState) => Result<T>): Result<T> {
  const draft = clone(state);
  const result = fn(draft);
  if (result.ok) {
    draft.seq += 1;
    state = draft;
    persist();
    listeners.forEach((l) => l());
  }
  return result;
}

/** 需要把“写入失败”也落盘（WAL 必须真正持久化，否则无法演示恢复） */
export function commitFailure(fn: (draft: StoreState) => Result<unknown>): Result<unknown> {
  const draft = clone(state);
  const result = fn(draft);
  draft.seq += 1;
  state = draft;
  persist();
  listeners.forEach((l) => l());
  return result;
}

export function resetFresh(): void {
  state = freshState();
  engine.migrate(state);
  persist();
  listeners.forEach((l) => l());
}

/** 载入 v1 旧数据并立即触发升级迁移（回填指纹，历史证明保留） */
export function loadLegacyAndMigrate(): void {
  const draft = legacyV1State();
  engine.migrate(draft);
  state = draft;
  persist();
  listeners.forEach((l) => l());
}

export function snapshotForExport(): string {
  return JSON.stringify(state, null, 2);
}
