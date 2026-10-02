import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as eng from './engine';
import { freshState, legacyV1State } from './seed';
import type { Attestation, ConflictInfo, Result, StoreState } from './types';

function setup(): StoreState {
  const s = freshState();
  eng.migrate(s);
  return s;
}
function expectErr<T>(r: Result<T>): { code: string; conflict?: ConflictInfo } {
  assert.equal(r.ok, false);
  if (r.ok) throw new Error('unreachable');
  return r;
}
function expectOk<T>(r: Result<T>): T {
  assert.equal(r.ok, true);
  if (!r.ok) throw new Error('unreachable');
  return r.value;
}
function newest(s: StoreState, id: string): Attestation {
  return eng.attestationsOf(s, id)[0];
}

test('初始证明：收集+评估后等待双签，双签一致才生效；重算期间确认被拒', () => {
  const s = setup();
  const att = eng.invalidateForSourceChange(s, 'react', '初始化', 1000)!;
  assert.equal(att.status, 'recomputing');
  // 自动阶段未跑完时确认被拒
  assert.equal(expectErr(eng.reconfirm(s, att.id)).code, 'RECOMPUTING');
  // 同一来源重复触发重算不会产生重复证明
  assert.equal(eng.invalidateForSourceChange(s, 'react', '再次评估', 1002)!.id, att.id);
  const advanced = expectOk(eng.advanceAutomated(s, att.id, { now: 1001 }));
  assert.equal(advanced.status, 'awaiting-signatures');

  const fp = s.artifacts.find((a) => a.id === 'react')!.fingerprint!;
  const ev = eng.boundEvidenceVersionOf(s.evidence, 'react');
  let sign = eng.submitSignature(s, att.id, { reviewer: 'A', verdict: 'approve', opinion: 'ok', seenFingerprint: fp, seenEvidenceVersion: ev }, 1004);
  assert.equal(expectOk(sign).status, 'awaiting-signatures');
  sign = eng.submitSignature(s, att.id, { reviewer: 'B', verdict: 'approve', opinion: 'ok', seenFingerprint: fp, seenEvidenceVersion: ev }, 1005);
  const done = expectOk(sign);
  assert.equal(done.status, 'finalized');
  assert.ok(done.finalDigest);
});

test('来源一变旧证明立即失效，重算期间确认/签署被拒', () => {
  const s = setup();
  const a1 = eng.invalidateForSourceChange(s, 'hljs', '初始化', 2000)!;
  eng.advanceAutomated(s, a1.id, { now: 2001 });
  const fp = s.artifacts.find((x) => x.id === 'hljs')!.fingerprint!;
  const ev = eng.boundEvidenceVersionOf(s.evidence, 'hljs');
  eng.submitSignature(s, a1.id, { reviewer: 'A', verdict: 'approve', opinion: 'x', seenFingerprint: fp, seenEvidenceVersion: ev }, 2002);
  eng.submitSignature(s, a1.id, { reviewer: 'B', verdict: 'approve', opinion: 'x', seenFingerprint: fp, seenEvidenceVersion: ev }, 2003);
  assert.equal(newest(s, 'hljs').status, 'finalized');

  // 构件替换（版本与来源地址变更）
  eng.replaceArtifact(s, { id: 'hljs', version: '11.11.0', origin: 'https://registry.npmjs.org/highlight.js/11.11.0' }, 2004);
  const old = s.attestations.find((x) => x.id === a1.id)!;
  const next = newest(s, 'hljs');
  assert.equal(old.status, 'superseded');
  assert.equal(old.stale, true);
  assert.equal(old.supersededBy, next.id);
  assert.equal(next.status, 'recomputing');
  assert.notEqual(next.boundFingerprint, fp);

  // 对旧证明确认 -> 拒绝；对新证明确认（重算中）-> 拒绝；签署 -> 拒绝
  assert.equal(expectErr(eng.reconfirm(s, old.id)).code, 'ATT_NO_LONGER_OPEN');
  assert.equal(expectErr(eng.reconfirm(s, next.id)).code, 'RECOMPUTING');
  const sign = eng.submitSignature(s, next.id, { reviewer: 'A', verdict: 'approve', opinion: 'x', seenFingerprint: next.boundFingerprint, seenEvidenceVersion: next.boundEvidenceVersion }, 2005);
  assert.equal(expectErr(sign).code, 'RECOMPUTING');
});

test('证据补齐使证明失效重算；旧证据版本的签署被视为过期', () => {
  const s = setup();
  const a1 = eng.invalidateForSourceChange(s, 'legacy-parser', '初始化', 3000)!;
  eng.advanceAutomated(s, a1.id, { now: 3001 });
  const fp0 = s.artifacts.find((x) => x.id === 'legacy-parser')!.fingerprint!;
  const ev0 = eng.boundEvidenceVersionOf(s.evidence, 'legacy-parser');
  eng.upsertEvidence(s, { id: 'ev-legacy-manual', artifactId: 'legacy-parser', kind: 'manual-review', body: '法务复核：已隔离为独立进程，可接受。', reviewer: 'Chen Shen' }, 3002);
  const next = newest(s, 'legacy-parser');
  assert.equal(next.status, 'recomputing');
  // 重算未跑完：优先被 RECOMPUTING 拦截
  assert.equal(
    expectErr(eng.submitSignature(s, next.id, { reviewer: 'A', verdict: 'approve', opinion: 'x', seenFingerprint: fp0, seenEvidenceVersion: ev0 }, 3003)).code,
    'RECOMPUTING',
  );
  eng.advanceAutomated(s, next.id, { now: 3004 });
  const ev1 = eng.boundEvidenceVersionOf(s.evidence, 'legacy-parser');
  // 自动阶段跑完后，旧证据版本签署 -> STALE_SIGNATURE
  assert.equal(
    expectErr(eng.submitSignature(s, next.id, { reviewer: 'A', verdict: 'approve', opinion: 'x', seenFingerprint: fp0, seenEvidenceVersion: ev0 }, 3005)).code,
    'STALE_SIGNATURE',
  );
  assert.ok(eng.submitSignature(s, next.id, { reviewer: 'A', verdict: 'approve', opinion: 'x', seenFingerprint: fp0, seenEvidenceVersion: ev1 }, 3006).ok);
});

test('两个复核人同时提交：保留先到，后到者拿回意见与冲突；落败后仍可走第二签署位', () => {
  const s = setup();
  const a = eng.invalidateForSourceChange(s, 'react', '初始化', 4000)!;
  eng.advanceAutomated(s, a.id, { now: 4001 });
  const fp = s.artifacts.find((x) => x.id === 'react')!.fingerprint!;
  const ev = eng.boundEvidenceVersionOf(s.evidence, 'react');
  const token = 'slot-1';
  assert.ok(eng.submitSignature(s, a.id, { reviewer: 'A', verdict: 'approve', opinion: 'MIT 无异议', seenFingerprint: fp, seenEvidenceVersion: ev, slotToken: token }, 4002).ok);
  const lost = expectErr(
    eng.submitSignature(s, a.id, { reviewer: 'B', verdict: 'approve', opinion: '我也同意', seenFingerprint: fp, seenEvidenceVersion: ev, slotToken: token }, 4003),
  );
  assert.equal(lost.code, 'ALREADY_SIGNED');
  assert.equal(lost.conflict!.winner.reviewer, 'A');
  assert.equal(lost.conflict!.winner.opinion, 'MIT 无异议');
  assert.equal(lost.conflict!.loser.opinion, '我也同意');
  assert.equal(a.signatures.length, 1); // 只保留先到
  // B 阅读意见后走第二签署位
  const done = expectOk(eng.submitSignature(s, a.id, { reviewer: 'B', verdict: 'approve', opinion: '已阅 A 的意见，同意', seenFingerprint: fp, seenEvidenceVersion: ev }, 4004));
  assert.equal(done.status, 'finalized');
  // 生效后再提交 -> 证明不再开放
  assert.equal(
    expectErr(eng.submitSignature(s, a.id, { reviewer: 'A', verdict: 'reject', opinion: '反悔', seenFingerprint: fp, seenEvidenceVersion: ev }, 4005)).code,
    'ATT_NO_LONGER_OPEN',
  );
  // 待签署态下，同一复核人重复提交 -> 拿回其先到的签署
  const b = eng.invalidateForSourceChange(s, 'lodash', '初始化', 4006)!;
  eng.advanceAutomated(s, b.id, { now: 4007 });
  const fp2 = s.artifacts.find((x) => x.id === 'lodash')!.fingerprint!;
  const ev2 = eng.boundEvidenceVersionOf(s.evidence, 'lodash');
  eng.submitSignature(s, b.id, { reviewer: 'A', verdict: 'approve', opinion: '先到意见', seenFingerprint: fp2, seenEvidenceVersion: ev2 }, 4008);
  const dup = expectErr(eng.submitSignature(s, b.id, { reviewer: 'A', verdict: 'reject', opinion: '后到意见', seenFingerprint: fp2, seenEvidenceVersion: ev2 }, 4009));
  assert.equal(dup.code, 'ALREADY_SIGNED');
  assert.equal(dup.conflict!.winner.opinion, '先到意见');
  assert.equal(dup.conflict!.loser.opinion, '后到意见');
  assert.equal(b.signatures.length, 1);
});

test('签署意见冲突 -> 证明被拒且不可再确认', () => {
  const s = setup();
  const a = eng.invalidateForSourceChange(s, 'react', '初始化', 5000)!;
  eng.advanceAutomated(s, a.id, { now: 5001 });
  const fp = s.artifacts.find((x) => x.id === 'react')!.fingerprint!;
  const ev = eng.boundEvidenceVersionOf(s.evidence, 'react');
  eng.submitSignature(s, a.id, { reviewer: 'A', verdict: 'approve', opinion: 'ok', seenFingerprint: fp, seenEvidenceVersion: ev }, 5002);
  const done = expectOk(eng.submitSignature(s, a.id, { reviewer: 'B', verdict: 'reject', opinion: '发现额外条款', seenFingerprint: fp, seenEvidenceVersion: ev }, 5003));
  assert.equal(done.status, 'rejected');
  assert.equal(expectErr(eng.reconfirm(s, a.id)).code, 'ATT_NO_LONGER_OPEN');
});

test('写入中途失败：从最后完整证明恢复，只补未完成部分', () => {
  const s = setup();
  const a = eng.invalidateForSourceChange(s, 'react', '初始化', 6000)!;
  // 在 evaluate 步骤注入写入失败
  const failed = expectErr(eng.advanceAutomated(s, a.id, { failAt: 'evaluate', now: 6001 }));
  assert.equal(failed.code, 'WRITE_FAILED');
  assert.equal(s.wal.length, 1);
  assert.equal(s.wal[0].lastCompleteSeq, 1); // collect 已完整落盘
  assert.equal(a.writeInterrupted, true);
  assert.deepEqual(a.steps.map((x) => x.state), ['done', 'failed', 'pending', 'pending', 'pending']);

  // 恢复：跳过 collect，只补 evaluate
  expectOk(eng.recoverInterrupted(s, a.id, 6002));
  assert.equal(s.wal.length, 0);
  assert.equal(a.writeInterrupted, false);
  assert.deepEqual(a.steps.map((x) => x.state), ['done', 'done', 'pending', 'pending', 'pending']);
  const doneLogs = s.events.filter((e) => e.kind === 'step-done').map((e) => e.message);
  assert.equal(doneLogs.filter((m) => m.includes('收集')).length, 1); // collect 没有重跑
  assert.equal(doneLogs.filter((m) => m.includes('评估')).length, 1);

  // 重复恢复是幂等的
  assert.ok(eng.recoverInterrupted(s, a.id, 6003).ok);
  assert.equal(s.events.filter((e) => e.kind === 'write-recovered').length, 1);
});

test('恢复时来源又变过 -> 对最新来源重新锚定', () => {
  const s = setup();
  const a = eng.invalidateForSourceChange(s, 'react', '初始化', 7000)!;
  eng.advanceAutomated(s, a.id, { failAt: 'evaluate', now: 7001 });
  eng.replaceArtifact(s, { id: 'react', version: '19.0.0', origin: 'https://registry.npmjs.org/react/19.0.0' }, 7002);
  const r = expectErr(eng.recoverInterrupted(s, a.id, 7003));
  assert.equal(r.code, 'RECOMPUTING');
  assert.equal(newest(s, 'react').status, 'recomputing');
  assert.equal(s.wal.length, 0);
});

test('旧数据升级：回填指纹与证据版本，历史证明保留可查询', () => {
  const s = legacyV1State();
  assert.equal(s.artifacts[0].fingerprint, undefined);
  assert.equal(s.evidence[0].version, '');
  assert.equal(s.attestations[0].status, 'finalized');
  assert.ok(eng.migrate(s, 8000));
  assert.ok(s.artifacts[0].fingerprint!.startsWith('cyrb53/v1:'));
  assert.ok(s.evidence[0].version.startsWith('cyrb53/v1:'));
  const att = s.attestations[0];
  assert.equal(att.status, 'historical');
  assert.equal(att.legacy, true);
  // 历史证明仍可查询
  assert.equal(eng.attestationsOf(s, 'old-lib')[0].id, 'att-old-lib-1');
  // 迁移幂等
  assert.equal(eng.migrate(s), false);
  // 回填指纹后替换构件：新证明产生，历史证明保留
  const before = s.artifacts[0].fingerprint!;
  eng.replaceArtifact(s, { id: 'old-lib', version: '1.5.0' }, 8001);
  assert.notEqual(s.artifacts[0].fingerprint, before);
  const list = eng.attestationsOf(s, 'old-lib');
  assert.equal(list.length, 2);
  assert.ok(list.some((x) => x.status === 'historical'));
});

test('指纹确定性且来源敏感', () => {
  const s = setup();
  const a = s.artifacts[0];
  const f1 = eng.computeArtifactFingerprint(a);
  assert.equal(f1, eng.computeArtifactFingerprint(a));
  assert.notEqual(eng.computeArtifactFingerprint({ ...a, origin: 'http://changed' }), f1);
  const e = s.evidence[0];
  const v1 = eng.computeEvidenceVersion(e);
  assert.notEqual(eng.computeEvidenceVersion({ ...e, body: e.body + ' 更新' }), v1);
});
