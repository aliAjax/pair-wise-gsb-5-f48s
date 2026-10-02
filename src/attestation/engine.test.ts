import { describe, expect, it } from 'vitest';
import { AttestationEngine } from './engine';
import { DurableStore, CommitFaultError, StageFaultError } from './store';
import { Artifact, Evidence } from './types';

let clock = 1_700_000_000_000;
const now = () => (clock += 10);

function newEngine() {
  clock = 1_700_000_000_000;
  const store = new DurableStore(now);
  const engine = new AttestationEngine({ store, now, id: (p) => `${p}_${Math.random().toString(36).slice(2, 8)}` });
  return { store, engine };
}

async function seed(engine: AttestationEngine, risk: Evidence['risk'] = 'permissive') {
  const { artifact } = await engine.upsertArtifact({ id: 'a1', name: 'widget', version: '1.0.0', source: 'npm' });
  const evidence = await engine.createEvidence({
    artifactId: 'a1',
    license: 'MIT',
    risk,
    entries: [{ kind: 'license-file', ref: 'LICENSE', sha256: 'e1' }],
  });
  return { artifact, evidence };
}

describe('证明绑定指纹与证据版本：来源一变即失效重算', () => {
  it('正常路径：计算完成 → 两位复核人签署 → 可放行', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const att = await engine.requestAttestation('a1', evidence.id);

    expect(att.state).toBe('ready');
    expect(att.checkpoint?.completedIndex).toBe(4);
    expect(att.proofHash).toMatch(/^[0-9a-f]{64}$/);
    expect(att.report).toContain('合规证明');

    const r1 = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '义务清晰',
      bindingHash: att.binding.bindingHash,
    });
    expect(r1.ok).toBe(true);
    if (r1.ok) expect(r1.sealed).toBe(false);

    const r2 = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-b',
      opinion: 'approve',
      comment: '同意',
      bindingHash: att.binding.bindingHash,
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) {
      expect(r2.sealed).toBe(true);
      expect(r2.attestation.state).toBe('signed');
    }

    expect(engine.getGatingAttestation('a1')?.id).toBe(att.id);
  });

  it('构件被替换（指纹变化）后，旧证明立即失效，后继证明重新计算', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const first = await engine.requestAttestation('a1', evidence.id);

    const { replaced } = await engine.upsertArtifact({
      id: 'a1',
      name: 'widget',
      version: '2.0.0', // 构件替换
      source: 'npm',
    });
    expect(replaced).toBe(true);
    expect(engine.getAttestation(first.id)?.state).toBe('invalidated');
    expect(engine.getGatingAttestation('a1')).toBeUndefined(); // 旧证明不得继续放行

    const second = await engine.requestAttestation('a1', evidence.id);
    expect(second.id).not.toBe(first.id);
    expect(second.state).toBe('ready');
    expect(second.predecessorId).toBe(first.id);
    expect(second.binding.artifactFingerprint).not.toBe(first.binding.artifactFingerprint);

    const old = engine.getAttestation(first.id)!;
    expect(old.successorId).toBe(second.id);
    expect(old.invalidReason).toContain('构件已替换');
  });

  it('证据补齐（版本递增）后旧证明失效，且必须用新证据版本重算', async () => {
    const { engine } = newEngine();
    const { evidence: v1 } = await seed(engine);
    const first = await engine.requestAttestation('a1', v1.id);

    const v2 = await engine.updateEvidence(v1.id, {
      entries: [
        { kind: 'license-file', ref: 'LICENSE', sha256: 'e1' },
        { kind: 'sbom', ref: 'sbom.json', sha256: 'e2' }, // 新补齐的材料
      ],
    });
    expect(v2.version).toBe(2);
    expect(engine.getAttestation(first.id)?.state).toBe('invalidated');

    const second = await engine.requestAttestation('a1', v1.id);
    expect(second.binding.evidenceVersion).toBe(2);
    expect(second.binding.bindingHash).not.toBe(first.binding.bindingHash);
    expect(engine.getAttestation(first.id)?.successorId).toBe(second.id);
  });

  it('重算期间再次确认（签署）一律拒绝', async () => {
    const { store, engine } = newEngine();
    const { evidence } = await seed(engine);

    // 让 assemble 阶段执行失败 → 证明停留在 computing（policy 检查点已落盘）
    store.injectFault({ match: 'stage:assemble', point: 'stage', times: 1 });
    const attPromise = engine.requestAttestation('a1', evidence.id);
    await expect(attPromise).rejects.toBeInstanceOf(StageFaultError);

    const stuck = engine.listHistory({ artifactId: 'a1' })[0];
    expect(stuck.state).toBe('computing');
    expect(stuck.checkpoint?.completedIndex).toBe(2); // collect、analyze、policy 已完成

    const review = await engine.submitReview({
      attestationId: stuck.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '先签了再说',
      bindingHash: stuck.binding.bindingHash,
    });
    expect(review.ok).toBe(false);
    if (!review.ok) expect(review.code).toBe('REJECTED_RECOMPUTING');

    // 对失效的旧证明签署也被拒绝
    await engine.upsertArtifact({ id: 'a1', name: 'widget', version: '9.9.9', source: 'npm' });
    const reviewOld = await engine.submitReview({
      attestationId: stuck.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '',
      bindingHash: stuck.binding.bindingHash,
    });
    expect(reviewOld.ok).toBe(false);
    if (!reviewOld.ok) expect(reviewOld.code).toBe('INVALIDATED');
  });
});

describe('写入中途失败：从最后完整证明恢复，只补未完成部分', () => {
  it('阶段提交前崩溃：正式键停在上一检查点，重启后续跑，已完成阶段不重跑', async () => {
    const { store, engine } = newEngine();
    const stageCalls: string[] = [];
    (engine as unknown as { onStage: (id: string, s: string) => void }).onStage = (_id, s) =>
      stageCalls.push(s);

    const { evidence } = await seed(engine);

    // policy 阶段检查点落盘中途崩溃
    store.injectFault({ match: 'checkpoint:policy', point: 'commit', times: 1 });
    await expect(engine.requestAttestation('a1', evidence.id)).rejects.toBeInstanceOf(CommitFaultError);

    // 临时键残留，正式证明仍停在 policy 之前的完整检查点
    expect(store.pendingTempKeys().length).toBe(1);
    const partial = engine.listHistory({ artifactId: 'a1' })[0];
    expect(partial.state).toBe('computing');
    expect(partial.checkpoint?.completedIndex).toBe(1); // collect、analyze 完整
    expect(partial.checkpoint?.payload).not.toHaveProperty('decision');
    expect(partial.proofHash).toBeUndefined(); // 还没有“完整证明”

    // 崩溃重启：丢弃临时写
    store.simulateCrashAndRestart();
    expect(store.pendingTempKeys()).toEqual([]);

    const { resumed } = await engine.recover();
    expect(resumed).toEqual([partial.id]);

    const recovered = engine.getAttestation(partial.id)!;
    expect(recovered.state).toBe('ready');
    expect(recovered.checkpoint?.completedIndex).toBe(4);
    expect(recovered.proofHash).toMatch(/^[0-9a-f]{64}$/);

    // 恢复后只补未完成部分：collect/analyze 已完整落盘，绝不重跑；
    // policy 的提交中途崩溃，那次执行从未落盘，恢复时重新执行一次（正常）。
    expect(stageCalls).toEqual(['collect', 'analyze', 'policy', 'policy', 'assemble', 'seal']);
    expect(recovered.checkpoint?.stageAttempts).toMatchObject({
      collect: 1,
      analyze: 1,
      policy: 1, // 只有恢复后的这次执行落盘
      assemble: 1,
      seal: 1,
    });
  });

  it('阶段执行本身失败：检查点未动，重试只执行该阶段一次', async () => {
    const { store, engine } = newEngine();
    const stageCalls: string[] = [];
    (engine as unknown as { onStage: (id: string, s: string) => void }).onStage = (_id, s) =>
      stageCalls.push(s);

    const { evidence } = await seed(engine);
    store.injectFault({ match: 'stage:policy', point: 'stage', times: 1 });
    await expect(engine.requestAttestation('a1', evidence.id)).rejects.toBeInstanceOf(StageFaultError);
    expect(stageCalls).toEqual(['collect', 'analyze', 'policy']);

    // 恢复：policy 再跑一次，之后阶段各一次（重试只补未完成部分）
    await engine.recover();
    expect(stageCalls).toEqual(['collect', 'analyze', 'policy', 'policy', 'assemble', 'seal']);
    const att = engine.listHistory({ artifactId: 'a1' })[0];
    expect(att.state).toBe('ready');
    // 崩溃的那次尝试未及落盘，检查点只记录成功提交；最终 seal 一次封存
    expect(att.checkpoint?.stageAttempts).toMatchObject({ collect: 1, seal: 1 });
    expect(att.checkpoint?.completedIndex).toBe(4);
  });

  it('多次崩溃后仍从最后完整检查点继续，最终证明一致', async () => {    const { store, engine } = newEngine();
    const { evidence } = await seed(engine);

    const run = () => engine.requestAttestation('a1', evidence.id).catch(() => undefined);

    store.injectFault({ match: 'checkpoint:assemble', point: 'commit', times: 1 });
    await run();
    store.simulateCrashAndRestart();
    store.injectFault({ match: 'stage:seal', point: 'stage', times: 1 });
    await engine.recover().catch(() => undefined);
    store.simulateCrashAndRestart();
    await engine.recover();

    const att = engine.listHistory({ artifactId: 'a1' })[0];
    expect(att.state).toBe('ready');
    expect(att.checkpoint?.completedIndex).toBe(4);
  });

  it('计算过程中来源已变（未走失效路径的直接篡改/漂移）：各阶段立即中止，不封存过期证明', async () => {
    const { store, engine } = newEngine();
    const stageCalls: string[] = [];
    (engine as unknown as { onStage: (id: string, s: string) => void }).onStage = (_id, s) =>
      stageCalls.push(s);

    const { evidence } = await seed(engine);

    // 在 assemble 阶段执行中途故障：已落盘到 policy，尚未 assemble/seal
    store.injectFault({ match: 'stage:assemble', point: 'stage', times: 1 });
    await expect(engine.requestAttestation('a1', evidence.id)).rejects.toBeInstanceOf(StageFaultError);
    const stuck = engine.listHistory({ artifactId: 'a1' })[0];
    expect(stuck.checkpoint?.completedIndex).toBe(2);

    // 崩溃期间证据版本发生漂移（未经引擎失效路径，例如存储被旁路更新 / 复制延迟）
    store.simulateCrashAndRestart();
    const evEnv = store.list<Evidence>('evidence:')[0];
    store.mutate<Evidence>(evEnv.key, (prev) => ({ ...prev!.value, version: 99, updatedAt: now() }));

    // 恢复时 assemble 阶段的绑定现场校验立即中止，且绝不会跑到 seal
    const { resumed, aborted } = await engine.recover();
    expect(aborted).toEqual([stuck.id]);
    expect(resumed).toEqual([]);
    expect(stageCalls).not.toContain('seal');

    const dead = engine.getAttestation(stuck.id)!;
    expect(dead.state).toBe('invalidated');
    expect(dead.proofHash).toBeUndefined(); // 没有封存出任何“完整证明”
  });
});

describe('两位复核人并发签署：先到保留，后到拿回意见与冲突', () => {
  it('并发提交时先到者落盘，后到者拿到 REVIEW_CONFLICT 与先到意见', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const att = await engine.requestAttestation('a1', evidence.id);

    // 两个不同复核人“同时”提交（submitReview 在读取后、提交前让出事件循环，
    // 两次调用在此交错；提交时由 CAS 按版本号裁决）
    const pA = engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: 'A 的同意意见',
      bindingHash: att.binding.bindingHash,
    });
    const pB = engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-b',
      opinion: 'reject',
      comment: 'B 的驳回意见',
      bindingHash: att.binding.bindingHash,
    });
    const [rA, rB] = await Promise.all([pA, pB]);

    const winner = rA.ok ? rA : rB;
    const loser = !rA.ok ? rA : rB;
    expect(winner.ok).toBe(true);

    expect('conflict' in loser && loser.conflict).toBeTruthy();
    if (!loser.ok && loser.conflict) {
      expect(loser.conflict.code).toBe('REVIEW_CONFLICT');
      // 后到者拿回的是“先到的一份”及其意见
      expect(loser.conflict.accepted.comment).toBe('A 的同意意见');
      expect(loser.conflict.accepted.opinion).toBe('approve');
      expect(loser.conflict.rejected.comment).toBe('B 的驳回意见');
      expect(loser.message).toContain('先到的一份');
    }

    // 存储中只保留先到的一份；证明不因冲突签署而封存
    const final = engine.getAttestation(att.id)!;
    expect(final.signatures).toHaveLength(1);
    expect(final.state).toBe('ready');
  });

  it('同一复核人串行重复签署被拒绝；协调后第二人正常签署可封存', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const att = await engine.requestAttestation('a1', evidence.id);

    const ok = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '同意',
      bindingHash: att.binding.bindingHash,
    });
    expect(ok.ok).toBe(true);

    const dup = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-a',
      opinion: 'reject',
      comment: '反悔',
      bindingHash: att.binding.bindingHash,
    });
    expect(dup.ok).toBe(false);
    if (!dup.ok) expect(dup.code).toBe('DUPLICATE_REVIEWER');

    // B 看到 A 的意见后协调一致，再签署 → 封存
    const b = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-b',
      opinion: 'approve',
      comment: '与 rev-a 一致',
      bindingHash: att.binding.bindingHash,
    });
    expect(b.ok).toBe(true);
    if (b.ok) expect(b.attestation.state).toBe('signed');
  });

  it('绑定哈希过期（签署旧内容）被拒绝', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const att = await engine.requestAttestation('a1', evidence.id);
    const stale = await engine.submitReview({
      attestationId: att.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '',
      bindingHash: 'deadbeef'.repeat(8),
    });
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.code).toBe('STALE_BINDING');
  });
});

describe('旧数据升级：回填指纹，历史证明仍可查询', () => {
  it('缺指纹的旧构件被回填；旧证明标记 legacy 可查但不放行（迁移幂等）', async () => {
    const { engine } = newEngine();

    // 模拟旧数据：构件没有 fingerprint 字段
    const legacyArtifacts: Array<Partial<Artifact> & { id: string; name: string; version: string; source: string }> = [
      { id: 'legacy-a', name: 'old-lib', version: '0.9.0', source: 'manual' },
    ];
    const legacyAttestations = [
      { id: 'legacy-att-1', artifactId: 'legacy-a', report: '2019 年人工签署的纸质证明', signedAt: 1_577_836_800_000 },
    ];

    const r1 = await engine.migrateLegacy(legacyArtifacts, legacyAttestations);
    expect(r1.backfilledArtifacts).toEqual(['legacy-a']);
    expect(r1.legacyAttestations).toEqual(['legacy-att-1']);

    const a = engine.getArtifact('legacy-a')!;
    expect(a.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(a.revision).toBe(1);

    // 历史证明仍可查询
    const history = engine.listHistory();
    const old = history.find((h) => h.id === 'legacy-att-1')!;
    expect(old.legacy).toBe(true);
    expect(old.state).toBe('legacy');
    expect(old.report).toContain('纸质证明');

    // 但不能作为放行依据，也不能被签署
    expect(engine.getGatingAttestation('legacy-a')).toBeUndefined();
    const sign = await engine.submitReview({
      attestationId: old.id,
      reviewerId: 'rev-a',
      opinion: 'approve',
      comment: '',
      bindingHash: old.binding.bindingHash,
    });
    expect(sign.ok).toBe(false);
    if (!sign.ok) expect(sign.code).toBe('LEGACY_NOT_GATING');

    // 迁移幂等：再跑一遍不重复回填、不覆盖历史
    const r2 = await engine.migrateLegacy(legacyArtifacts, legacyAttestations);
    expect(r2.backfilledArtifacts).toEqual([]);
    expect(r2.legacyAttestations).toEqual([]);
    expect(engine.listHistory()).toHaveLength(1);
  });

  it('旧构件之后发生替换，历史证明链仍完整可查，放行只认新证明', async () => {
    const { engine } = newEngine();
    await engine.migrateLegacy(
      [{ id: 'a9', name: 'lib', version: '1.0.0', source: 'npm' }],
      [{ id: 'old-att', artifactId: 'a9', report: '旧', signedAt: 1_500_000_000_000 }],
    );

    // 替换构件并登记新证据、完成新证明
    await engine.upsertArtifact({ id: 'a9', name: 'lib', version: '2.0.0', source: 'npm' });
    const ev = await engine.createEvidence({
      artifactId: 'a9',
      license: 'MIT',
      risk: 'permissive',
      entries: [{ kind: 'license-file', ref: 'LICENSE', sha256: 'x' }],
    });
    const att = await engine.requestAttestation('a9', ev.id);
    await engine.submitReview({ attestationId: att.id, reviewerId: 'r1', opinion: 'approve', comment: '', bindingHash: att.binding.bindingHash });
    await engine.submitReview({ attestationId: att.id, reviewerId: 'r2', opinion: 'approve', comment: '', bindingHash: att.binding.bindingHash });

    // 历史全部可查：legacy + 新证明，且按时间排序
    const history = engine.listHistory({ artifactId: 'a9' });
    expect(history).toHaveLength(2);
    expect(history[0].id).toBe('old-att');
    expect(history[0].legacy).toBe(true);
    expect(history[1].id).toBe(att.id);

    // 只有新证明可放行
    expect(engine.getGatingAttestation('a9')?.id).toBe(att.id);
  });
});

describe('三方分开维护 + 幂等', () => {
  it('同一绑定重复发起证明是幂等的，不产生多余记录', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const a1 = await engine.requestAttestation('a1', evidence.id);
    const a2 = await engine.requestAttestation('a1', evidence.id);
    expect(a1.id).toBe(a2.id);
    expect(engine.listHistory({ artifactId: 'a1' })).toHaveLength(1);
  });

  it('构件内容未变（重复 upsert）不会使证明失效', async () => {
    const { engine } = newEngine();
    const { evidence } = await seed(engine);
    const att = await engine.requestAttestation('a1', evidence.id);
    await engine.upsertArtifact({ id: 'a1', name: 'widget', version: '1.0.0', source: 'npm' });
    expect(engine.getAttestation(att.id)?.state).toBe('ready');
    expect(engine.getArtifact('a1')?.revision).toBe(1);
  });
});
