# 可恢复的合规证明引擎（Attestation Engine）

解决的问题：构件清单、许可证证据、合规证明原本分开维护，构件被替换或证据补齐后，
**旧证明仍被当作有效证明放行**。本模块把证明流程改造成「可恢复、可失效、可仲裁」的状态机。

## 领域对象（三类分开维护）

| 对象 | 键前缀 | 可变内容 | 版本标识 |
|---|---|---|---|
| `Artifact` 构件 | `artifact:` | 名称 / 版本 / 来源 | `fingerprint`（内容指纹）+ `revision` |
| `Evidence` 许可证证据 | `evidence:` | 许可证、风险、证据材料 | `version`（补齐即 +1） |
| `Attestation` 合规证明 | `attestation:` | 状态机 + 检查点 + 签署 | 绑定 `(构件指纹, 证据版本, bindingHash)` |

## 证明状态机

```
                 requestAttestation
   (不存在) ───────────────────────▶ computing ──全部检查点落盘──▶ ready
                                      │  ▲                           │ 两份签署
              来源变化（构件替换/      │  │ recover() 从检查点续跑      ▼
              证据换版/恢复时漂移）    │  └────────────────────────  signed（完整证明，可放行）
                                      ▼
                                 invalidated（保留可查，不放行；带 successorId）

   旧数据迁移而来 ─▶ legacy（历史可查，任何签署 / 放行路径都拒绝）
```

## 关键不变量

1. **绑定即失效**：每份证明封存 `bindingHash = SHA256(构件指纹, 证据版本, 证据内容)`。
   - `upsertArtifact` 发现指纹变化（构件替换）→ 所有活动证明 `invalidated`，`revision +1`；
   - `updateEvidence` 补齐证据 → 版本 +1，绑定旧版本的证明全部 `invalidated`；
   - `getGatingAttestation()` 只认 `signed` 且绑定仍新鲜、非 legacy 的证明。
2. **重算期间拒绝确认**：`computing` 状态下 `submitReview()` 一律返回
   `REJECTED_RECOMPUTING`；`invalidated` 的旧证明返回 `INVALIDATED`。
3. **每个阶段现场校验来源**：`collect … seal` 每个阶段执行前都比对绑定，
   恢复期间来源漂移也不会封存出旧内容的完整证明（`seal` 前还有第二道闸）。

## 可恢复的分阶段计算

证明计算分 5 个检查点阶段，**每个阶段一次两阶段持久化**（先写 `key.__tmp__`，
再原子替换正式键）：

```
collect → analyze → policy → assemble → seal
 汇总      义务分析     策略判定    组装证明文档   封存 proofHash
```

- `DurableStore.mutate()` 模拟崩溃：
  - `stage` 故障：阶段动作中途失败，检查点停在上一完整阶段；
  - `commit` 故障：临时键已写、正式键未替换，临时键残留。
- `simulateCrashAndRestart()` 丢弃所有残留临时键（正式键永远是最后完整版本）。
- `recover()` 扫描所有 `computing` 证明，**只从 `completedIndex+1` 续跑**，
  已落盘阶段绝不重放；恢复时发现绑定过期则置 `invalidated` 并计入 `aborted`。
- 在 `seal` 成功前 `proofHash` 为空——系统中根本不存在“完整证明”可被误用。

故障注入（演练 / 测试）：

```ts
store.injectFault({ match: 'checkpoint:seal', point: 'commit', times: 1 });
store.injectFault({ match: 'stage:policy', point: 'stage', times: 1 });
```

## 双人复核与并发仲裁

- 一份证明需要两位**不同**复核人签署；同一复核人重复签 → `DUPLICATE_REVIEWER`。
- 签署必须携带当前 `bindingHash`，对不上 → `STALE_BINDING`（签的是过期页面）。
- 两位复核人**同时提交**：`submitReview` 的“读校验”与“CAS 提交”是两次独立存储访问，
  中间让出事件循环使并发真实交错；提交时带 `expectedVersion`，
  **先到者落盘，后到者 CAS 失败**，拿回：
  - `code: 'REVIEW_CONFLICT'`
  - `conflict.accepted`：先到那一份签署（复核人、同意/驳回意见、评论）
  - `conflict.rejected`：被退回的后到提交
  存储中始终只有先到的一份。

## 旧数据升级（幂等）

`migrateLegacy(旧构件, 旧证明)` 可反复执行：

- 缺 `fingerprint` 的旧构件按当前内容 **SHA-256 回填**，`revision` 保持；
- 旧证明无完整可信绑定 → `state='legacy'`、`legacy=true`，
  `listHistory()` 仍可查询，但 `submitReview()` 返回 `LEGACY_NOT_GATING`，
  也不会被 `getGatingAttestation()` 选中。

## 最小用法

```ts
const store = new DurableStore();
const engine = new AttestationEngine({ store });

const { artifact } = await engine.upsertArtifact({ id: 'a1', name: 'widget', version: '1.0.0', source: 'npm' });
const evidence = await engine.createEvidence({
  artifactId: 'a1', license: 'MIT', risk: 'permissive',
  entries: [{ kind: 'license-file', ref: 'LICENSE', sha256: '…' }],
});

const att = await engine.requestAttestation('a1', evidence.id); // computing → ready
await engine.submitReview({ attestationId: att.id, reviewerId: 'rev-a',
  opinion: 'approve', comment: '义务清晰', bindingHash: att.binding.bindingHash });
await engine.submitReview({ attestationId: att.id, reviewerId: 'rev-b',
  opinion: 'approve', comment: '同意', bindingHash: att.binding.bindingHash });

engine.getGatingAttestation('a1'); // 仅此为放行依据

// 进程重启
store.simulateCrashAndRestart();
await engine.recover();            // { resumed, aborted }：只补未完成阶段
```

测试：`npm test`（15 个用例，覆盖失效重算、重算期拒绝确认、崩溃恢复、
并发签署冲突、旧数据迁移与幂等）。
