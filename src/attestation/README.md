# 可恢复的合规证明流程

证明（Attestation）不再独立放行，而是**绑定构件指纹 + 证据版本**，并按分阶段流水线写入，
任何中断都可从最后完整证明恢复。

## 文件

| 文件 | 职责 |
|---|---|
| `types.ts` | 领域模型：构件 / 证据 / 证明 / 步骤 / 签署 / WAL / 审计事件 / 结果类型 |
| `hash.ts` | 确定性指纹：规范化 JSON + cyrb53，算法版本写入前缀 |
| `engine.ts` | 纯领域逻辑（无 React、无存储）：失效、重算、签署竞争、恢复、迁移 |
| `seed.ts` | v2 初始数据与 v1 旧数据快照（无指纹，用于演示升级） |
| `store.ts` | localStorage 持久化 + 事务提交（草稿→纯函数→原子落盘）+ 启动迁移 |
| `AttestationCenter.tsx` | 证明中心界面（清单 / 证据 / 证明流水线 / 签署 / 审计） |
| `engine.test.ts` | 9 个场景测试，`npm test` 运行 |

## 需求对应

1. **证明绑定构件指纹与证据版本，来源一变就失效重算**
   - 构件指纹输入：name/version/license/source/origin（`computeArtifactFingerprint`）。
   - 证据版本为内容寻址（kind/body/reviewer，`computeEvidenceVersion`），
     证明绑定的是该构件全部证据版本集合的再哈希。
   - `replaceArtifact` / `upsertEvidence` 检测到指纹或证据版本变化时调用
     `invalidateForSourceChange`：旧证明置 `superseded`（保留可查询），
     新证明以新指纹/新证据版本进入 `recomputing`。

2. **重算期间再次确认会被拒绝**
   - 统一闸口 `reconfirm`：`recomputing` → `RECOMPUTING`；
     已失效/历史证明 → `ATT_NO_LONGER_OPEN`；已生效/已拒 → `ATT_NO_LONGER_OPEN`。
   - 签署入口也经过该闸口；自动阶段（收集、评估）未完成时签署一律拒绝。
   - 另设来源乐观锁：签署携带 `seenFingerprint/seenEvidenceVersion`，
     与当前绑定不符返回 `STALE_SIGNATURE`。

3. **两名复核人同时提交：保留先到，后到者拿回意见和冲突**
   - 相同 `slotToken` 的并行请求竞争同一签署位（`state.slotLocks`，运行时态不落盘）。
   - 后到者收到 `ALREADY_SIGNED` + `ConflictInfo { winner, loser, reason }`，
     winner 含先到者的意见；落败方阅读意见后可正常提交第二签署位。
   - 两份签署意见不一致 → 证明 `rejected`，出具步骤跳过。

4. **写入中途失败：从最后完整证明恢复，只补未完成部分**
   - 流水线 5 步：collect → evaluate → sign-primary → sign-secondary → finalize，
     每步带序号。注入失败时该步置 `failed` 并写 **WAL**（`lastCompleteSeq`）。
   - `recoverInterrupted` 消费 WAL：`done` 步骤全部跳过，只重做未完成部分；
     恢复前再次校验来源，若期间来源又变则作废本次恢复并重新锚定最新来源。

5. **旧数据升级：回填指纹，历史证明仍可查询**
   - `migrate`（schema v1→v2，幂等）：为缺指纹构件回填指纹、为证据回填版本；
     升级前证明标记为 `historical/legacy`，永不删除，证明链中可逐版查询。

## 测试

```bash
npm test        # 引擎场景测试（9 个）
npm run build   # 类型检查 + 构建
```
