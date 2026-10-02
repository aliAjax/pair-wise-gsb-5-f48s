// 演示数据：一份 v2 正常数据，以及用于演示“旧数据升级”的 v1 快照（缺指纹）
import { FP_ALGORITHM, computeArtifactFingerprint, computeEvidenceVersion, LEGACY_FP } from './engine';
import type { Artifact, Attestation, Evidence, StoreState } from './types';

function art(p: Omit<Artifact, 'fpAlgorithm' | 'updatedAt' | 'fingerprint'> & Partial<Pick<Artifact, 'fingerprint'>>): Artifact {
  return { fpAlgorithm: FP_ALGORITHM, updatedAt: Date.now(), ...p } as Artifact;
}

export function freshState(): StoreState {
  const t0 = Date.now();
  const artifacts: Artifact[] = [
    art({ id: 'react', name: 'react', version: '18.3.1', license: 'MIT', source: 'npm', origin: 'https://registry.npmjs.org/react/18.3.1', risk: 'ok', note: '宽松许可，可商用' }),
    art({ id: 'lodash', name: 'lodash', version: '4.17.21', license: 'MIT', source: 'npm', origin: 'https://registry.npmjs.org/lodash/4.17.21', risk: 'ok', note: '宽松许可，可商用' }),
    art({ id: 'hljs', name: 'highlight.js', version: '11.10.0', license: 'BSD-3-Clause', source: 'npm', origin: 'https://registry.npmjs.org/highlight.js/11.10.0', risk: 'warn', note: '再发布需保留版权声明' }),
    art({ id: 'legacy-parser', name: 'legacy-parser', version: '2.1.0', license: 'GPL-3.0', source: '手动', origin: 'vendor/legacy-parser-2.1.0.tgz', risk: 'risk', note: '可能与闭源分发冲突' }),
  ].map((a) => ({ ...a, fingerprint: computeArtifactFingerprint(a) }));

  const evidenceRaw: Omit<Evidence, 'version'>[] = [
    { id: 'ev-react-license', artifactId: 'react', kind: 'license-file', body: 'MIT License — Copyright (c) Meta Platforms, Inc. 完整 LICENSE 文件已归档。', reviewer: '系统扫描', updatedAt: t0 },
    { id: 'ev-hljs-license', artifactId: 'hljs', kind: 'license-file', body: 'BSD 3-Clause License — Copyright (c) Ivan Sagalaev. 需保留版权声明。', reviewer: '系统扫描', updatedAt: t0 },
    { id: 'ev-legacy-scan', artifactId: 'legacy-parser', kind: 'scan-report', body: '扫描报告：GPL-3.0 传染性条款，闭源分发存在冲突风险，建议替换。', reviewer: 'Zen Li', updatedAt: t0 },
  ];
  const evidence: Evidence[] = evidenceRaw.map((e) => ({ ...e, version: computeEvidenceVersion({ ...e, version: '' } as Evidence) }));

  return { schemaVersion: 2, artifacts, evidence, attestations: [], events: [], seq: 0, wal: [], slotLocks: {} };
}

/** 模拟升级前的 v1 数据：构件无指纹、证据无版本、证明直接绑名称且仍被当放行依据 */
export function legacyV1State(): StoreState {
  const t0 = Date.now() - 1000 * 60 * 60 * 24 * 30;
  const artifacts: Artifact[] = [
    { id: 'old-lib', name: 'old-lib', version: '1.4.0', license: 'Apache-2.0', source: '内部镜像', origin: 'http://mirror.local/old-lib-1.4.0.jar', fpAlgorithm: '', risk: 'warn', note: '旧清单条目', updatedAt: t0 },
  ];
  const evidence: Evidence[] = [
    { id: 'ev-old', artifactId: 'old-lib', kind: 'manual-review', body: '历史评审：Apache-2.0 合规，已留存 NOTICE。', reviewer: 'Wang Wu', version: '', updatedAt: t0 },
  ];
  const legacyAtt: Attestation = {
    id: 'att-old-lib-1',
    artifactId: 'old-lib',
    boundFingerprint: LEGACY_FP,
    boundEvidenceVersion: LEGACY_FP,
    status: 'finalized',
    steps: [],
    signatures: [],
    issueNo: 1,
    createdAt: t0,
    updatedAt: t0,
  };
  return { schemaVersion: 1, artifacts, evidence, attestations: [legacyAtt], events: [], seq: 0, wal: [], slotLocks: {} };
}
