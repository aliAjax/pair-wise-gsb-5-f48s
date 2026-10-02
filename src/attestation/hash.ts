/**
 * 指纹与哈希工具。
 * 使用 Web Crypto（Node 18+/浏览器均内置），全部为确定性 SHA-256。
 */

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(',')}}`;
}

export async function sha256Hex(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(typeof value === 'string' ? value : stableJson(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** 构件内容指纹：只与“构件是什么”有关，与内部修订号 / 时间无关 */
export function fingerprintArtifactInput(a: {
  name: string;
  version: string;
  source: string;
}): string {
  // 先做规范化字符串，再由调用方异步取哈希，便于迁移时复用
  return stableJson({ name: a.name, version: a.version, source: a.source });
}

/** 证据内容指纹（证据版本本身也在证明绑定中单独记录） */
export function fingerprintEvidenceInput(e: {
  artifactId: string;
  license: string;
  risk: string;
  entries: { kind: string; ref: string; sha256: string }[];
}): string {
  return stableJson(e);
}

/** 证明绑定哈希：构件指纹 + 证据版本 + 证据内容，任一变化绑定即变 */
export async function computeBindingHash(args: {
  artifactFingerprint: string;
  evidenceVersion: number;
  evidenceFingerprint: string;
}): Promise<string> {
  return sha256Hex(stableJson(args));
}
