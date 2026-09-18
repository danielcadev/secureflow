export const MAX_SECURITY_CASE_BYTES = 32 * 1024 * 1024;
export const SECURITY_CASE_CONTRACT = 'secureflow-security-case-v1';

export type Decision = 'validated' | 'rejected' | 'abstained';
export type SourceKind =
  | 'secure-engine'
  | 'secure-skill-contextual'
  | 'external-sarif'
  | 'agent';
export type CandidateClass =
  | 'engine-candidate'
  | 'contextual-candidate'
  | 'external-tool-candidate';

export type SecurityCase = {
  contract_version: typeof SECURITY_CASE_CONTRACT;
  case_id: string;
  created_at: string;
  target: {
    label: string;
    root_sha256: string;
    revision?: { kind: string; value: string };
    authorization: {
      status: 'authorized';
      basis: string;
      reviewer: string;
      reference?: string;
      expires_at?: string;
    };
  };
  sources: Array<{
    source_id: string;
    kind: SourceKind;
    name: string;
    version: string;
    artifact_sha256: string;
    methodology?: string;
  }>;
  evidence: Array<{
    evidence_id: string;
    source_id: string;
    sha256: string;
    description: string;
    relative_path?: string;
  }>;
  candidates: Array<{
    candidate_id: string;
    source_id: string;
    class: CandidateClass;
    title: string;
    severity?: string;
    confidence: string;
    evidence_ids: string[];
    limitations: string[];
  }>;
  staged_recommendations: Array<{
    stage_id: string;
    candidate_id: string;
    agent_name: string;
    recommendation: string;
    rationale: string;
    created_at: string;
  }>;
  decisions: Array<{
    decision_id: string;
    candidate_id: string;
    decision: Decision;
    reviewer: string;
    rationale: string;
    decided_at: string;
    evidence_reference?: string;
  }>;
};

type JsonObject = Record<string, unknown>;
type SecurityCaseFile = {
  size: number;
  arrayBuffer: () => Promise<ArrayBuffer>;
};

const encoder = new TextEncoder();
const idPattern = /^sf_(?:case|source|evidence|candidate|stage|decision)_[a-z0-9_]{16,}$/;
const shaPattern = /^[0-9a-f]{64}$/;
const rfc3339Pattern =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/;

function fail(path: string, reason: string): never {
  throw new Error(`Invalid Security Case at ${path}: ${reason}.`);
}

function objectAt(value: unknown, path: string): JsonObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail(path, 'expected an object');
  }
  return value as JsonObject;
}

function fields(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): JsonObject {
  const object = objectAt(value, path);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) fail(`${path}.${key}`, 'unknown field');
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) fail(`${path}.${key}`, 'missing field');
  }
  return object;
}

function arrayAt(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path, 'expected an array');
  return value;
}

function stringAt(value: unknown, path: string, maxBytes?: number): string {
  if (typeof value !== 'string') fail(path, 'expected a string');
  if (value.trim().length === 0) fail(path, 'must not be blank');
  if (maxBytes !== undefined && encoder.encode(value).byteLength > maxBytes) {
    fail(path, `must not exceed ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function optionalString(
  object: JsonObject,
  key: string,
  path: string,
  maxBytes: number,
): string | undefined {
  return Object.hasOwn(object, key)
    ? stringAt(object[key], `${path}.${key}`, maxBytes)
    : undefined;
}

function idAt(value: unknown, prefix: string, path: string): string {
  const id = stringAt(value, path);
  if (
    id.length > 100 ||
    !id.startsWith(prefix) ||
    !idPattern.test(id)
  ) {
    fail(path, `expected a ${prefix} identifier`);
  }
  return id;
}

function shaAt(value: unknown, path: string): string {
  const sha = stringAt(value, path);
  if (!shaPattern.test(sha)) fail(path, 'expected 64 lowercase hexadecimal characters');
  return sha;
}

function timestampAt(value: unknown, path: string): string {
  const timestamp = stringAt(value, path);
  const match = rfc3339Pattern.exec(timestamp);
  if (match === null || Number.isNaN(Date.parse(timestamp))) {
    fail(path, 'expected an RFC 3339 timestamp');
  }
  const [year, month, day, hour, minute, second, offsetHour = 0, offsetMinute = 0] =
    match.slice(1).map(Number);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1] ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    fail(path, 'expected an RFC 3339 timestamp');
  }
  return timestamp;
}

function enumAt<T extends string>(
  value: unknown,
  options: readonly T[],
  path: string,
): T {
  if (typeof value !== 'string' || !options.includes(value as T)) {
    fail(path, `expected one of ${options.join(', ')}`);
  }
  return value as T;
}

function unique(id: string, seen: Set<string>, path: string): void {
  if (seen.has(id)) fail(path, `duplicate identifier ${id}`);
  seen.add(id);
}

function stringsAt(value: unknown, path: string, maxBytes: number): string[] {
  return arrayAt(value, path).map((item, index) =>
    stringAt(item, `${path}[${index}]`, maxBytes),
  );
}

export function parseSecurityCase(input: unknown): SecurityCase {
  let value: unknown = input;
  if (typeof input === 'string') {
    try {
      value = JSON.parse(input) as unknown;
    } catch {
      fail('$', 'malformed JSON');
    }
  }

  const root = fields(value, '$', [
    'contract_version',
    'case_id',
    'created_at',
    'target',
    'sources',
    'evidence',
    'candidates',
    'staged_recommendations',
    'decisions',
  ]);
  const contractVersion = enumAt(
    root.contract_version,
    [SECURITY_CASE_CONTRACT] as const,
    '$.contract_version',
  );
  const caseId = idAt(root.case_id, 'sf_case_', '$.case_id');
  const createdAt = timestampAt(root.created_at, '$.created_at');

  const targetObject = fields(
    root.target,
    '$.target',
    ['label', 'root_sha256', 'authorization'],
    ['revision'],
  );
  const authorizationObject = fields(
    targetObject.authorization,
    '$.target.authorization',
    ['status', 'basis', 'reviewer'],
    ['reference', 'expires_at'],
  );
  const authorization: SecurityCase['target']['authorization'] = {
    status: enumAt(
      authorizationObject.status,
      ['authorized'] as const,
      '$.target.authorization.status',
    ),
    basis: stringAt(authorizationObject.basis, '$.target.authorization.basis', 100),
    reviewer: stringAt(
      authorizationObject.reviewer,
      '$.target.authorization.reviewer',
      200,
    ),
  };
  const reference = optionalString(
    authorizationObject,
    'reference',
    '$.target.authorization',
    300,
  );
  if (reference !== undefined) authorization.reference = reference;
  if (Object.hasOwn(authorizationObject, 'expires_at')) {
    authorization.expires_at = timestampAt(
      authorizationObject.expires_at,
      '$.target.authorization.expires_at',
    );
  }

  let revision: SecurityCase['target']['revision'];
  if (Object.hasOwn(targetObject, 'revision')) {
    const revisionObject = fields(
      targetObject.revision,
      '$.target.revision',
      ['kind', 'value'],
    );
    revision = {
      kind: stringAt(revisionObject.kind, '$.target.revision.kind', 40),
      value: stringAt(revisionObject.value, '$.target.revision.value', 200),
    };
  }

  const sourceIds = new Set<string>();
  const sourceKinds = new Map<string, SourceKind>();
  const sources: SecurityCase['sources'] = arrayAt(root.sources, '$.sources').map(
    (entry, index) => {
      const path = `$.sources[${index}]`;
      const source = fields(
        entry,
        path,
        ['source_id', 'kind', 'name', 'version', 'artifact_sha256'],
        ['methodology'],
      );
      const sourceId = idAt(source.source_id, 'sf_source_', `${path}.source_id`);
      unique(sourceId, sourceIds, `${path}.source_id`);
      const kind = enumAt(
        source.kind,
        ['secure-engine', 'secure-skill-contextual', 'external-sarif', 'agent'] as const,
        `${path}.kind`,
      );
      sourceKinds.set(sourceId, kind);
      const parsed: SecurityCase['sources'][number] = {
        source_id: sourceId,
        kind,
        name: stringAt(source.name, `${path}.name`, 200),
        version: stringAt(source.version, `${path}.version`, 200),
        artifact_sha256: shaAt(source.artifact_sha256, `${path}.artifact_sha256`),
      };
      const methodology = optionalString(source, 'methodology', path, 2000);
      if (methodology !== undefined) parsed.methodology = methodology;
      return parsed;
    },
  );

  const evidenceIds = new Set<string>();
  const evidence: SecurityCase['evidence'] = arrayAt(root.evidence, '$.evidence').map(
    (entry, index) => {
      const path = `$.evidence[${index}]`;
      const item = fields(
        entry,
        path,
        ['evidence_id', 'source_id', 'sha256', 'description'],
        ['relative_path'],
      );
      const evidenceId = idAt(item.evidence_id, 'sf_evidence_', `${path}.evidence_id`);
      unique(evidenceId, evidenceIds, `${path}.evidence_id`);
      const sourceId = stringAt(item.source_id, `${path}.source_id`);
      if (!sourceIds.has(sourceId)) fail(`${path}.source_id`, 'dangling source reference');
      const parsed: SecurityCase['evidence'][number] = {
        evidence_id: evidenceId,
        source_id: sourceId,
        sha256: shaAt(item.sha256, `${path}.sha256`),
        description: stringAt(item.description, `${path}.description`, 4000),
      };
      const relativePath = optionalString(item, 'relative_path', path, Number.MAX_SAFE_INTEGER);
      if (
        relativePath !== undefined &&
        (relativePath.startsWith('/') ||
          relativePath.split('/').some((part) => part.length === 0 || part === '..'))
      ) {
        fail(`${path}.relative_path`, 'expected a normalized relative path');
      }
      if (relativePath !== undefined) parsed.relative_path = relativePath;
      return parsed;
    },
  );

  const candidateIds = new Set<string>();
  const classForSource: Record<Exclude<SourceKind, 'agent'>, CandidateClass> = {
    'secure-engine': 'engine-candidate',
    'secure-skill-contextual': 'contextual-candidate',
    'external-sarif': 'external-tool-candidate',
  };
  const candidates: SecurityCase['candidates'] = arrayAt(
    root.candidates,
    '$.candidates',
  ).map((entry, index) => {
    const path = `$.candidates[${index}]`;
    const candidate = fields(
      entry,
      path,
      [
        'candidate_id',
        'source_id',
        'class',
        'title',
        'confidence',
        'evidence_ids',
        'limitations',
      ],
      ['severity'],
    );
    const candidateId = idAt(
      candidate.candidate_id,
      'sf_candidate_',
      `${path}.candidate_id`,
    );
    unique(candidateId, candidateIds, `${path}.candidate_id`);
    const sourceId = stringAt(candidate.source_id, `${path}.source_id`);
    const sourceKind = sourceKinds.get(sourceId);
    if (sourceKind === undefined) fail(`${path}.source_id`, 'dangling source reference');
    const candidateClass = enumAt(
      candidate.class,
      ['engine-candidate', 'contextual-candidate', 'external-tool-candidate'] as const,
      `${path}.class`,
    );
    if (sourceKind === 'agent' || classForSource[sourceKind] !== candidateClass) {
      fail(`${path}.class`, `not authorized for source kind ${sourceKind}`);
    }
    const linkedEvidence = stringsAt(candidate.evidence_ids, `${path}.evidence_ids`, 100);
    for (const [evidenceIndex, evidenceId] of linkedEvidence.entries()) {
      if (!evidenceIds.has(evidenceId)) {
        fail(`${path}.evidence_ids[${evidenceIndex}]`, 'dangling evidence reference');
      }
    }
    const parsed: SecurityCase['candidates'][number] = {
      candidate_id: candidateId,
      source_id: sourceId,
      class: candidateClass,
      title: stringAt(candidate.title, `${path}.title`, 500),
      confidence: stringAt(candidate.confidence, `${path}.confidence`, 40),
      evidence_ids: linkedEvidence,
      limitations: stringsAt(candidate.limitations, `${path}.limitations`, 4000),
    };
    const severity = optionalString(candidate, 'severity', path, 40);
    if (severity !== undefined) parsed.severity = severity;
    return parsed;
  });

  const stageIds = new Set<string>();
  const stagedRecommendations: SecurityCase['staged_recommendations'] = arrayAt(
    root.staged_recommendations,
    '$.staged_recommendations',
  ).map((entry, index) => {
    const path = `$.staged_recommendations[${index}]`;
    const stage = fields(entry, path, [
      'stage_id',
      'candidate_id',
      'agent_name',
      'recommendation',
      'rationale',
      'created_at',
    ]);
    const stageId = idAt(stage.stage_id, 'sf_stage_', `${path}.stage_id`);
    unique(stageId, stageIds, `${path}.stage_id`);
    const candidateId = stringAt(stage.candidate_id, `${path}.candidate_id`);
    if (!candidateIds.has(candidateId)) {
      fail(`${path}.candidate_id`, 'dangling candidate reference');
    }
    return {
      stage_id: stageId,
      candidate_id: candidateId,
      agent_name: stringAt(stage.agent_name, `${path}.agent_name`, 200),
      recommendation: stringAt(stage.recommendation, `${path}.recommendation`, 40),
      rationale: stringAt(stage.rationale, `${path}.rationale`, 3000),
      created_at: timestampAt(stage.created_at, `${path}.created_at`),
    };
  });

  const decisionIds = new Set<string>();
  const decidedCandidates = new Set<string>();
  const decisions: SecurityCase['decisions'] = arrayAt(
    root.decisions,
    '$.decisions',
  ).map((entry, index) => {
    const path = `$.decisions[${index}]`;
    const decision = fields(
      entry,
      path,
      ['decision_id', 'candidate_id', 'decision', 'reviewer', 'rationale', 'decided_at'],
      ['evidence_reference'],
    );
    const decisionId = idAt(
      decision.decision_id,
      'sf_decision_',
      `${path}.decision_id`,
    );
    unique(decisionId, decisionIds, `${path}.decision_id`);
    const candidateId = stringAt(decision.candidate_id, `${path}.candidate_id`);
    if (!candidateIds.has(candidateId)) {
      fail(`${path}.candidate_id`, 'dangling candidate reference');
    }
    if (decidedCandidates.has(candidateId)) {
      fail(`${path}.candidate_id`, 'candidate already has a final decision');
    }
    decidedCandidates.add(candidateId);
    const parsed: SecurityCase['decisions'][number] = {
      decision_id: decisionId,
      candidate_id: candidateId,
      decision: enumAt(
        decision.decision,
        ['validated', 'rejected', 'abstained'] as const,
        `${path}.decision`,
      ),
      reviewer: stringAt(decision.reviewer, `${path}.reviewer`, 200),
      rationale: stringAt(decision.rationale, `${path}.rationale`, 3000),
      decided_at: timestampAt(decision.decided_at, `${path}.decided_at`),
    };
    const evidenceReference = optionalString(
      decision,
      'evidence_reference',
      path,
      300,
    );
    if (evidenceReference !== undefined) parsed.evidence_reference = evidenceReference;
    return parsed;
  });

  const target: SecurityCase['target'] = {
    label: stringAt(targetObject.label, '$.target.label', 200),
    root_sha256: shaAt(targetObject.root_sha256, '$.target.root_sha256'),
    authorization,
  };
  if (revision !== undefined) target.revision = revision;

  return {
    contract_version: contractVersion,
    case_id: caseId,
    created_at: createdAt,
    target,
    sources,
    evidence,
    candidates,
    staged_recommendations: stagedRecommendations,
    decisions,
  };
}

export async function parseSecurityCaseFile(file: SecurityCaseFile): Promise<SecurityCase> {
  if (file.size > MAX_SECURITY_CASE_BYTES) {
    throw new Error('The Security Case exceeds the 32 MiB local file limit.');
  }
  const bytes = await file.arrayBuffer();
  if (bytes.byteLength > MAX_SECURITY_CASE_BYTES) {
    throw new Error('The Security Case exceeds the 32 MiB local file limit.');
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('The Security Case is not valid UTF-8.');
  }
  return parseSecurityCase(text);
}
