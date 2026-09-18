import assert from 'node:assert/strict';
import test from 'node:test';
import {
  MAX_SECURITY_CASE_BYTES,
  parseSecurityCase,
  parseSecurityCaseFile,
  SECURITY_CASE_CONTRACT,
  type CandidateClass,
  type SecurityCase,
  type SourceKind,
} from './security-case.ts';

const identifier = (kind: string, suffix: string) =>
  `sf_${kind}_${suffix.padEnd(16, '0')}`;

function fixture(kind: SourceKind = 'secure-engine', candidate = true): SecurityCase {
  const sourceId = identifier('source', 'source');
  const evidenceId = identifier('evidence', 'evidence');
  const classes: Record<Exclude<SourceKind, 'agent'>, CandidateClass> = {
    'secure-engine': 'engine-candidate',
    'secure-skill-contextual': 'contextual-candidate',
    'external-sarif': 'external-tool-candidate',
  };
  return {
    contract_version: SECURITY_CASE_CONTRACT,
    case_id: identifier('case', 'case'),
    created_at: '2026-09-17T12:00:00Z',
    target: {
      label: 'local fixture',
      root_sha256: '0'.repeat(64),
      authorization: {
        status: 'authorized',
        basis: 'test',
        reviewer: 'test reviewer',
      },
    },
    sources: [
      {
        source_id: sourceId,
        kind,
        name: 'fixture source',
        version: '1',
        artifact_sha256: '1'.repeat(64),
      },
    ],
    evidence: [
      {
        evidence_id: evidenceId,
        source_id: sourceId,
        sha256: '2'.repeat(64),
        description: 'retained fixture',
      },
    ],
    candidates:
      candidate && kind !== 'agent'
        ? [
            {
              candidate_id: identifier('candidate', 'candidate'),
              source_id: sourceId,
              class: classes[kind],
              title: 'fixture candidate',
              confidence: 'unknown',
              evidence_ids: [evidenceId],
              limitations: [],
            },
          ]
        : [],
    staged_recommendations: [],
    decisions: [],
  };
}

type MutableCase = Record<string, unknown> & {
  case_id: string;
  created_at: string;
  target: Record<string, unknown> & { root_sha256: string };
  sources: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  candidates: Array<Record<string, unknown>>;
  staged_recommendations: Array<Record<string, unknown>>;
  decisions: Array<Record<string, unknown>>;
};

function mutableFixture(): MutableCase {
  return structuredClone(fixture()) as unknown as MutableCase;
}

void test('accepts canonical cases with and without an optional revision', () => {
  assert.deepEqual(parseSecurityCase(JSON.stringify(fixture())), fixture());
  const revised = fixture();
  revised.target.revision = { kind: 'git', value: '4f162ad' };
  assert.deepEqual(parseSecurityCase(revised), revised);
  assert.doesNotThrow(() => parseSecurityCase(fixture('agent', false)));
});

void test('bounded file parsing preserves Unicode and rejects malformed UTF-8', async () => {
  const unicode = fixture();
  unicode.target.label = 'Revisión local 🔒';
  const validBytes = new TextEncoder().encode(JSON.stringify(unicode));
  const parsed = await parseSecurityCaseFile({
    size: validBytes.byteLength,
    arrayBuffer: async () => validBytes.slice().buffer,
  });
  assert.equal(parsed.target.label, unicode.target.label);

  const invalidBytes = Uint8Array.from([0xc3, 0x28]);
  await assert.rejects(
    parseSecurityCaseFile({
      size: invalidBytes.byteLength,
      arrayBuffer: async () => invalidBytes.buffer,
    }),
    /not valid UTF-8/,
  );

  let read = false;
  await assert.rejects(
    parseSecurityCaseFile({
      size: MAX_SECURITY_CASE_BYTES + 1,
      arrayBuffer: async () => {
        read = true;
        return new ArrayBuffer(0);
      },
    }),
    /32 MiB/,
  );
  assert.equal(read, false, 'oversized files must be rejected before reading');
});

void test('rejects malformed JSON and unknown fields', () => {
  assert.throws(() => parseSecurityCase('{'), /malformed JSON/);
  const value = mutableFixture();
  value.unexpected = true;
  assert.throws(() => parseSecurityCase(value), /unknown field/);
});

void test('rejects invalid hashes, identifiers, enums, and timestamps', () => {
  for (const hash of [
    `g${'0'.repeat(63)}`,
    `z${'0'.repeat(63)}`,
    `A${'0'.repeat(63)}`,
    '0'.repeat(63),
  ]) {
    const value = mutableFixture();
    value.target.root_sha256 = hash;
    assert.throws(() => parseSecurityCase(value), /lowercase hexadecimal/);
  }

  const invalidId = mutableFixture();
  invalidId.case_id = 'sf_case_UPPERCASE000000';
  assert.throws(() => parseSecurityCase(invalidId), /identifier/);

  const invalidSourceKind = mutableFixture();
  invalidSourceKind.sources[0].kind = 'unknown';
  assert.throws(() => parseSecurityCase(invalidSourceKind), /expected one of/);

  const invalidCandidateClass = mutableFixture();
  invalidCandidateClass.candidates[0].class = 'unknown';
  assert.throws(() => parseSecurityCase(invalidCandidateClass), /expected one of/);

  const invalidDecision = mutableFixture();
  invalidDecision.decisions = [
    {
      ...decision(String(invalidDecision.candidates[0].candidate_id), 'decision'),
      decision: 'unknown',
    },
  ];
  assert.throws(() => parseSecurityCase(invalidDecision), /expected one of/);

  for (const timestamp of ['2026-13-17T12:00:00Z', '2026-02-30T12:00:00Z']) {
    const invalidTimestamp = mutableFixture();
    invalidTimestamp.created_at = timestamp;
    assert.throws(() => parseSecurityCase(invalidTimestamp), /RFC 3339/);
  }
});

void test('rejects dangling references', () => {
  const mutations: Array<(value: MutableCase) => void> = [
    (value) => {
      value.evidence[0].source_id = identifier('source', 'missing');
    },
    (value) => {
      value.candidates[0].source_id = identifier('source', 'missing');
    },
    (value) => {
      value.candidates[0].evidence_ids = [identifier('evidence', 'missing')];
    },
    (value) => {
      value.staged_recommendations = [
        {
          stage_id: identifier('stage', 'stage'),
          candidate_id: identifier('candidate', 'missing'),
          agent_name: 'agent',
          recommendation: 'abstained',
          rationale: 'insufficient retained evidence',
          created_at: '2026-09-17T12:00:00Z',
        },
      ];
    },
    (value) => {
      value.decisions = [decision(identifier('candidate', 'missing'), 'decision')];
    },
  ];
  for (const mutate of mutations) {
    const value = mutableFixture();
    mutate(value);
    assert.throws(() => parseSecurityCase(value), /dangling/);
  }
});

function decision(candidateId: string, suffix: string) {
  return {
    decision_id: identifier('decision', suffix),
    candidate_id: candidateId,
    decision: 'abstained',
    reviewer: 'reviewer',
    rationale: 'insufficient retained evidence',
    decided_at: '2026-09-17T12:00:00Z',
  };
}

void test('rejects duplicate identifiers and duplicate candidate decisions', () => {
  const duplicateCollections = ['sources', 'evidence', 'candidates'] as const;
  for (const collection of duplicateCollections) {
    const value = mutableFixture();
    value[collection].push(structuredClone(value[collection][0]));
    assert.throws(() => parseSecurityCase(value), /duplicate identifier/);
  }

  const duplicateStage = mutableFixture();
  duplicateStage.staged_recommendations = [
    {
      stage_id: identifier('stage', 'stage'),
      candidate_id: duplicateStage.candidates[0].candidate_id,
      agent_name: 'agent',
      recommendation: 'abstained',
      rationale: 'insufficient retained evidence',
      created_at: '2026-09-17T12:00:00Z',
    },
  ];
  duplicateStage.staged_recommendations.push(
    structuredClone(duplicateStage.staged_recommendations[0]),
  );
  assert.throws(() => parseSecurityCase(duplicateStage), /duplicate identifier/);

  const candidateId = String(mutableFixture().candidates[0].candidate_id);
  const duplicateDecisionId = mutableFixture();
  duplicateDecisionId.decisions = [
    decision(candidateId, 'decision'),
    decision(candidateId, 'decision'),
  ];
  assert.throws(() => parseSecurityCase(duplicateDecisionId), /duplicate identifier/);

  const duplicateCandidateDecision = mutableFixture();
  duplicateCandidateDecision.decisions = [
    decision(candidateId, 'decisiona'),
    decision(candidateId, 'decisionb'),
  ];
  assert.throws(
    () => parseSecurityCase(duplicateCandidateDecision),
    /already has a final decision/,
  );
});

void test('enforces every source-kind to candidate-class pairing', () => {
  const sourceKinds: SourceKind[] = [
    'secure-engine',
    'secure-skill-contextual',
    'external-sarif',
    'agent',
  ];
  const candidateClasses: CandidateClass[] = [
    'engine-candidate',
    'contextual-candidate',
    'external-tool-candidate',
  ];
  const expected = new Map<SourceKind, CandidateClass>([
    ['secure-engine', 'engine-candidate'],
    ['secure-skill-contextual', 'contextual-candidate'],
    ['external-sarif', 'external-tool-candidate'],
  ]);

  for (const sourceKind of sourceKinds) {
    for (const candidateClass of candidateClasses) {
      const value = mutableFixture();
      value.sources[0].kind = sourceKind;
      value.candidates[0].class = candidateClass;
      if (expected.get(sourceKind) === candidateClass) {
        assert.doesNotThrow(() => parseSecurityCase(value));
      } else {
        assert.throws(() => parseSecurityCase(value), /not authorized/);
      }
    }
  }
});
