import assert from 'node:assert/strict';
import test from 'node:test';
import {
  candidateKeyInputSchema,
  filterReviewCandidates,
  parseCandidatePageRequest,
  summarizeReviewCandidates,
  type ReviewCandidateIndex,
} from './review-efficiency.ts';

const candidates: ReviewCandidateIndex[] = [
  {
    key: 'case:a',
    id: 'a',
    caseLabel: 'web',
    severity: 'high',
    title: 'Repeated signal',
    source: 'engine-candidate',
  },
  {
    key: 'case:b',
    id: 'b',
    caseLabel: 'server',
    severity: 'high',
    title: 'Repeated signal',
    source: 'engine-candidate',
  },
  {
    key: 'case:c',
    id: 'c',
    caseLabel: 'web',
    severity: 'low',
    title: 'Distinct signal',
    source: 'external-tool-candidate',
  },
];

void test('summarizes repeated signals without transferring decisions', () => {
  const summary = summarizeReviewCandidates(candidates, {
    'case:a': { decision: 'rejected', authoritative: true },
    'case:b': { decision: 'rejected', authoritative: false },
  });
  assert.equal(summary.total, 3);
  assert.deepEqual(summary.byState, {
    pending: 1,
    draft: 1,
    validated: 0,
    rejected: 1,
    abstained: 0,
  });
  assert.equal(summary.repeatedGroups[0].count, 2);
});

void test('filters by state, severity, query, and exact signal group', () => {
  const decisions = {
    'case:a': { decision: 'validated' as const, authoritative: true },
  };
  assert.deepEqual(
    filterReviewCandidates(candidates, decisions, { reviewState: 'pending' }).map(
      (candidate) => candidate.id,
    ),
    ['b', 'c'],
  );
  const groupKey = summarizeReviewCandidates(candidates, decisions)
    .repeatedGroups[0].key;
  assert.equal(
    filterReviewCandidates(candidates, decisions, {
      severity: 'high',
      query: 'signal',
      groupKey,
    }).length,
    2,
  );
});

void test('uses a constant candidate-key schema and bounded page requests', () => {
  assert.equal('enum' in candidateKeyInputSchema, false);
  assert.deepEqual(parseCandidatePageRequest({ cursor: 20, limit: 10 }), {
    cursor: 20,
    limit: 10,
    query: undefined,
    severity: undefined,
    reviewState: undefined,
  });
  assert.throws(() => parseCandidatePageRequest({ limit: 51 }), /limit/);
  assert.throws(() => parseCandidatePageRequest({ cursor: -1 }), /cursor/);
});
