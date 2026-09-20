export type ReviewState =
  | 'all'
  | 'pending'
  | 'draft'
  | 'recorded'
  | 'validated'
  | 'rejected'
  | 'abstained';

export type ReviewCandidateIndex = {
  key: string;
  id: string;
  caseLabel: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  source: string;
};

export type ReviewDecisionIndex = {
  decision: 'validated' | 'rejected' | 'abstained';
  authoritative: boolean;
};

export const WEB_MCP_DEFAULT_PAGE_SIZE = 20;
export const WEB_MCP_MAX_PAGE_SIZE = 50;

export const candidateKeyInputSchema = {
  type: 'string',
  minLength: 1,
  maxLength: 201,
} as const;

export function candidateGroupKey(
  candidate: Pick<ReviewCandidateIndex, 'source' | 'title'>,
) {
  return `${candidate.source}\u0000${candidate.title.trim().toLowerCase()}`;
}

export function candidateReviewState(
  candidate: Pick<ReviewCandidateIndex, 'key'>,
  decisions: Record<string, ReviewDecisionIndex>,
): Exclude<ReviewState, 'all' | 'recorded'> {
  const review = decisions[candidate.key];
  if (!review) return 'pending';
  if (!review.authoritative) return 'draft';
  return review.decision;
}

export function filterReviewCandidates<T extends ReviewCandidateIndex>(
  candidates: T[],
  decisions: Record<string, ReviewDecisionIndex>,
  filters: {
    query?: string;
    severity?: 'all' | ReviewCandidateIndex['severity'];
    reviewState?: ReviewState;
    groupKey?: string;
  },
) {
  const query = filters.query?.trim().toLowerCase() ?? '';
  return candidates.filter((candidate) => {
    const state = candidateReviewState(candidate, decisions);
    const stateMatches =
      !filters.reviewState ||
      filters.reviewState === 'all' ||
      filters.reviewState === state ||
      (filters.reviewState === 'recorded' &&
        decisions[candidate.key]?.authoritative === true);
    return (
      stateMatches &&
      (!filters.severity ||
        filters.severity === 'all' ||
        candidate.severity === filters.severity) &&
      (!filters.groupKey || candidateGroupKey(candidate) === filters.groupKey) &&
      (!query ||
        `${candidate.id} ${candidate.title} ${candidate.caseLabel} ${candidate.source}`
          .toLowerCase()
          .includes(query))
    );
  });
}

export function summarizeReviewCandidates(
  candidates: ReviewCandidateIndex[],
  decisions: Record<string, ReviewDecisionIndex>,
) {
  const bySeverity = { high: 0, medium: 0, low: 0 };
  const byState: Record<Exclude<ReviewState, 'all' | 'recorded'>, number> = {
    pending: 0,
    draft: 0,
    validated: 0,
    rejected: 0,
    abstained: 0,
  };
  const groups = new Map<
    string,
    { key: string; title: string; source: string; count: number }
  >();
  for (const candidate of candidates) {
    bySeverity[candidate.severity] += 1;
    byState[candidateReviewState(candidate, decisions)] += 1;
    const key = candidateGroupKey(candidate);
    const group = groups.get(key) ?? {
      key,
      title: candidate.title,
      source: candidate.source,
      count: 0,
    };
    group.count += 1;
    groups.set(key, group);
  }
  return {
    total: candidates.length,
    bySeverity,
    byState,
    repeatedGroups: [...groups.values()]
      .filter((group) => group.count > 1)
      .sort(
        (left, right) =>
          right.count - left.count || left.title.localeCompare(right.title),
      ),
  };
}

export function parseCandidatePageRequest(input: unknown) {
  const value =
    typeof input === 'object' && input !== null
      ? (input as Record<string, unknown>)
      : {};
  const cursor = value.cursor ?? 0;
  const limit = value.limit ?? WEB_MCP_DEFAULT_PAGE_SIZE;
  if (!Number.isInteger(cursor) || Number(cursor) < 0) {
    throw new Error('cursor must be a non-negative integer');
  }
  if (
    !Number.isInteger(limit) ||
    Number(limit) < 1 ||
    Number(limit) > WEB_MCP_MAX_PAGE_SIZE
  ) {
    throw new Error(`limit must be from 1 to ${WEB_MCP_MAX_PAGE_SIZE}`);
  }
  const query = value.query;
  if (query !== undefined && (typeof query !== 'string' || query.length > 200)) {
    throw new Error('query must be a string no longer than 200 characters');
  }
  const severity = value.severity;
  if (
    severity !== undefined &&
    (typeof severity !== 'string' ||
      !['high', 'medium', 'low'].includes(severity))
  ) {
    throw new Error('severity must be high, medium, or low');
  }
  const reviewState = value.reviewState;
  if (
    reviewState !== undefined &&
    (typeof reviewState !== 'string' ||
      ![
        'pending',
        'draft',
        'recorded',
        'validated',
        'rejected',
        'abstained',
      ].includes(reviewState))
  ) {
    throw new Error('reviewState is invalid');
  }
  return {
    cursor: Number(cursor),
    limit: Number(limit),
    query: typeof query === 'string' ? query : undefined,
    severity: severity as ReviewCandidateIndex['severity'] | undefined,
    reviewState: reviewState as ReviewState | undefined,
  };
}
