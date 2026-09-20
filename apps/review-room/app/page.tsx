'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  Boxes,
  Check,
  CheckSquare2,
  CircleAlert,
  CircleCheckBig,
  Copy,
  Download,
  FileCode2,
  Fingerprint,
  GitCompareArrows,
  LockKeyhole,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldQuestion,
  Square,
  UserCheck,
  Wrench,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from '@/components/ui/pagination';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import {
  createRemediationDraft,
  loadSecurityCaseFile,
  loadReviewSessionPayload,
  reviewSessionEndpoint,
  type Decision,
  type LoadedSecurityCase,
  type SecurityCase,
} from '@/lib/security-case';
import {
  candidateKeyInputSchema,
  filterReviewCandidates,
  parseCandidatePageRequest,
  summarizeReviewCandidates,
  type ReviewState,
  WEB_MCP_MAX_PAGE_SIZE,
} from '@/lib/review-efficiency';

type Candidate = {
  key: string;
  id: string;
  caseId: string;
  caseLabel: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  summary: string;
  location: string;
  confidence: number;
  recommendation: Decision;
  agentReason: string;
  hardening: string;
  source: string;
  guard: string;
  sink: string;
  revision: string;
};
type ReviewDraft = {
  decision: Decision;
  rationale: string;
  authoritative: boolean;
};
type AuditEvent = {
  actor: 'agent' | 'human' | 'system';
  action: string;
  time: string;
};
type ToolDefinition = {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: { readOnlyHint: boolean; untrustedContentHint: boolean };
  execute: (input: unknown) => unknown;
};

declare global {
  interface Document {
    modelContext?: {
      registerTool: (
        tool: ToolDefinition,
        options?: { signal?: AbortSignal },
      ) => void | Promise<void>;
    };
  }
}

const STORAGE_KEY = 'secureflow-review-room-v2';
const MAX_REVIEW_CASES = 1_024;
const MAX_REVIEW_CASE_BYTES = 128 * 1024 * 1024;
const CANDIDATE_PAGE_SIZE = 5;
const severityFor = (value?: string): Candidate['severity'] =>
  value === 'high' || value === 'medium' || value === 'low' ? value : 'low';
const confidenceFor = (value: string) =>
  value === 'high' ? 75 : value === 'medium' ? 50 : value === 'low' ? 25 : 0;
const isDecision = (value: string): value is Decision =>
  value === 'validated' || value === 'rejected' || value === 'abstained';
const clock = () =>
  new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date());
const label = (decision: Decision) =>
  decision === 'validated'
    ? 'Validate'
    : decision === 'rejected'
      ? 'Reject'
      : 'Abstain';
const compactIdentifier = (value: string) =>
  value.length > 28 ? `${value.slice(0, 18)}…${value.slice(-6)}` : value;

function candidateFromCase(
  loaded: LoadedSecurityCase,
  candidate: SecurityCase['candidates'][number],
): Candidate {
  const staged = loaded.document.staged_recommendations
    .filter((entry) => entry.candidate_id === candidate.candidate_id)
    .at(-1);
  const recommendation =
    staged && isDecision(staged.recommendation)
      ? staged.recommendation
      : 'abstained';
  return {
    key: `${loaded.document.case_id}:${candidate.candidate_id}`,
    id: candidate.candidate_id,
    caseId: loaded.document.case_id,
    caseLabel: loaded.document.target.label,
    severity: severityFor(candidate.severity),
    title: candidate.title,
    summary: `${candidate.class} retained in ${loaded.fileName}.`,
    location: candidate.evidence_ids.join(', ') || 'No linked evidence identifier',
    confidence: confidenceFor(candidate.confidence),
    recommendation,
    agentReason:
      staged?.rationale ??
      'No agent recommendation is retained. Inspect the evidence and limitations before deciding.',
    hardening:
      'Prepare a minimal code change only after a final human validation and a separate remediation authorization.',
    source: candidate.class,
    guard: 'Not asserted by the universal case',
    sink: candidate.evidence_ids.join(', ') || 'No linked evidence identifier',
    revision:
      candidate.limitations.join(' ') ||
      'No additional revision context retained.',
  };
}

function downloadJson(value: unknown, fileName: string) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function Home() {
  const [loadedCases, setLoadedCases] = useState<LoadedSecurityCase[]>([]);
  const [selectedKey, setSelectedKey] = useState('');
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<
    'all' | Candidate['severity']
  >('all');
  const [reviewFilter, setReviewFilter] = useState<ReviewState>('all');
  const [groupFilter, setGroupFilter] = useState('');
  const [candidatePage, setCandidatePage] = useState(0);
  const [mode, setMode] = useState<'manual' | 'agent'>('manual');
  const [staged, setStaged] = useState<Decision | null>(null);
  const [rationale, setRationale] = useState('');
  const [decisions, setDecisions] = useState<Record<string, ReviewDraft>>({});
  const [remediationSelection, setRemediationSelection] = useState<string[]>([]);
  const [allowedPaths, setAllowedPaths] = useState('');
  const [handoffError, setHandoffError] = useState('');
  const [audit, setAudit] = useState<AuditEvent[]>([
    { actor: 'system', action: 'Waiting for local Security Cases', time: clock() },
  ]);
  const [copied, setCopied] = useState(false);
  const [webMcpStatus, setWebMcpStatus] = useState<
    'ready' | 'unavailable' | 'error'
  >('unavailable');
  const decisionsRef = useRef(decisions);
  const selectionRef = useRef(remediationSelection);
  const sessionLoadStarted = useRef(false);

  const candidates = useMemo(
    () =>
      loadedCases.flatMap((loaded) =>
        loaded.document.candidates.map((candidate) =>
          candidateFromCase(loaded, candidate),
        ),
      ),
    [loadedCases],
  );
  const selected =
    candidates.find((candidate) => candidate.key === selectedKey) ?? candidates[0];
  const selectedCase = loadedCases.find(
    (loaded) => loaded.document.case_id === selected?.caseId,
  );
  const reviewSummary = useMemo(
    () => summarizeReviewCandidates(candidates, decisions),
    [candidates, decisions],
  );
  const filtered = useMemo(
    () =>
      filterReviewCandidates(candidates, decisions, {
        query,
        severity: severityFilter,
        reviewState: reviewFilter,
        groupKey: groupFilter || undefined,
      }),
    [query, severityFilter, reviewFilter, groupFilter, candidates, decisions],
  );
  const candidatePageCount = Math.max(
    1,
    Math.ceil(filtered.length / CANDIDATE_PAGE_SIZE),
  );
  const candidatePageStart = candidatePage * CANDIDATE_PAGE_SIZE;
  const visibleCandidates = filtered.slice(
    candidatePageStart,
    candidatePageStart + CANDIDATE_PAGE_SIZE,
  );
  const dispositionCount = Object.values(decisions).length;

  useEffect(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    try {
      const stored = JSON.parse(raw) as {
        decisions?: Record<string, ReviewDraft>;
        audit?: AuditEvent[];
        allowedPaths?: string;
      };
      queueMicrotask(() => {
        if (stored.decisions) setDecisions(stored.decisions);
        if (stored.audit) setAudit(stored.audit);
        if (stored.allowedPaths) setAllowedPaths(stored.allowedPaths);
      });
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);
  useEffect(() => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ decisions, audit, allowedPaths }),
    );
  }, [decisions, audit, allowedPaths]);
  useEffect(() => {
    decisionsRef.current = decisions;
    selectionRef.current = remediationSelection;
  }, [decisions, remediationSelection]);

  function choose(key: string) {
    setSelectedKey(key);
    const decision = decisions[key];
    setStaged(decision?.decision ?? null);
    setRationale(decision?.rationale ?? '');
  }

  function acceptLoadedCases(parsed: LoadedSecurityCase[]) {
    const caseIds = new Set<string>();
    for (const loaded of parsed) {
      if (caseIds.has(loaded.document.case_id)) {
        throw new Error(`Duplicate case identity: ${loaded.document.case_id}`);
      }
      caseIds.add(loaded.document.case_id);
    }
    const nextCandidates = parsed.flatMap((loaded) =>
      loaded.document.candidates.map((candidate) =>
        candidateFromCase(loaded, candidate),
      ),
    );
    const authoritative: Record<string, ReviewDraft> = {};
    for (const loaded of parsed) {
      for (const decision of loaded.document.decisions) {
        authoritative[`${loaded.document.case_id}:${decision.candidate_id}`] = {
          decision: decision.decision,
          rationale: decision.rationale,
          authoritative: true,
        };
      }
    }
    setLoadedCases(parsed);
    setSelectedKey(nextCandidates[0]?.key ?? '');
    setCandidatePage(0);
    setQuery('');
    setSeverityFilter('all');
    setReviewFilter('all');
    setGroupFilter('');
    setDecisions(authoritative);
    setRemediationSelection([]);
    setAudit([
      {
        actor: 'system',
        action: `Loaded ${parsed.length} cases with ${nextCandidates.length} evidence-bound candidates`,
        time: clock(),
      },
    ]);
  }

  function stageRecommendation() {
    if (!selected) return;
    setStaged(selected.recommendation);
    setRationale(selected.agentReason);
    setAudit((events) => [
      ...events,
      {
        actor: 'agent',
        action: `Staged ${selected.recommendation} recommendation for ${selected.id}`,
        time: clock(),
      },
    ]);
  }

  function saveReviewDraft() {
    if (!selected || !staged || rationale.trim().length < 12) return;
    setDecisions((current) => ({
      ...current,
      [selected.key]: {
        decision: staged,
        rationale: rationale.trim(),
        authoritative: false,
      },
    }));
    setRemediationSelection((current) =>
      current.filter((key) => key !== selected.key),
    );
    setAudit((events) => [
      ...events,
      {
        actor: 'human',
        action: `Saved ${staged} review draft for ${selected.id}`,
        time: clock(),
      },
    ]);
  }

  function toggleRemediation(key: string) {
    if (decisions[key]?.decision !== 'validated' || !decisions[key]?.authoritative) return;
    setRemediationSelection((current) =>
      current.includes(key)
        ? current.filter((candidateKey) => candidateKey !== key)
        : [...current, key],
    );
  }

  function reset() {
    const authoritative: Record<string, ReviewDraft> = {};
    for (const loaded of loadedCases) {
      for (const decision of loaded.document.decisions) {
        authoritative[`${loaded.document.case_id}:${decision.candidate_id}`] = {
          decision: decision.decision,
          rationale: decision.rationale,
          authoritative: true,
        };
      }
    }
    setDecisions(authoritative);
    setRemediationSelection([]);
    setAllowedPaths('');
    setStaged(null);
    setRationale('');
    setAudit([
      {
        actor: 'system',
        action: loadedCases.length
          ? 'Loaded cases retained; browser drafts reset'
          : 'Waiting for local Security Cases',
        time: clock(),
      },
    ]);
    localStorage.removeItem(STORAGE_KEY);
  }

  function exportAudit() {
    downloadJson(
      {
        schema: 'secureflow-review-room-audit-v2',
        cases: loadedCases.map((loaded) => ({
          case_id: loaded.document.case_id,
          case_sha256: loaded.sha256,
          file_name: loaded.fileName,
        })),
        review_drafts: decisions,
        remediation_selection: remediationSelection,
        audit,
        authority:
          'Browser review drafts are not final Security Case decisions or remediation authorization.',
      },
      'secureflow-review-audit.json',
    );
  }

  async function exportRemediationDraft() {
    setHandoffError('');
    try {
      const draft = await createRemediationDraft(
        loadedCases,
        remediationSelection,
        allowedPaths.split(/[,\n]/),
      );
      downloadJson(draft, `${draft.handoff_id}-draft.json`);
      setAudit((events) => [
        ...events,
        {
          actor: 'human',
          action: `Exported remediation draft for ${remediationSelection.length} selected candidates`,
          time: clock(),
        },
      ]);
    } catch (error) {
      setHandoffError(
        error instanceof Error
          ? error.message
          : 'Could not create the handoff draft.',
      );
    }
  }

  async function loadCases(files: FileList | null) {
    if (!files?.length) return;
    setLoadError('');
    try {
      if (files.length > MAX_REVIEW_CASES) {
        throw new Error(`Choose no more than ${MAX_REVIEW_CASES} component cases.`);
      }
      const totalBytes = Array.from(files).reduce((sum, file) => sum + file.size, 0);
      if (totalBytes > MAX_REVIEW_CASE_BYTES) {
        throw new Error('The selected component set exceeds the 128 MiB session limit.');
      }
      const parsed = await Promise.all(Array.from(files, loadSecurityCaseFile));
      acceptLoadedCases(parsed);
    } catch (error) {
      setLoadError(
        error instanceof Error
          ? error.message
          : 'Could not read the Security Cases.',
      );
    }
  }

  useEffect(() => {
    if (sessionLoadStarted.current) return;
    sessionLoadStarted.current = true;
    let endpoint: string | null;
    try {
      endpoint = reviewSessionEndpoint(window.location.search);
    } catch (error) {
      queueMicrotask(() =>
        setLoadError(error instanceof Error ? error.message : 'Invalid local session.'),
      );
      return;
    }
    if (endpoint === null) return;
    const controller = new AbortController();
    void fetch(endpoint, {
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not open the local Review Room session.');
        return loadReviewSessionPayload(await response.json());
      })
      .then(acceptLoadedCases)
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setLoadError(
          error instanceof Error
            ? error.message
            : 'Could not open the local Review Room session.',
        );
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool || candidates.length === 0) return;
    const lifecycle = new AbortController();
    const candidateFor = (input: unknown) => {
      const key =
        typeof input === 'object' && input !== null && 'candidateKey' in input
          ? (input as { candidateKey?: unknown }).candidateKey
          : null;
      if (typeof key !== 'string') throw new Error('candidateKey must be a string');
      const candidate = candidates.find((entry) => entry.key === key);
      if (!candidate) throw new Error(`Unknown candidateKey: ${key}`);
      return candidate;
    };
    const candidateSchema = {
      type: 'object',
      properties: {
        candidateKey: candidateKeyInputSchema,
      },
      required: ['candidateKey'],
      additionalProperties: false,
    };
    const tools: ToolDefinition[] = [
      {
        name: 'list_security_cases',
        title: 'List loaded Security Cases',
        description:
          'List exact local case identities and component coverage. This does not imply repository-wide coverage.',
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        execute: () => ({
          cases: loadedCases.map((loaded) => ({
            id: loaded.document.case_id,
            target: loaded.document.target.label,
            sha256: loaded.sha256,
            candidateCount: loaded.document.candidates.length,
          })),
          coverage: 'component cases only',
        }),
      },
      {
        name: 'summarize_candidates',
        title: 'Summarize security candidates',
        description:
          'Return compact counts and repeated signal groups before requesting individual candidate pages.',
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        execute: () => ({
          ...summarizeReviewCandidates(candidates, decisionsRef.current),
          coverage: 'loaded component cases only',
          finalAuthority: 'human-only',
        }),
      },
      {
        name: 'list_candidates',
        title: 'List security candidates',
        description:
          'Page through compact candidate summaries. Filter first, then inspect only selected candidates.',
        inputSchema: {
          type: 'object',
          properties: {
            cursor: { type: 'integer', minimum: 0, default: 0 },
            limit: {
              type: 'integer',
              minimum: 1,
              maximum: WEB_MCP_MAX_PAGE_SIZE,
              default: 20,
            },
            severity: { enum: ['high', 'medium', 'low'] },
            reviewState: {
              enum: [
                'pending',
                'draft',
                'recorded',
                'validated',
                'rejected',
                'abstained',
              ],
            },
            query: { type: 'string', maxLength: 200 },
          },
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        execute: (input) => {
          const request = parseCandidatePageRequest(input);
          const matching = filterReviewCandidates(
            candidates,
            decisionsRef.current,
            request,
          );
          const page = matching.slice(
            request.cursor,
            request.cursor + request.limit,
          );
          const nextCursor =
            request.cursor + page.length < matching.length
              ? request.cursor + page.length
              : null;
          return {
            total: candidates.length,
            matched: matching.length,
            returned: page.length,
            cursor: request.cursor,
            nextCursor,
            candidates: page.map((candidate) => ({
              key: candidate.key,
              id: candidate.id,
              caseId: candidate.caseId,
              component: candidate.caseLabel,
              severity: candidate.severity,
              source: candidate.source,
              title: candidate.title,
              reviewState:
                decisionsRef.current[candidate.key]?.authoritative === true
                  ? decisionsRef.current[candidate.key]?.decision
                  : decisionsRef.current[candidate.key]
                    ? 'draft'
                    : 'pending',
            })),
            finalAuthority: 'human-only',
          };
        },
      },
      {
        name: 'inspect_evidence',
        title: 'Inspect candidate evidence',
        description:
          'Select a candidate and return its retained evidence boundary without claiming exploitability.',
        inputSchema: candidateSchema,
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        execute: (input) => {
          const candidate = candidateFor(input);
          setQuery('');
          setSeverityFilter('all');
          setReviewFilter('all');
          setGroupFilter('');
          setCandidatePage(
            Math.floor(candidates.indexOf(candidate) / CANDIDATE_PAGE_SIZE),
          );
          setSelectedKey(candidate.key);
          return {
            key: candidate.key,
            summary: candidate.summary,
            location: candidate.location,
            source: candidate.source,
            visibleGuard: candidate.guard,
            sink: candidate.sink,
            boundary:
              'Static evidence only; runtime controls and exploitability need human validation.',
          };
        },
      },
      {
        name: 'stage_agent_recommendation',
        title: 'Stage agent recommendation',
        description:
          'Prepare the visible review draft. This cannot record a final human decision or remediation authorization.',
        inputSchema: candidateSchema,
        annotations: { readOnlyHint: false, untrustedContentHint: true },
        execute: (input) => {
          const candidate = candidateFor(input);
          setQuery('');
          setSeverityFilter('all');
          setReviewFilter('all');
          setGroupFilter('');
          setCandidatePage(
            Math.floor(candidates.indexOf(candidate) / CANDIDATE_PAGE_SIZE),
          );
          setSelectedKey(candidate.key);
          setMode('agent');
          setStaged(candidate.recommendation);
          setRationale(candidate.agentReason);
          return {
            key: candidate.key,
            stagedRecommendation: candidate.recommendation,
            finalized: false,
          };
        },
      },
      {
        name: 'prepare_remediation_handoff',
        title: 'Prepare remediation handoff',
        description:
          'Read the human-selected remediation scope and report whether a handoff can be drafted. This never edits code.',
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, untrustedContentHint: true },
        execute: () => ({
          selectedCandidateKeys: selectionRef.current,
          status: selectionRef.current.length
            ? 'draft_ready'
            : 'awaiting_human_selection',
          requiredNextStep:
            'Export the draft from recorded decisions, then authorize it with secureflow remediation-authorize.',
          mergeAuthorized: false,
          deployAuthorized: false,
        }),
      },
    ];
    try {
      Promise.all(
        tools.map((tool) =>
          Promise.resolve(
            context.registerTool(tool, { signal: lifecycle.signal }),
          ),
        ),
      )
        .then(() => setWebMcpStatus('ready'))
        .catch(() => setWebMcpStatus('error'));
    } catch {
      queueMicrotask(() => setWebMcpStatus('error'));
    }
    return () => lifecycle.abort();
  }, [candidates, loadedCases]);

  if (!selected || !selectedCase) {
    return (
      <main className="review-shell min-h-screen">
        <section className="case-loader max-w-3xl mx-auto mt-16">
          <div className="loader-mark"><ShieldCheck /></div>
          <p className="section-kicker">Local evidence / Unified Review Room</p>
          <h1>Open your security review</h1>
          <p className="case-deck">
            Load one Security Case or a component set. Everything stays in this
            browser; candidates remain unconfirmed until a person decides.
          </p>
          <label className="load-button" htmlFor="case-files">
            <Boxes /> Choose Security Case JSON files
          </label>
          <input
            id="case-files"
            className="sr-only"
            type="file"
            multiple
            accept="application/json,.json"
            onChange={(event) => void loadCases(event.target.files)}
          />
          <div className="loader-boundary">
            <LockKeyhole /> No target traffic, no automatic verdicts, no
            autonomous patching.
          </div>
          {loadError && <p className="load-error" role="alert">{loadError}</p>}
        </section>
      </main>
    );
  }

  const selectedReview = decisions[selected.key];
  const remediationEligible = selectedReview?.decision === 'validated' && selectedReview.authoritative;

  return (
    <main className="review-shell min-h-screen">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark"><ShieldCheck /></span>
          <span className="brand-name">SECUREFLOW</span>
          <span className="brand-divider" />
          <span className="brand-product">Unified Review Room</span>
        </div>
        <div className="topbar-actions">
          <span className="status-line status-authorized"><LockKeyhole /> Authorized scope</span>
          <span className="status-line">{loadedCases.length} local cases</span>
          <span className={`status-line ${webMcpStatus === 'ready' ? 'status-agent' : ''}`}>
            <span className="status-dot" />
            {webMcpStatus === 'ready'
              ? 'WebMCP ready'
              : webMcpStatus === 'error'
                ? 'WebMCP error'
                : 'WebMCP unavailable'}
          </span>
          <Button variant="ghost" size="sm" onClick={reset} className="utility-button"><RotateCcw /> Reset drafts</Button>
          <Button variant="outline" size="sm" onClick={exportAudit} className="utility-button"><Download /> Export audit</Button>
        </div>
      </header>

      <section className="workflow-rail" aria-label="SecureFlow workflow">
        {[
          ['Evidence', true],
          ['Human review', dispositionCount > 0],
          ['Fix authorization', remediationSelection.length > 0],
          ['Patch + tests', false],
          ['Re-scan', false],
        ].map(([name, active], index) => (
          <div className={active ? 'workflow-step workflow-step-active' : 'workflow-step'} key={String(name)}>
            <span>{active ? <CircleCheckBig /> : index + 1}</span>
            <strong>{name}</strong>
          </div>
        ))}
      </section>

      <section className="case-masthead">
        <div>
          <p className="section-kicker">Active component / {selected.caseLabel}</p>
          <h1>{selected.title}</h1>
          <p className="case-deck">
            Investigate manually or with an agent. Human review and remediation
            authorization remain separate, explicit actions.
          </p>
        </div>
        <div className="case-metadata">
          <button
            className="case-id"
            onClick={() => {
              void navigator.clipboard.writeText(selected.caseId);
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            }}
          >
            <Fingerprint /> {selected.caseId} {copied ? <Check /> : <Copy />}
          </button>
          <span>REV {selectedCase.document.target.revision?.value ?? 'unrecorded'}</span>
          <span>CASE SHA {selectedCase.sha256.slice(0, 16)}…</span>
        </div>
        <div className="review-progress">
          <div><span>Review drafts</span><strong>{dispositionCount} / {candidates.length}</strong></div>
          <Progress value={candidates.length ? (dispositionCount / candidates.length) * 100 : 0} className="h-1 bg-black/10 [&>div]:bg-[#146b4d]" />
        </div>
      </section>

      <div className="workbench">
        <aside id="candidate-queue" className="queue-pane" aria-label="Candidate queue">
          <div className="pane-heading">
            <div><p className="section-kicker">Candidate queue</p><h2>Component signals</h2></div>
            <span className="count-cell" title={`${candidates.length} total candidates`}>
              {filtered.length}/{candidates.length}
            </span>
          </div>
          <div className="queue-search"><Search /><input aria-label="Search candidates" value={query} onChange={(event) => { setQuery(event.target.value); setCandidatePage(0); }} placeholder="ID, title, or component" /></div>
          <div className="queue-filters">
            <label>
              <span>Review</span>
              <select
                aria-label="Filter by review state"
                value={reviewFilter}
                onChange={(event) => {
                  setReviewFilter(event.target.value as ReviewState);
                  setCandidatePage(0);
                }}
              >
                <option value="all">All states</option>
                <option value="pending">Pending ({reviewSummary.byState.pending})</option>
                <option value="draft">Draft ({reviewSummary.byState.draft})</option>
                <option value="recorded">Recorded</option>
                <option value="validated">Validated ({reviewSummary.byState.validated})</option>
                <option value="rejected">Rejected ({reviewSummary.byState.rejected})</option>
                <option value="abstained">Abstained ({reviewSummary.byState.abstained})</option>
              </select>
            </label>
            <label>
              <span>Severity</span>
              <select
                aria-label="Filter by severity"
                value={severityFilter}
                onChange={(event) => {
                  setSeverityFilter(
                    event.target.value as 'all' | Candidate['severity'],
                  );
                  setCandidatePage(0);
                }}
              >
                <option value="all">All levels</option>
                <option value="high">High ({reviewSummary.bySeverity.high})</option>
                <option value="medium">Medium ({reviewSummary.bySeverity.medium})</option>
                <option value="low">Low ({reviewSummary.bySeverity.low})</option>
              </select>
            </label>
          </div>
          {reviewSummary.repeatedGroups.length > 0 && (
            <div className="signal-groups" aria-label="Repeated signal groups">
              <div className="signal-groups-heading">
                <span>Repeated signals</span>
                {groupFilter && (
                  <button
                    type="button"
                    onClick={() => {
                      setGroupFilter('');
                      setCandidatePage(0);
                    }}
                  >
                    Clear
                  </button>
                )}
              </div>
              {reviewSummary.repeatedGroups.slice(0, 3).map((group) => (
                <button
                  type="button"
                  key={group.key}
                  className={groupFilter === group.key ? 'signal-group-active' : ''}
                  aria-pressed={groupFilter === group.key}
                  title={group.title}
                  onClick={() => {
                    setGroupFilter(groupFilter === group.key ? '' : group.key);
                    setCandidatePage(0);
                  }}
                >
                  <span>{group.title}</span>
                  <strong>{group.count}</strong>
                </button>
              ))}
            </div>
          )}
          <div className="queue-columns" aria-hidden="true"><span>Signal</span><span>Evidence</span></div>
          <div className="candidate-list">
            {visibleCandidates.map((candidate) => (
              <button key={candidate.key} onClick={() => choose(candidate.key)} className={`candidate-row ${candidate.key === selected.key ? 'candidate-row-active' : ''}`}>
                <span className={`severity-rule severity-${candidate.severity}`} />
                <span className="candidate-copy">
                  <span className="component-name">{candidate.caseLabel}</span>
                  <span className="candidate-id" title={candidate.id}>
                    {compactIdentifier(candidate.id)} · {candidate.severity}
                  </span>
                  <span className="candidate-title">{candidate.title}</span>
                  <span className="candidate-state">
                    {decisions[candidate.key]
                      ? `${decisions[candidate.key].authoritative ? 'recorded' : 'draft'}: ${decisions[candidate.key].decision}`
                      : 'awaiting review'}
                  </span>
                </span>
                <strong>{candidate.confidence}%</strong>
              </button>
            ))}
            {filtered.length === 0 && <p className="queue-empty">No candidates match this filter.</p>}
          </div>
          {filtered.length > 0 && (
            <Pagination className="queue-pagination" aria-label="Candidate pages">
              <PaginationContent className="queue-pagination-content">
                <PaginationItem>
                  <PaginationPrevious
                    href="#candidate-queue"
                    text="Previous"
                    aria-disabled={candidatePage === 0}
                    tabIndex={candidatePage === 0 ? -1 : 0}
                    onClick={(event) => {
                      event.preventDefault();
                      if (candidatePage > 0) setCandidatePage(candidatePage - 1);
                    }}
                  />
                </PaginationItem>
                <PaginationItem>
                  <output className="queue-page-status" aria-live="polite">
                    {candidatePageStart + 1}–{Math.min(candidatePageStart + CANDIDATE_PAGE_SIZE, filtered.length)} of {filtered.length}
                  </output>
                </PaginationItem>
                <PaginationItem>
                  <PaginationNext
                    href="#candidate-queue"
                    text="Next"
                    aria-disabled={candidatePage >= candidatePageCount - 1}
                    tabIndex={candidatePage >= candidatePageCount - 1 ? -1 : 0}
                    onClick={(event) => {
                      event.preventDefault();
                      if (candidatePage < candidatePageCount - 1) {
                        setCandidatePage(candidatePage + 1);
                      }
                    }}
                  />
                </PaginationItem>
              </PaginationContent>
            </Pagination>
          )}
          <div className="queue-footnote">Component coverage is explicit; this view does not claim full-repository coverage.</div>
        </aside>

        <section className="evidence-pane">
          <header className="finding-header">
            <div className="finding-reference">
              <span title={selected.id}>{compactIdentifier(selected.id)}</span>
              <span className={`severity-label severity-text-${selected.severity}`}>{selected.severity} signal</span>
            </div>
            <h2>{selected.title}</h2>
            <p>{selected.summary}</p>
            <div className="source-location"><FileCode2 /> {selected.location}</div>
            <div className="confidence-readout"><strong>{selected.confidence}</strong><span>%<br />evidence confidence</span></div>
          </header>

          <Tabs defaultValue="evidence" className="evidence-tabs">
            <TabsList variant="line" className="evidence-tab-list">
              <TabsTrigger value="evidence">Evidence record</TabsTrigger>
              <TabsTrigger value="flow">Source → sink</TabsTrigger>
              <TabsTrigger value="revision">Revision context</TabsTrigger>
            </TabsList>
            <TabsContent value="evidence" className="evidence-content">
              <div className="record-table">
                {[
                  ['01 / source', 'Analysis source', selected.source],
                  ['02 / control', 'Visible guard', selected.guard],
                  ['03 / sink', 'Bound evidence', selected.sink],
                ].map(([index, title, value]) => (
                  <div className="record-row" key={index}><span className="record-index">{index}</span><span className="record-label">{title}</span><code>{value}</code></div>
                ))}
              </div>
              <div className="boundary-note"><CircleAlert /><div><strong>Evidence boundary</strong><p>Static evidence only. Runtime reachability, hidden policy layers, and exploitability require human-controlled validation.</p></div></div>
            </TabsContent>
            <TabsContent value="flow" className="evidence-content">
              <div className="flow-ledger">
                {[
                  ['INPUT', 'Untrusted or contextual source', selected.source],
                  ['GUARD', 'Observed control', selected.guard],
                  ['OPERATION', 'Sensitive evidence target', selected.sink],
                ].map(([kind, title, value], index) => (
                  <div className="flow-entry" key={kind}><span>{String(index + 1).padStart(2, '0')}</span><div><small>{kind}</small><strong>{title}</strong><code>{value}</code></div></div>
                ))}
              </div>
            </TabsContent>
            <TabsContent value="revision" className="evidence-content">
              <div className="revision-note"><GitCompareArrows /><div><span>REVISION {selectedCase.document.target.revision?.value ?? 'unrecorded'}</span><p>{selected.revision}</p></div></div>
            </TabsContent>
          </Tabs>
        </section>

        <aside className="review-pane" aria-label="Review and remediation controls">
          <section className="review-section mode-section">
            <fieldset className="mode-switch" aria-label="Review mode">
              <button className={mode === 'manual' ? 'mode-active' : ''} onClick={() => setMode('manual')}><UserCheck /> Manual</button>
              <button className={mode === 'agent' ? 'mode-active' : ''} onClick={() => setMode('agent')}><Bot /> Agent-assisted</button>
            </fieldset>
            <p>{mode === 'manual' ? 'Inspect and draft your own disposition.' : 'Let WebMCP investigate and stage a recommendation; you still decide.'}</p>
          </section>

          {mode === 'agent' && (
            <section className="review-section agent-section">
              <div className="review-section-heading"><Bot /><div><span>Agent memorandum</span><small>Provisional / evidence-bound</small></div></div>
              <div className="agent-disposition"><span>Suggested disposition</span><strong>{label(selected.recommendation)}</strong></div>
              <p className="review-copy">{selected.agentReason}</p>
              <div className="hardening-note"><span>Hardening direction</span><p>{selected.hardening}</p></div>
              <Button onClick={stageRecommendation} className="stage-button">Stage recommendation</Button>
            </section>
          )}

          <section className="review-section human-section">
            <div className="review-section-heading"><UserCheck /><div><span>Human review draft</span><small>CLI persists final authority</small></div></div>
            <fieldset className="decision-options" aria-label="Human disposition">
              {(['validated', 'rejected', 'abstained'] as Decision[]).map((decision) => (
                <button key={decision} aria-pressed={staged === decision} onClick={() => setStaged(decision)} className={staged === decision ? 'decision-active' : ''}>{label(decision)}</button>
              ))}
            </fieldset>
            <label htmlFor="rationale">Reviewer rationale <span>required</span></label>
            <Textarea id="rationale" value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Cite the evidence supporting this disposition…" className="decision-rationale" />
            <Button onClick={saveReviewDraft} disabled={!staged || rationale.trim().length < 12} className="record-button"><ShieldQuestion /> Save review draft</Button>
            <p className="authority-note">This browser action is not a final Security Case decision. SecureFlow CLI records the named reviewer.</p>
          </section>

          <section className="review-section remediation-section">
            <div className="review-section-heading"><Wrench /><div><span>Remediation handoff</span><small>Separate authorization boundary</small></div></div>
            <button className={`remediation-select ${remediationSelection.includes(selected.key) ? 'remediation-selected' : ''}`} disabled={!remediationEligible} onClick={() => toggleRemediation(selected.key)}>
              {remediationSelection.includes(selected.key) ? <CheckSquare2 /> : <Square />}
              {remediationEligible ? 'Include this validated candidate' : 'Load a recorded validated decision to select this candidate'}
            </button>
            <label htmlFor="allowed-paths">Allowed repository paths <span>one per line</span></label>
            <Textarea id="allowed-paths" value={allowedPaths} onChange={(event) => setAllowedPaths(event.target.value)} placeholder={'apps/api/src/auth.ts\npackages/security'} className="scope-paths" />
            <Button onClick={() => void exportRemediationDraft()} disabled={remediationSelection.length === 0} className="handoff-button"><Download /> Export fix handoff ({remediationSelection.length})</Button>
            {handoffError && <p className="handoff-error" role="alert">{handoffError}</p>}
            <p className="authority-note">The draft permits neither merge nor deploy. Run <code>secureflow remediation-authorize</code> against exact decided cases before editing.</p>
          </section>

          <section className="review-section audit-section">
            <div className="audit-heading"><span>Audit ledger</span><small>local view</small></div>
            <div className="audit-list">
              {audit.slice().reverse().map((event, index) => (
                <div className="audit-entry" key={`${event.time}-${index}`}>
                  <span className={`actor-mark actor-${event.actor}`}>{event.actor === 'human' ? <UserCheck /> : event.actor === 'agent' ? <Bot /> : <LockKeyhole />}</span>
                  <div><p>{event.action}</p><small>{event.actor} / {event.time}</small></div>
                </div>
              ))}
            </div>
          </section>
        </aside>
      </div>

      <footer className="review-footer"><span>SecureFlow / local-first review and remediation handoff</span><strong>AI investigates. Humans decide. Authorized agents patch. Evidence persists.</strong></footer>
    </main>
  );
}
