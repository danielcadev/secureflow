'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  Check,
  CircleAlert,
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
  UserCheck,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';

type Decision = 'validated' | 'rejected' | 'abstained';
type Candidate = {
  id: string;
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

const STORAGE_KEY = 'secureflow-review-room-v1';
type CaseDocument = {
  contract_version: string;
  case_id: string;
  target: { label: string; revision?: { value: string } };
  candidates: Array<{
    candidate_id: string;
    class: string;
    title: string;
    severity?: string;
    confidence: string;
    evidence_ids: string[];
    limitations: string[];
  }>;
  decisions: Array<{ candidate_id: string; decision: Decision; rationale: string }>;
};

const severityFor = (value?: string): Candidate['severity'] =>
  value === 'high' || value === 'medium' || value === 'low' ? value : 'low';
const confidenceFor = (value: string) =>
  value === 'high' ? 75 : value === 'medium' ? 50 : value === 'low' ? 25 : 0;
const candidateFromCase = (candidate: CaseDocument['candidates'][number]): Candidate => ({
  id: candidate.candidate_id,
  severity: severityFor(candidate.severity),
  title: candidate.title,
  summary: `${candidate.class} retained in the loaded Security Case.`,
  location: candidate.evidence_ids.join(', ') || 'No linked evidence identifier',
  confidence: confidenceFor(candidate.confidence),
  recommendation: 'abstained',
  agentReason:
    'No agent recommendation is authoritative. A human reviewer must assess the retained evidence and limitations.',
  hardening: 'Review the retained evidence and document any safe follow-up separately.',
  source: candidate.class,
  guard: 'Not asserted by the universal case',
  sink: candidate.evidence_ids.join(', ') || 'No linked evidence identifier',
  revision: candidate.limitations.join(' ') || 'No additional revision context retained.',
});

const clock = () =>
  new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date());
const label = (d: Decision) =>
  d === 'validated' ? 'Validate' : d === 'rejected' ? 'Reject' : 'Abstain';

export default function Home() {
  const [caseDocument, setCaseDocument] = useState<CaseDocument | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [staged, setStaged] = useState<Decision | null>(null);
  const [rationale, setRationale] = useState('');
  const [decisions, setDecisions] = useState<
    Record<string, { decision: Decision; rationale: string }>
  >({});
  const [audit, setAudit] = useState<AuditEvent[]>([
    {
      actor: 'system',
      action: 'Waiting for a local Security Case',
      time: '09:41:02',
    },
  ]);
  const [copied, setCopied] = useState(false);
  const [webMcpStatus, setWebMcpStatus] = useState<
    'ready' | 'unavailable' | 'error'
  >('unavailable');
  const decisionsRef = useRef(decisions);

  useEffect(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw)
      try {
        const s = JSON.parse(raw);
        queueMicrotask(() => {
          if (s.decisions) setDecisions(s.decisions);
          if (s.audit) setAudit(s.audit);
        });
      } catch {
        localStorage.removeItem(STORAGE_KEY);
      }
  }, []);
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ decisions, audit }));
  }, [decisions, audit]);
  useEffect(() => {
    decisionsRef.current = decisions;
  }, [decisions]);
  const selected = candidates.find((c) => c.id === selectedId) ?? candidates[0];
  const filtered = useMemo(
    () =>
      candidates.filter((c) =>
        `${c.id} ${c.title}`.toLowerCase().includes(query.toLowerCase()),
      ),
    [query, candidates],
  );

  function choose(id: string) {
    setSelectedId(id);
    const d = decisions[id];
    setStaged(d?.decision ?? null);
    setRationale(d?.rationale ?? '');
  }
  function stage() {
    if (!selected) return;
    setStaged(selected.recommendation);
    setRationale(selected.agentReason);
    setAudit((a) => [
      ...a,
      {
        actor: 'agent',
        action: `Staged ${selected.recommendation} recommendation for ${selected.id}`,
        time: clock(),
      },
    ]);
  }
  function record() {
    if (!selected || !staged || rationale.trim().length < 12) return;
    setDecisions((d) => ({
      ...d,
      [selected.id]: { decision: staged, rationale: rationale.trim() },
    }));
    setAudit((a) => [
      ...a,
      {
        actor: 'human',
        action: `Recorded ${staged} decision for ${selected.id}`,
        time: clock(),
      },
    ]);
  }
  function reset() {
    setDecisions({});
    setStaged(null);
    setRationale('');
    setAudit([
      {
        actor: 'system',
        action: caseDocument
          ? 'Loaded Security Case retained; local review draft reset'
          : 'Waiting for a local Security Case',
        time: clock(),
      },
    ]);
    localStorage.removeItem(STORAGE_KEY);
  }
  function exportAudit() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            schema: 'secureflow-review-room-audit-v1',
            caseId: caseDocument?.case_id,
            contract: caseDocument?.contract_version,
            decisions,
            audit,
          },
          null,
          2,
        ),
      ],
      { type: 'application/json' },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(caseDocument?.case_id ?? 'secureflow').toLowerCase()}-audit.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function loadCase(file: File | undefined) {
    if (!file) return;
    setLoadError('');
    try {
      const parsed = JSON.parse(await file.text()) as CaseDocument;
      if (parsed.contract_version !== 'secureflow-security-case-v1')
        throw new Error('Select a secureflow-security-case-v1 JSON file.');
      if (!parsed.case_id || !Array.isArray(parsed.candidates) || !Array.isArray(parsed.decisions))
        throw new Error('The Security Case is missing required review fields.');
      const loaded = parsed.candidates.map(candidateFromCase);
      setCaseDocument(parsed);
      setCandidates(loaded);
      setSelectedId(loaded[0]?.id ?? '');
      setDecisions(Object.fromEntries(parsed.decisions.map((decision) => [decision.candidate_id, { decision: decision.decision, rationale: decision.rationale }])));
      setAudit([{ actor: 'system', action: `Loaded ${parsed.case_id}; ${loaded.length} evidence-bound candidates`, time: clock() }]);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Could not read the Security Case.');
    }
  }

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) {
      return;
    }
    const lifecycle = new AbortController();
    const candidateFor = (input: unknown) => {
      const id =
        typeof input === 'object' && input !== null && 'candidateId' in input
          ? (input as { candidateId?: unknown }).candidateId
          : null;
      if (typeof id !== 'string')
        throw new Error('candidateId must be a string');
      const candidate = candidates.find((c) => c.id === id);
      if (!candidate) throw new Error(`Unknown candidateId: ${id}`);
      return candidate;
    };
    const schema = {
      type: 'object',
      properties: {
        candidateId: { type: 'string', enum: candidates.map((c) => c.id) },
      },
      required: ['candidateId'],
      additionalProperties: false,
    };
    const tools: ToolDefinition[] = [
      {
        name: 'list_candidates',
        title: 'List security candidates',
        description:
          'List the structured candidates in this authorized review case. Candidates are not confirmed vulnerabilities.',
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute: () => ({
          caseId: caseDocument?.case_id,
          contract: caseDocument?.contract_version,
          candidates: candidates.map((c) => ({
            id: c.id,
            severity: c.severity,
            title: c.title,
            evidenceConfidence: c.confidence,
            humanDecision: decisionsRef.current[c.id]?.decision ?? null,
          })),
        }),
      },
      {
        name: 'inspect_evidence',
        title: 'Inspect candidate evidence',
        description:
          'Select a candidate in the visible review room and return its evidence boundary, source, visible guard, and sink.',
        inputSchema: schema,
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute: (input) => {
          const c = candidateFor(input);
          setSelectedId(c.id);
          return {
            id: c.id,
            summary: c.summary,
            location: c.location,
            source: c.source,
            visibleGuard: c.guard,
            sink: c.sink,
            evidenceConfidence: c.confidence,
            boundary:
              'Static evidence only; runtime reachability and hidden controls require human validation.',
          };
        },
      },
      {
        name: 'compare_revision',
        title: 'Compare candidate revision',
        description:
          'Select a candidate and return the supplied revision note without claiming exploitability.',
        inputSchema: schema,
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute: (input) => {
          const c = candidateFor(input);
          setSelectedId(c.id);
          return { id: c.id, revision: '7f3c1ad', note: c.revision };
        },
      },
      {
        name: 'draft_hardening',
        title: 'Draft hardening recommendation',
        description:
          'Return an evidence-bound hardening direction for a candidate. This does not confirm a vulnerability or modify code.',
        inputSchema: schema,
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute: (input) => {
          const c = candidateFor(input);
          setSelectedId(c.id);
          return {
            id: c.id,
            hardening: c.hardening,
            limitations:
              'Recommendation only; verify framework behavior and regression tests before implementation.',
          };
        },
      },
      {
        name: 'stage_agent_recommendation',
        title: 'Stage agent recommendation',
        description:
          'Stage a provisional recommendation and rationale in the visible human decision form. This cannot record or finalize a security decision.',
        inputSchema: schema,
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        execute: (input) => {
          const c = candidateFor(input);
          setSelectedId(c.id);
          setStaged(c.recommendation);
          setRationale(c.agentReason);
          setAudit((a) => [
            ...a,
            {
              actor: 'agent',
              action: `WebMCP staged ${c.recommendation} recommendation for ${c.id}`,
              time: clock(),
            },
          ]);
          return {
            id: c.id,
            stagedRecommendation: c.recommendation,
            status: 'awaiting_human_decision',
            finalized: false,
          };
        },
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
  }, [candidates, caseDocument]);

  if (!selected || !caseDocument) {
    return (
      <main className="review-shell min-h-screen">
        <section className="case-masthead max-w-3xl mx-auto mt-16">
          <p className="section-kicker">Local evidence / Security Case</p>
          <h1>Load a Security Case</h1>
          <p className="case-deck">
            Review Room consumes a local <code>secureflow-security-case-v1</code>{' '}
            document. It does not ship synthetic candidates or contact a target.
          </p>
          <label className="utility-button inline-flex mt-6 cursor-pointer" htmlFor="case-file">
            <FileCode2 /> Choose Security Case JSON
          </label>
          <input id="case-file" className="sr-only" type="file" accept="application/json,.json" onChange={(event) => void loadCase(event.target.files?.[0])} />
          {loadError && <p className="mt-4 text-sm text-red-700" role="alert">{loadError}</p>}
        </section>
      </main>
    );
  }

  return (
    <main className="review-shell min-h-screen">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark">
            <ShieldCheck />
          </span>
          <span className="brand-name">SECUREFLOW</span>
          <span className="brand-divider" />
          <span className="brand-product">Review Room</span>
        </div>
        <div className="topbar-actions">
          <span className="status-line status-authorized">
            <LockKeyhole /> Authorized scope
          </span>
          <span className="status-line">Offline evidence</span>
          <span
            className={`status-line ${webMcpStatus === 'ready' ? 'status-agent' : ''}`}
          >
            <span className="status-dot" />
            {webMcpStatus === 'ready'
              ? 'WebMCP ready'
              : webMcpStatus === 'error'
                ? 'WebMCP error'
                : 'WebMCP unavailable'}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={reset}
            className="utility-button"
          >
            <RotateCcw /> Reset
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={exportAudit}
            className="utility-button"
          >
            <Download /> Export audit
          </Button>
        </div>
      </header>

      <section className="case-masthead">
        <div>
          <p className="section-kicker">Active review / authorization</p>
          <h1>{caseDocument.target.label}</h1>
          <p className="case-deck">
            Structured evidence for an explicitly authorized local case. The
            agent may investigate and stage; only the reviewer may decide.
          </p>
        </div>
        <div className="case-metadata">
          <button
            className="case-id"
            onClick={() => {
              void navigator.clipboard.writeText(caseDocument.case_id);
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            }}
          >
            <Fingerprint /> {caseDocument.case_id} {copied ? <Check /> : <Copy />}
          </button>
          <span>REV {caseDocument.target.revision?.value ?? 'unrecorded'}</span>
          <span>SCOPE authorized local target</span>
        </div>
        <div className="review-progress">
          <div>
            <span>Human dispositions</span>
            <strong>{Object.keys(decisions).length} / {candidates.length}</strong>
          </div>
          <Progress
            value={candidates.length ? (Object.keys(decisions).length / candidates.length) * 100 : 0}
            className="h-1 bg-black/10 [&>div]:bg-[#146b4d]"
          />
        </div>
      </section>

      <div className="workbench">
        <aside className="queue-pane" aria-label="Candidate queue">
          <div className="pane-heading">
            <div>
              <p className="section-kicker">Candidate queue</p>
              <h2>Unresolved signals</h2>
            </div>
            <span className="count-cell">{candidates.length}</span>
          </div>
          <div className="queue-search">
            <Search />
            <input
              aria-label="Search candidates"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by ID or title"
            />
          </div>
          <div className="queue-columns" aria-hidden="true">
            <span>Signal</span>
            <span>Evidence</span>
          </div>
          <div className="candidate-list">
            {filtered.map((c) => (
              <button
                key={c.id}
                onClick={() => choose(c.id)}
                className={`candidate-row ${c.id === selected.id ? 'candidate-row-active' : ''}`}
              >
                <span className={`severity-rule severity-${c.severity}`} />
                <span className="candidate-copy">
                  <span className="candidate-id">
                    {c.id} · {c.severity}
                  </span>
                  <span className="candidate-title">{c.title}</span>
                  <span className="candidate-state">
                    {decisions[c.id]
                      ? `human: ${decisions[c.id].decision}`
                      : 'awaiting review'}
                  </span>
                </span>
                <strong>{c.confidence}%</strong>
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="queue-empty">No candidates match this filter.</p>
            )}
          </div>
          <div className="queue-footnote">
            Candidates are leads, not confirmed vulnerabilities.
          </div>
        </aside>

        <section className="evidence-pane">
          <header className="finding-header">
            <div className="finding-reference">
              <span>{selected.id}</span>
              <span
                className={`severity-label severity-text-${selected.severity}`}
              >
                {selected.severity} signal
              </span>
            </div>
            <h2>{selected.title}</h2>
            <p>{selected.summary}</p>
            <div className="source-location">
              <FileCode2 /> {selected.location}
            </div>
            <div className="confidence-readout">
              <strong>{selected.confidence}</strong>
              <span>
                %<br />
                evidence confidence
              </span>
            </div>
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
                  ['01 / source', 'Untrusted input', selected.source],
                  ['02 / control', 'Visible guard', selected.guard],
                  ['03 / sink', 'Sensitive operation', selected.sink],
                ].map(([index, title, value]) => (
                  <div className="record-row" key={index}>
                    <span className="record-index">{index}</span>
                    <span className="record-label">{title}</span>
                    <code>{value}</code>
                  </div>
                ))}
              </div>
              <div className="boundary-note">
                <CircleAlert />
                <div>
                  <strong>Evidence boundary</strong>
                  <p>
                    Static evidence only. Runtime reachability, hidden policy
                    layers, and exploitability require human-controlled
                    validation.
                  </p>
                </div>
              </div>
            </TabsContent>
            <TabsContent value="flow" className="evidence-content">
              <div className="flow-ledger">
                {[
                  ['INPUT', 'Untrusted request value', selected.source],
                  ['GUARD', 'Observed control', selected.guard],
                  ['OPERATION', 'Sensitive sink', selected.sink],
                ].map(([kind, title, value], index) => (
                  <div className="flow-entry" key={kind}>
                    <span>{String(index + 1).padStart(2, '0')}</span>
                    <div>
                      <small>{kind}</small>
                      <strong>{title}</strong>
                      <code>{value}</code>
                    </div>
                  </div>
                ))}
              </div>
            </TabsContent>
            <TabsContent value="revision" className="evidence-content">
              <div className="revision-note">
                <GitCompareArrows />
                <div>
                  <span>REVISION 7f3c1ad</span>
                  <p>{selected.revision}</p>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </section>

        <aside className="review-pane" aria-label="Review controls">
          <section className="review-section agent-section">
            <div className="review-section-heading">
              <Bot />
              <div>
                <span>Agent memorandum</span>
                <small>Provisional / evidence-bound</small>
              </div>
            </div>
            <div className="agent-disposition">
              <span>Suggested disposition</span>
              <strong>{label(selected.recommendation)}</strong>
            </div>
            <p className="review-copy">{selected.agentReason}</p>
            <div className="hardening-note">
              <span>Hardening direction</span>
              <p>{selected.hardening}</p>
            </div>
            <Button onClick={stage} className="stage-button">
              Stage recommendation
            </Button>
          </section>

          <section className="review-section human-section">
            <div className="review-section-heading">
              <UserCheck />
              <div>
                <span>Human disposition</span>
                <small>Not exposed to agent tools</small>
              </div>
            </div>
            <fieldset
              className="decision-options"
              aria-label="Human disposition"
            >
              {(['validated', 'rejected', 'abstained'] as Decision[]).map(
                (d) => (
                  <button
                    key={d}
                    aria-pressed={staged === d}
                    onClick={() => setStaged(d)}
                    className={staged === d ? 'decision-active' : ''}
                  >
                    {label(d)}
                  </button>
                ),
              )}
            </fieldset>
            <label htmlFor="rationale">
              Reviewer rationale <span>required</span>
            </label>
            <Textarea
              id="rationale"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Cite the evidence supporting this disposition…"
              className="decision-rationale"
            />
            <Button
              onClick={record}
              disabled={!staged || rationale.trim().length < 12}
              className="record-button"
            >
              <ShieldQuestion /> Record human decision
            </Button>
          </section>

          <section className="review-section audit-section">
            <div className="audit-heading">
              <span>Audit ledger</span>
              <small>append-only view</small>
            </div>
            <div className="audit-list">
              {audit
                .slice()
                .reverse()
                .map((event, index) => (
                  <div className="audit-entry" key={`${event.time}-${index}`}>
                    <span className={`actor-mark actor-${event.actor}`}>
                      {event.actor === 'human' ? (
                        <UserCheck />
                      ) : event.actor === 'agent' ? (
                        <Bot />
                      ) : (
                        <LockKeyhole />
                      )}
                    </span>
                    <div>
                      <p>{event.action}</p>
                      <small>
                        {event.actor} / {event.time}
                      </small>
                    </div>
                  </div>
                ))}
            </div>
          </section>
        </aside>
      </div>

      <footer className="review-footer">
        <span>SecureFlow Review Room / local-first demonstration</span>
        <strong>AI investigates. Humans decide. Evidence persists.</strong>
      </footer>
    </main>
  );
}
