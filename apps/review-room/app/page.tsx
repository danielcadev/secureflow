'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Download,
  RotateCcw,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
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

const CASE_ID = 'SF-DEMO-042';
const STORAGE_KEY = 'secureflow-review-room-v1';
const candidates: Candidate[] = [
  {
    id: 'AUTHZ-014',
    severity: 'high',
    title: 'Tenant boundary missing from project lookup',
    summary:
      'A URL-controlled project ID reaches a record lookup that is not visibly constrained to the active organization.',
    location: 'app/api/projects/[projectId]/route.ts:42',
    confidence: 86,
    recommendation: 'validated',
    agentReason:
      'The code path has session authentication but no visible tenant predicate. Human validation must confirm that project IDs are obtainable and no repository-level policy is hidden.',
    hardening:
      'Bind the lookup to session.organizationId and add negative tests using two tenants with cross-owned project IDs.',
    source: 'request.params.projectId',
    guard: 'requireSession(request)',
    sink: 'prisma.project.findUnique({ where: { id } })',
    revision:
      'Guard changed from requireUser() to requireSession(), but the data query remained unchanged.',
  },
  {
    id: 'WEBHOOK-009',
    severity: 'medium',
    title: 'Signature check may use reconstructed payload',
    summary:
      'The handler parses JSON and later verifies a signature over serialized data without retaining the original request bytes.',
    location: 'app/api/webhooks/billing/route.ts:27',
    confidence: 68,
    recommendation: 'abstained',
    agentReason:
      'This is suspicious, but validity depends on the provider signature contract. The supplied evidence omits the protocol specification and a known-good signed fixture.',
    hardening:
      'Preserve raw request bytes, document the provider contract, and test a known-good and mutated payload.',
    source: 'await request.json()',
    guard: 'verifySignature(JSON.stringify(payload))',
    sink: 'applySubscriptionUpdate(payload)',
    revision:
      'New endpoint. No earlier revision or protocol test was supplied.',
  },
  {
    id: 'CACHE-003',
    severity: 'low',
    title: 'Personalized response cache heuristic',
    summary:
      'A generic scanner flagged a personalized response, while response controls explicitly disable shared caching.',
    location: 'app/api/me/route.ts:18',
    confidence: 91,
    recommendation: 'rejected',
    agentReason:
      'The complete response includes private, no-store, Vary: Cookie, and force-dynamic. The candidate is a useful negative control, not a vulnerability.',
    hardening:
      'Keep the cache regression test and preserve the explicit response headers.',
    source: 'session.user',
    guard: "Cache-Control: 'private, no-store'",
    sink: 'Response.json(profile)',
    revision:
      'Current revision added explicit private caching controls and a regression test.',
  },
];

const clock = () =>
  new Intl.DateTimeFormat('en', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date());
const label = (d: Decision) =>
  d === 'validated' ? 'Validate' : d === 'rejected' ? 'Reject' : 'Abstain';

export default function Home() {
  const [selectedId, setSelectedId] = useState(candidates[0].id);
  const [query, setQuery] = useState('');
  const [staged, setStaged] = useState<Decision | null>(null);
  const [rationale, setRationale] = useState('');
  const [decisions, setDecisions] = useState<
    Record<string, { decision: Decision; rationale: string }>
  >({});
  const [audit, setAudit] = useState<AuditEvent[]>([
    {
      actor: 'system',
      action: 'Authorization and synthetic scope verified',
      time: '09:41:02',
    },
    {
      actor: 'agent',
      action: 'Imported three structured candidates',
      time: '09:41:08',
    },
  ]);
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
    [query],
  );

  function choose(id: string) {
    setSelectedId(id);
    const d = decisions[id];
    setStaged(d?.decision ?? null);
    setRationale(d?.rationale ?? '');
  }
  function stage() {
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
    if (!staged || rationale.trim().length < 12) return;
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
        action: 'Authorization and synthetic scope verified',
        time: clock(),
      },
      {
        actor: 'agent',
        action: 'Imported three structured candidates',
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
            schema: 'secureflow-review-v1',
            caseId: CASE_ID,
            scope: 'synthetic-authorized',
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
    a.download = `${CASE_ID.toLowerCase()}-audit.json`;
    a.click();
    URL.revokeObjectURL(url);
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
          caseId: CASE_ID,
          scope: 'synthetic-authorized',
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
  }, []);

  return (
    <main className="min-h-screen bg-white text-[#1f2328]">
      <header className="border-b border-[#d8dee4]">
        <div className="mx-auto flex h-14 max-w-[1440px] items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <ShieldCheck className="size-5 text-[#176b45]" />
            <strong className="text-[15px] tracking-[-0.02em]">SecureFlow</strong>
            <span className="h-5 w-px bg-[#d8dee4]" />
            <span className="text-sm text-[#57606a]">Review room</span>
          </div>
          <div className="flex items-center gap-3 text-xs text-[#57606a]">
            <span className="hidden items-center gap-1.5 sm:flex">
              <span className="size-1.5 rounded-full bg-[#1a7f37]" /> Authorized scope
            </span>
            <span className="hidden items-center gap-1.5 md:flex">
              <span
                className={`size-1.5 rounded-full ${
                  webMcpStatus === 'ready' ? 'bg-[#1a7f37]' : 'bg-[#8c959f]'
                }`}
              />
              {webMcpStatus === 'ready'
                ? 'WebMCP ready'
                : webMcpStatus === 'error'
                  ? 'WebMCP error'
                  : 'WebMCP unavailable'}
            </span>
            <Button variant="ghost" size="sm" onClick={reset} className="h-8 px-2 text-xs">
              <RotateCcw className="size-3.5" /> Reset
            </Button>
            <Button variant="outline" size="sm" onClick={exportAudit} className="h-8 rounded px-2 text-xs">
              <Download className="size-3.5" /> Export
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1440px] lg:grid-cols-[300px_minmax(0,1fr)]">
        <aside className="border-b border-[#d8dee4] lg:min-h-[calc(100vh-3.5rem)] lg:border-r lg:border-b-0" aria-label="Candidate queue">
          <div className="flex items-center justify-between px-6 pt-8 pb-5">
            <h2 className="text-base font-semibold">Findings</h2>
            <span className="text-sm text-[#57606a]">{candidates.length}</span>
          </div>
          <div className="relative mx-6 mb-3">
            <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-[#8c959f]" />
            <input
              className="h-9 w-full border border-[#d0d7de] bg-white pr-3 pl-9 text-sm outline-none focus:border-[#1f6f4a]"
              aria-label="Search candidates"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter findings"
            />
          </div>
          <div>
            {filtered.map((c) => (
              <button
                key={c.id}
                onClick={() => choose(c.id)}
                className={`relative block w-full border-t border-[#e6e8eb] px-6 py-4 text-left transition-colors hover:bg-[#f6f8fa] ${
                  c.id === selected.id ? 'bg-[#f6f8fa]' : 'bg-white'
                }`}
              >
                {c.id === selected.id && <span className="absolute inset-y-0 left-0 w-0.5 bg-[#1f6f4a]" />}
                <span className="block text-sm font-medium leading-5 text-[#1f2328]">{c.title}</span>
                <span className="mt-2 flex items-center justify-between text-xs text-[#57606a]">
                  <span>{c.id} · {c.severity}</span>
                  <span>{c.confidence}%</span>
                </span>
                <span className="mt-1 block text-xs text-[#6e7781]">
                    {decisions[c.id]
                      ? `human: ${decisions[c.id].decision}`
                      : 'awaiting review'}
                </span>
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="px-6 py-5 text-sm text-[#57606a]">No findings match this filter.</p>
            )}
          </div>
          <p className="border-t border-[#e6e8eb] px-6 py-4 text-xs leading-5 text-[#6e7781]">
            Candidates are leads, not confirmed vulnerabilities.
          </p>
        </aside>

        <div className="min-w-0 px-6 py-8 lg:px-12">
          <section>
          <header className="border-b border-[#d8dee4] pb-6">
            <div className="flex items-center gap-3 text-sm">
              <span className="text-[#57606a]">{selected.id}</span>
              <span className="h-4 w-px bg-[#d8dee4]" />
              <span className={selected.severity === 'high' ? 'text-[#cf222e]' : selected.severity === 'medium' ? 'text-[#bc4c00]' : 'text-[#0969da]'}>
                {selected.severity} signal
              </span>
            </div>
            <h1 className="mt-3 max-w-4xl text-3xl font-semibold tracking-[-0.035em] text-[#1f2328]">{selected.title}</h1>
            <p className="mt-3 max-w-3xl text-base leading-7 text-[#57606a]">{selected.summary}</p>
            <div className="mt-5 flex flex-wrap items-center justify-between gap-4">
              <code className="border border-[#d0d7de] bg-[#f6f8fa] px-3 py-2 text-xs text-[#24292f]">{selected.location}</code>
              <span className="text-sm text-[#57606a]"><strong className="font-semibold text-[#1f2328]">{selected.confidence}%</strong> evidence confidence</span>
            </div>
          </header>

          <Tabs defaultValue="evidence" className="mt-5 gap-0">
            <div className="mb-1 text-base font-semibold">Evidence</div>
            <TabsList variant="line" className="h-11 w-full justify-start gap-7 border-b border-[#d8dee4] bg-transparent p-0">
              <TabsTrigger value="evidence" className="h-full flex-none rounded-none px-0 text-sm data-active:bg-transparent data-active:shadow-none">Record</TabsTrigger>
              <TabsTrigger value="flow" className="h-full flex-none rounded-none px-0 text-sm data-active:bg-transparent data-active:shadow-none">Source → sink</TabsTrigger>
              <TabsTrigger value="revision" className="h-full flex-none rounded-none px-0 text-sm data-active:bg-transparent data-active:shadow-none">Revision</TabsTrigger>
            </TabsList>
            <TabsContent value="evidence" className="pt-1">
              <div>
                {[
                  ['01 / source', 'Untrusted input', selected.source],
                  ['02 / control', 'Visible guard', selected.guard],
                  ['03 / sink', 'Sensitive operation', selected.sink],
                ].map(([index, title, value]) => (
                  <div className="grid gap-2 border-b border-[#e6e8eb] py-4 text-sm sm:grid-cols-[110px_160px_minmax(0,1fr)]" key={index}>
                    <span className="text-[#6e7781]">{index}</span>
                    <span className="font-medium">{title}</span>
                    <code className="break-all text-[#24292f]">{value}</code>
                  </div>
                ))}
              </div>
              <div className="mt-5 border-l-2 border-[#bf8700] pl-4 text-sm leading-6 text-[#57606a]">
                <strong className="block font-medium text-[#1f2328]">Evidence boundary</strong>
                Static evidence only. Runtime reachability, hidden policy layers, and exploitability require human-controlled validation.
              </div>
            </TabsContent>
            <TabsContent value="flow" className="pt-1">
              <div>
                {[
                  ['INPUT', 'Untrusted request value', selected.source],
                  ['GUARD', 'Observed control', selected.guard],
                  ['OPERATION', 'Sensitive sink', selected.sink],
                ].map(([kind, title, value], index) => (
                  <div className="grid gap-2 border-b border-[#e6e8eb] py-4 text-sm sm:grid-cols-[110px_160px_minmax(0,1fr)]" key={kind}>
                    <span className="text-[#6e7781]">{String(index + 1).padStart(2, '0')} / {kind.toLowerCase()}</span>
                    <strong className="font-medium">{title}</strong>
                    <code className="break-all">{value}</code>
                  </div>
                ))}
              </div>
            </TabsContent>
            <TabsContent value="revision" className="py-5">
              <div className="text-sm leading-6 text-[#57606a]">
                <span className="mb-2 block text-xs text-[#6e7781]">Revision 7f3c1ad</span>
                <p>{selected.revision}</p>
              </div>
            </TabsContent>
          </Tabs>
          </section>

          <section className="mt-10 border-t border-[#d8dee4]" aria-label="Review controls">
            <div className="grid border-b border-[#d8dee4] md:grid-cols-2">
              <section className="py-7 md:border-r md:border-[#d8dee4] md:pr-8">
                <h2 className="text-base font-semibold">Agent recommendation</h2>
                <p className="mt-1 text-xs text-[#6e7781]">Provisional and evidence-bound</p>
                <div className="mt-5 flex items-center justify-between border-y border-[#e6e8eb] py-3 text-sm">
                  <span className="text-[#57606a]">Suggested disposition</span>
                  <strong>{label(selected.recommendation)}</strong>
                </div>
                <p className="mt-4 text-sm leading-6 text-[#57606a]">{selected.agentReason}</p>
                <div className="mt-4 bg-[#f6f8fa] p-4 text-sm leading-6 text-[#57606a]">
                  <strong className="mb-1 block font-medium text-[#1f2328]">Hardening direction</strong>
                  {selected.hardening}
                </div>
                <Button variant="outline" onClick={stage} className="mt-5 h-9 rounded px-4 text-sm">
                  Stage recommendation
                </Button>
              </section>

              <section className="py-7 md:pl-8">
                <h2 className="text-base font-semibold">Human decision</h2>
                <p className="mt-1 text-xs text-[#6e7781]">Not exposed to agent tools</p>
                <fieldset className="mt-5 grid grid-cols-3" aria-label="Human disposition">
                  {(['validated', 'rejected', 'abstained'] as Decision[]).map((d) => (
                    <button
                      key={d}
                      aria-pressed={staged === d}
                      onClick={() => setStaged(d)}
                      className={`h-9 border border-r-0 border-[#d0d7de] text-sm first:rounded-l last:rounded-r last:border-r ${
                        staged === d ? 'bg-[#1f6f4a] text-white' : 'bg-white text-[#24292f] hover:bg-[#f6f8fa]'
                      }`}
                    >
                      {label(d)}
                    </button>
                  ))}
                </fieldset>
                <label htmlFor="rationale" className="mt-5 block text-sm font-medium">
                  Reviewer rationale <span className="font-normal text-[#6e7781]">required</span>
                </label>
                <Textarea
                  id="rationale"
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  placeholder="Cite the evidence supporting this disposition…"
                  className="mt-2 min-h-24 rounded border-[#d0d7de] text-sm shadow-none focus-visible:border-[#1f6f4a] focus-visible:ring-0"
                />
                <Button
                  onClick={record}
                  disabled={!staged || rationale.trim().length < 12}
                  className="mt-4 h-9 w-full rounded bg-[#1f6f4a] text-sm text-white hover:bg-[#185c3d]"
                >
                  Record human decision
                </Button>
              </section>
            </div>

            <section className="py-7">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold">Audit log</h2>
                <span className="text-xs text-[#6e7781]">Append-only view</span>
              </div>
              <div className="mt-4 divide-y divide-[#e6e8eb] border-y border-[#e6e8eb]">
                {audit.slice().reverse().map((event, index) => (
                  <div className="grid gap-1 py-3 text-sm sm:grid-cols-[90px_minmax(0,1fr)_110px]" key={`${event.time}-${index}`}>
                    <span className="text-[#6e7781]">{event.actor}</span>
                    <p>{event.action}</p>
                    <time className="text-[#6e7781] sm:text-right">{event.time}</time>
                  </div>
                ))}
              </div>
            </section>
          </section>
        </div>
      </div>
    </main>
  );
}
