'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  Check,
  ChevronRight,
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
  Sparkles,
  UserCheck,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
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
    <main className="min-h-screen bg-[#080c12] text-slate-100">
      <header className="border-b border-white/8 bg-[#080c12]/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-5 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="grid size-10 place-items-center rounded-xl border border-emerald-300/20 bg-emerald-300/10 text-emerald-300">
              <ShieldCheck className="size-5" />
            </div>
            <div>
              <p className="text-sm font-semibold">SecureFlow</p>
              <p className="text-xs text-slate-500">Review Room</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              variant="outline"
              className="border-emerald-300/20 bg-emerald-300/8 text-emerald-200"
            >
              <LockKeyhole className="size-3" /> Authorized synthetic case
            </Badge>
            <Badge
              variant="outline"
              className="border-white/10 bg-white/4 text-slate-400"
            >
              Offline evidence
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              onClick={reset}
              className="text-slate-400 hover:bg-white/5 hover:text-white"
            >
              <RotateCcw />
              Reset
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={exportAudit}
              className="border-white/12 bg-white/5 hover:bg-white/10"
            >
              <Download />
              Export audit
            </Button>
          </div>
        </div>
      </header>

      <section className="mx-auto max-w-[1600px] border-b border-white/8 px-5 py-5 lg:px-8">
        <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
          <div>
            <p className="eyebrow">Active review</p>
            <div className="mt-1 flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
                Northstar API authorization review
              </h1>
              <Badge
                className={`${webMcpStatus === 'ready' ? 'bg-violet-400/12 text-violet-200' : 'bg-white/6 text-slate-400'} hover:bg-violet-400/12`}
              >
                {webMcpStatus === 'ready'
                  ? 'WebMCP agent ready'
                  : webMcpStatus === 'error'
                    ? 'WebMCP registration error'
                    : 'Open in a WebMCP browser'}
              </Badge>
            </div>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              The agent investigates evidence and stages recommendations. A
              human owns every final security decision.
            </p>
          </div>
          <div className="min-w-64 rounded-xl border border-white/8 bg-white/[.025] p-3">
            <div className="mb-2 flex justify-between text-xs">
              <span className="text-slate-500">Human review progress</span>
              <span className="font-mono text-slate-300">
                {Object.keys(decisions).length} / 3
              </span>
            </div>
            <Progress
              value={(Object.keys(decisions).length / 3) * 100}
              className="h-1.5 bg-white/8 [&>div]:bg-emerald-300"
            />
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 font-mono text-xs text-slate-500">
          <button
            className="flex items-center gap-1.5 hover:text-slate-300"
            onClick={() => {
              void navigator.clipboard.writeText(CASE_ID);
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            }}
          >
            <Fingerprint className="size-3.5" />
            {CASE_ID}
            {copied ? (
              <Check className="size-3 text-emerald-300" />
            ) : (
              <Copy className="size-3" />
            )}
          </button>
          <span>revision 7f3c1ad</span>
          <span>scope synthetic/northstar-api</span>
        </div>
      </section>

      <div className="mx-auto grid max-w-[1600px] gap-4 px-5 py-5 lg:grid-cols-[300px_minmax(420px,1fr)_360px] lg:px-8">
        <aside className="rounded-2xl border border-white/8 bg-[#0c1119] p-3">
          <div className="flex items-center justify-between px-2 py-2">
            <div>
              <p className="eyebrow">Candidate queue</p>
              <p className="mt-1 text-xs text-slate-500">
                Structured, not confirmed
              </p>
            </div>
            <Badge variant="secondary" className="bg-white/6 text-slate-300">
              3
            </Badge>
          </div>
          <div className="relative my-3">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-600" />
            <input
              aria-label="Search candidates"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search candidates"
              className="h-9 w-full rounded-lg border border-white/8 bg-black/20 pl-9 pr-3 text-sm outline-none placeholder:text-slate-600 focus:border-emerald-300/40"
            />
          </div>
          <div className="space-y-2">
            {filtered.map((c) => (
              <button
                key={c.id}
                onClick={() => choose(c.id)}
                className={`candidate-card ${c.id === selected.id ? 'candidate-card-active' : ''}`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[11px] text-slate-500">
                    {c.id}
                  </span>
                  <span
                    className={`size-2 rounded-full ${c.severity === 'high' ? 'bg-rose-400' : c.severity === 'medium' ? 'bg-amber-300' : 'bg-sky-300'}`}
                  />
                </div>
                <p className="mt-2 text-left text-sm font-medium leading-5 text-slate-200">
                  {c.title}
                </p>
                <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500">
                  <span>{c.confidence}% evidence</span>
                  {decisions[c.id] ? (
                    <span className="text-emerald-300">
                      {decisions[c.id].decision}
                    </span>
                  ) : (
                    <ChevronRight className="size-3.5" />
                  )}
                </div>
              </button>
            ))}
          </div>
        </aside>

        <section className="min-w-0 rounded-2xl border border-white/8 bg-[#0c1119]">
          <div className="border-b border-white/8 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-emerald-300">
                    {selected.id}
                  </span>
                  <Badge
                    variant="outline"
                    className="border-white/10 text-slate-400"
                  >
                    {selected.severity}
                  </Badge>
                </div>
                <h2 className="mt-2 text-xl font-semibold tracking-tight">
                  {selected.title}
                </h2>
              </div>
              <div className="text-right">
                <p className="text-2xl font-semibold">{selected.confidence}%</p>
                <p className="text-[11px] uppercase tracking-wider text-slate-500">
                  evidence confidence
                </p>
              </div>
            </div>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
              {selected.summary}
            </p>
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-white/8 bg-black/20 px-3 py-2 font-mono text-xs text-slate-400">
              <FileCode2 className="size-4 text-violet-300" />
              <span className="truncate">{selected.location}</span>
            </div>
          </div>
          <Tabs defaultValue="evidence" className="p-5">
            <TabsList className="bg-black/25">
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="flow">Data flow</TabsTrigger>
              <TabsTrigger value="revision">Revision</TabsTrigger>
            </TabsList>
            <TabsContent value="evidence" className="mt-5 space-y-3">
              <div className="grid gap-3 sm:grid-cols-3">
                {[
                  ['Source', selected.source],
                  ['Visible guard', selected.guard],
                  ['Sensitive sink', selected.sink],
                ].map(([k, v]) => (
                  <div
                    key={k}
                    className="rounded-xl border border-white/8 bg-black/15 p-4"
                  >
                    <p className="eyebrow">{k}</p>
                    <p className="mt-2 break-words font-mono text-xs leading-5 text-slate-300">
                      {v}
                    </p>
                  </div>
                ))}
              </div>
              <div className="rounded-xl border border-amber-300/15 bg-amber-300/[.045] p-4">
                <div className="flex gap-3">
                  <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-300" />
                  <div>
                    <p className="text-sm font-medium text-amber-100">
                      Evidence boundary
                    </p>
                    <p className="mt-1 text-xs leading-5 text-slate-400">
                      Static evidence only. Runtime reachability, hidden policy
                      layers, and exploitability still require human-controlled
                      validation.
                    </p>
                  </div>
                </div>
              </div>
            </TabsContent>
            <TabsContent value="flow" className="mt-5">
              <div className="space-y-2">
                {[
                  ['01', 'Untrusted input', selected.source],
                  ['02', 'Observed control', selected.guard],
                  ['03', 'Operation', selected.sink],
                ].map(([n, k, v]) => (
                  <div key={n} className="trace-step">
                    <span className="font-mono text-xs text-emerald-300">
                      {n}
                    </span>
                    <div>
                      <p className="text-xs text-slate-500">{k}</p>
                      <p className="mt-1 break-all font-mono text-sm text-slate-200">
                        {v}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </TabsContent>
            <TabsContent value="revision" className="mt-5">
              <div className="rounded-xl border border-white/8 bg-black/15 p-5">
                <div className="flex items-center gap-2 text-violet-300">
                  <GitCompareArrows className="size-4" />
                  <span className="eyebrow text-violet-300">Revision note</span>
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-300">
                  {selected.revision}
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </section>

        <aside className="space-y-4">
          <section className="rounded-2xl border border-violet-300/15 bg-gradient-to-b from-violet-400/[.07] to-[#0c1119] p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="grid size-8 place-items-center rounded-lg bg-violet-300/12 text-violet-200">
                  <Bot className="size-4" />
                </div>
                <div>
                  <p className="text-sm font-semibold">Agent recommendation</p>
                  <p className="text-[11px] text-slate-500">
                    Provisional · evidence-bound
                  </p>
                </div>
              </div>
              <Sparkles className="size-4 text-violet-300" />
            </div>
            <div className="my-4 rounded-xl border border-white/8 bg-black/20 p-4">
              <p className="eyebrow">Suggested disposition</p>
              <p className="mt-2 text-lg font-semibold">
                {label(selected.recommendation)}
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {selected.agentReason}
              </p>
            </div>
            <p className="eyebrow">Hardening direction</p>
            <p className="mt-2 text-xs leading-5 text-slate-400">
              {selected.hardening}
            </p>
            <Button
              onClick={stage}
              className="mt-5 w-full bg-violet-300 text-violet-950 hover:bg-violet-200"
            >
              <Sparkles />
              Stage for human review
            </Button>
          </section>
          <section className="rounded-2xl border border-emerald-300/15 bg-[#0c1119] p-5">
            <div className="flex items-center gap-2">
              <UserCheck className="size-4 text-emerald-300" />
              <div>
                <p className="text-sm font-semibold">Human decision</p>
                <p className="text-[11px] text-slate-500">
                  Agent tools cannot invoke this action
                </p>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2">
              {(['validated', 'rejected', 'abstained'] as Decision[]).map(
                (d) => (
                  <button
                    key={d}
                    onClick={() => setStaged(d)}
                    className={`rounded-lg border px-2 py-2 text-xs font-medium transition ${staged === d ? 'border-emerald-300/50 bg-emerald-300/10 text-emerald-200' : 'border-white/8 bg-white/[.025] text-slate-400 hover:border-white/20'}`}
                  >
                    {label(d)}
                  </button>
                ),
              )}
            </div>
            <label
              className="mt-4 block text-xs text-slate-400"
              htmlFor="rationale"
            >
              Decision rationale{' '}
              <span className="text-slate-600">(required)</span>
            </label>
            <Textarea
              id="rationale"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Cite the evidence that supports this decision…"
              className="mt-2 min-h-24 border-white/10 bg-black/20 text-sm placeholder:text-slate-600"
            />
            <Button
              onClick={record}
              disabled={!staged || rationale.trim().length < 12}
              className="mt-3 w-full bg-emerald-300 text-emerald-950 hover:bg-emerald-200"
            >
              <ShieldQuestion />
              Record human decision
            </Button>
          </section>
          <section className="rounded-2xl border border-white/8 bg-[#0c1119] p-5">
            <div className="flex justify-between">
              <p className="text-sm font-semibold">Audit trail</p>
              <span className="font-mono text-[10px] text-slate-600">
                append-only view
              </span>
            </div>
            <div className="mt-4 max-h-48 space-y-4 overflow-auto">
              {audit
                .slice()
                .reverse()
                .map((e, i) => (
                  <div key={`${e.time}-${i}`} className="flex gap-3">
                    <div
                      className={`mt-0.5 grid size-6 shrink-0 place-items-center rounded-full ${e.actor === 'human' ? 'bg-emerald-300/10 text-emerald-300' : e.actor === 'agent' ? 'bg-violet-300/10 text-violet-300' : 'bg-white/5 text-slate-500'}`}
                    >
                      {e.actor === 'human' ? (
                        <UserCheck className="size-3" />
                      ) : e.actor === 'agent' ? (
                        <Bot className="size-3" />
                      ) : (
                        <LockKeyhole className="size-3" />
                      )}
                    </div>
                    <div>
                      <p className="text-xs leading-5 text-slate-300">
                        {e.action}
                      </p>
                      <p className="font-mono text-[10px] text-slate-600">
                        {e.actor} · {e.time}
                      </p>
                    </div>
                  </div>
                ))}
            </div>
          </section>
        </aside>
      </div>
      <footer className="mx-auto flex max-w-[1600px] flex-wrap justify-between gap-3 border-t border-white/8 px-5 py-5 text-xs text-slate-600 lg:px-8">
        <span>SecureFlow Review Room · local-first demonstration</span>
        <span>AI recommends. Humans decide. Evidence persists.</span>
      </footer>
    </main>
  );
}
