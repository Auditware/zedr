import { useQuery } from '@tanstack/react-query'
import { getRouteApi, useNavigate } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { CornerDownLeft, Lock, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { PageHeader } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Handle, Panel, Split } from '@/components/ui/panes'
import { ApiError, api, type Agent, type HuntResult } from '@/lib/api'
import { cn } from '@/lib/cn'
import { clock, subnet } from '@/lib/format'
import { huntPieces, type PieceKind } from '@/lib/hunt-syntax'
import { useAgents, useMedia } from '@/lib/queries'

const route = getRouteApi('/app/hunt')

const STARTERS: { title: string; query: string }[] = [
  {
    title: 'Office application starting a script host',
    query: 'process where parent.name in (winword.exe, excel.exe, outlook.exe, powerpnt.exe) and name in (powershell.exe, cmd.exe, wscript.exe, mshta.exe)',
  },
  { title: 'System binary run from a user-writable folder', query: 'process where name in (rundll32.exe, regsvr32.exe) and command ~ "\\users\\public"' },
  { title: 'Encoded PowerShell', query: 'process where name = powershell.exe and command ~ " -enc "' },
  { title: 'Shell started by a server process', query: 'process where name in (sh, bash, cmd.exe, powershell.exe) and parent.name in (nginx, apache2, httpd, w3wp.exe, postgres)' },
  { title: 'Every endpoint that reached an address', query: 'connection where dest.ip = 203.0.113.47' },
  { title: 'Executables written by a script host', query: 'file where process.name in (powershell.exe, cmd.exe, bash, sh) and path ~ ".dll"' },
  { title: 'High findings', query: 'detection where level = high' },
  { title: 'Autostart items that download code', query: 'persistence where command ~ curl or command ~ wget' },
]

const WIDTHS: Record<string, string> = {
  process: '150px 130px minmax(200px,1fr) 60px 52px',
  connection: '170px minmax(160px,1fr) 80px 96px',
  file: '170px 84px minmax(160px,1fr)',
  detection: 'minmax(220px,1.2fr) 100px 72px minmax(160px,1fr)',
  persistence: 'minmax(130px,0.8fr) 110px minmax(200px,1.4fr) minmax(160px,1fr) 64px',
}
const DATED = new Set(['process', 'connection', 'file', 'detection'])
const ROW = 34
const BINS = 64
const MATRIX_LIMIT = 1500

const PIECE: Record<PieceKind, string> = {
  kind: 'font-semibold text-accent-strong',
  keyword: 'text-mauve',
  field: 'text-steel',
  operator: 'text-muted',
  value: 'text-sage',
  plain: '',
}

function Highlighted({ source, mark }: { source: string; mark?: number | null }) {
  return (
    <>
      {huntPieces(source).map((piece) => (
        <span
          key={piece.start}
          className={cn(
            PIECE[piece.kind],
            mark != null && mark > piece.start && mark <= piece.start + piece.text.length && 'underline decoration-alert decoration-wavy underline-offset-4',
          )}
        >
          {piece.text}
        </span>
      ))}
    </>
  )
}

function withoutImage(command: string, name: string): string {
  const first = command.split(' ', 1)[0] ?? ''
  const rest = command.slice(first.length).trim()
  return name !== '' && rest !== '' && first.toLowerCase().endsWith(name.toLowerCase()) ? rest : command
}

function Reach({
  result,
  agents,
  host,
  onHost,
}: {
  result: HuntResult
  agents: Agent[]
  host: string | undefined
  onHost: (id: string | undefined) => void
}) {
  const matches = useMemo(() => new Map(result.endpoints.map((endpoint) => [endpoint.agent_id, endpoint.matches])), [result.endpoints])
  const peak = Math.max(1, ...result.endpoints.map((endpoint) => endpoint.matches))
  const groups = useMemo(() => {
    const bySubnet = new Map<string, Agent[]>()
    for (const agent of agents) {
      const key = subnet(agent.ip_address)
      bySubnet.set(key, [...(bySubnet.get(key) ?? []), agent])
    }
    return [...bySubnet.entries()]
      .map(([label, members]) => ({ label, members: members.sort((a, b) => a.hostname.localeCompare(b.hostname)) }))
      .sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }))
  }, [agents])
  const shown = result.rows.length < result.total ? `, newest ${result.rows.length} shown` : ''

  return (
    <div aria-label="Reach" className="h-full overflow-y-auto rounded-card border border-line bg-surface">
      <div className="px-3.5 pt-3">
        <div className="font-display text-[30px] font-medium leading-none tracking-tight text-accent-strong">
          {result.endpoints.length} <span className="text-sm font-normal tracking-normal text-muted">of {agents.length} endpoints</span>
        </div>
        <div className="mt-1.5 font-mono text-[11px] text-muted">
          {result.total} {result.total === 1 ? 'match' : 'matches'}
          {shown}
        </div>
      </div>
      {agents.length <= MATRIX_LIMIT ? (
        <div aria-label="Where it matched" className="grid grid-cols-[repeat(auto-fill,minmax(118px,1fr))] gap-x-4 gap-y-3 px-3.5 pb-3 pt-4">
          {groups.map((group) => {
            const hits = group.members.filter((agent) => matches.has(agent.id)).length
            return (
              <div key={group.label}>
                <div className={cn('mb-1.5 flex justify-between font-mono text-[10px]', hits > 0 ? 'text-soft' : 'text-faint')}>
                  <span>{group.label}</span>
                  {hits > 0 ? <span>{hits}</span> : null}
                </div>
                <div className="flex flex-wrap gap-[3px]">
                  {group.members.map((agent) => {
                    const count = matches.get(agent.id)
                    if (count === undefined) return <span key={agent.id} title={agent.hostname} className="h-[7px] w-[7px] rounded-full bg-line-strong" />
                    const picked = agent.id === host
                    return (
                      <button
                        key={agent.id}
                        type="button"
                        data-reach-dot
                        title={`${agent.hostname} · ${count}`}
                        aria-label={`${agent.hostname}, ${count} ${count === 1 ? 'match' : 'matches'}`}
                        aria-pressed={picked}
                        onClick={() => onHost(picked ? undefined : agent.id)}
                        className={cn('h-[7px] w-[7px] rounded-full bg-accent-strong outline-offset-2', picked && 'ring-2 ring-accent-strong/40')}
                        style={{ opacity: 0.5 + 0.5 * (count / peak) }}
                      />
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      ) : null}
      <div role="list" aria-label="Endpoints with matches" className="border-t border-line p-2">
        {result.endpoints.map((endpoint) => {
          const picked = endpoint.agent_id === host
          return (
            <button
              key={endpoint.agent_id}
              type="button"
              role="listitem"
              aria-pressed={picked}
              onClick={() => onHost(picked ? undefined : endpoint.agent_id)}
              className={cn(
                'relative flex h-8 w-full items-center gap-3 overflow-hidden rounded-lg border border-transparent px-2.5 text-left font-mono text-xs hover:bg-raised',
                picked && 'border-accent bg-selected hover:bg-selected',
              )}
            >
              <span className="absolute inset-y-1 left-0 rounded-r bg-accent-strong/10" style={{ width: `${(endpoint.matches / peak) * 100}%` }} aria-hidden />
              <span className="relative min-w-0 flex-1 truncate text-text">{endpoint.hostname}</span>
              <span className="relative shrink-0 text-soft">{endpoint.matches}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function Timeline({ times }: { times: number[] }) {
  const from = Math.min(...times)
  const to = Math.max(...times)
  if (times.length < 2 || to === from) return null
  const bins = new Array<number>(BINS).fill(0)
  for (const time of times) {
    const index = Math.min(BINS - 1, Math.floor(((time - from) / (to - from)) * BINS))
    bins[index] = (bins[index] ?? 0) + 1
  }
  const peak = Math.max(...bins)
  return (
    <div aria-label="When it matched" className="border-b border-line px-4 pb-1.5 pt-3">
      <div className="flex h-9 items-end gap-px">
        {bins.map((count, index) => (
          <span
            key={index}
            className={cn('min-w-0 flex-1 rounded-t-[1px]', count > 0 ? 'bg-node' : 'bg-hairline')}
            style={{ height: count > 0 ? `${Math.max(12, (count / peak) * 100)}%` : 1 }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-faint">
        <span>{clock(from)}</span>
        <span>{clock(to)}</span>
      </div>
    </div>
  )
}

function Results({ result, host, onHost }: { result: HuntResult; host: string | undefined; onHost: (id: string | undefined) => void }) {
  const navigate = useNavigate()
  const narrow = useMedia('(max-width: 860px)')
  const { data: agents } = useAgents()
  const scrollRef = useRef<HTMLDivElement>(null)
  const rows = useMemo(() => (host ? result.rows.filter((row) => row.agent_id === host) : result.rows), [result.rows, host])
  const times = useMemo(() => (DATED.has(result.entity) ? rows.map((row) => row.time) : []), [rows, result.entity])
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 14 })
  const grid = { gridTemplateColumns: `68px 150px ${WIDTHS[result.entity] ?? ''}` }
  const lens = result.entity === 'connection' ? 'network' : result.entity === 'file' ? 'files' : result.entity === 'persistence' ? 'persistence' : undefined

  return (
    <Split id={narrow ? 'hunt-narrow' : 'hunt'} orientation={narrow ? 'vertical' : 'horizontal'}>
      <Panel id="endpoints" defaultSize={narrow ? 220 : 320} minSize={narrow ? 120 : 240} maxSize={480}>
        <Reach result={result} agents={agents ?? []} host={host} onHost={onHost} />
      </Panel>
      <Handle orientation={narrow ? 'vertical' : 'horizontal'} />
      <Panel id="rows" minSize={narrow ? 200 : 360}>
        <div className="flex h-full flex-col overflow-hidden rounded-card border border-line bg-surface">
          {times.length > 0 ? <Timeline times={times} /> : null}
          <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
            <div className="sticky top-0 z-10 grid h-8 min-w-[640px] items-center gap-3 border-b border-line bg-surface px-4 text-[11px] uppercase tracking-wider text-muted" style={grid}>
              <span>Time</span>
              <span>Host</span>
              {result.columns.map((column) => (
                <span key={column}>{column}</span>
              ))}
            </div>
            <div className="min-w-[640px]" style={{ height: virtual.getTotalSize(), position: 'relative' }}>
              {virtual.getVirtualItems().map((item) => {
                const row = rows[item.index]!
                return (
                  <button
                    key={item.index}
                    type="button"
                    data-hunt-row
                    onClick={() =>
                      void navigate({
                        to: '/endpoints',
                        search: { host: row.agent_id, proc: row.process ?? undefined, view: lens, find: lens === 'persistence' ? row.cells[0] : undefined },
                      })
                    }
                    className="absolute left-0 grid w-full items-center gap-3 border-b border-hairline px-4 text-left font-mono text-xs hover:bg-raised"
                    style={{ ...grid, height: ROW, transform: `translateY(${item.start}px)` }}
                  >
                    <span className="text-muted">{clock(row.time)}</span>
                    <span className="truncate text-text">{row.hostname}</span>
                    {row.cells.map((cell, index) => (
                      <span key={index} className={cn('truncate', index === 0 ? 'text-text' : 'text-soft')} title={cell}>
                        {result.columns[index] === 'command' ? withoutImage(cell, row.cells[0] ?? '') : cell}
                      </span>
                    ))}
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      </Panel>
    </Split>
  )
}

export function Hunt() {
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const executed = search.q ?? ''
  const [draft, setDraft] = useState(executed)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => setDraft(executed), [executed])

  const result = useQuery({ queryKey: ['hunt', executed], queryFn: () => api.hunt(executed), enabled: executed !== '', retry: false })
  const { data: entities } = useQuery({ queryKey: ['hunt-fields'], queryFn: api.huntFields, staleTime: Infinity })

  const run = (query: string) => {
    const trimmed = query.trim()
    setDraft(trimmed)
    if (trimmed === executed) void result.refetch()
    else void navigate({ search: { q: trimmed || undefined }, replace: true })
  }
  const insert = (text: string) => {
    setDraft((current) => (current === '' || current.endsWith(' ') ? current + text : `${current} ${text}`))
    inputRef.current?.focus()
  }

  const entity = entities?.find((item) => item.name === draft.trim().split(/\s+/)[0]?.toLowerCase())
  const failure = result.error instanceof ApiError ? result.error : null
  const data = result.data

  return (
    <div className="absolute inset-0 flex flex-col gap-3 overflow-hidden px-6 pb-5 pt-4">
      <PageHeader title="Hunt" />

      <div className={cn('shrink-0 rounded-card border bg-surface p-3', failure ? 'border-alert-line' : 'border-line focus-within:border-line-hover')}>
        <div className="flex items-start gap-2">
          <div className="relative min-w-0 flex-1 font-mono text-[14px] leading-relaxed">
            <pre aria-hidden className="pointer-events-none min-h-[46px] whitespace-pre-wrap break-words font-mono">
              <Highlighted source={draft} mark={failure && draft === executed ? failure.column : null} />
              {'​'}
            </pre>
            <textarea
              ref={inputRef}
              value={draft}
              spellCheck={false}
              autoFocus
              aria-label="Hunt query"
              placeholder="process where name = rundll32.exe and parent.name = powershell.exe"
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  run(draft)
                }
              }}
              className="absolute inset-0 h-full w-full resize-none overflow-hidden whitespace-pre-wrap break-words bg-transparent text-transparent caret-accent-strong outline-none placeholder:text-faint focus-visible:outline-none"
            />
          </div>
          {draft ? (
            <Button variant="ghost" size="icon" aria-label="Clear query" onClick={() => run('')}>
              <X size={16} strokeWidth={1.5} aria-hidden />
            </Button>
          ) : null}
          <Button variant="primary" onClick={() => run(draft)} disabled={!draft.trim() || result.isFetching}>
            Run
            <CornerDownLeft size={14} strokeWidth={1.75} aria-hidden />
          </Button>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-1" aria-label={entity ? `Fields of ${entity.name}` : 'Kinds of record'}>
          {(entity ? entity.fields : (entities ?? []).map((item) => `${item.name} where`)).map((word) => (
            <button
              key={word}
              type="button"
              onClick={() => insert(`${word} `)}
              className={cn(
                'rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] hover:border-line-hover hover:text-text',
                entity ? 'text-steel' : 'text-soft',
              )}
            >
              {word}
            </button>
          ))}
        </div>
        <p data-hunt-scope className="mt-2 flex items-center gap-1.5 text-xs text-muted">
          <Lock size={12} strokeWidth={1.75} className="shrink-0 text-steel" aria-hidden />
          Hunt searches opened events only: what a rule released on an endpoint. Sealed telemetry cannot be searched.
        </p>
        {failure ? (
          <div role="alert" className="mt-2 font-mono text-xs text-alert-soft">
            {failure.message}
            {failure.column !== null ? `, at column ${failure.column}` : ''}
          </div>
        ) : null}
      </div>

      <div className="min-h-0 flex-1">
        {data && data.total > 0 ? (
          <Results
            result={data}
            host={search.host}
            onHost={(host) => void navigate({ search: (previous) => ({ ...previous, host }), replace: true })}
          />
        ) : data ? (
          <div className="rounded-card border border-line bg-surface px-4 py-3 font-mono text-xs text-muted">No endpoint has a match.</div>
        ) : executed === '' ? (
          <div className="grid max-h-full grid-cols-3 gap-2 overflow-y-auto max-xl:grid-cols-2 max-lg:grid-cols-1">
            {STARTERS.map((starter) => (
              <button
                key={starter.title}
                type="button"
                onClick={() => run(starter.query)}
                className="group flex min-h-[92px] flex-col rounded-card border border-line bg-row px-3.5 py-3 text-left transition-colors hover:border-line-hover hover:bg-surface"
              >
                <span className="block text-[13px] font-medium text-text">{starter.title}</span>
                <span className="mt-1.5 line-clamp-2 block break-words font-mono text-[11px] leading-relaxed opacity-80 group-hover:opacity-100">
                  <Highlighted source={starter.query} />
                </span>
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  )
}
