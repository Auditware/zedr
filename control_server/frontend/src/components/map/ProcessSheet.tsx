import { ChevronLeft } from 'lucide-react'
import { Chip, CopyButton, FindingLine, SectionTitle } from '@/components/ui/bits'
import { clock, dateTime, span } from '@/lib/format'
import { lineage, type Proc } from '@/lib/process-tree'

type Props = {
  proc: Proc
  host: string
  now: number
  onSelect: (key: string) => void
  onClose: () => void
}

export function ProcessSheet({ proc, host, now, onSelect, onClose }: Props) {
  const chain = lineage(proc)
  const outbound = proc.connections.length > 0

  return (
    <div className="flex min-h-full flex-col">
      <button
        type="button"
        onClick={onClose}
        className="-ml-1.5 mb-3 inline-flex h-8 w-fit items-center gap-1 rounded-md pl-1 pr-2 text-muted hover:bg-raised hover:text-text"
      >
        <ChevronLeft size={18} strokeWidth={1.5} aria-hidden />
        {host}
      </button>

      <h2 className="truncate font-mono text-xl font-medium tracking-tight">{proc.name}</h2>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Chip tone={proc.end === null ? 'accent' : 'neutral'}>{proc.end === null ? 'running' : 'exited'}</Chip>
        {outbound ? <Chip tone="accent">{proc.connections.length} outbound</Chip> : null}
      </div>

      {proc.findings.length > 0 ? (
        <div className="mt-4 flex flex-col gap-2 rounded-xl border border-line bg-row p-3" role="list" aria-label="Findings">
          {proc.findings.map((finding) => (
            <div key={finding.rule} role="listitem" className="flex">
              <FindingLine title={finding.title} technique={finding.technique} high={finding.level === 'high'} />
            </div>
          ))}
        </div>
      ) : null}

      <dl className="mt-4 grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-1.5 font-mono text-xs">
        <dt className="text-muted">pid</dt>
        <dd>
          {proc.pid} <span className="text-muted">← {proc.ppid}</span>
        </dd>
        <dt className="text-muted">uid</dt>
        <dd>{proc.uid}</dd>
        <dt className="text-muted">started</dt>
        <dd>{dateTime(proc.start)}</dd>
        <dt className="text-muted">{proc.end === null ? 'age' : 'ran'}</dt>
        <dd>{span((proc.end ?? now) - proc.start)}</dd>
      </dl>

      <SectionTitle className="mb-1.5 mt-5">Image</SectionTitle>
      <div className="flex items-start gap-1 rounded-control bg-sunken p-2.5 font-mono text-xs">
        <span className="min-w-0 flex-1 break-all text-soft">{proc.path}</span>
        <CopyButton value={proc.path} label="Copy path" className="h-5 w-5" />
      </div>

      <SectionTitle className="mb-1.5 mt-4">Command line</SectionTitle>
      <div className="flex items-start gap-1 rounded-control bg-sunken p-2.5 font-mono text-xs">
        <span className="min-w-0 flex-1 break-all text-text">{proc.command || '-'}</span>
        <CopyButton value={proc.command} label="Copy command line" className="h-5 w-5" />
      </div>

      <SectionTitle className="mb-1.5 mt-4">Lineage</SectionTitle>
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 font-mono text-xs">
        {chain.map((ancestor, index) => (
          <span key={ancestor.key} className="inline-flex items-center gap-1.5">
            {index > 0 ? <span className="text-muted">›</span> : null}
            <button
              type="button"
              onClick={() => onSelect(ancestor.key)}
              className={ancestor.key === proc.key ? 'text-accent' : 'text-soft hover:text-text hover:underline'}
            >
              {ancestor.name}
            </button>
          </span>
        ))}
      </div>

      {proc.connections.length > 0 ? (
        <>
          <SectionTitle className="mb-1.5 mt-5">Connections</SectionTitle>
          {proc.connections.slice(0, 40).map((connection, index) => (
            <div key={index} className="flex h-8 items-center gap-3 border-b border-hairline font-mono text-xs">
              <span className="w-[58px] shrink-0 text-muted">{clock(connection.time)}</span>
              <span className="min-w-0 flex-1 truncate text-text">
                {connection.destIp}:{connection.destPort}
              </span>
              <span className="shrink-0 text-muted">
                ↑{connection.sent} ↓{connection.received}
              </span>
            </div>
          ))}
        </>
      ) : null}

      {proc.files.length > 0 ? (
        <>
          <SectionTitle className="mb-1.5 mt-5">Files</SectionTitle>
          {proc.files.slice(0, 40).map((file, index) => (
            <div key={index} className="flex min-h-8 items-center gap-3 border-b border-hairline py-1 font-mono text-xs">
              <span className="w-[58px] shrink-0 text-muted">{clock(file.time)}</span>
              <span className="w-12 shrink-0 text-warn">{file.action}</span>
              <span className="min-w-0 flex-1 break-all text-soft">{file.path}</span>
            </div>
          ))}
        </>
      ) : null}
    </div>
  )
}
