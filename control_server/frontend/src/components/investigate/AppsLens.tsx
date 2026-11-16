import { useMemo, useState } from 'react'
import { Empty } from '@/components/ui/bits'
import { Segmented } from '@/components/ui/segmented'
import { cn } from '@/lib/cn'
import { bytes } from '@/lib/format'
import { tone } from '@/lib/palette'
import { apps, type App } from '@/lib/process-tree'
import { useSize } from '@/lib/queries'
import { squarify } from '@/lib/treemap'
import { SEVERITY_DOT, SEVERITY_TONE, useProbe } from './probe'

type Measure = 'runs' | 'traffic' | 'files'
const MEASURES: { id: Measure; label: string }[] = [
  { id: 'runs', label: 'Runs' },
  { id: 'traffic', label: 'Traffic' },
  { id: 'files', label: 'Files' },
]

const BINS = 28
const DOTS = 24
const FLOOR = 0.012
const COLUMN = {
  name: 'min-w-0 flex-1 @[820px]:w-[200px] @[820px]:flex-none',
  count: 'w-8 shrink-0 text-right',
  launches: 'hidden w-[112px] shrink-0 @[520px]:block',
  bar: 'hidden min-w-0 flex-1 @[820px]:block',
  bytes: 'w-[68px] shrink-0 text-right',
  files: 'hidden w-10 shrink-0 text-right @[420px]:block',
}

function measured(app: App, measure: Measure): number {
  return measure === 'runs' ? app.procs.length : measure === 'traffic' ? app.bytes : app.files
}

function said(app: App, measure: Measure): string {
  if (measure === 'traffic') return bytes(app.bytes)
  if (measure === 'files') return `${app.files} ${app.files === 1 ? 'file touch' : 'file touches'}`
  return `${app.procs.length} ${app.procs.length === 1 ? 'run' : 'runs'}`
}

function Launches({ app, from, to }: { app: App; from: number; to: number }) {
  const bins = new Array<number>(BINS).fill(0)
  const width = Math.max(1, to - from)
  for (const proc of app.procs) {
    const index = Math.min(BINS - 1, Math.floor(((proc.start - from) / width) * BINS))
    bins[index] = (bins[index] ?? 0) + 1
  }
  const peak = Math.max(1, ...bins)
  return (
    <svg viewBox={`0 0 ${BINS * 4} 20`} className={cn(COLUMN.launches, 'h-5')} role="img" aria-label={`${app.procs.length} launches`}>
      <line x1="0" x2={BINS * 4} y1="19.5" y2="19.5" stroke={tone('line')} />
      {bins.map((count, index) =>
        count > 0 ? (
          <rect key={index} x={index * 4} y={19 - (count / peak) * 18} width="3" height={(count / peak) * 18} rx="1" fill={SEVERITY_TONE[app.severity]} />
        ) : null,
      )}
    </svg>
  )
}

function Footprint({
  list,
  measure,
  hot,
  onHot,
  onOpen,
}: {
  list: App[]
  measure: Measure
  hot: string | null
  onHot: (key: string | null) => void
  onOpen: (name: string) => void
}) {
  const [frame, size] = useSize<HTMLDivElement>()
  const tiles = useMemo(() => {
    const total = list.reduce((sum, app) => sum + measured(app, measure), 0)
    const weighted = list
      .filter((app) => measured(app, measure) > 0)
      .map((app) => ({ item: app, value: Math.max(measured(app, measure), total * FLOOR) }))
    return squarify(weighted, size.width, size.height)
  }, [list, measure, size])

  return (
    <div ref={frame} role="group" aria-label="Footprint" className="relative h-[40%] max-h-[280px] min-h-[128px] shrink-0">
      {size.width > 0 && tiles.length === 0 ? (
        <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-line font-mono text-xs text-muted">
          Nothing to size by {measure} on this endpoint.
        </div>
      ) : null}
      {tiles.map(({ item: app, x, y, width, height }) => {
        const alert = app.severity === 'alert'
        const roomy = width > 76 && height > 40
        return (
          <button
            key={app.key}
            type="button"
            data-tile={app.name}
            title={`${app.name}\n${app.path}\n${said(app, measure)}, ${app.running} running`}
            onClick={() => onOpen(app.name)}
            onMouseEnter={() => onHot(app.key)}
            onMouseLeave={() => onHot(null)}
            onFocus={() => onHot(app.key)}
            onBlur={() => onHot(null)}
            className={cn(
              'absolute flex flex-col overflow-hidden rounded-lg border px-2 py-1.5 text-left font-mono transition-colors',
              alert
                ? 'border-alert-line bg-alert-surface hover:border-alert'
                : app.running > 0
                  ? 'border-line-strong bg-raised hover:border-line-hover'
                  : 'border-line bg-row hover:border-line-hover',
              hot === app.key && (alert ? 'border-alert' : 'border-accent'),
            )}
            style={{ left: x + 1.5, top: y + 1.5, width: Math.max(0, width - 3), height: Math.max(0, height - 3) }}
          >
            {width > 46 && height > 22 ? (
              <span className={cn('truncate text-xs leading-tight', alert ? 'text-accent-strong' : app.running > 0 ? 'text-text' : 'text-muted')}>{app.name}</span>
            ) : null}
            {roomy ? <span className={cn('truncate text-[10px]', alert ? 'text-alert-soft' : 'text-muted')}>{said(app, measure)}</span> : null}
            {roomy && height > 62 ? (
              <span className="mt-auto flex flex-wrap gap-[3px]" aria-hidden>
                {app.procs.slice(0, DOTS).map((proc) => (
                  <span
                    key={proc.key}
                    className={cn('h-[7px] w-[7px] rounded-[2px]', proc.end === null ? (alert ? 'bg-alert' : 'bg-soft') : alert ? 'border border-alert-line' : 'border border-faint')}
                  />
                ))}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}

export function AppsLens({ onOpen }: { onOpen: (name: string) => void }) {
  const probe = useProbe()
  const [measure, setMeasure] = useState<Measure>('runs')
  const [hot, setHot] = useState<string | null>(null)
  const list = useMemo(() => apps(probe.model), [probe.model])
  const { from, to, peak, running } = useMemo(() => {
    let first = Infinity
    let last = -Infinity
    let most = 1
    let alive = 0
    for (const app of list) {
      first = Math.min(first, app.first)
      last = Math.max(last, app.last)
      most = Math.max(most, app.bytes)
      if (app.running > 0) alive += 1
    }
    return { from: first, to: last, peak: most, running: alive }
  }, [list])

  if (list.length === 0) return <Empty title="No applications seen" />

  return (
    <div className="absolute inset-0 flex flex-col px-4 pb-3">
      <div className="flex shrink-0 flex-wrap items-center gap-2 pb-2">
        <Segmented label="Size by" value={measure} options={MEASURES} onChange={setMeasure} />
        <span className="ml-auto font-mono text-xs text-muted">
          {list.length} {list.length === 1 ? 'app' : 'apps'} · {running} running
        </span>
      </div>
      <Footprint list={list} measure={measure} hot={hot} onHot={setHot} onOpen={onOpen} />
      <div className="@container mt-2 min-h-0 flex-1 overflow-y-auto rounded-card border border-line bg-surface">
        <div className="sticky top-0 z-10 flex h-8 items-center gap-4 border-b border-line bg-surface px-3 font-display text-[11px] uppercase tracking-wider text-muted">
          <span className="w-2 shrink-0" />
          <span className={COLUMN.name}>App</span>
          <span className={COLUMN.count}>Runs</span>
          <span className={COLUMN.launches}>Launches</span>
          <span className={COLUMN.bar}>Traffic</span>
          <span className={cn(COLUMN.bytes, '@[820px]:invisible')}>Traffic</span>
          <span className={COLUMN.files}>Files</span>
        </div>
        {list.map((app) => (
          <button
            key={app.key}
            type="button"
            data-app={app.name}
            onClick={() => onOpen(app.name)}
            onMouseEnter={() => setHot(app.key)}
            onMouseLeave={() => setHot(null)}
            title={app.path}
            className={cn(
              'flex h-10 w-full items-center gap-4 border-b border-hairline px-3 text-left font-mono text-xs hover:bg-raised',
              app.severity === 'alert' && 'bg-alert-surface/50',
              hot === app.key && 'bg-raised',
            )}
          >
            <span className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[app.severity])} aria-hidden />
            <span className={COLUMN.name}>
              <span className="block truncate text-text">{app.name}</span>
              <span className="block truncate text-[10px] leading-tight text-faint">{app.path}</span>
            </span>
            <span className={cn(COLUMN.count, 'text-soft')} aria-label={`${app.running} running of ${app.procs.length}`}>
              {app.procs.length}
            </span>
            <Launches app={app} from={from} to={to} />
            <span className={cn(COLUMN.bar, 'h-1.5 overflow-hidden rounded-full bg-sunken')} aria-hidden>
              {app.bytes > 0 ? (
                <span
                  className={cn('block h-full rounded-full', app.severity === 'alert' ? 'bg-alert' : 'bg-soft')}
                  style={{ width: `${Math.max(2, (app.bytes / peak) * 100)}%` }}
                />
              ) : null}
            </span>
            <span className={cn(COLUMN.bytes, 'text-soft')}>{app.bytes > 0 ? bytes(app.bytes) : ''}</span>
            <span className={cn(COLUMN.files, 'text-muted')}>{app.files > 0 ? app.files : ''}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
