import type { Viewport } from '@xyflow/react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Empty } from '@/components/ui/bits'
import { FindBox } from '@/components/ui/find-box'
import { Segmented } from '@/components/ui/segmented'
import { inPeriod, type Period } from '@/lib/activity'
import type { Moment } from '@/lib/persistence'
import {
  alertTrail,
  expose,
  findProcs,
  hotSet,
  layoutProcessTree,
  lineage,
  ROOT,
  shownCount,
  type Focus,
  type ProcessModel,
  type TreeOptions,
} from '@/lib/process-tree'
import { FilesLens } from './FilesLens'
import { NetworkGraph } from './NetworkGraph'
import { ProcessGraph } from './ProcessGraph'
import { ProcessList } from './ProcessList'
import { ProbeContext, type Probe } from './probe'
import { SealedList } from './SealedList'

export type Lens = 'processes' | 'network' | 'files' | 'persistence' | 'sealed' | 'agent'
export type Arrangement = 'tree' | 'list'

export type InvestigationState = {
  lens: Lens
  arrangement: Arrangement
  focus: Focus | undefined
  find: string
  proc: string | null
  item: string | null
  window: number | null
  when: Moment | null
  cam: Viewport | null
  period: Period | null
}

type Props = {
  agentId: string
  model: ProcessModel
  loading: boolean
  now: number
  state: InvestigationState
  onChange: (patch: Partial<InvestigationState>) => void
}

const FOCUS: { id: Focus; label: string }[] = [
  { id: 'notable', label: 'Notable' },
  { id: 'all', label: 'All' },
]
const ARRANGEMENTS: { id: Arrangement; label: string }[] = [
  { id: 'tree', label: 'Tree' },
  { id: 'list', label: 'List' },
]
const BUSY_TREE = 60

export default function Investigation({ agentId, model, loading, now, state, onChange }: Props) {
  const hot = useMemo(() => hotSet(model), [model])
  const focus: Focus = state.focus ?? (hot.size > 0 && model.all.length > BUSY_TREE ? 'notable' : 'all')
  const [folds, setFolds] = useState<{ folded: Set<string>; opened: Set<string> }>({ folded: new Set(), opened: new Set() })
  const options = useMemo<TreeOptions>(() => ({ focus, folded: folds.folded, opened: folds.opened }), [focus, folds])
  const layout = useMemo(() => layoutProcessTree(model, options), [model, options])
  const selected = state.proc ? model.byKey.get(state.proc) : undefined
  const findRef = useRef<HTMLInputElement>(null)
  const [anchor, setAnchor] = useState<string | null>(null)

  useEffect(() => {
    if (!selected || layout.nodeOf.get(selected.key) === selected.key) return
    const next = expose(selected, options, hot)
    setFolds({ folded: new Set(next.folded), opened: new Set(next.opened) })
  }, [selected, layout, options, hot])

  const inside = useMemo(
    () => (state.period ? new Set(model.all.filter((proc) => inPeriod(proc, state.period!)).map((proc) => proc.key)) : null),
    [model, state.period],
  )
  const found = useMemo(() => {
    const hits = findProcs(model, state.find)
    return inside ? hits.filter((proc) => inside.has(proc.key)) : hits
  }, [model, state.find, inside])
  const position = selected ? found.indexOf(selected) : -1

  const probe = useMemo<Probe>(
    () => ({
      agentId,
      model,
      layout,
      focus,
      anchor,
      selectedKey: selected?.key ?? null,
      lineage: new Set(selected ? lineage(selected).map((proc) => proc.key) : []),
      trail: alertTrail(model),
      matches: state.find.trim() ? new Set(found.map((proc) => proc.key)) : inside,
      onSelect: (key) => {
        if (key) setAnchor(key)
        onChange({ proc: key })
      },
      onFold: (key) => {
        setAnchor(key)
        setFolds((current) => {
          const folded = new Set(current.folded)
          if (folded.has(key)) folded.delete(key)
          else folded.add(key)
          return { folded, opened: current.opened }
        })
      },
      onOpen: (groupId) => {
        const parent = groupId.slice(0, groupId.lastIndexOf('/'))
        setAnchor(parent === ROOT ? null : parent)
        setFolds((current) => ({ folded: current.folded, opened: new Set(current.opened).add(groupId) }))
      },
    }),
    [agentId, model, layout, focus, anchor, selected, state.find, found, inside, onChange],
  )

  const jump = (direction: 1 | -1) => {
    if (found.length === 0) return
    const next = found[(position + direction + found.length) % found.length]!
    onChange({ proc: next.key })
  }

  if (model.all.length === 0) {
    return loading ? <Empty title="Loading opened events" /> : <SealedList agentId={agentId} />
  }

  const onCam = (cam: Viewport) => onChange({ cam })
  const shown = shownCount(layout)

  return (
    <ProbeContext.Provider value={probe}>
      <div
        className="absolute inset-0 flex flex-col"
        onKeyDown={(event) => {
          if (event.key === '/' && !(event.target instanceof HTMLInputElement)) {
            event.preventDefault()
            findRef.current?.focus()
          }
        }}
      >
        {state.lens === 'processes' ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2 px-4 pb-2">
            <FindBox
              value={state.find}
              onChange={(find) => onChange({ find })}
              onEnter={(backwards) => jump(backwards ? -1 : 1)}
              placeholder="Find process, command, pid"
              label="Find in processes"
              inputRef={findRef}
            >
              <span className="shrink-0 font-mono text-[11px] text-muted" aria-live="polite">
                {found.length === 0 ? '0' : `${position + 1 || '-'}/${found.length}`}
              </span>
              <button type="button" aria-label="Previous match" onClick={() => jump(-1)} className="shrink-0 rounded text-muted hover:text-text">
                <ChevronUp size={15} strokeWidth={1.5} aria-hidden />
              </button>
              <button type="button" aria-label="Next match" onClick={() => jump(1)} className="shrink-0 rounded text-muted hover:text-text">
                <ChevronDown size={15} strokeWidth={1.5} aria-hidden />
              </button>
            </FindBox>
            {hot.size > 0 ? <Segmented label="Show" value={focus} options={FOCUS} onChange={(next) => onChange({ focus: next })} /> : null}
            <Segmented label="Layout" value={state.arrangement} options={ARRANGEMENTS} onChange={(next) => onChange({ arrangement: next })} />
            <span className="ml-auto font-mono text-xs text-muted">
              {inside
                ? `${inside.size} in the time window`
                : shown === model.all.length
                  ? `${shown} processes`
                  : `${shown} of ${model.all.length} processes`}
            </span>
          </div>
        ) : null}
        <div className="relative min-h-0 flex-1">
          {state.lens === 'processes' && state.arrangement === 'tree' ? <ProcessGraph cam={state.cam} onCam={onCam} /> : null}
          {state.lens === 'processes' && state.arrangement === 'list' ? <ProcessList now={now} /> : null}
          {state.lens === 'network' ? <NetworkGraph cam={state.cam} onCam={onCam} /> : null}
          {state.lens === 'files' ? <FilesLens period={state.period} find={state.find} onFind={(find) => onChange({ find })} /> : null}
        </div>
      </div>
    </ProbeContext.Provider>
  )
}
