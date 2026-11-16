import { Chip, CopyButton, PageHeader } from '@/components/ui/bits'
import { count } from '@/lib/chain'
import { cn } from '@/lib/cn'
import { shortHash } from '@/lib/format'
import { useRuleset } from '@/lib/queries'

const GRID = 'grid grid-cols-[minmax(200px,1.5fr)_88px_92px_minmax(150px,1fr)_72px] items-center gap-x-3 px-4'
const LEVEL: Record<string, { label: string; tone: 'alert' | 'warn' | 'neutral' }> = {
  high: { label: 'high', tone: 'alert' },
  medium: { label: 'medium', tone: 'warn' },
  info: { label: 'follow-up', tone: 'neutral' },
}

export function Rules() {
  const { data } = useRuleset()
  const rules = data?.rules ?? []
  const released = rules.reduce((sum, rule) => sum + rule.releases, 0)

  return (
    <div className="absolute inset-0 flex flex-col gap-3 overflow-y-auto px-6 pb-5 pt-4">
      <PageHeader title="Rules" meta={data ? `${rules.length} rules · ${count(released)} ${released === 1 ? 'release' : 'releases'}` : undefined} />
      <p className="max-w-[860px] shrink-0 text-[13px] leading-relaxed text-soft">
        This is everything that can open your data. Endpoints seal what their sensors see, and only a rule on this page, firing on the endpoint,
        releases the events it read. The server cannot open anything else.
      </p>

      <section aria-label="Accepted rule programs" className="shrink-0 rounded-card border border-line bg-surface px-4 py-3">
        <h2 className="font-display text-[11px] uppercase tracking-wider text-muted">Accepted rule programs</h2>
        <p className="mt-1 max-w-[860px] text-xs leading-relaxed text-muted">
          These rules, built into the program a proof is about. A proof counts only when it was made by one of these.
        </p>
        {data && data.image_ids.length === 0 ? (
          <p role="status" className="mt-2 flex flex-wrap items-center gap-2 text-[13px] text-soft">
            <Chip tone="warn">none</Chip>
            This server accepts no rule program, so it can verify no proof. Sealing and releasing work as always, and every window stays unproven.
          </p>
        ) : (
          <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1">
            {data?.image_ids.map((id) => (
              <li key={id} data-image-id={id} className="flex items-center gap-1 font-mono text-[13px] text-sage">
                <span title={id}>{shortHash(id)}</span>
                <CopyButton value={id} label="Copy image ID" className="h-6 w-6" />
              </li>
            ))}
          </ul>
        )}
      </section>

      <div role="table" aria-label="Rules" className="min-w-0 shrink-0 overflow-x-auto rounded-card border border-line bg-surface">
        <div className="min-w-[680px]">
          <div role="row" className={cn(GRID, 'h-8 border-b border-line text-[11px] uppercase tracking-wider text-muted')}>
            <span role="columnheader">Rule</span>
            <span role="columnheader">Technique</span>
            <span role="columnheader">Level</span>
            <span role="columnheader">A match opens</span>
            <span role="columnheader" className="text-right">
              Releases
            </span>
          </div>
          {rules.map((rule) => {
            const level = LEVEL[rule.level] ?? { label: rule.level, tone: 'neutral' as const }
            return (
              <div key={rule.id} role="row" data-rule={rule.id} className={cn(GRID, 'min-h-[46px] border-b border-hairline py-1.5 last:border-b-0')}>
                <span role="cell" className="min-w-0">
                  <span className="block truncate text-[13px] text-text" title={rule.title}>
                    {rule.title}
                  </span>
                  <span className="block truncate font-mono text-[11px] text-faint">{rule.id}</span>
                </span>
                <span role="cell" className="font-mono text-xs text-soft">
                  {rule.technique}
                </span>
                <span role="cell">
                  <Chip tone={level.tone}>{level.label}</Chip>
                </span>
                <span role="cell" className="text-[13px] text-soft">
                  {rule.opens}
                </span>
                <span role="cell" className={cn('text-right font-mono text-xs', rule.releases > 0 ? 'text-text' : 'text-faint')}>
                  {count(rule.releases)}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
