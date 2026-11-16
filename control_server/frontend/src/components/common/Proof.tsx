import { Link } from '@tanstack/react-router'
import { Lock } from 'lucide-react'
import { Chip } from '@/components/ui/bits'
import { count, indices, PROOF_CHIP, PROOF_SAID } from '@/lib/chain'
import { cn } from '@/lib/cn'
import { proofOf, releaseOf, type Finding, type ProofStatus } from '@/lib/findings'
import { useChain, useWindow } from '@/lib/queries'

export function ProofChip({ status, className }: { status: ProofStatus; className?: string }) {
  return (
    <Chip tone={PROOF_CHIP[status].tone} title={PROOF_SAID[status]} className={className}>
      {PROOF_CHIP[status].label}
    </Chip>
  )
}

export function FindingProof({ agentId, finding, className }: { agentId: string; finding: Finding; className?: string }) {
  const { data: window } = useWindow(agentId, finding.window)
  if (finding.window === null || finding.trigger === null) return null
  const context = releaseOf(finding, window)?.context ?? []
  return (
    <div data-finding-proof={finding.rule} className={cn('flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[11px] text-muted', className)}>
      <ProofChip status={proofOf(finding, window)} />
      <Link to="/endpoints" search={{ host: agentId, view: 'agent', win: finding.window }} className="text-steel hover:underline">
        window {finding.window}
      </Link>
      <span>
        opened by this match: trigger #{finding.trigger}
        {context.length > 0 ? `, context ${indices(context)}` : ''}
      </span>
    </div>
  )
}

export function SealedCount({ agentId, className }: { agentId: string; className?: string }) {
  const { data: chain } = useChain(agentId)
  if (!chain) return null
  const { events, opened } = chain.totals
  return (
    <span
      data-sealed-count
      title="Events this endpoint committed and sealed, and how many of them a rule match opened. The views show the opened ones only."
      className={cn('inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs text-steel', className)}
    >
      <Lock size={13} strokeWidth={1.75} aria-hidden />
      {count(events - opened)} sealed · {count(opened)} opened
    </span>
  )
}
