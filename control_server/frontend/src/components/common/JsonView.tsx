import { Fragment, type ReactNode } from 'react'
import { cn } from '@/lib/cn'

const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g

function colorize(source: string): ReactNode[] {
  const out: ReactNode[] = []
  let last = 0
  let key = 0
  for (const match of source.matchAll(TOKEN)) {
    const index = match.index
    if (index > last) out.push(<Fragment key={key++}>{source.slice(last, index)}</Fragment>)
    const [whole, str, colon, literal, number] = match
    if (str && colon) {
      out.push(<span key={key++} className="text-steel">{str}</span>, <Fragment key={key++}>{colon}</Fragment>)
    } else if (str) {
      out.push(<span key={key++} className="text-soft">{str}</span>)
    } else if (literal) {
      out.push(<span key={key++} className="text-warn">{literal}</span>)
    } else if (number) {
      out.push(<span key={key++} className="text-sage">{number}</span>)
    } else {
      out.push(<Fragment key={key++}>{whole}</Fragment>)
    }
    last = index + whole.length
  }
  if (last < source.length) out.push(<Fragment key={key++}>{source.slice(last)}</Fragment>)
  return out
}

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  let source: string
  if (typeof value === 'string') {
    try {
      source = JSON.stringify(JSON.parse(value), null, 2)
    } catch {
      source = value
    }
  } else {
    source = JSON.stringify(value, null, 2)
  }

  return (
    <pre className={cn('overflow-auto whitespace-pre-wrap break-all rounded-control bg-sunken p-3 font-mono text-xs leading-relaxed text-muted', className)}>
      {colorize(source)}
    </pre>
  )
}
