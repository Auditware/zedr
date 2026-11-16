export type Tone =
  | 'ink'
  | 'sunken'
  | 'hairline'
  | 'line'
  | 'line-strong'
  | 'line-hover'
  | 'text'
  | 'soft'
  | 'muted'
  | 'faint'
  | 'accent'
  | 'node'
  | 'warn'
  | 'alert'
  | 'steel'
  | 'mauve'
  | 'sage'

export function tone(name: Tone): string {
  return `var(--color-${name})`
}

export function resolveTone(name: Tone): string {
  return getComputedStyle(document.documentElement).getPropertyValue(`--color-${name}`).trim()
}

export function toneNumber(name: Tone): number {
  return Number.parseInt(resolveTone(name).slice(1), 16)
}
