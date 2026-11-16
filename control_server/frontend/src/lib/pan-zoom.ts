export type View = { scale: number; x: number; y: number }

export function zoomAt(view: View, px: number, py: number, factor: number, min: number, max: number): View {
  const scale = Math.min(max, Math.max(min, view.scale * factor))
  const ratio = scale / view.scale
  return { scale, x: px - (px - view.x) * ratio, y: py - (py - view.y) * ratio }
}

export type WheelIntent = { kind: 'zoom'; factor: number } | { kind: 'pan'; dx: number; dy: number }

type WheelLike = { deltaX: number; deltaY: number; deltaMode: number; ctrlKey: boolean; metaKey: boolean }

export function wheelIntent(event: WheelLike): WheelIntent {
  const unit = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? 400 : 1
  if (event.ctrlKey || event.metaKey) {
    const delta = Math.max(-40, Math.min(40, event.deltaY * unit))
    return { kind: 'zoom', factor: Math.exp(-delta * 0.012) }
  }
  return { kind: 'pan', dx: -event.deltaX * unit, dy: -event.deltaY * unit }
}
