type Point = { id: string; x: number; y: number }

type Bridge = {
  map?: { nodes: () => (Point & { label: string; state: string })[]; view: () => { scale: number; x: number; y: number } }
  canvas?: { nodes: () => Point[]; viewport: () => { x: number; y: number; zoom: number } }
}

declare global {
  interface Window {
    __zedr?: Bridge
  }
}

export function expose<K extends keyof Bridge>(key: K, value: NonNullable<Bridge[K]>): () => void {
  if (localStorage.getItem('zedr.debug') !== '1') return () => undefined
  const bridge = (window.__zedr ??= {})
  bridge[key] = value
  return () => {
    delete bridge[key]
  }
}
