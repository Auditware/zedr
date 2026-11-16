import type { Application, Container, Sprite, Texture } from 'pixi.js'
import { useEffect, useRef, useState } from 'react'
import { ZoomControls } from '@/components/ui/zoom-controls'
import { cn } from '@/lib/cn'
import { expose } from '@/lib/debug'
import { fitView, STATE_LABEL, type Layout, type NodeState, type View } from '@/lib/map-layout'
import { toneNumber, type Tone } from '@/lib/palette'
import { wheelIntent, zoomAt } from '@/lib/pan-zoom'

export type MapNode = { id: string; label: string; state: NodeState }

type Item = { node: MapNode; dot: Sprite; aura: Sprite | null; x: number; y: number; tx: number; ty: number }

type Scene = {
  app: Application
  auras: Container
  dots: Container
  selection: Sprite
  disc: Texture
  ring: Texture
  SpriteClass: typeof Sprite
  items: Map<string, Item>
  view: View
  userMoved: boolean
  hover: string | null
  selected: string | null
  focus: Set<string> | null
  clock: number
  frame: () => void
  zoomBy: (factor: number) => void
}

const DOT_RADIUS = 4.2
const TEXTURE_RADIUS = 16
const MIN_SCALE = 0.08
const MAX_SCALE = 8

const STYLE: Record<NodeState, { hollow: boolean; tone: Tone; radius: number }> = {
  active: { hollow: false, tone: 'node', radius: DOT_RADIUS },
  stale: { hollow: true, tone: 'soft', radius: DOT_RADIUS },
  suspect: { hollow: true, tone: 'warn', radius: DOT_RADIUS * 1.15 },
  incident: { hollow: false, tone: 'alert', radius: DOT_RADIUS * 1.5 },
  stopped: { hollow: true, tone: 'faint', radius: DOT_RADIUS },
}

type Props = {
  nodes: MapNode[]
  layout: Layout
  selectedId: string | undefined
  selectedGroup: string | undefined
  focusIds: string[] | null
  onSelect: (id: string | null) => void
  onSelectGroup: (key: string) => void
}

export function EndpointMap({
  nodes,
  layout,
  selectedId,
  selectedGroup,
  focusIds,
  onSelect,
  onSelectGroup,
}: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const sceneRef = useRef<Scene | null>(null)
  const latest = useRef({ layout, onSelect })
  latest.current = { layout, onSelect }
  const [ready, setReady] = useState(false)
  const [view, setView] = useState<View>({ scale: 1, x: 0, y: 0 })
  const [hover, setHover] = useState<string | null>(null)

  useEffect(() => {
    const host = hostRef.current
    if (!host) return
    let cancelled = false
    let teardown = () => undefined as void
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    void (async () => {
      const { Application, Container, Graphics, Sprite } = await import('pixi.js')
      const app = new Application()
      await app.init({
        resizeTo: host,
        backgroundAlpha: 0,
        antialias: true,
        autoDensity: true,
        resolution: Math.min(2, window.devicePixelRatio || 1),
      })
      if (cancelled) {
        app.destroy(true, { children: true, texture: true })
        return
      }
      host.prepend(app.canvas)
      app.canvas.style.display = 'block'

      const disc = app.renderer.generateTexture({
        target: new Graphics().circle(0, 0, TEXTURE_RADIUS).fill({ color: 0xffffff }),
        resolution: 4,
        antialias: true,
      })
      const ring = app.renderer.generateTexture({
        target: new Graphics().circle(0, 0, TEXTURE_RADIUS - 2).stroke({ width: 4.5, color: 0xffffff }),
        resolution: 4,
        antialias: true,
      })

      const world = new Container()
      const auras = new Container()
      const dots = new Container()
      const selection = new Sprite(ring)
      selection.anchor.set(0.5)
      selection.visible = false
      world.addChild(auras, dots, selection)
      app.stage.addChild(world)

      const applyView = (next: View) => {
        scene.view = next
        world.position.set(next.x, next.y)
        world.scale.set(next.scale)
        setView(next)
      }

      const frame = () => {
        const width = host.clientWidth
        const height = host.clientHeight
        if (scene.focus && scene.focus.size > 0) {
          const bounds = { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity }
          for (const id of scene.focus) {
            const point = latest.current.layout.points.get(id)
            if (!point) continue
            bounds.minX = Math.min(bounds.minX, point.x)
            bounds.maxX = Math.max(bounds.maxX, point.x)
            bounds.minY = Math.min(bounds.minY, point.y)
            bounds.maxY = Math.max(bounds.maxY, point.y)
          }
          if (Number.isFinite(bounds.minX)) {
            const pad = scene.focus.size === 1 ? 90 : 40
            const fitted = fitView(
              { minX: bounds.minX - pad, minY: bounds.minY - pad, maxX: bounds.maxX + pad, maxY: bounds.maxY + pad + 30 },
              width,
              height,
            )
            scene.userMoved = false
            applyView(fitted)
            return
          }
        }
        scene.userMoved = false
        applyView(fitView(latest.current.layout.bounds, width, height))
      }

      const scene: Scene = {
        app,
        auras,
        dots,
        selection,
        disc,
        ring,
        SpriteClass: Sprite,
        items: new Map(),
        view: { scale: 1, x: 0, y: 0 },
        userMoved: false,
        hover: null,
        selected: null,
        focus: null,
        clock: 0,
        frame,
        zoomBy: (factor) => {
          scene.userMoved = true
          applyView(zoomAt(scene.view, host.clientWidth / 2, host.clientHeight / 2, factor, MIN_SCALE, MAX_SCALE))
        },
      }
      sceneRef.current = scene
      const hide = expose('map', {
        view: () => scene.view,
        nodes: () => {
          const rect = host.getBoundingClientRect()
          return [...scene.items].map(([id, item]) => ({
            id,
            label: item.node.label,
            state: item.node.state,
            x: rect.left + item.x * scene.view.scale + scene.view.x,
            y: rect.top + item.y * scene.view.scale + scene.view.y,
          }))
        },
      })

      const pick = (clientX: number, clientY: number): string | null => {
        const rect = host.getBoundingClientRect()
        const wx = (clientX - rect.left - scene.view.x) / scene.view.scale
        const wy = (clientY - rect.top - scene.view.y) / scene.view.scale
        let best: string | null = null
        let bestDistance = Math.max(DOT_RADIUS * 2, 11 / scene.view.scale)
        for (const [id, item] of scene.items) {
          const distance = Math.hypot(item.x - wx, item.y - wy)
          if (distance < bestDistance) {
            bestDistance = distance
            best = id
          }
        }
        return best
      }

      let drag: { x: number; y: number; moved: boolean } | null = null
      const touches = new Map<number, { x: number; y: number }>()
      let pinch: { distance: number; x: number; y: number } | null = null
      const measure = () => {
        const [a, b] = [...touches.values()]
        if (!a || !b) return null
        return { distance: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y)), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }
      }
      const onDown = (event: PointerEvent) => {
        if (event.target !== app.canvas) return
        touches.set(event.pointerId, { x: event.clientX, y: event.clientY })
        host.setPointerCapture(event.pointerId)
        if (touches.size === 2) {
          drag = null
          pinch = measure()
          return
        }
        drag = { x: event.clientX, y: event.clientY, moved: false }
      }
      const onMove = (event: PointerEvent) => {
        if (touches.has(event.pointerId)) touches.set(event.pointerId, { x: event.clientX, y: event.clientY })
        const spread = pinch ? measure() : null
        if (pinch && spread) {
          const rect = host.getBoundingClientRect()
          const zoomed = zoomAt(scene.view, pinch.x - rect.left, pinch.y - rect.top, spread.distance / pinch.distance, MIN_SCALE, MAX_SCALE)
          scene.userMoved = true
          applyView({ scale: zoomed.scale, x: zoomed.x + spread.x - pinch.x, y: zoomed.y + spread.y - pinch.y })
          pinch = spread
          return
        }
        if (drag) {
          const dx = event.clientX - drag.x
          const dy = event.clientY - drag.y
          if (drag.moved || Math.hypot(dx, dy) > 3) {
            drag = { x: event.clientX, y: event.clientY, moved: true }
            scene.userMoved = true
            host.style.cursor = 'grabbing'
            applyView({ ...scene.view, x: scene.view.x + dx, y: scene.view.y + dy })
            return
          }
        }
        const id = event.target === app.canvas || drag ? pick(event.clientX, event.clientY) : null
        if (id !== scene.hover) {
          scene.hover = id
          setHover(id)
          host.style.cursor = id ? 'pointer' : 'grab'
        }
      }
      const onUp = (event: PointerEvent) => {
        touches.delete(event.pointerId)
        if (host.hasPointerCapture(event.pointerId)) host.releasePointerCapture(event.pointerId)
        if (pinch) {
          pinch = null
          drag = null
          return
        }
        if (!drag) return
        const wasDrag = drag.moved
        drag = null
        host.style.cursor = 'grab'
        if (!wasDrag && event.type === 'pointerup') latest.current.onSelect(pick(event.clientX, event.clientY))
      }
      const onLeave = () => {
        scene.hover = null
        setHover(null)
      }
      const onWheel = (event: WheelEvent) => {
        event.preventDefault()
        const rect = host.getBoundingClientRect()
        const intent = wheelIntent(event)
        scene.userMoved = true
        if (intent.kind === 'pan') {
          applyView({ ...scene.view, x: scene.view.x + intent.dx, y: scene.view.y + intent.dy })
        } else {
          applyView(zoomAt(scene.view, event.clientX - rect.left, event.clientY - rect.top, intent.factor, MIN_SCALE, MAX_SCALE))
        }
      }

      host.addEventListener('pointerdown', onDown)
      host.addEventListener('pointermove', onMove)
      host.addEventListener('pointerup', onUp)
      host.addEventListener('pointercancel', onUp)
      host.addEventListener('pointerleave', onLeave)
      host.addEventListener('wheel', onWheel, { passive: false })

      const resize = new ResizeObserver(() => {
        app.resize()
        if (!scene.userMoved) frame()
      })
      resize.observe(host)

      app.ticker.add((ticker) => {
        scene.clock += ticker.deltaMS
        const ease = still ? 1 : 1 - Math.pow(0.001, ticker.deltaMS / 700)
        const beat = (scene.clock % 1800) / 1800
        for (const [id, item] of scene.items) {
          item.x += (item.tx - item.x) * ease
          item.y += (item.ty - item.y) * ease
          item.dot.position.set(item.x, item.y)
          const base = STYLE[item.node.state].radius / TEXTURE_RADIUS
          const dim = scene.focus !== null && !scene.focus.has(id)
          item.dot.scale.set(id === scene.hover ? base * 1.6 : base)
          item.dot.alpha = dim ? 0.28 : 1
          if (item.aura) {
            item.aura.position.set(item.x, item.y)
            item.aura.scale.set(base * (1 + (still ? 0.8 : beat * 2.6)))
            item.aura.alpha = (still ? 0.25 : 0.55 * (1 - beat)) * (dim ? 0.4 : 1)
          }
        }
        const selected = scene.selected ? scene.items.get(scene.selected) : undefined
        scene.selection.visible = !!selected
        if (selected) {
          scene.selection.position.set(selected.x, selected.y)
          scene.selection.scale.set((STYLE[selected.node.state].radius + 5) / TEXTURE_RADIUS)
        }
      })

      teardown = () => {
        resize.disconnect()
        host.removeEventListener('pointerdown', onDown)
        host.removeEventListener('pointermove', onMove)
        host.removeEventListener('pointerup', onUp)
        host.removeEventListener('pointercancel', onUp)
        host.removeEventListener('pointerleave', onLeave)
        host.removeEventListener('wheel', onWheel)
        hide()
        sceneRef.current = null
        app.destroy(true, { children: true, texture: true })
      }
      setReady(true)
    })()

    return () => {
      cancelled = true
      teardown()
    }
  }, [])

  const focusKey = focusIds ? focusIds.join(',') : ''

  useEffect(() => {
    const scene = sceneRef.current
    if (!ready || !scene) return
    const seen = new Set<string>()

    for (const node of nodes) {
      const point = layout.points.get(node.id)
      if (!point) continue
      seen.add(node.id)
      let item = scene.items.get(node.id)
      if (!item) {
        const dot = new scene.SpriteClass(scene.disc)
        dot.anchor.set(0.5)
        scene.dots.addChild(dot)
        item = { node, dot, aura: null, x: point.x, y: point.y, tx: point.x, ty: point.y }
        scene.items.set(node.id, item)
      }
      item.node = node
      item.tx = point.x
      item.ty = point.y

      const style = STYLE[node.state]
      item.dot.texture = style.hollow ? scene.ring : scene.disc
      item.dot.tint = toneNumber(style.tone)

      const wantsAura = node.state === 'incident'
      if (wantsAura && !item.aura) {
        item.aura = new scene.SpriteClass(scene.disc)
        item.aura.anchor.set(0.5)
        scene.auras.addChild(item.aura)
      } else if (!wantsAura && item.aura) {
        item.aura.destroy()
        item.aura = null
      }
      if (item.aura) item.aura.tint = toneNumber('alert')
    }

    for (const [id, item] of scene.items) {
      if (seen.has(id)) continue
      item.dot.destroy()
      item.aura?.destroy()
      scene.items.delete(id)
    }

    scene.selected = selectedId ?? null
    scene.focus = focusIds ? new Set(focusIds) : null
    if (!scene.userMoved) scene.frame()
    // focusIds is tracked through focusKey
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, layout, ready, selectedId, focusKey])

  useEffect(() => {
    const scene = sceneRef.current
    if (ready && scene) scene.frame()
  }, [focusKey, ready])

  const hovered = hover ? nodes.find((node) => node.id === hover) : undefined
  const hoveredPoint = hover ? layout.points.get(hover) : undefined

  return (
    <div
      ref={hostRef}
      role="img"
      aria-label={`Map of ${nodes.length} endpoints`}
      className="absolute inset-0 cursor-grab touch-none select-none overflow-hidden"
    >
      {layout.groups.map((group) => (
        <button
          key={group.key}
          type="button"
          onClick={() => onSelectGroup(group.key)}
          className={cn(
            'absolute left-0 top-0 whitespace-nowrap rounded-md px-1.5 py-0.5 text-center hover:bg-raised',
            selectedGroup === group.key && 'bg-raised outline outline-1 outline-accent',
          )}
          style={{
            transform: `translate(${group.x * view.scale + view.x}px, ${(group.y + group.r) * view.scale + view.y + 2}px) translateX(-50%)`,
          }}
        >
          <span className="block font-display text-[13px] font-medium text-soft">{group.key}</span>
          <span className="block font-mono text-[11px] text-muted">{group.count}</span>
        </button>
      ))}
      {hovered && hoveredPoint ? (
        <div
          className="pointer-events-none absolute left-0 top-0 z-10 rounded-md border border-line-strong bg-raised px-2 py-1 shadow-lg"
          style={{
            transform: `translate(${hoveredPoint.x * view.scale + view.x + 12}px, ${hoveredPoint.y * view.scale + view.y - 30}px)`,
          }}
        >
          <span className="font-mono text-xs text-text">{hovered.label}</span>
          <span className="ml-2 text-[11px] text-muted">{STATE_LABEL[hovered.state]}</span>
        </div>
      ) : null}
      <ZoomControls
        onZoomIn={() => sceneRef.current?.zoomBy(1.4)}
        onZoomOut={() => sceneRef.current?.zoomBy(1 / 1.4)}
        onFit={() => sceneRef.current?.frame()}
      />
    </div>
  )
}
