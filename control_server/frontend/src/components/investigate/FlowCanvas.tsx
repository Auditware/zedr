import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useStore,
  useStoreApi,
  type Edge,
  type Node,
  type NodeMouseHandler,
  type NodeTypes,
  type Viewport,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import './flow.css'
import { useCallback, useEffect, useRef, type KeyboardEvent, type ReactNode, type RefObject } from 'react'
import { cn } from '@/lib/cn'
import { expose } from '@/lib/debug'

export type Spot = { key: string; x: number; y: number; width: number; height: number }

type Props<N extends Node> = {
  label: string
  nodes: N[]
  edges: Edge[]
  nodeTypes: NodeTypes
  cam: Viewport | null
  onCam: (viewport: Viewport) => void
  home: Spot | null
  lead: Spot | null
  spot: Spot | null
  anchor: string | null
  homeKey: string
  minimapColor: (node: N) => string
  onNodeClick: NodeMouseHandler<N>
  onPaneClick: () => void
  onKeyDown?: (event: KeyboardEvent<HTMLDivElement>) => void
  children?: ReactNode
}

const READABLE = 0.7
const FAR = 0.45
const MARGIN = 56
const TIGHT = 560

function Camera<N extends Node>({
  nodes,
  cam,
  home,
  lead,
  spot,
  anchor,
  homeKey,
  touched,
}: Pick<Props<N>, 'nodes' | 'cam' | 'home' | 'lead' | 'spot' | 'anchor' | 'homeKey'> & { touched: RefObject<boolean> }) {
  const flow = useReactFlow()
  const store = useStoreApi()
  const ready = useStore((state) => state.width > 0 && state.height > 0)
  const paneWidth = useStore((state) => state.width)
  const paneHeight = useStore((state) => state.height)
  const placed = useRef(false)
  const lastSpot = useRef<string | null>(null)
  const lastHome = useRef(homeKey)
  const positions = useRef(new Map<string, { x: number; y: number }>())
  const still = useRef(window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  const goHome = useCallback(() => {
    const { width, height } = store.getState()
    if (spot) {
      void flow.setCenter(spot.x + spot.width / 2, spot.y + spot.height / 2, { zoom: 1, duration: 0 })
      return
    }
    if (lead) {
      const tight = width < TIGHT
      const zoom = tight ? 0.8 : 0.9
      const x = tight ? width - MARGIN / 2 - (lead.x + lead.width) * zoom : width * 0.66 - (lead.x + lead.width / 2) * zoom
      void flow.setViewport({ x, y: height / 2 - (lead.y + lead.height / 2) * zoom, zoom }, { duration: 0 })
      return
    }
    let maxX = 0
    let maxY = 0
    for (const node of nodes) {
      maxX = Math.max(maxX, node.position.x + (node.width ?? 0))
      maxY = Math.max(maxY, node.position.y + (node.height ?? 0))
    }
    const fits = Math.min((width - MARGIN * 2) / maxX, (height - MARGIN * 2) / maxY) >= READABLE
    if (fits || !home) {
      void flow.fitView({ padding: 0.08, maxZoom: 1, duration: 0 })
      return
    }
    const zoom = 0.9
    void flow.setViewport({ x: MARGIN - home.x * zoom, y: height / 2 - (home.y + home.height / 2) * zoom, zoom }, { duration: 0 })
  }, [flow, store, nodes, home, lead, spot])

  useEffect(() => {
    const before = positions.current
    positions.current = new Map(nodes.map((node) => [node.id, node.position]))
    if (!ready || nodes.length === 0) return
    if (!placed.current) {
      placed.current = true
      lastSpot.current = spot?.key ?? null
      if (!cam) goHome()
      return
    }
    if (lastHome.current !== homeKey) {
      lastHome.current = homeKey
      goHome()
      return
    }
    const was = anchor ? before.get(anchor) : undefined
    const now = anchor ? positions.current.get(anchor) : undefined
    if (!was || !now || (was.x === now.x && was.y === now.y)) return
    const [tx, ty, zoom] = store.getState().transform
    void flow.setViewport({ x: tx + (was.x - now.x) * zoom, y: ty + (was.y - now.y) * zoom, zoom }, { duration: 0 })
    // placement follows the layout, not every prop identity
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, nodes, homeKey])

  useEffect(() => {
    if (placed.current && !touched.current && !cam) goHome()
    // only a pane that changed size before the analyst moved the view is placed again
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paneWidth, paneHeight])

  useEffect(() => {
    if (!placed.current || !spot || spot.key === lastSpot.current) return
    lastSpot.current = spot.key
    const { width, height, transform } = store.getState()
    const [tx, ty, zoom] = transform
    const left = spot.x * zoom + tx
    const top = spot.y * zoom + ty
    const inView =
      left >= MARGIN && top >= MARGIN && left + spot.width * zoom <= width - MARGIN && top + spot.height * zoom <= height - MARGIN
    if (inView && zoom >= FAR) return
    void flow.setCenter(spot.x + spot.width / 2, spot.y + spot.height / 2, {
      zoom: Math.max(zoom, 0.9),
      duration: still.current ? 0 : 320,
    })
  }, [spot, flow, store])

  useEffect(
    () =>
      expose('canvas', {
        viewport: () => flow.getViewport(),
        nodes: () => {
          const { transform, domNode } = store.getState()
          const origin = domNode?.getBoundingClientRect()
          const [tx, ty, zoom] = transform
          return flow.getNodes().map((node) => ({
            id: node.id,
            x: (origin?.left ?? 0) + node.position.x * zoom + tx + ((node.width ?? 0) * zoom) / 2,
            y: (origin?.top ?? 0) + node.position.y * zoom + ty + ((node.height ?? 0) * zoom) / 2,
          }))
        },
      }),
    [flow, store],
  )

  return null
}

function Surface<N extends Node>(props: Props<N>) {
  const far = useStore((state) => state.transform[2] < FAR)
  const roomy = useStore((state) => state.width >= TIGHT)
  const { cam, onCam } = props
  const initial = useRef(cam)
  const touched = useRef(false)

  return (
    <div
      role="application"
      aria-label={props.label}
      tabIndex={0}
      onKeyDown={props.onKeyDown}
      className="absolute inset-0 outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-line-hover"
    >
      <ReactFlow
        nodes={props.nodes}
        edges={props.edges}
        nodeTypes={props.nodeTypes}
        defaultViewport={initial.current ?? undefined}
        onMoveStart={(event) => {
          if (event) touched.current = true
        }}
        onMoveEnd={(_, viewport) => onCam(viewport)}
        onNodeClick={props.onNodeClick}
        onPaneClick={props.onPaneClick}
        minZoom={0.08}
        maxZoom={2}
        panOnDrag
        panOnScroll
        panOnScrollSpeed={1}
        zoomOnScroll={false}
        zoomOnPinch
        zoomOnDoubleClick={false}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        elementsSelectable={false}
        disableKeyboardA11y
        deleteKeyCode={null}
        onlyRenderVisibleElements={props.nodes.length > 600}
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
        className={cn('group/flow', far && 'far')}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} />
        <Controls showInteractive={false} position="bottom-right" orientation="horizontal" />
        {roomy ? (
          <MiniMap
            pannable
            zoomable
            position="bottom-right"
            nodeColor={props.minimapColor}
            nodeStrokeWidth={0}
            nodeBorderRadius={6}
            ariaLabel="Overview"
            style={{ width: 148, height: 96, marginBottom: 52 }}
          />
        ) : null}
        <Camera
          nodes={props.nodes}
          cam={initial.current}
          home={props.home}
          lead={props.lead}
          spot={props.spot}
          anchor={props.anchor}
          homeKey={props.homeKey}
          touched={touched}
        />
        {props.children}
      </ReactFlow>
    </div>
  )
}

export function FlowCanvas<N extends Node>(props: Props<N>) {
  return (
    <ReactFlowProvider>
      <Surface {...props} />
    </ReactFlowProvider>
  )
}
